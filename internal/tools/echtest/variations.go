package echtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/OmarTariq612/goech"
	"github.com/sirupsen/logrus"

	"github.com/jmuecke/echtools/internal/cli"
	"github.com/jmuecke/echtools/pkg/dial"
	"github.com/jmuecke/echtools/pkg/dnsrr"
	"github.com/jmuecke/echtools/pkg/ech"
	"github.com/jmuecke/echtools/pkg/echfmt"
)

// Outcome of offering a varied config, used both as the JSON "status" value and
// as the STATUS column in table/text output.
const (
	statusAccepted    = "accepted"
	statusRejected    = "rejected"
	statusNotAccepted = "not_accepted"
	statusFailed      = "failed"
	statusError       = "error"
)

// variationResult is the outcome of one testVariation call: which field was
// varied, its baseline and replaced values, the result, and the configs
// involved (the offered config, and the server's retry configs on rejection).
type variationResult struct {
	Target   string // the target argument the variation was offered to, as given on the command line
	Kind     string // the field that was varied, e.g. "public_name" or "config_id"
	Original string // the baseline's value for that field
	Replaced string // the value offered in its place
	Status   string // one of the status constants above
	Detail   string // human-readable elaboration (error text, or the server's suggested value)
	Offered  goech.ECHConfigList
	Retry    goech.ECHConfigList // set only when Status == statusRejected
}

// jsonRecord is variationResult's on-the-wire JSON shape. The *Parsed fields
// carry the same configs as the base64 strings, decoded, so consumers get both
// the wire format and a human-readable view without a second decoding pass.
type jsonRecord struct {
	Target              string                           `json:"target"`
	Kind                string                           `json:"kind"`
	Original            string                           `json:"original"`
	Replaced            string                           `json:"replaced"`
	Status              string                           `json:"status"`
	OfferedConfig       string                           `json:"offered_config"`
	OfferedConfigParsed echfmt.SerializableECHConfigList `json:"offered_config_parsed"`
	RetryConfig         string                           `json:"retry_config,omitempty"`
	RetryConfigParsed   echfmt.SerializableECHConfigList `json:"retry_config_parsed,omitempty"`
}

func (r variationResult) toJSON() (jsonRecord, error) {
	offered, err := r.Offered.ToBase64()
	if err != nil {
		return jsonRecord{}, fmt.Errorf("encoding offered config to base64: %w", err)
	}
	rec := jsonRecord{
		Target:              r.Target,
		Kind:                r.Kind,
		Original:            r.Original,
		Replaced:            r.Replaced,
		Status:              r.Status,
		OfferedConfig:       offered,
		OfferedConfigParsed: echfmt.ToSerializableList(r.Offered),
	}
	if len(r.Retry) > 0 {
		retry, err := r.Retry.ToBase64()
		if err != nil {
			return jsonRecord{}, fmt.Errorf("encoding retry config to base64: %w", err)
		}
		rec.RetryConfig = retry
		rec.RetryConfigParsed = echfmt.ToSerializableList(r.Retry)
	}
	return rec, nil
}

// runVariations offers, one factor at a time, variations of a baseline ECH config
// to each target and reports which values the servers accept. Targets are probed
// concurrently (mirroring grace-period), but the combined report lists them in
// input order. A target whose baseline cannot be resolved does not stop the
// others: its error is returned - joined with any siblings' - after the report.
func runVariations(ctx context.Context, out io.Writer, o *variationsOptions, targets []string) error {
	dialFn := o.dialFn()

	var wg sync.WaitGroup
	perTarget := make([][]variationResult, len(targets))
	errs := make([]error, len(targets))
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()
			perTarget[i], errs[i] = targetVariations(ctx, o, target, dialFn)
		}(i, target)
	}
	wg.Wait()

	var results []variationResult
	for _, rs := range perTarget {
		results = append(results, rs...)
	}
	if err := renderResults(out, o.Format, results); err != nil {
		return err
	}
	return errors.Join(errs...)
}

// targetVariations resolves target's baseline config and runs the requested
// sweeps against it. The public-name and config-id sweeps are independent:
// within each, only the swept field changes.
func targetVariations(ctx context.Context, o *variationsOptions, target string, dialFn dial.Fn) ([]variationResult, error) {
	host, address := cli.ParseTarget(target, defaultPort)
	address = o.dns.Address(address)

	baseline, err := baselineConfig(ctx, o, host, address, dialFn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", target, err)
	}
	ech.LogEchConfigs(fmt.Sprintf("Baseline config for %s", host), baseline)

	var results []variationResult
	for _, name := range o.publicNames {
		r := testVariation(o, host, address, baseline,
			ech.Overrides{PublicName: &name}, "public_name", dialFn)
		r.Target = target
		results = append(results, r)
	}
	for _, idv := range o.configIDs {
		id := uint8(idv)
		r := testVariation(o, host, address, baseline,
			ech.Overrides{ConfigID: &id}, "config_id", dialFn)
		r.Target = target
		results = append(results, r)
	}
	return results, nil
}

// baselineConfig returns the config to vary: the user-supplied --ech-config
// when set; otherwise the first config from the target's DNS HTTPS RR; and, if
// the target has no ECH record in DNS, the RetryConfigs elicited by a GREASE
// probe (a real config is required either way, since varying one field of a
// fake GREASE config could never be accepted).
func baselineConfig(ctx context.Context, o *variationsOptions, host, address string, dialFn dial.Fn) (goech.ECHConfig, error) {
	var list goech.ECHConfigList
	switch {
	case o.echConfig != "":
		l, err := echfmt.DecodeECHConfigList(o.echConfig)
		if err != nil {
			return goech.ECHConfig{}, fmt.Errorf("parsing --ech-config: %w", err)
		}
		list = l
	default:
		l, found, err := dnsrr.LookupECH(ctx, host, o.dns.DNSServer)
		if err != nil {
			return goech.ECHConfig{}, fmt.Errorf("looking up baseline config in DNS: %w", err)
		}
		if found {
			list = l
			break
		}
		logrus.Infof("%s: no ECH config in DNS HTTPS RR; eliciting one via a GREASE probe", host)
		l, err = o.greaseProbe(&o.overrides, host, address, dialFn)
		if err != nil {
			return goech.ECHConfig{}, fmt.Errorf("no ECH config in %s's DNS HTTPS RR, and eliciting one via a GREASE probe failed: %w", host, err)
		}
		list = l
	}
	if len(list) == 0 {
		return goech.ECHConfig{}, fmt.Errorf("baseline ECHConfigList is empty")
	}
	return list[0], nil
}

// fieldValue returns config's human-readable value for the field named by kind.
func fieldValue(kind string, config goech.ECHConfig) string {
	switch kind {
	case "public_name":
		return string(config.RawPublicName)
	case "config_id":
		return fmt.Sprintf("%d", config.ConfigID)
	default:
		return ""
	}
}

// testVariation offers one varied config and returns the outcome and, on
// acceptance, the varied value responsible; on rejection it records the value the
// server actually wants (or that it was not reported). Progress and diagnostic
// detail go to the logger; only the returned result is meant for the report.
func testVariation(o *variationsOptions, host, address string, baseline goech.ECHConfig, ov ech.Overrides, kind string, dialFn dial.Fn) variationResult {
	varied := ov.Apply(baseline)
	result := variationResult{
		Kind:     kind,
		Original: fieldValue(kind, baseline),
		Replaced: fieldValue(kind, varied),
		Offered:  goech.ECHConfigList{varied},
	}
	logrus.Infof("testing variation %s=%q (baseline %q)", result.Kind, result.Replaced, result.Original)

	cfg, err := o.tlsConfig(host, result.Offered)
	if err != nil {
		result.Status = statusError
		result.Detail = fmt.Sprintf("error building TLS config: %v", err)
		logrus.WithError(err).Errorf("variation %s=%q: error building TLS config", result.Kind, result.Replaced)
		return result
	}
	conn, _, state, dialErr := dialFn(address, cfg)
	if conn != nil {
		conn.Close()
	}

	if rejectErr := ech.RetryConfigs(dialErr); rejectErr != nil {
		retry, _ := goech.UnmarshalECHConfigList(rejectErr.RetryConfigList)
		result.Status = statusRejected
		result.Retry = retry
		result.Detail = "server returned RetryConfigs"
		if len(retry) > 0 {
			if diffs := diffFields(varied, retry[0]); len(diffs) > 0 {
				result.Detail = fmt.Sprintf("server returned RetryConfigs; server accepts instead: %s", strings.Join(diffs, ", "))
			} else {
				result.Detail = "server returned RetryConfigs; value that causes acceptance not reported"
			}
		}
		logrus.Infof("variation %s=%q: rejected (%s)", result.Kind, result.Replaced, result.Detail)
		return result
	}
	if dialErr != nil {
		result.Status = statusFailed
		result.Detail = dial.DescribeError(dialErr)
		logrus.Warnf("variation %s=%q: failed (%s)", result.Kind, result.Replaced, result.Detail)
		return result
	}
	if !state.ECHAccepted {
		result.Status = statusNotAccepted
		result.Detail = "handshake succeeded but ECH was not accepted"
		logrus.Infof("variation %s=%q: not accepted", result.Kind, result.Replaced)
		return result
	}

	result.Status = statusAccepted
	if diffs := diffFields(baseline, varied); len(diffs) > 0 {
		result.Detail = fmt.Sprintf("value that caused acceptance: %s", strings.Join(diffs, ", "))
	} else {
		result.Detail = "value that caused acceptance: not reported (variation identical to baseline)"
	}
	logrus.Infof("variation %s=%q: accepted", result.Kind, result.Replaced)
	return result
}

// renderResults writes the variation report in the selected format. text and
// table are meant for humans; json emits one jsonRecord per result; b64 emits
// just the offered config's base64, one per line.
func renderResults(out io.Writer, format string, results []variationResult) error {
	switch format {
	case echfmt.FormatJSON:
		return renderResultsJSON(out, results)
	case echfmt.FormatTable:
		return renderResultsTable(out, results)
	case echfmt.FormatBase64:
		return renderResultsBase64(out, results)
	default:
		return renderResultsText(out, results)
	}
}

func renderResultsJSON(out io.Writer, results []variationResult) error {
	records := make([]jsonRecord, len(results))
	for i, r := range results {
		rec, err := r.toJSON()
		if err != nil {
			return err
		}
		records[i] = rec
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(records)
}

func renderResultsTable(out io.Writer, results []variationResult) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TARGET\tKIND\tORIGINAL\tREPLACED\tSTATUS\tDETAIL")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Target, r.Kind, r.Original, r.Replaced, r.Status, r.Detail)
	}
	return w.Flush()
}

func renderResultsText(out io.Writer, results []variationResult) error {
	for i, r := range results {
		fmt.Fprintf(out, "target: %s\n", r.Target)
		fmt.Fprintf(out, "variation: %s=%q (baseline: %q)\n", r.Kind, r.Replaced, r.Original)
		fmt.Fprintf(out, "  status: %s\n", r.Status)
		if r.Detail != "" {
			fmt.Fprintf(out, "  detail: %s\n", r.Detail)
		}
		if i != len(results)-1 {
			fmt.Fprintln(out)
		}
	}
	return nil
}

func renderResultsBase64(out io.Writer, results []variationResult) error {
	for _, r := range results {
		b64, err := r.Offered.ToBase64()
		if err != nil {
			return fmt.Errorf("encoding offered config to base64: %w", err)
		}
		if _, err := fmt.Fprintln(out, b64); err != nil {
			return err
		}
	}
	return nil
}

// diffFields returns human-readable descriptions of the fields where b differs
// from a, expressed as b's values. It compares the fields a variation can change;
// the public key is included so a differing server config is not silently equal.
func diffFields(a, b goech.ECHConfig) []string {
	sa := echfmt.ToSerializable(a)
	sb := echfmt.ToSerializable(b)
	var diffs []string
	if sa.RawPublicName != sb.RawPublicName {
		diffs = append(diffs, fmt.Sprintf("public_name=%q", sb.RawPublicName))
	}
	if sa.ConfigID != sb.ConfigID {
		diffs = append(diffs, fmt.Sprintf("config_id=%d", sb.ConfigID))
	}
	if sa.Version != sb.Version {
		diffs = append(diffs, fmt.Sprintf("version=0x%04x", sb.Version))
	}
	if sa.MaxNameLength != sb.MaxNameLength {
		diffs = append(diffs, fmt.Sprintf("max_name_length=%d", sb.MaxNameLength))
	}
	if !cipherSuitesEqual(sa.CipherSuites, sb.CipherSuites) {
		diffs = append(diffs, "cipher_suites")
	}
	if sa.PublicKey != sb.PublicKey {
		diffs = append(diffs, "public_key")
	}
	return diffs
}

func cipherSuitesEqual(a, b []echfmt.SerializableHpkeCipherSuite) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
