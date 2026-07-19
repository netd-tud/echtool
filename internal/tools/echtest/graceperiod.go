package echtest

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/OmarTariq612/goech"
	"github.com/sirupsen/logrus"

	"github.com/jmuecke/echtools/internal/cli"
	"github.com/jmuecke/echtools/pkg/dial"
	"github.com/jmuecke/echtools/pkg/dnsrr"
	"github.com/jmuecke/echtools/pkg/ech"
)

// runGracePeriod probes each domain to learn how long the server keeps accepting
// the ECH retry config it initially handed back, tracking DNS rotation alongside.
func runGracePeriod(ctx context.Context, out io.Writer, o *graceOptions, domains []string) error {
	st, err := openStore(o.stateDir)
	if err != nil {
		return err
	}
	dialFn := o.dialFn()

	var wg sync.WaitGroup
	perDomain := make([][]*graceReport, len(domains))
	for i, domain := range domains {
		wg.Add(1)
		go func(i int, domain string) {
			defer wg.Done()
			perDomain[i] = trackDomain(ctx, o, st, domain, dialFn)
		}(i, domain)
	}
	wg.Wait()

	for _, reports := range perDomain {
		for _, r := range reports {
			r.write(out)
		}
	}
	return nil
}

// graceReport is the summary of one bootstrap-to-death cycle ("sample") for a
// domain. trackDomain produces a sequence of these back to back: as soon as a
// config is declared dead, it bootstraps a fresh one and starts the next
// sample, so consecutive samples can be compared against each other for
// consistency instead of trusting a single lifetime measurement. The first
// sample is the least trustworthy of the bunch - the config under test may
// already have been live for a while before this run happened to observe it
// - later samples start right as their config takes over, so they're a
// cleaner read on the true grace period.
type graceReport struct {
	domain         string
	sample         int // 1-indexed position in this domain's sequence of samples
	firstSeen      time.Time
	dnsChanged     time.Time           // when DNS first advertised a config other than the one under test
	retryChanged   time.Time           // when the server first handed back a different config via RetryConfigs
	dnsLastSeen    goech.ECHConfigList // most recently observed DNS answer; starts as the config under test
	retryLastSeen  goech.ECHConfigList // most recently observed RetryConfigs value; starts as the config under test
	dnsRotations   int                 // number of distinct configs DNS has advertised, beyond the one under test
	retryRotations int                 // number of distinct configs the server has handed back via RetryConfigs, beyond the one under test
	death          time.Time           // when the config-under-test first failed in the fatal streak
	declaredAt     time.Time           // when death was confirmed (after maxFailures)
	deathReason    string              // one of the Death* constants; what kind of failure the fatal streak consisted of
	alive          bool                // true if observation ended (ctx cancelled) before death
	observed       []Record
	bootstrapOK    bool
	repeatedConfig bool // the rerun bootstrap returned the same config the previous sample tested to death
}

// rotation returns the earliest of dnsChanged and retryChanged, and the
// source that observed it first, i.e. the first sign - from either channel -
// that the server moved on from the config under test. It is zero/"" if
// neither has fired yet.
func (r *graceReport) rotation() (time.Time, string) {
	switch {
	case r.dnsChanged.IsZero():
		return r.retryChanged, SourceRetry
	case r.retryChanged.IsZero():
		return r.dnsChanged, SourceDNS
	case r.retryChanged.Before(r.dnsChanged):
		return r.retryChanged, SourceRetry
	default:
		return r.dnsChanged, SourceDNS
	}
}

func (r *graceReport) write(out io.Writer) {
	fmt.Fprintf(out, "\n=== %s (sample %d) ===\n", r.domain, r.sample)
	if !r.bootstrapOK {
		fmt.Fprintf(out, "  bootstrap failed: no retry config obtained; nothing tracked\n")
		return
	}
	fmt.Fprintf(out, "  config first observed: %s\n", r.firstSeen.Format(time.RFC3339))
	if r.repeatedConfig {
		fmt.Fprintf(out, "  NOTE: bootstrap returned the same config the previous sample tested to death\n")
	}
	for _, rec := range r.observed {
		suffix := ""
		if rec.ECHConfigListBase64 != "" {
			suffix = " " + rec.ECHConfigListBase64
		}
		fmt.Fprintf(out, "  [%s] %-6s %s%s\n", rec.Timestamp.Format(time.RFC3339), rec.Source, rec.Event, suffix)
	}
	if !r.dnsChanged.IsZero() {
		fmt.Fprintf(out, "  DNS advertised a new config at:          %s (%d rotation(s) seen)\n", r.dnsChanged.Format(time.RFC3339), r.dnsRotations)
	} else {
		fmt.Fprintf(out, "  DNS never advertised a different config during observation\n")
	}
	if !r.retryChanged.IsZero() {
		fmt.Fprintf(out, "  server first retried with a new config at: %s (%d rotation(s) seen)\n", r.retryChanged.Format(time.RFC3339), r.retryRotations)
	} else {
		fmt.Fprintf(out, "  server never retried with a different config during observation\n")
	}
	if r.alive {
		fmt.Fprintf(out, "  observation stopped before the config was rejected (still accepted)\n")
		return
	}
	fmt.Fprintf(out, "  config no longer accepted (%s); declared at %s (after the configured failure streak)\n", r.deathReason, r.declaredAt.Format(time.RFC3339))
	fmt.Fprintf(out, "  lifetime (first-seen -> death): %s\n", r.death.Sub(r.firstSeen).Round(time.Second))
	if rotatedAt, source := r.rotation(); !rotatedAt.IsZero() {
		fmt.Fprintf(out, "  grace period (rotation[%s] -> death): %s\n", source, r.death.Sub(rotatedAt).Round(time.Second))
	}
}

// trackDomain runs a sequence of samples for domain: bootstrap a retry
// config, track it to death (or until ctx ends), write its summary, and - if
// it died and there's budget left (--samples, 0 = unbounded) - bootstrap the
// next one and repeat. Each rerun bootstraps completely fresh, exactly like
// the first sample; the dead sample's config is only carried along so the
// rerun can flag it if the server hands the very same config back. Returns
// every sample produced, in order.
func trackDomain(ctx context.Context, o *graceOptions, st *store, domain string, dialFn dial.Fn) []*graceReport {
	host, address := cli.ParseTarget(domain, defaultPort)
	address = o.dns.Address(address)

	var reports []*graceReport
	var prev goech.ECHConfigList
	for sampleN := 1; o.samples == 0 || sampleN <= o.samples; sampleN++ {
		report := &graceReport{domain: host, sample: sampleN}
		reports = append(reports, report)

		underTest, died := runSample(ctx, o, st, host, address, dialFn, report, prev)
		writeSummary(st, report)
		if !died {
			// Bootstrap failed, or ctx ended before the config was rejected:
			// either way there's no clean point to start the next sample from.
			break
		}
		prev = underTest
	}
	return reports
}

// runSample bootstraps a retry config and re-offers it every interval,
// recording rotation (DNS and retry) and declaring the config dead after
// maxFailures consecutive failed attempts. prev is the previous sample's
// config under test (nil for the first sample); see bootstrap. It returns the
// config under test and true if death was declared (report.death/declaredAt
// are set), false if bootstrap failed or ctx ended first (report.alive is set
// in the latter case).
func runSample(ctx context.Context, o *graceOptions, st *store, host, address string, dialFn dial.Fn, report *graceReport, prev goech.ECHConfigList) (goech.ECHConfigList, bool) {
	underTest, firstSeen, ok := bootstrap(ctx, o, st, host, address, dialFn, report, prev)
	if !ok {
		return nil, false
	}
	report.bootstrapOK = true
	report.firstSeen = firstSeen

	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()

	consecutiveFailures := 0
	streakRejections := 0
	var streakStart time.Time

	for {
		select {
		case <-ctx.Done():
			report.alive = true
			return underTest, false
		case <-ticker.C:
		}

		// Poll DNS to catch rotation away from the config under test.
		pollDNS(ctx, o, st, host, report)

		accepted, rejected, retry := attempt(o, st, host, address, underTest, dialFn)
		switch {
		case accepted:
			consecutiveFailures = 0
			streakRejections = 0
			streakStart = time.Time{}
			logrus.Infof("%s: config under test still accepted", host)
		default:
			if consecutiveFailures == 0 {
				streakStart = time.Now().UTC()
			}
			consecutiveFailures++
			if rejected {
				streakRejections++
			}
			if rejected && len(retry) > 0 {
				recordIfChanged(st, host, SourceRetry, "server returned a changed retry config", retry, report)
				dnsrr.CompareAndLog(ctx, host, o.dns.DNSServer, retry)
			}
			logrus.Warnf("%s: attempt failed (%d/%d consecutive)", host, consecutiveFailures, o.maxFailures)
			if consecutiveFailures >= o.maxFailures {
				report.death = streakStart
				report.declaredAt = time.Now().UTC()
				report.deathReason = deathReason(streakRejections, consecutiveFailures)
				st.append(Record{Timestamp: report.declaredAt, Domain: host, Source: SourceRetry,
					Event: fmt.Sprintf("config declared no longer accepted (%s)", report.deathReason)})
				return underTest, true
			}
		}
	}
}

// deathReason classifies a fatal failure streak by what its attempts observed.
// Only a streak of pure ECH rejections cleanly means the server stopped
// accepting the config; anything else may just as well be network trouble.
func deathReason(rejections, total int) string {
	switch rejections {
	case total:
		return DeathECHRejected
	case 0:
		return DeathConnectFailed
	default:
		return DeathMixed
	}
}

// writeSummary persists r's final outcome to the domain's summary file.
func writeSummary(st *store, r *graceReport) {
	sum := Summary{
		Timestamp:      time.Now().UTC(),
		Domain:         r.domain,
		Sample:         r.sample,
		BootstrapOK:    r.bootstrapOK,
		Alive:          r.alive,
		RepeatedConfig: r.repeatedConfig,
	}
	if r.bootstrapOK {
		sum.FirstSeen = &r.firstSeen
	}
	if !r.dnsChanged.IsZero() {
		sum.DNSChanged = &r.dnsChanged
		sum.DNSRotations = r.dnsRotations
	}
	if !r.retryChanged.IsZero() {
		sum.RetryChanged = &r.retryChanged
		sum.RetryRotations = r.retryRotations
	}
	if rotatedAt, source := r.rotation(); !rotatedAt.IsZero() {
		sum.RotationChanged = &rotatedAt
		sum.RotationSource = &source
	}
	if r.bootstrapOK && !r.alive {
		sum.DeclaredAt = &r.declaredAt
		sum.DeathReason = r.deathReason
		sum.Death = &r.death
		lifetime := int64(r.death.Sub(r.firstSeen).Round(time.Second).Seconds())
		sum.LifetimeSeconds = &lifetime
		if rotatedAt, _ := r.rotation(); !rotatedAt.IsZero() {
			overlap := int64(r.death.Sub(rotatedAt).Round(time.Second).Seconds())
			sum.OverlapSeconds = &overlap
		}
	}
	if err := st.writeSummary(r.domain, sum); err != nil {
		logrus.WithError(err).Errorf("%s: writing summary", r.domain)
	}
}

// bootstrap performs the initial GREASE probe and records the retry config that
// becomes the config under test. prev is the previous sample's config under
// test (nil for the first sample). Reruns differ from the first sample in two
// ways only: a failed probe is retried every interval for up to maxFailures
// consecutive attempts (mirroring the death-streak semantics) instead of
// failing fast, since right after a rotation the server may still be in
// churn; and if the server hands back the very config that just died, the
// sample proceeds anyway but is flagged (repeatedConfig) so it can be
// discounted when comparing consecutive lifetimes.
func bootstrap(ctx context.Context, o *graceOptions, st *store, host, address string, dialFn dial.Fn, report *graceReport, prev goech.ECHConfigList) (goech.ECHConfigList, time.Time, bool) {
	rerun := prev != nil
	retry, err := o.greaseProbe(&o.overrides, host, address, dialFn)
	for failures := 1; err != nil && rerun && failures < o.maxFailures; failures++ {
		logrus.WithError(err).Warnf("%s: GREASE rerun bootstrap failed (%d/%d consecutive)", host, failures, o.maxFailures)
		select {
		case <-ctx.Done():
			return nil, time.Time{}, false
		case <-time.After(o.interval):
		}
		retry, err = o.greaseProbe(&o.overrides, host, address, dialFn)
	}
	if err != nil {
		logrus.WithError(err).Warnf("%s: GREASE bootstrap failed", host)
		return nil, time.Time{}, false
	}

	event := "initial retry config obtained"
	if rerun && prev.Equal(retry) {
		report.repeatedConfig = true
		event = "initial retry config obtained (same config the previous sample tested to death)"
		logrus.Warnf("%s: rerun bootstrap returned the same config the previous sample tested to death", host)
	}

	now := time.Now().UTC()
	b64, _ := retry.ToBase64()
	rec := Record{Timestamp: now, Domain: host, Source: SourceGrease, Event: event, ECHConfigListBase64: b64}
	st.append(rec)
	report.observed = append(report.observed, rec)
	ech.LogEchConfigs(fmt.Sprintf("%s: config under test", host), retry...)

	// Both channels start out having "last seen" the config under test, so the
	// first divergence either observes - during the baseline poll below or on a
	// later attempt/tick - is what counts as rotation #1.
	report.dnsLastSeen = retry
	report.retryLastSeen = retry

	// Baseline the DNS view; a pre-existing mismatch (e.g. facebook.com) is noted.
	pollDNS(ctx, o, st, host, report)
	return retry, now, true
}

// attempt offers the config under test, classifies the outcome, and logs it as
// a Record (source "probe") regardless of outcome, so every request performed
// against the domain is recoverable from the state-dir log.
func attempt(o *graceOptions, st *store, host, address string, underTest goech.ECHConfigList, dialFn dial.Fn) (accepted, rejected bool, retry goech.ECHConfigList) {
	b64, _ := underTest.ToBase64()
	logRequest := func(event string) {
		st.append(Record{Timestamp: time.Now().UTC(), Domain: host, Source: SourceProbe, Event: event, ECHConfigListBase64: b64})
	}

	cfg, err := o.tlsConfig(host, underTest)
	if err != nil {
		logrus.WithError(err).Errorf("%s: building TLS config", host)
		logRequest(fmt.Sprintf("failed: building TLS config: %v", err))
		return false, false, nil
	}
	conn, _, state, dialErr := dialFn(address, cfg)
	if conn != nil {
		conn.Close()
	}
	if rejectErr := ech.RetryConfigs(dialErr); rejectErr != nil {
		retry, _ = goech.UnmarshalECHConfigList(rejectErr.RetryConfigList)
		logRequest("rejected")
		return false, true, retry
	}
	if dialErr != nil {
		logRequest(fmt.Sprintf("failed: %s", dial.DescribeError(dialErr)))
		return false, false, nil
	}
	if !state.ECHAccepted {
		logRequest("handshake succeeded but ECH was not accepted")
		return false, false, nil
	}
	logRequest("accepted")
	return true, false, nil
}

// pollDNS looks up the domain's DNS HTTPS RR and, whenever it differs from the
// last DNS answer observed (starting from the config under test), records the
// rotation: every distinct config DNS advertises during the run gets its own
// entry, not just the first.
func pollDNS(ctx context.Context, o *graceOptions, st *store, host string, report *graceReport) {
	dnsList, found, err := dnsrr.LookupECH(ctx, host, o.dns.DNSServer)
	if err != nil || !found {
		return
	}
	if report.dnsLastSeen.Equal(dnsList) {
		return
	}
	now := time.Now().UTC()
	report.dnsLastSeen = dnsList
	report.dnsRotations++
	if report.dnsChanged.IsZero() {
		report.dnsChanged = now
	}
	b64, _ := dnsList.ToBase64()
	event := fmt.Sprintf("DNS advertises a new ECH config (rotation #%d)", report.dnsRotations)
	rec := Record{Timestamp: now, Domain: host, Source: SourceDNS, Event: event, ECHConfigListBase64: b64}
	st.append(rec)
	report.observed = append(report.observed, rec)
	logrus.Warnf("%s: DNS now advertises a different ECH config (rotation #%d)", host, report.dnsRotations)
}

// recordIfChanged appends a retry-config observation whenever seen differs
// from the last retry config observed (starting from the config under test),
// so every distinct config the server hands back via RetryConfigs during the
// run gets its own entry - not just the first, and not a repeat log line for
// the same (already-dead) config handed back again. The first time it fires,
// it also marks report's retryChanged timestamp - the server itself telling
// us it moved on, which can beat DNS to the news (or be the only signal at
// all, if DNS never updates).
func recordIfChanged(st *store, host, source, event string, seen goech.ECHConfigList, report *graceReport) {
	if report.retryLastSeen.Equal(seen) {
		return
	}
	now := time.Now().UTC()
	report.retryLastSeen = seen
	report.retryRotations++
	if report.retryChanged.IsZero() {
		report.retryChanged = now
	}
	b64, _ := seen.ToBase64()
	rec := Record{Timestamp: now, Domain: host, Source: source, Event: fmt.Sprintf("%s (rotation #%d)", event, report.retryRotations), ECHConfigListBase64: b64}
	st.append(rec)
	report.observed = append(report.observed, rec)
}
