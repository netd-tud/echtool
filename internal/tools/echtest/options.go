package echtest

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/OmarTariq612/goech"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jmuecke/echtools/internal/cli"
	"github.com/jmuecke/echtools/pkg/dial"
	"github.com/jmuecke/echtools/pkg/ech"
)

const defaultPort = "443"

// connOptions holds the connection/transport flags shared by both echtest modes
// and knows how to turn them into a dialer and a *tls.Config. It deliberately
// excludes --format: grace-period's report is text-only, so only the modes
// that actually render via echfmt (variations) register cli.Common.
type connOptions struct {
	transport string
	tls       cli.TLSParams
	dns       cli.DNSParams
}

func (c *connOptions) addFlags(f *pflag.FlagSet) {
	f.StringVar(&c.transport, "transport", "tcp", "transport: tcp | quic")
	cli.AddTLSParamsFlags(f, &c.tls)
	cli.AddDNSParamsFlags(f, &c.dns)
}

func (c *connOptions) validate() error {
	switch c.transport {
	case "tcp", "quic":
	default:
		return fmt.Errorf("invalid --transport %q: must be tcp or quic", c.transport)
	}
	// QUIC mandates ALPN; default it to h3 when the user supplied none, at the
	// same pre-run point where greasy's dial subcommands apply their default.
	if c.transport == "quic" && len(c.tls.ALPN) == 0 {
		c.tls.ALPN = []string{"h3"}
	}
	return nil
}

// dialFn returns the dialer for the configured transport.
func (c *connOptions) dialFn() dial.Fn {
	if c.transport == "quic" {
		return dial.QUIC
	}
	return dial.TCP
}

// tlsConfig builds a *tls.Config offering list to target with the shared TLS
// settings.
func (c *connOptions) tlsConfig(target string, list goech.ECHConfigList) (*tls.Config, error) {
	return c.tls.TLS(target, list)
}

// greaseProbe offers a GREASE ECHConfig (built from overrides, with the
// public name defaulting to host) to address and returns the RetryConfigs the
// server hands back on rejection. Both modes bootstrap their config under
// test this way.
func (c *connOptions) greaseProbe(overrides *cli.ECHConfigOverrides, host, address string, dialFn dial.Fn) (goech.ECHConfigList, error) {
	pubName := overrides.PubName
	if pubName == "" {
		pubName = host
	}
	list, err := ech.Grease(pubName, overrides.GreaseOptions()...)
	if err != nil {
		return nil, fmt.Errorf("building GREASE config: %w", err)
	}
	cfg, err := c.tlsConfig(host, list)
	if err != nil {
		return nil, fmt.Errorf("building TLS config: %w", err)
	}

	conn, _, _, dialErr := dialFn(address, cfg)
	if conn != nil {
		conn.Close()
	}
	rejectErr := ech.RetryConfigs(dialErr)
	if rejectErr == nil {
		return nil, fmt.Errorf("GREASE probe did not yield RetryConfigs (dial error: %s)", dial.DescribeError(dialErr))
	}
	retry, err := goech.UnmarshalECHConfigList(rejectErr.RetryConfigList)
	if err != nil {
		return nil, fmt.Errorf("decoding RetryConfigs: %w", err)
	}
	if len(retry) == 0 {
		return nil, fmt.Errorf("server returned empty RetryConfigs")
	}
	return retry, nil
}

// graceOptions configures the grace-period mode.
type graceOptions struct {
	connOptions
	interval    time.Duration
	stateDir    string
	maxFailures int
	samples     int           // how many bootstrap-to-death cycles to run per domain; 0 means unbounded
	maxRuntime  time.Duration // 0 means unbounded

	// overrides holds the GREASE bootstrap knobs (used for the initial probe
	// that elicits the retry config under test).
	overrides cli.ECHConfigOverrides
}

func (o *graceOptions) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	o.connOptions.addFlags(f)
	f.DurationVar(&o.interval, "interval", time.Minute, "delay between reconnection attempts")
	f.StringVar(&o.stateDir, "state-dir", "./echtest-state", "directory for the append-only per-domain observation logs")
	f.IntVar(&o.maxFailures, "max-failures", 3, "consecutive failed attempts before declaring the config no longer accepted")
	f.IntVar(&o.samples, "samples", 3, "bootstrap-to-death cycles to run per domain, so consecutive lifetimes can be checked against each other for consistency (0 = keep sampling until --max-runtime or SIGINT)")
	f.DurationVar(&o.maxRuntime, "max-runtime", 0, "abort the test after this long regardless of outcome (0 = unbounded)")
	cli.AddECHConfigOverrideFlags(f, &o.overrides, "")
}

func (o *graceOptions) validate() error {
	if err := o.connOptions.validate(); err != nil {
		return err
	}
	if o.interval <= 0 {
		return fmt.Errorf("invalid --interval %s: must be positive", o.interval)
	}
	if o.maxFailures < 1 {
		return fmt.Errorf("invalid --max-failures %d: must be >= 1", o.maxFailures)
	}
	if o.samples < 0 {
		return fmt.Errorf("invalid --samples %d: must be >= 0", o.samples)
	}
	if o.maxRuntime < 0 {
		return fmt.Errorf("invalid --max-runtime %s: must be >= 0", o.maxRuntime)
	}
	return o.overrides.Validate("")
}

// variationsOptions configures the configuration-variations mode.
type variationsOptions struct {
	connOptions
	cli.Common
	echConfig   string // baseline ECHConfigList; when empty, fetched from DNS or a GREASE fallback probe
	publicNames []string
	configIDs   []int

	// overrides configures the GREASE fallback probe used to elicit a baseline
	// via the server's RetryConfigs when the target has no ECH record in DNS.
	// Its flags are prefixed with grease- since --pub-name/--config-id are
	// already taken by the sweep flags above.
	overrides cli.ECHConfigOverrides
}

func (o *variationsOptions) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	o.connOptions.addFlags(f)
	cli.AddCommonFlags(f, &o.Common)
	f.StringVar(&o.echConfig, "ech-config", "",
		"baseline base64 ECHConfigList to vary (fetched from the target's DNS HTTPS RR, "+
			"or via a GREASE probe's RetryConfigs if not published there, when omitted)")
	f.StringSliceVar(&o.publicNames, "public-name", nil, "public name(s) to try in place of the baseline (repeatable)")
	f.IntSliceVar(&o.configIDs, "config-id", nil, "config_id value(s) to try in place of the baseline (repeatable, 0-255)")

	// The GREASE fallback-probe knobs are registered under the grease- prefix
	// since --pub-name/--config-id are already taken by the sweep flags above.
	cli.AddECHConfigOverrideFlags(f, &o.overrides, "grease-")
}

func (o *variationsOptions) validate() error {
	if err := o.connOptions.validate(); err != nil {
		return err
	}
	if err := o.Common.Validate(); err != nil {
		return err
	}
	if len(o.publicNames) == 0 && len(o.configIDs) == 0 {
		return fmt.Errorf("provide at least one --public-name or --config-id to vary")
	}
	for _, id := range o.configIDs {
		if id < 0 || id > 255 {
			return fmt.Errorf("invalid --config-id %d: must be 0-255", id)
		}
	}
	return o.overrides.Validate("grease-")
}
