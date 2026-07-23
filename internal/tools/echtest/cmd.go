// Package echtest implements the "test" command: longitudinal ECH experiments
// against one or more domains. It has two modes: grace-period (how long a
// server keeps accepting a retry config after DNS rotates) and
// configuration-variations (which single-field variations of a config the
// server accepts).
package echtest

import (
	"context"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/netd-tud/echtool/internal/cli"
)

// NewCmd returns the "test" command with its two mode subcommands. It owns its
// own flags so it is self-contained whether built standalone or under echtool.
func NewCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "test",
		Short:         "Longitudinal ECH experiments (grace period, config variations)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newGraceCmd())
	root.AddCommand(newVariationsCmd())
	cli.AddLogLevelFlag(root)
	return root
}

func newGraceCmd() *cobra.Command {
	var o graceOptions
	cmd := &cobra.Command{
		Use:   "grace-period <domain> [domain...]",
		Short: "Measure how long a server keeps accepting an ECH retry config after DNS rotates",
		Long: "For each domain, elicit a retry config with a GREASE probe, then re-offer " +
			"it every --interval. Track rotation via both DNS and the server's own " +
			"RetryConfigs, and declare the config dead after --max-failures consecutive " +
			"failed attempts, reporting its lifetime and the grace period between rotation " +
			"and death. On death, bootstrap a fresh config and repeat for --samples cycles " +
			"(default 3), so consecutive lifetimes can be checked against each other for " +
			"consistency rather than trusting a single measurement. Observations are " +
			"persisted under --state-dir. Send SIGINT, or let --max-runtime elapse, to stop " +
			"and print the report so far.",
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return o.validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			if o.maxRuntime > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, o.maxRuntime)
				defer cancel()
			}
			return runGracePeriod(ctx, cmd.OutOrStdout(), &o, args)
		},
	}
	o.addFlags(cmd)
	return cmd
}

func newVariationsCmd() *cobra.Command {
	var o variationsOptions
	cmd := &cobra.Command{
		Use:   "configuration-variations <target> [target...]",
		Short: "Probe which single-field variations of an ECH config a server accepts",
		Long: "For each target, vary one ECH field at a time — public name (--public-name) " +
			"and config_id (--config-id), independently — of a baseline config (--ech-config, " +
			"the target's DNS HTTPS RR, or a GREASE probe's RetryConfigs as a fallback) and " +
			"report which values the server accepts. Targets are probed concurrently.",
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return o.validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVariations(context.Background(), cmd.OutOrStdout(), &o, args)
		},
	}
	o.addFlags(cmd)
	return cmd
}
