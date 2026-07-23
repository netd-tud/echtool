package dech

import (
	"github.com/spf13/cobra"

	"github.com/netd-tud/echtool/internal/cli"
)

// NewCmd returns the "dech" command, which decodes an ECHConfigList. The command
// owns its own flags, so it is self-contained whether built as a standalone
// binary or added under the echtool umbrella.
func NewCmd() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:   "dech",
		Short: "Decode an ECH configuration list",
		Long: "Decode a base64-encoded ECHConfigList provided via --ech-config " +
			"or stdin",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return o.Validate()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, &o)
		},
	}
	o.addFlags(cmd)
	cli.AddLogLevelFlag(cmd)
	return cmd
}
