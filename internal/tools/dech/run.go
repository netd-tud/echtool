package dech

import (
	"fmt"

	"github.com/spf13/cobra"

	echconfigfmt "github.com/netd-tud/echtool/pkg/echfmt"
)

func run(cmd *cobra.Command, o *options) error {
	configs, err := o.input()
	if err != nil {
		return err
	}

	if err := echconfigfmt.Render(cmd.OutOrStdout(), configs, echconfigfmt.Options{
		Format:     o.Format,
		ShowConfig: -1,
	}); err != nil {
		return fmt.Errorf("rendering output: %w", err)
	}
	return nil
}
