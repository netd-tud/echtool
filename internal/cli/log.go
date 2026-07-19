package cli

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func AddLogLevelFlag(cmd *cobra.Command) {
	var level string
	cmd.PersistentFlags().StringVar(&level, "log-level", logrus.InfoLevel.String(),
		"log verbosity: trace | debug | info | warn | error")

	prev := cmd.PersistentPreRunE
	cmd.PersistentPreRunE = func(c *cobra.Command, args []string) error {
		lvl, err := logrus.ParseLevel(level)
		if err != nil {
			return fmt.Errorf("invalid --log-level %q: %w", level, err)
		}
		logrus.SetLevel(lvl)
		if prev != nil {
			return prev(c, args)
		}
		return nil
	}
}
