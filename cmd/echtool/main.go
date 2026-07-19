package main

import (
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/jmuecke/echtools/internal/tools/dech"
	"github.com/jmuecke/echtools/internal/tools/echtest"
	"github.com/jmuecke/echtools/internal/tools/greasy"
)

func main() {
	version := buildVersion()

	if cmd := symlinkCmd(filepath.Base(os.Args[0])); cmd != nil {
		cmd.Version = version
		if err := cmd.Execute(); err != nil {
			logrus.Fatal(err)
		}
		return
	}

	root := &cobra.Command{
		Use:           "echtool",
		Short:         "ECH Tool",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(dech.NewCmd())
	root.AddCommand(greasy.NewCmd())
	root.AddCommand(greasy.NewConnCmd())
	root.AddCommand(echtest.NewCmd())

	if err := root.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}

// Decide on subcommand.when called via symlink
func symlinkCmd(name string) *cobra.Command {
	var cmd *cobra.Command
	switch name {
	case "greasy":
		cmd = greasy.NewCmd()
	case "dech":
		cmd = dech.NewCmd()
	case "echconn":
		cmd = greasy.NewConnCmd()
	case "echtest":
		cmd = echtest.NewCmd()
	default:
		return nil
	}
	cmd.Use = name
	return cmd
}
