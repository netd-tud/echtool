package dech

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/OmarTariq612/goech"
	"github.com/spf13/cobra"

	"github.com/netd-tud/echtool/internal/cli"
	"github.com/netd-tud/echtool/pkg/echfmt"
)

type options struct {
	// echConfig is a base64-encoded ECHConfigList. When empty, read stdin
	echConfig string

	cli.Common
}

func (o *options) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.echConfig, "ech-config", "", "base64-encoded ECHConfigList (reads from stdin if omitted)")
	cli.AddCommonFlags(f, &o.Common)
}

func (o *options) input() (goech.ECHConfigList, error) {
	raw := strings.TrimSpace(o.echConfig)
	if raw == "" {
		// On an interactive terminal, an empty --ech-config otherwise looks
		// like a silent hang while ReadAll waits for stdin to close.
		if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintln(os.Stderr, "reading base64 ECHConfigList from stdin; paste it and press Ctrl-D (or pass --ech-config)")
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading ECHConfigList from stdin: %w", err)
		}
		raw = strings.TrimSpace(string(data))
	}
	if raw == "" {
		return nil, fmt.Errorf("no ECHConfigList provided via --ech-config or stdin")
	}
	return echfmt.DecodeECHConfigList(raw)
}
