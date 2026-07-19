// Package cli holds options and helpers shared by every echtools subcommand,
// so that each tool works both as a standalone binary and as a cobra subcommand
// under the echtool umbrella.
package cli

import (
	"github.com/spf13/pflag"

	"github.com/jmuecke/echtools/pkg/echfmt"
)

// AddFormatFlag registers the --format/-o flag onto f, binding into p, so every
// command phrases the flag identically.
func AddFormatFlag(f *pflag.FlagSet, p *string) {
	f.StringVarP(p, "format", "o", echfmt.FormatText, "output format: text | json | table | b64")
}

// Common holds the --format flag, the only flag literally shared by every
// echtools subcommand. Each command embeds it and calls AddCommonFlags, so
// the flag, its field and its validation are defined exactly once and
// promoted onto the embedding struct.
type Common struct {
	Format string
}

// AddCommonFlags binds the shared flags onto f.
func AddCommonFlags(f *pflag.FlagSet, c *Common) {
	AddFormatFlag(f, &c.Format)
}

// Validate checks that Format holds a renderable value.
func (c *Common) Validate() error {
	return echfmt.ValidateFormat(c.Format)
}
