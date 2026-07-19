package greasy

import (
	"fmt"
	"strings"

	"github.com/OmarTariq612/goech"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jmuecke/echtools/internal/cli"
	"github.com/jmuecke/echtools/pkg/ech"
	"github.com/jmuecke/echtools/pkg/echfmt"
)

type options struct {
	requireConfig bool

	echConfig string // base64 ECHConfigList; optional unless requireConfig

	overrides cli.ECHConfigOverrides
	tls       cli.TLSParams
	dns       cli.DNSParams
	cli.Common

	validateConfig     bool
	validateAllConfigs bool
	showConfig         int
}

func (o *options) addFlags(cmd *cobra.Command, echConfigHelp string) {
	f := cmd.PersistentFlags()
	f.StringVar(&o.echConfig, "ech-config", "", echConfigHelp)
	cli.AddECHConfigOverrideFlags(f, &o.overrides, "")
	cli.AddTLSParamsFlags(f, &o.tls)
	cli.AddDNSParamsFlags(f, &o.dns)
	cli.AddCommonFlags(f, &o.Common)
	f.BoolVar(&o.validateAllConfigs, "validate-all-configs", false, "send a second handshake for every returned retry config")
	f.IntVar(&o.showConfig, "show-config", -1, "limit output to config #N (default: all)")
	// Validate Retrieved Configuration by default
	o.validateConfig = true
}

func (o *options) validate() error {
	if o.requireConfig && strings.TrimSpace(o.echConfig) == "" {
		return fmt.Errorf("no ECHConfigList provided via --ech-config")
	}
	if err := o.Common.Validate(); err != nil {
		return err
	}
	if err := o.overrides.Validate(""); err != nil {
		return err
	}
	if o.showConfig < -1 {
		return fmt.Errorf("invalid --show-config %d: must be >= -1 (-1 shows all)", o.showConfig)
	}
	return nil
}

// resolveConfigList returns the ECHConfigList to offer.
//
// When now echConfig is set, create e new GREASE config.
// Apply user modifications in both cases
func (o *options) resolveConfigList(f *pflag.FlagSet, pubName string) (goech.ECHConfigList, error) {
	raw := strings.TrimSpace(o.echConfig)
	if raw == "" {
		return ech.Grease(pubName, o.overrides.GreaseOptions()...)
	}

	list, err := echfmt.DecodeECHConfigList(raw)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		logrus.Warn("provided ECHConfigList is empty")
	}
	return o.overrides.Resolve(f).ApplyList(list), nil
}

func (o *options) renderOptions() echfmt.Options {
	return echfmt.Options{
		Format:        o.Format,
		ShowConfig:    o.showConfig,
		IncludeBase64: true,
	}
}
