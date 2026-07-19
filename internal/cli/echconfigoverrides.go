package cli

import (
	"fmt"

	"github.com/OmarTariq612/goech"
	"github.com/spf13/pflag"

	"github.com/jmuecke/echtools/pkg/ech"
)

type ECHConfigOverrides struct {
	PubName       string
	ConfigID      int // -1 = unset (random config_id for GREASE; no override for conn)
	ECHVersion    uint16
	CipherSuites  []goech.HpkeSymmetricCipherSuite
	MaxNameLength uint8
}

func AddECHConfigOverrideFlags(f *pflag.FlagSet, s *ECHConfigOverrides, prefix string) {
	f.StringVar(&s.PubName, prefix+"pub-name", "",
		"ECH public name / SNI (overrides a supplied config's, or the target host if generating one)")
	f.IntVar(&s.ConfigID, prefix+"config-id", -1,
		"ECH config_id 0-255 (overrides a supplied config's, or random if generating one)")
	f.Uint16Var(&s.ECHVersion, prefix+"ech-version", goech.DraftTLSESNI16,
		"ECH config version (overrides a supplied config's, or the draft default if generating one)")
	f.Var(NewCipherSuites(&s.CipherSuites), prefix+"cipher-suite",
		"HPKE cipher suite(s) as KDF/AEAD, e.g. SHA256/AES128GCM (repeatable; overrides a supplied config's, or all supported if generating one)")
	f.Uint8Var(&s.MaxNameLength, prefix+"max-name-length", 0,
		"ECH maximum_name_length (overrides a supplied config's, or 0 if generating one)")
}

func (s *ECHConfigOverrides) Validate(prefix string) error {
	if s.ConfigID < -1 || s.ConfigID > 255 {
		return fmt.Errorf("invalid --%sconfig-id %d: must be 0-255", prefix, s.ConfigID)
	}
	return nil
}

func (s *ECHConfigOverrides) GreaseOptions() []ech.GreaseOption {
	opts := []ech.GreaseOption{
		ech.WithVersion(s.ECHVersion),
		ech.WithMaxNameLength(s.MaxNameLength),
		ech.WithCipherSuites(s.CipherSuites...),
	}
	if s.ConfigID >= 0 {
		opts = append(opts, ech.WithConfigID(uint8(s.ConfigID)))
	}
	return opts
}

func (s *ECHConfigOverrides) Resolve(f *pflag.FlagSet) ech.Overrides {
	var ov ech.Overrides
	if f.Changed("pub-name") {
		ov.PublicName = &s.PubName
	}
	if f.Changed("config-id") {
		id := uint8(s.ConfigID)
		ov.ConfigID = &id
	}
	if f.Changed("ech-version") {
		ov.Version = &s.ECHVersion
	}
	if f.Changed("max-name-length") {
		ov.MaxNameLength = &s.MaxNameLength
	}
	if f.Changed("cipher-suite") {
		ov.CipherSuites = s.CipherSuites
	}
	return ov
}
