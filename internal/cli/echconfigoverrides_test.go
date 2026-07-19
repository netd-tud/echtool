package cli

import (
	"testing"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
	"github.com/spf13/pflag"

	"github.com/jmuecke/echtools/pkg/ech"
)

func TestECHConfigOverridesValidate(t *testing.T) {
	tests := []struct {
		name    string
		id      int
		wantErr bool
	}{
		{"unset sentinel", -1, false},
		{"zero", 0, false},
		{"max", 255, false},
		{"below sentinel", -2, true},
		{"above range", 256, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ECHConfigOverrides{ConfigID: tt.id}
			err := s.Validate("")
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(id=%d) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

// TestECHConfigOverridesGreaseOptionsPinnedConfigID checks the GREASE options
// end-to-end: feeding them to ech.Grease must produce a config carrying every
// overridden field.
func TestECHConfigOverridesGreaseOptionsPinnedConfigID(t *testing.T) {
	suite := goech.HpkeSymmetricCipherSuite{KDF: hpke.KDF_HKDF_SHA384, AEAD: hpke.AEAD_AES256GCM}
	s := ECHConfigOverrides{
		ConfigID:      42,
		ECHVersion:    goech.DraftTLSESNI16,
		MaxNameLength: 64,
		CipherSuites:  []goech.HpkeSymmetricCipherSuite{suite},
	}

	list, err := ech.Grease("pub.example", s.GreaseOptions()...)
	if err != nil {
		t.Fatalf("Grease: %v", err)
	}
	c := list[0]
	if c.ConfigID != 42 {
		t.Errorf("config id = %d, want 42", c.ConfigID)
	}
	if c.Version != goech.DraftTLSESNI16 {
		t.Errorf("version = %#x, want %#x", c.Version, goech.DraftTLSESNI16)
	}
	if c.MaxNameLength != 64 {
		t.Errorf("max name length = %d, want 64", c.MaxNameLength)
	}
	if len(c.CipherSuites) != 1 || c.CipherSuites[0] != suite {
		t.Errorf("cipher suites = %+v, want exactly %+v", c.CipherSuites, suite)
	}
}

// TestECHConfigOverridesGreaseOptionsConfigIDConditional pins down the one
// conditional in GreaseOptions: WithConfigID is appended only when a
// config_id is set (>= 0), so an unset value yields one fewer option.
func TestECHConfigOverridesGreaseOptionsConfigIDConditional(t *testing.T) {
	unset := ECHConfigOverrides{ConfigID: -1}
	set := ECHConfigOverrides{ConfigID: 0}
	withUnset := len(unset.GreaseOptions())
	withSet := len(set.GreaseOptions())
	if withSet != withUnset+1 {
		t.Errorf("GreaseOptions with a config id = %d opts, without = %d; want exactly one more when set",
			withSet, withUnset)
	}
}

func TestECHConfigOverridesResolveOnlyChangedFlags(t *testing.T) {
	var s ECHConfigOverrides
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	AddECHConfigOverrideFlags(fs, &s, "")
	if err := fs.Parse([]string{
		"--pub-name=over.example",
		"--config-id=9",
		"--cipher-suite=SHA256/AES128GCM",
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	ov := s.Resolve(fs)
	if ov.PublicName == nil || *ov.PublicName != "over.example" {
		t.Errorf("PublicName = %v, want over.example", ov.PublicName)
	}
	if ov.ConfigID == nil || *ov.ConfigID != 9 {
		t.Errorf("ConfigID = %v, want 9", ov.ConfigID)
	}
	if ov.CipherSuites == nil {
		t.Error("CipherSuites should be set")
	}
	// Flags left at their defaults must stay nil so "unset" is distinguishable.
	if ov.Version != nil {
		t.Errorf("Version = %v, want nil (flag unchanged)", ov.Version)
	}
	if ov.MaxNameLength != nil {
		t.Errorf("MaxNameLength = %v, want nil (flag unchanged)", ov.MaxNameLength)
	}
	if ov.Empty() {
		t.Error("Resolve with changed flags should not be Empty")
	}
}

func TestECHConfigOverridesResolveEmptyWhenNothingChanged(t *testing.T) {
	var s ECHConfigOverrides
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	AddECHConfigOverrideFlags(fs, &s, "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ov := s.Resolve(fs); !ov.Empty() {
		t.Errorf("Resolve with no changed flags should be Empty, got %+v", ov)
	}
}
