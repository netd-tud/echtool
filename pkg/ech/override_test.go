package ech

import (
	"testing"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
)

func ptr[T any](v T) *T { return &v }

func baseConfig(t *testing.T) goech.ECHConfig {
	t.Helper()
	list, err := Grease("base.example", WithConfigID(5))
	if err != nil {
		t.Fatalf("Grease: %v", err)
	}
	return list[0]
}

func TestOverridesEmpty(t *testing.T) {
	if !(Overrides{}).Empty() {
		t.Error("zero Overrides should be Empty")
	}
	if (Overrides{ConfigID: ptr[uint8](1)}).Empty() {
		t.Error("Overrides with a field set should not be Empty")
	}
}

func TestOverridesApplyEachField(t *testing.T) {
	base := baseConfig(t)
	wantKey, _ := base.PublicKey.MarshalBinary()

	suite := goech.HpkeSymmetricCipherSuite{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES128GCM}
	got := Overrides{
		PublicName:    ptr("override.example"),
		ConfigID:      ptr[uint8](42),
		Version:       ptr[uint16](0xabcd),
		MaxNameLength: ptr[uint8](99),
		CipherSuites:  []goech.HpkeSymmetricCipherSuite{suite},
	}.Apply(base)

	if string(got.RawPublicName) != "override.example" {
		t.Errorf("public name = %q", got.RawPublicName)
	}
	if got.ConfigID != 42 {
		t.Errorf("config id = %d", got.ConfigID)
	}
	if got.Version != 0xabcd {
		t.Errorf("version = %#x", got.Version)
	}
	if got.MaxNameLength != 99 {
		t.Errorf("max name length = %d", got.MaxNameLength)
	}
	if len(got.CipherSuites) != 1 || got.CipherSuites[0] != suite {
		t.Errorf("cipher suites = %+v", got.CipherSuites)
	}

	// Unset fields (public key, KEM) must be preserved.
	gotKey, _ := got.PublicKey.MarshalBinary()
	if string(gotKey) != string(wantKey) {
		t.Error("public key must be preserved by Apply")
	}
	if got.KEM != base.KEM {
		t.Error("KEM must be preserved by Apply")
	}
}

func TestOverridesLeaveUnsetFieldsUntouched(t *testing.T) {
	base := baseConfig(t)
	got := Overrides{ConfigID: ptr[uint8](7)}.Apply(base)

	if got.ConfigID != 7 {
		t.Errorf("config id = %d, want 7", got.ConfigID)
	}
	if string(got.RawPublicName) != string(base.RawPublicName) {
		t.Error("public name should be untouched")
	}
	if got.Version != base.Version {
		t.Error("version should be untouched")
	}
	if got.MaxNameLength != base.MaxNameLength {
		t.Error("max name length should be untouched")
	}
	if len(got.CipherSuites) != len(base.CipherSuites) {
		t.Error("cipher suites should be untouched")
	}
}

func TestOverridesApplyListEmptyReturnsInput(t *testing.T) {
	base := goech.ECHConfigList{baseConfig(t)}
	got := (Overrides{}).ApplyList(base)
	if len(got) != 1 || got[0].ConfigID != base[0].ConfigID {
		t.Error("empty Overrides.ApplyList should return the list unchanged")
	}
}

func TestOverridesApplyListAppliesToAllAndCopies(t *testing.T) {
	list := goech.ECHConfigList{baseConfig(t), baseConfig(t)}
	origID := list[0].ConfigID // baseConfig pins config id 5

	got := Overrides{ConfigID: ptr[uint8](200)}.ApplyList(list)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	for i, c := range got {
		if c.ConfigID != 200 {
			t.Errorf("got[%d].ConfigID = %d, want 200", i, c.ConfigID)
		}
	}
	// The override must be applied to a copy, leaving the input list untouched.
	if list[0].ConfigID != origID || list[1].ConfigID != origID {
		t.Error("ApplyList must not mutate the input list")
	}
}
