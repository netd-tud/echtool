package ech

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
)

func TestGreaseBuildsSingleConfig(t *testing.T) {
	list, err := Grease("example.com", WithConfigID(42), WithVersion(goech.DraftTLSESNI16))
	if err != nil {
		t.Fatalf("Grease: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 config, got %d", len(list))
	}
	c := list[0]
	if got := string(c.RawPublicName); got != "example.com" {
		t.Errorf("public name = %q, want example.com", got)
	}
	if c.ConfigID != 42 {
		t.Errorf("config id = %d, want 42", c.ConfigID)
	}
	if c.Version != goech.DraftTLSESNI16 {
		t.Errorf("version = %#x, want %#x", c.Version, goech.DraftTLSESNI16)
	}
}

func TestGreaseCipherSuitesAndMaxNameLength(t *testing.T) {
	suite := goech.HpkeSymmetricCipherSuite{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES128GCM}
	list, err := Grease("example.com",
		WithConfigID(3),
		WithCipherSuites(suite),
		WithMaxNameLength(64),
	)
	if err != nil {
		t.Fatalf("Grease: %v", err)
	}
	c := list[0]
	if c.MaxNameLength != 64 {
		t.Errorf("max name length = %d, want 64", c.MaxNameLength)
	}
	if len(c.CipherSuites) != 1 || c.CipherSuites[0] != suite {
		t.Errorf("cipher suites = %+v, want exactly %+v", c.CipherSuites, suite)
	}
}

func TestGreaseDefaultsAllCipherSuites(t *testing.T) {
	list, err := Grease("example.com")
	if err != nil {
		t.Fatalf("Grease: %v", err)
	}
	if len(list[0].CipherSuites) < 2 {
		t.Errorf("expected the full default cipher suite set, got %d", len(list[0].CipherSuites))
	}
}

func TestGreaseRandomConfigID(t *testing.T) {
	// Two greases without a pinned config id should (almost surely) still each
	// produce a valid, marshalable config.
	for i := 0; i < 2; i++ {
		list, err := Grease("example.com")
		if err != nil {
			t.Fatalf("Grease: %v", err)
		}
		if _, err := list.MarshalBinary(); err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
	}
}

func TestTLSSeedsConfig(t *testing.T) {
	list, err := Grease("example.com", WithConfigID(1))
	if err != nil {
		t.Fatalf("Grease: %v", err)
	}
	cfg, err := TLS("example.com", list,
		WithInsecureSkipVerify(true),
		WithALPN("h2", "http/1.1"),
	)
	if err != nil {
		t.Fatalf("TLS: %v", err)
	}
	if cfg.ServerName != "example.com" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify not set")
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("versions = %#x/%#x, want TLS1.3", cfg.MinVersion, cfg.MaxVersion)
	}
	want, _ := list.MarshalBinary()
	if string(cfg.EncryptedClientHelloConfigList) != string(want) {
		t.Error("EncryptedClientHelloConfigList not seeded from list")
	}
	if cfg.EncryptedClientHelloRejectionVerify == nil {
		t.Error("EncryptedClientHelloRejectionVerify not set: crypto/tls ignores InsecureSkipVerify on ECH rejection without it")
	} else if err := cfg.EncryptedClientHelloRejectionVerify(tls.ConnectionState{}); err != nil {
		t.Errorf("EncryptedClientHelloRejectionVerify(...) = %v, want nil", err)
	}
}

func TestTLSSecureLeavesRejectionVerifyUnset(t *testing.T) {
	list, err := Grease("example.com", WithConfigID(1))
	if err != nil {
		t.Fatalf("Grease: %v", err)
	}
	cfg, err := TLS("example.com", list)
	if err != nil {
		t.Fatalf("TLS: %v", err)
	}
	if cfg.EncryptedClientHelloRejectionVerify != nil {
		t.Error("EncryptedClientHelloRejectionVerify set without --insecure: would suppress normal ECH-rejection certificate verification")
	}
}

func TestRetryConfigs(t *testing.T) {
	rej := &tls.ECHRejectionError{RetryConfigList: []byte("retry")}

	if got := RetryConfigs(rej); got != rej {
		t.Errorf("RetryConfigs(rej) = %v, want the rejection error", got)
	}
	if got := RetryConfigs(fmt.Errorf("wrap: %w", rej)); got != rej {
		t.Errorf("RetryConfigs(wrapped) = %v, want the rejection error", got)
	}
	if got := RetryConfigs(fmt.Errorf("plain")); got != nil {
		t.Errorf("RetryConfigs(plain) = %v, want nil", got)
	}
	if got := RetryConfigs(nil); got != nil {
		t.Errorf("RetryConfigs(nil) = %v, want nil", got)
	}
}

func TestReplace(t *testing.T) {
	list, err := Grease("provider.example", WithConfigID(7))
	if err != nil {
		t.Fatalf("Grease: %v", err)
	}
	cfg := &tls.Config{}
	clone, err := Replace(cfg, list[0])
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if cfg.EncryptedClientHelloConfigList != nil {
		t.Fatalf("Replace modified the original config")
	}
	got, err := goech.UnmarshalECHConfigList(clone.EncryptedClientHelloConfigList)
	if err != nil {
		t.Fatalf("UnmarshalECHConfigList: %v", err)
	}
	if len(got) != 1 || got[0].ConfigID != 7 {
		t.Fatalf("Replace did not install the chosen config: %+v", got)
	}
}
