package cli

import (
	"testing"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
)

func TestCipherSuitesParsing(t *testing.T) {
	var suites []goech.HpkeSymmetricCipherSuite
	v := NewCipherSuites(&suites)

	// A comma-separated spec and a later repeated flag both accumulate.
	if err := v.Set("SHA256/AES128GCM,SHA384/AES256GCM"); err != nil {
		t.Fatalf("Set comma-separated: %v", err)
	}
	if err := v.Set("sha512/chacha20poly1305"); err != nil { // case-insensitive
		t.Fatalf("Set repeated: %v", err)
	}

	want := []goech.HpkeSymmetricCipherSuite{
		{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES128GCM},
		{KDF: hpke.KDF_HKDF_SHA384, AEAD: hpke.AEAD_AES256GCM},
		{KDF: hpke.KDF_HKDF_SHA512, AEAD: hpke.AEAD_ChaCha20Poly1305},
	}
	if len(suites) != len(want) {
		t.Fatalf("parsed %d suites, want %d: %+v", len(suites), len(want), suites)
	}
	for i := range want {
		if suites[i] != want[i] {
			t.Errorf("suite[%d] = %+v, want %+v", i, suites[i], want[i])
		}
	}

	// String() renders back to canonical KDF/AEAD names, comma-joined.
	if got, want := v.String(), "SHA256/AES128GCM,SHA384/AES256GCM,SHA512/CHACHA20POLY1305"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestCipherSuitesErrors(t *testing.T) {
	tests := []struct {
		name string
		spec string
	}{
		{"missing slash", "SHA256"},
		{"unknown KDF", "BOGUS/AES128GCM"},
		{"unknown AEAD", "SHA256/BOGUS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var suites []goech.HpkeSymmetricCipherSuite
			if err := NewCipherSuites(&suites).Set(tt.spec); err == nil {
				t.Errorf("Set(%q) = nil error, want an error", tt.spec)
			}
		})
	}
}
