package echfmt

import (
	"bytes"
	"strings"
	"testing"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
)

func sampleList(t *testing.T, n int) goech.ECHConfigList {
	t.Helper()
	list := make(goech.ECHConfigList, n)
	for i := range list {
		ks, err := goech.GenerateECHKeySet(uint8(i), "example.com", hpke.KEM_X25519_HKDF_SHA256, nil)
		if err != nil {
			t.Fatalf("GenerateECHKeySet: %v", err)
		}
		list[i] = ks.ECHConfig
	}
	return list
}

func TestRenderBase64RoundTrips(t *testing.T) {
	list := sampleList(t, 2)

	var buf bytes.Buffer
	if err := Render(&buf, list, Options{Format: FormatBase64, ShowConfig: -1}); err != nil {
		t.Fatalf("Render b64: %v", err)
	}

	got, err := goech.ECHConfigListFromBase64(strings.TrimSpace(buf.String()))
	if err != nil {
		t.Fatalf("decoding rendered base64: %v", err)
	}
	if !got.Equal(list) {
		t.Fatalf("round-tripped list differs from original")
	}
}

func TestRenderShowConfigFilters(t *testing.T) {
	list := sampleList(t, 3)

	var buf bytes.Buffer
	if err := Render(&buf, list, Options{Format: FormatText, ShowConfig: 1}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	// A single-element list is re-indexed from #0, and config #1 has config_id 1.
	if strings.Count(out, "ECHConfig #") != 1 {
		t.Fatalf("expected exactly one config in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Config ID:       1") {
		t.Fatalf("expected the config with id 1, got:\n%s", out)
	}
}

func TestRenderShowConfigOutOfRange(t *testing.T) {
	list := sampleList(t, 2)
	if err := Render(&bytes.Buffer{}, list, Options{Format: FormatText, ShowConfig: 5}); err == nil {
		t.Fatal("expected out-of-range --show-config to error")
	}
}

func TestRenderJSONBackwardCompatible(t *testing.T) {
	list := sampleList(t, 1)

	var buf bytes.Buffer
	// dech renders with IncludeBase64 false and must keep emitting a bare array.
	if err := Render(&buf, list, Options{Format: FormatJSON, ShowConfig: -1}); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); !strings.HasPrefix(got, "[") {
		t.Fatalf("expected a JSON array, got:\n%s", got)
	}
}

func TestRenderJSONWithBase64IsObject(t *testing.T) {
	list := sampleList(t, 1)

	var buf bytes.Buffer
	if err := Render(&buf, list, Options{Format: FormatJSON, ShowConfig: -1, IncludeBase64: true}); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"ech_config_list_base64"`) || !strings.Contains(out, `"configs"`) {
		t.Fatalf("expected wrapped object with base64 field, got:\n%s", out)
	}
}

func TestRenderTextIncludeBase64Line(t *testing.T) {
	list := sampleList(t, 1)

	var buf bytes.Buffer
	if err := Render(&buf, list, Options{Format: FormatText, ShowConfig: -1, IncludeBase64: true}); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !strings.Contains(buf.String(), "ECHConfigList (base64): ") {
		t.Fatalf("expected trailing base64 line, got:\n%s", buf.String())
	}
}

func TestParseECHConfigList(t *testing.T) {
	tests := map[string]string{
		"AEX...":                             "AEX...",
		`example.com. IN HTTPS 1 . ech="AB"`: "AB",
		"foo ech=BAR baz":                    "BAR",
		"ech=BAR":                            "BAR",
		// Base64 that merely ends in "ech=" ('=' being padding) is not an
		// "ech=" token: it neither starts the input nor follows whitespace.
		"AEXNech=":    "AEXNech=",
		"AEX ech=BAR": "BAR",
	}
	for in, want := range tests {
		got, err := ParseECHConfigList(in)
		if err != nil {
			t.Errorf("ParseECHConfigList(%q) returned error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseECHConfigList(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseECHConfigList(`ech=`); err == nil {
		t.Errorf(`ParseECHConfigList("ech=") = nil error, want error for empty value`)
	}
}
