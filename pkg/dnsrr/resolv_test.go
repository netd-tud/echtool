package dnsrr

import (
	"context"
	"net"
	"testing"
)

func TestSystemServer(t *testing.T) {
	server, err := systemServer(context.Background())
	if err != nil {
		t.Fatalf("systemServer: %v", err)
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		t.Errorf("systemServer returned %q, not a valid host:port: %v", server, err)
	}
}

func TestFQDN(t *testing.T) {
	tests := map[string]string{
		"example.com":  "example.com.",
		"example.com.": "example.com.",
		"a":            "a.",
	}
	for in, want := range tests {
		if got := fqdn(in); got != want {
			t.Errorf("fqdn(%q) = %q, want %q", in, got, want)
		}
	}
}
