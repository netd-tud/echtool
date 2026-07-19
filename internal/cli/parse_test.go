package cli

import "testing"

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name        string
		arg         string
		defaultPort string
		wantHost    string
		wantAddress string
	}{
		{
			name:        "bare host uses default port",
			arg:         "facebook.com",
			defaultPort: "443",
			wantHost:    "facebook.com",
			wantAddress: "facebook.com:443",
		},
		{
			name:        "explicit port is preserved",
			arg:         "facebook.com:8443",
			defaultPort: "443",
			wantHost:    "facebook.com",
			wantAddress: "facebook.com:8443",
		},
		{
			name:        "short host with explicit port",
			arg:         "facebook:123",
			defaultPort: "443",
			wantHost:    "facebook",
			wantAddress: "facebook:123",
		},
		{
			name:        "bare IPv6 gets bracketed with default port",
			arg:         "::1",
			defaultPort: "443",
			wantHost:    "::1",
			wantAddress: "[::1]:443",
		},
		{
			name:        "bracketed IPv6 with explicit port",
			arg:         "[2001:db8::1]:8443",
			defaultPort: "443",
			wantHost:    "2001:db8::1",
			wantAddress: "[2001:db8::1]:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, address := ParseTarget(tt.arg, tt.defaultPort)
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if address != tt.wantAddress {
				t.Errorf("address = %q, want %q", address, tt.wantAddress)
			}
		})
	}
}

func TestResolveOverrides(t *testing.T) {
	tests := []struct {
		name     string
		entry    string
		lookup   string
		wantAddr string
	}{
		{
			name:     "IPv4 address",
			entry:    "example.com:443:93.184.216.34",
			lookup:   "example.com:443",
			wantAddr: "93.184.216.34:443",
		},
		{
			name:     "bare IPv6 address gets bracketed on lookup",
			entry:    "example.com:443:::1",
			lookup:   "example.com:443",
			wantAddr: "[::1]:443",
		},
		{
			name:     "bracketed IPv6 address (curl syntax)",
			entry:    "example.com:443:[2001:db8::1]",
			lookup:   "example.com:443",
			wantAddr: "[2001:db8::1]:443",
		},
		{
			name:     "only first address of a comma-separated list is kept",
			entry:    "example.com:443:10.0.0.1,10.0.0.2",
			lookup:   "example.com:443",
			wantAddr: "10.0.0.1:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := DNSParams{}
			if err := NewResolveOverrides(&p.Resolve).Set(tt.entry); err != nil {
				t.Fatalf("Set(%q) failed: %v", tt.entry, err)
			}
			if got := p.Address(tt.lookup); got != tt.wantAddr {
				t.Errorf("Address(%q) = %q, want %q", tt.lookup, got, tt.wantAddr)
			}
		})
	}
}
