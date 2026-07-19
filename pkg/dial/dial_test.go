package dial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestDescribeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string // substring the description must contain
	}{
		{
			name: "nil error yields empty string",
			err:  nil,
			want: "",
		},
		{
			name: "QUIC alert exposes the numeric code",
			err:  tls.AlertError(40),
			want: "TLS alert 40:",
		},
		{
			name: "TCP remote alert with known description resolves its code",
			err:  &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")},
			want: "(TLS alert 40, sent by the remote peer)",
		},
		{
			name: "TCP remote alert with unknown description still flagged as remote",
			err:  &net.OpError{Op: "remote error", Err: errors.New("tls: some future alert")},
			want: "(TLS alert sent by the remote peer)",
		},
		{
			name: "certificate verification names the subject",
			err: &tls.CertificateVerificationError{
				UnverifiedCertificates: []*x509.Certificate{
					{Subject: pkix.Name{CommonName: "bad.example"}},
				},
				Err: errors.New("boom"),
			},
			want: `certificate verification failed for "bad.example"`,
		},
		{
			name: "certificate verification without certificates",
			err:  &tls.CertificateVerificationError{Err: errors.New("boom")},
			want: "certificate verification failed:",
		},
		{
			name: "hostname mismatch",
			err:  x509.HostnameError{Certificate: &x509.Certificate{}, Host: "wrong.example"},
			want: "certificate hostname mismatch:",
		},
		{
			name: "unknown authority",
			err:  x509.UnknownAuthorityError{},
			want: "certificate signed by unknown authority:",
		},
		{
			name: "invalid certificate",
			err:  x509.CertificateInvalidError{Reason: x509.Expired},
			want: "certificate invalid:",
		},
		{
			name: "DNS not found",
			err:  &net.DNSError{Name: "nope.example", IsNotFound: true},
			want: `DNS lookup found no such host "nope.example"`,
		},
		{
			name: "DNS timeout",
			err:  &net.DNSError{Name: "slow.example", IsTimeout: true},
			want: `DNS lookup for "slow.example" timed out`,
		},
		{
			name: "DNS other failure",
			err:  &net.DNSError{Name: "x.example", Err: "servfail"},
			want: `DNS lookup for "x.example" failed:`,
		},
		{
			name: "deadline exceeded",
			err:  context.DeadlineExceeded,
			want: "timed out after",
		},
		{
			name: "non-remote op error is classified by op",
			err:  &net.OpError{Op: "dial", Err: errors.New("connection refused")},
			want: "dial error:",
		},
		{
			name: "unclassified error passes through unchanged",
			err:  errors.New("something odd"),
			want: "something odd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DescribeError(tt.err)
			if tt.want == "" {
				if got != "" {
					t.Errorf("DescribeError = %q, want empty", got)
				}
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("DescribeError = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

// TestDescribeErrorAlertTableMatchesRemotePath spot-checks that a couple of alert
// descriptions from the table are resolved to their RFC 8446 codes via the TCP
// remote-error path, guarding the table against silent drift.
func TestDescribeErrorAlertTableMatchesRemotePath(t *testing.T) {
	cases := map[string]int{
		"handshake failure":               40,
		"unrecognized name":               112,
		"encrypted client hello required": 121,
	}
	for desc, code := range cases {
		err := &net.OpError{Op: "remote error", Err: errors.New("tls: " + desc)}
		got := DescribeError(err)
		want := "(TLS alert " + strconv.Itoa(code) + ", sent by the remote peer)"
		if !strings.Contains(got, want) {
			t.Errorf("description %q: DescribeError = %q, want it to contain %q", desc, got, want)
		}
	}
}
