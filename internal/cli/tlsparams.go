package cli

import (
	"crypto/tls"

	"github.com/OmarTariq612/goech"
	"github.com/spf13/pflag"

	"github.com/netd-tud/echtool/pkg/ech"
)

// TLSParams holds the TLS/dial flags shared by every command that performs an
// ECH handshake (greasy, conn, echtest): --alpn, --insecure, --keylog.
type TLSParams struct {
	ALPN     []string
	Insecure bool
	Keylog   string
}

func AddTLSParamsFlags(f *pflag.FlagSet, c *TLSParams) {
	f.StringSliceVar(&c.ALPN, "alpn", nil, "ALPN protocol(s) to offer (repeatable; QUIC defaults to h3)")
	f.BoolVar(&c.Insecure, "insecure", false, "skip TLS certificate verification")
	f.StringVar(&c.Keylog, "keylog", "", "write TLS session keys to this file (defaults to $SSLKEYLOGFILE)")
}

// TLS builds a *tls.Config offering list to target using the shared TLS
// settings (--alpn, --insecure, --keylog).
func (c *TLSParams) TLS(target string, list goech.ECHConfigList) (*tls.Config, error) {
	keylog, err := KeylogWriter(c.Keylog)
	if err != nil {
		return nil, err
	}
	return ech.TLS(
		target, list,
		ech.WithInsecureSkipVerify(c.Insecure),
		ech.WithKeyLogger(keylog),
		ech.WithALPN(c.ALPN...),
	)
}
