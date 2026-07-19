package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
	"github.com/spf13/pflag"

	"github.com/jmuecke/echtools/pkg/echfmt"
)

// cipherSuitesValue is a pflag.Value that parses "KDF/AEAD" specs (e.g.
// "SHA256/AES128GCM") into goech cipher suites as the flag is parsed, using
// goech's KDF/AEAD name tables. Specs accumulate across repeated flags and/or
// comma-separated values (matching pflag's StringSlice UX). An unset flag leaves
// the slice nil, which makes ech.Grease advertise goech's full default set.
type cipherSuitesValue struct {
	v *[]goech.HpkeSymmetricCipherSuite
}

// NewCipherSuites binds a --cipher-suite flag to p.
func NewCipherSuites(p *[]goech.HpkeSymmetricCipherSuite) pflag.Value {
	return &cipherSuitesValue{p}
}

func (c *cipherSuitesValue) Set(s string) error {
	for _, spec := range strings.Split(s, ",") {
		kdfName, aeadName, ok := strings.Cut(spec, "/")
		if !ok {
			return fmt.Errorf("invalid --cipher-suite %q: expected KDF/AEAD (e.g. SHA256/AES128GCM)", spec)
		}
		kdf, err := lookupHPKEName(goech.KDFMapping[:], kdfName)
		if err != nil {
			return fmt.Errorf("--cipher-suite %q: unknown KDF %q", spec, kdfName)
		}
		aead, err := lookupHPKEName(goech.AEADMapping[:], aeadName)
		if err != nil {
			return fmt.Errorf("--cipher-suite %q: unknown AEAD %q", spec, aeadName)
		}
		*c.v = append(*c.v, goech.HpkeSymmetricCipherSuite{
			KDF:  hpke.KDF(kdf),
			AEAD: hpke.AEAD(aead),
		})
	}
	return nil
}

func (c *cipherSuitesValue) Type() string { return "strings" }

func (c *cipherSuitesValue) String() string {
	specs := make([]string, len(*c.v))
	for i, cs := range *c.v {
		specs[i] = fmt.Sprintf("%s/%s", echfmt.KDFName(uint16(cs.KDF)), echfmt.AEADName(uint16(cs.AEAD)))
	}
	return strings.Join(specs, ",")
}

// lookupHPKEName resolves a case-insensitive algorithm name to its HPKE
// identifier via one of goech's name tables (which are indexed by that id).
func lookupHPKEName(table []string, name string) (int, error) {
	for id, n := range table {
		if n != "" && strings.EqualFold(n, name) {
			return id, nil
		}
	}
	return 0, fmt.Errorf("unknown algorithm %q", name)
}

// resolveValue is a pflag.Value that parses curl-style "host:port:address"
// --resolve entries into a "host:port" -> address override map, accumulating
// across repeated flags the way curl's own --resolve does. Unlike curl it
// takes no wildcard host and no leading "+"/"-", and only the first address
// of a comma-separated list is kept (curl uses the rest for happy-eyeballs
// fallback, which none of our dialers do).
type resolveValue struct {
	m *map[string]string
}

// NewResolveOverrides binds a --resolve flag to p.
func NewResolveOverrides(p *map[string]string) pflag.Value {
	return &resolveValue{p}
}

func (r *resolveValue) Set(s string) error {
	host, rest, ok := strings.Cut(s, ":")
	if !ok {
		return fmt.Errorf("invalid --resolve %q: expected host:port:address", s)
	}
	port, addr, ok := strings.Cut(rest, ":")
	if !ok {
		return fmt.Errorf("invalid --resolve %q: expected host:port:address", s)
	}
	addr, _, _ = strings.Cut(addr, ",")
	// Accept curl's bracketed IPv6 form (host:port:[::1]); store the bare
	// address so DNSParams.Address can re-bracket it via net.JoinHostPort.
	if len(addr) >= 2 && addr[0] == '[' && addr[len(addr)-1] == ']' {
		addr = addr[1 : len(addr)-1]
	}
	if addr == "" {
		return fmt.Errorf("invalid --resolve %q: missing address", s)
	}
	if *r.m == nil {
		*r.m = make(map[string]string)
	}
	(*r.m)[net.JoinHostPort(host, port)] = addr
	return nil
}

func (r *resolveValue) Type() string { return "stringArray" }

func (r *resolveValue) String() string {
	if r.m == nil || len(*r.m) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(*r.m))
	for hostPort, addr := range *r.m {
		pairs = append(pairs, hostPort+":"+addr)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

// KeylogWriter opens the key log destination at path, falling back to
// $SSLKEYLOGFILE when path is empty and returning a nil writer when neither is
// set. The file is left open for the lifetime of the process: key-log writes go
// straight to the file descriptor (no buffering), so there is nothing to flush,
// and the OS closes the descriptor on exit.
func KeylogWriter(path string) (io.Writer, error) {
	if path == "" {
		path = os.Getenv("SSLKEYLOGFILE")
	}
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening keylog file %q: %w", path, err)
	}
	return f, nil
}

// ParseTarget splits a target argument into its host and a host:port dial
// address. A bare host (no ":port") uses defaultPort, so "facebook.com" becomes
// host "facebook.com" / "facebook.com:443" and "facebook:123" becomes host
// "facebook" / "facebook:123".
func ParseTarget(arg, defaultPort string) (host, address string) {
	h, port, err := net.SplitHostPort(arg)
	if err != nil {
		h, port = arg, defaultPort
	}
	return h, net.JoinHostPort(h, port)
}
