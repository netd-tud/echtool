package cli

import (
	"net"

	"github.com/spf13/pflag"
)

type DNSParams struct {
	// Only for resolving HTTPS RRs. Does not change hostname resolution
	DNSServer string

	// Allow users to override hostname resolution by providing an IP address
	Resolve map[string]string
}

func AddDNSParamsFlags(f *pflag.FlagSet, c *DNSParams) {
	f.StringVar(&c.DNSServer, "dns-server", "",
		"resolver (host:port) for the ECH-retry-vs-DNS HTTPS RR comparison (plain UDP, no DoH, DoT, DoQ); "+
			"does not affect how the connection itself is resolved (always system resolver)")
	f.Var(NewResolveOverrides(&c.Resolve), "resolve",
		"override DNS resolution for a target, like host:port:address (repeatable)")
}

func (c *DNSParams) Address(hostPort string) string {
	addr, ok := c.Resolve[hostPort]
	if !ok {
		return hostPort
	}
	_, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return net.JoinHostPort(addr, port)
}
