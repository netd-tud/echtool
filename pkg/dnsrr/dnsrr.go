package dnsrr

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/OmarTariq612/goech"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"
)

const lookupTimeout = 10 * time.Second

// Use this address to get an error from the system resolvers, which leaks the IP address.
// hack to support windows
const probeDomain = "dnsrr-system-server-probe.invalid."

var errServerCaptured = errors.New("dnsrr: system resolver address captured")

// maxAliasHops bounds how many HTTPS AliasMode records (RFC 9460 §2.1)
// LookupECH will follow before giving up, guarding against alias loops.
const maxAliasHops = 3

func LookupECH(ctx context.Context, domain, server string) (goech.ECHConfigList, bool, error) {
	if server == "" {
		s, err := systemServer(ctx)
		if err != nil {
			return nil, false, err
		}
		server = s
	}

	for hops := 0; ; hops++ {
		resp, err := query(ctx, domain, server)
		if err != nil {
			return nil, false, err
		}
		list, found, alias, err := parseHTTPSAnswers(resp)
		if err != nil {
			return nil, false, err
		}
		if found {
			return list, true, nil
		}
		if alias == "" {
			return nil, false, nil
		}
		if hops >= maxAliasHops {
			return nil, false, fmt.Errorf("HTTPS RR alias chain for %s exceeded %d hops", domain, maxAliasHops)
		}
		domain = alias
	}
}

// parseHTTPSAnswers scans resp's answer section for a HTTPS RR. It returns
// (list, true, "", nil) if a ServiceMode record with an ech SvcParam was
// found; (nil, false, target, nil) if only an AliasMode record (SvcPriority
// 0, RFC 9460 §2.1) was found, so the caller can re-query at target; and
// (nil, false, "", nil) if neither was present.
func parseHTTPSAnswers(resp []byte) (list goech.ECHConfigList, found bool, alias string, err error) {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return nil, false, "", fmt.Errorf("parsing DNS response: %w", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, false, "", fmt.Errorf("parsing DNS response questions: %w", err)
	}

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, false, "", fmt.Errorf("parsing DNS answer: %w", err)
		}
		if h.Type != dnsmessage.TypeHTTPS {
			if err := p.SkipAnswer(); err != nil {
				return nil, false, "", fmt.Errorf("skipping DNS answer: %w", err)
			}
			continue
		}
		https, err := p.HTTPSResource()
		if err != nil {
			return nil, false, "", fmt.Errorf("reading HTTPS record: %w", err)
		}
		if https.Priority == 0 {
			// AliasMode: no SvcParams, resolution continues at Target. A name
			// can't mix AliasMode with ServiceMode records, so this is the
			// only HTTPS answer for the RRset.
			alias = https.Target.String()
			continue
		}
		echRaw, ok := https.GetParam(dnsmessage.SVCParamECH)
		if !ok {
			continue
		}
		list, err := goech.UnmarshalECHConfigList(echRaw)
		if err != nil {
			return nil, false, "", fmt.Errorf("decoding ECHConfigList from HTTPS RR: %w", err)
		}
		return list, true, "", nil
	}
	return nil, false, alias, nil
}

func query(ctx context.Context, domain, server string) ([]byte, error) {
	name, err := dnsmessage.NewName(fqdn(domain))
	if err != nil {
		return nil, fmt.Errorf("invalid domain %q: %w", domain, err)
	}

	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("generating query id: %w", err)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               binary.BigEndian.Uint16(id[:]),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeHTTPS,
			Class: dnsmessage.ClassINET,
		}},
	}
	// Advertise a larger UDP buffer via EDNS0 so the full HTTPS record (which can
	// include IP hints alongside the ech param) is not truncated to 512 bytes.
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(4096, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, fmt.Errorf("building EDNS0 record: %w", err)
	}
	msg.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}

	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS query: %w", err)
	}

	return exchangeUDP(ctx, server, packed)
}

func systemServer(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	var mu sync.Mutex
	var server string
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			mu.Lock()
			if server == "" {
				server = address
			}
			mu.Unlock()
			return nil, errServerCaptured
		},
	}

	_, lookupErr := resolver.LookupHost(ctx, probeDomain)

	mu.Lock()
	defer mu.Unlock()
	if server == "" {
		if lookupErr != nil {
			return "", fmt.Errorf("discovering system resolver: %w", lookupErr)
		}
		return "", fmt.Errorf("discovering system resolver: no nameserver configured")
	}
	return server, nil
}

func fqdn(domain string) string {
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		return domain
	}
	return domain + "."
}

func checkResponseID(hdr dnsmessage.Header, packed []byte) error {
	if want := binary.BigEndian.Uint16(packed[:2]); hdr.ID != want {
		return fmt.Errorf("DNS response ID %d does not match query ID %d", hdr.ID, want)
	}
	return nil
}

func exchangeUDP(ctx context.Context, server string, packed []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, fmt.Errorf("dialing resolver %s: %w", server, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("sending UDP query: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("reading UDP response: %w", err)
	}

	var hp dnsmessage.Parser
	hdr, err := hp.Start(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("parsing UDP response header: %w", err)
	}
	if err := checkResponseID(hdr, packed); err != nil {
		return nil, err
	}
	if hdr.Truncated {
		return nil, fmt.Errorf("DNS response from %s was truncated despite EDNS0", server)
	}
	return buf[:n], nil
}

func CompareAndLog(ctx context.Context, domain, server string, retry goech.ECHConfigList) (dns goech.ECHConfigList, found bool, matches bool) {
	dnsList, found, err := LookupECH(ctx, domain, server)
	if err != nil {
		logrus.WithError(err).Warnf("HTTPS RR lookup for %s failed; skipping retry-vs-DNS comparison", domain)
		return nil, false, false
	}
	if !found {
		logrus.Infof("no ECH config in the DNS HTTPS RR for %s; nothing to compare against", domain)
		return nil, false, false
	}
	if retry.Equal(dnsList) {
		logrus.Infof("retry config for %s matches its DNS HTTPS RR", domain)
		return dnsList, true, true
	}
	logrus.Warnf("MISMATCH: retry config for %s differs from the ECH config published in its DNS HTTPS RR", domain)
	return dnsList, true, false
}
