// QUIC or TCP+TLS conection with error parsing
package dial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/quic"
)

type Fn func(address string, cfg *tls.Config) (io.Closer, net.Addr, tls.ConnectionState, error)

const Timeout = 15 * time.Second

func TCP(address string, cfg *tls.Config) (io.Closer, net.Addr, tls.ConnectionState, error) {
	dialer := &tls.Dialer{Config: cfg}
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, tls.ConnectionState{}, err
	}
	tlsConn := conn.(*tls.Conn)
	return tlsConn, tlsConn.RemoteAddr(), tlsConn.ConnectionState(), nil
}

func QUIC(address string, cfg *tls.Config) (io.Closer, net.Addr, tls.ConnectionState, error) {
	if len(cfg.NextProtos) == 0 {
		return nil, nil, tls.ConnectionState{}, errors.New("QUIC requires at least one ALPN protocol (use --alpn)")
	}

	ep, err := quic.Listen("udp", ":0", nil)
	if err != nil {
		return nil, nil, tls.ConnectionState{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	conn, err := ep.Dial(ctx, "udp", address, &quic.Config{TLSConfig: cfg})
	if err != nil {
		_ = ep.Close(context.Background())
		return nil, nil, tls.ConnectionState{}, err
	}

	return &quicCloser{conn: conn, ep: ep}, net.UDPAddrFromAddrPort(conn.RemoteAddr()), conn.ConnectionState(), nil
}

// quicCloser tears down both the QUIC connection and its endpoint.
type quicCloser struct {
	conn *quic.Conn
	ep   *quic.Endpoint
}

func (q *quicCloser) Close() error {
	_ = q.conn.Close()
	return q.ep.Close(context.Background())
}

// remoteAlertCodes maps: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6
var remoteAlertCodes = map[string]int{
	"close notify":                    0,
	"unexpected message":              10,
	"bad record MAC":                  20,
	"decryption failed":               21,
	"record overflow":                 22,
	"decompression failure":           30,
	"handshake failure":               40,
	"bad certificate":                 42,
	"unsupported certificate":         43,
	"revoked certificate":             44,
	"expired certificate":             45,
	"unknown certificate":             46,
	"illegal parameter":               47,
	"unknown certificate authority":   48,
	"access denied":                   49,
	"error decoding message":          50,
	"error decrypting message":        51,
	"export restriction":              60,
	"protocol version not supported":  70,
	"insufficient security level":     71,
	"internal error":                  80,
	"inappropriate fallback":          86,
	"user canceled":                   90,
	"no renegotiation":                100,
	"missing extension":               109,
	"unsupported extension":           110,
	"certificate unobtainable":        111,
	"unrecognized name":               112,
	"bad certificate status response": 113,
	"bad certificate hash value":      114,
	"unknown PSK identity":            115,
	"certificate required":            116,
	"general error":                   117,
	"no application protocol":         120,
	"encrypted client hello required": 121,
}

// Kind classifies a handshake/dial error into a small, stable set of machine-
// readable categories, for callers (e.g. a JSON API) that need to branch on
// the failure type rather than parse Classified.Message.
type Kind string

const (
	KindTLSAlert    Kind = "tls_alert"
	KindCertificate Kind = "certificate_error"
	KindDNS         Kind = "dns_error"
	KindTimeout     Kind = "timeout"
	KindNetwork     Kind = "network_error"
	KindOther       Kind = "other"
)

type ClassifiedError struct {
	Kind    Kind
	Message string
}

// Classify expands err — typically returned by a Fn — into a Kind plus
// diagnostic detail its own Error() text doesn't carry: for a TLS alert (the
// signal a peer sends when it aborts a handshake, e.g. "handshake failure"),
func Classify(err error) ClassifiedError {
	if err == nil {
		return ClassifiedError{}
	}

	// QUIC path: Go wraps the alert in an exported tls.AlertError.
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return ClassifiedError{KindTLSAlert, fmt.Sprintf("TLS alert %d: %s", uint8(alertErr), err.Error())}
	}

	// TCP path: the alert is only recoverable by matching its description
	// text inside the *net.OpError{Op: "remote error"} crypto/tls returns.
	var remoteErr *net.OpError
	if errors.As(err, &remoteErr) && remoteErr.Op == "remote error" {
		desc := strings.TrimPrefix(remoteErr.Err.Error(), "tls: ")
		if code, ok := remoteAlertCodes[desc]; ok {
			return ClassifiedError{KindTLSAlert, fmt.Sprintf("%s (TLS alert %d, sent by the remote peer)", err.Error(), code)}
		}
		return ClassifiedError{KindTLSAlert, fmt.Sprintf("%s (TLS alert sent by the remote peer)", err.Error())}
	}

	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		if len(certErr.UnverifiedCertificates) > 0 {
			return ClassifiedError{KindCertificate, fmt.Sprintf("certificate verification failed for %q: %s",
				certErr.UnverifiedCertificates[0].Subject.CommonName, err.Error())}
		}
		return ClassifiedError{KindCertificate, fmt.Sprintf("certificate verification failed: %s", err.Error())}
	}

	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return ClassifiedError{KindCertificate, fmt.Sprintf("certificate hostname mismatch: %s", err.Error())}
	}

	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		return ClassifiedError{KindCertificate, fmt.Sprintf("certificate signed by unknown authority: %s", err.Error())}
	}

	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return ClassifiedError{KindCertificate, fmt.Sprintf("certificate invalid: %s", err.Error())}
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return ClassifiedError{KindDNS, fmt.Sprintf("DNS lookup found no such host %q", dnsErr.Name)}
		case dnsErr.IsTimeout:
			return ClassifiedError{KindDNS, fmt.Sprintf("DNS lookup for %q timed out", dnsErr.Name)}
		default:
			return ClassifiedError{KindDNS, fmt.Sprintf("DNS lookup for %q failed: %s", dnsErr.Name, err.Error())}
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return ClassifiedError{KindTimeout, fmt.Sprintf("timed out after %s: %s", Timeout, err.Error())}
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op != "remote error" {
		return ClassifiedError{KindNetwork, fmt.Sprintf("%s error: %s", opErr.Op, err.Error())}
	}

	return ClassifiedError{KindOther, err.Error()}
}

func DescribeError(err error) string {
	return Classify(err).Message
}
