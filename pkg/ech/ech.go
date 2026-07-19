package ech

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/OmarTariq612/goech"
)

// Grease builds a well-formed, single-entry GREASE ECHConfigList for publicName.
// It synthesises a throwaway HPKE keypair via goech.GenerateECHKeySet, so the
// resulting config is structurally valid but cannot be decrypted by any real
// server — offering it reliably triggers ECH rejection and, from ECH-aware
// servers, a RetryConfigs list.
func Grease(publicName string, opts ...GreaseOption) (goech.ECHConfigList, error) {
	o := defaultGreaseOptions()
	for _, opt := range opts {
		opt(&o)
	}

	configID := o.configID
	if !o.configIDSet {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("generating random config id: %w", err)
		}
		configID = b[0]
	}

	keyset, err := goech.GenerateECHKeySet(configID, publicName, o.kem, o.cipherSuites)
	if err != nil {
		return nil, fmt.Errorf("generating GREASE ECH keyset: %w", err)
	}

	config := keyset.ECHConfig
	config.Version = o.version
	config.MaxNameLength = o.maxNameLength
	return goech.ECHConfigList{config}, nil
}

func TLS(target string, list goech.ECHConfigList, opts ...TLSOption) (*tls.Config, error) {
	var o tlsOptions
	for _, opt := range opts {
		opt(&o)
	}

	raw, err := list.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshaling ECHConfigList: %w", err)
	}

	cfg := &tls.Config{
		ServerName:                     target,
		EncryptedClientHelloConfigList: raw,
		MinVersion:                     tls.VersionTLS13,
		MaxVersion:                     tls.VersionTLS13,
		InsecureSkipVerify:             o.insecureSkipVerify,
		KeyLogWriter:                   o.keyLogger,
		NextProtos:                     o.alpn,
	}

	if o.insecureSkipVerify {
		cfg.EncryptedClientHelloRejectionVerify = func(tls.ConnectionState) error { return nil }
	}

	return cfg, nil
}

func RetryConfigs(err error) *tls.ECHRejectionError {
	var rejErr *tls.ECHRejectionError
	if errors.As(err, &rejErr) {
		return rejErr
	}
	return nil
}

func Replace(config *tls.Config, chosen goech.ECHConfig) (*tls.Config, error) {
	raw, err := goech.MarshalECHConfigArgs(chosen)
	if err != nil {
		return nil, fmt.Errorf("marshaling chosen ECHConfig: %w", err)
	}
	clone := config.Clone()
	clone.EncryptedClientHelloConfigList = raw
	return clone, nil
}
