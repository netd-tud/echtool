package ech

import (
	"io"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
)

type greaseOptions struct {
	configID      uint8
	configIDSet   bool
	version       uint16
	kem           hpke.KEM
	cipherSuites  []goech.HpkeSymmetricCipherSuite
	maxNameLength uint8
}

type GreaseOption func(*greaseOptions)

func WithConfigID(id uint8) GreaseOption {
	return func(o *greaseOptions) {
		o.configID = id
		o.configIDSet = true
	}
}

func WithVersion(version uint16) GreaseOption {
	return func(o *greaseOptions) { o.version = version }
}

func WithKEM(kem hpke.KEM) GreaseOption {
	return func(o *greaseOptions) { o.kem = kem }
}

func WithCipherSuites(suites ...goech.HpkeSymmetricCipherSuite) GreaseOption {
	return func(o *greaseOptions) { o.cipherSuites = suites }
}

func WithMaxNameLength(length uint8) GreaseOption {
	return func(o *greaseOptions) { o.maxNameLength = length }
}

func defaultGreaseOptions() greaseOptions {
	return greaseOptions{
		version: goech.DraftTLSESNI16,
		kem:     hpke.KEM_X25519_HKDF_SHA256,
	}
}

type tlsOptions struct {
	insecureSkipVerify bool
	keyLogger          io.Writer
	alpn               []string
}

type TLSOption func(*tlsOptions)

func WithInsecureSkipVerify(skip bool) TLSOption {
	return func(o *tlsOptions) { o.insecureSkipVerify = skip }
}

func WithKeyLogger(w io.Writer) TLSOption {
	return func(o *tlsOptions) { o.keyLogger = w }
}

func WithALPN(protocols ...string) TLSOption {
	return func(o *tlsOptions) { o.alpn = protocols }
}
