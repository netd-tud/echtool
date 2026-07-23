package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/OmarTariq612/goech"
	"github.com/sirupsen/logrus"

	"github.com/netd-tud/echtool/pkg/dial"
	"github.com/netd-tud/echtool/pkg/dnsrr"
	"github.com/netd-tud/echtool/pkg/ech"
)

const DefaultMaxValidations = 50

type RunInput struct {
	Target    string
	Address   string
	Offer     goech.ECHConfigList
	TLSConfig *tls.Config
	DialFn    dial.Fn

	DNSServer          string
	ValidateConfig     bool
	ValidateAllConfigs bool
	MaxValidations     int
}

type DNSComparison struct {
	Found   bool
	Matches bool
	Configs goech.ECHConfigList
}

type Result struct {
	Offered goech.ECHConfigList

	Accepted       bool
	PeerAddr       string
	NegotiatedALPN string
	TLSVersion     uint16

	Rejected     bool
	RetryConfigs goech.ECHConfigList
	DNS          *DNSComparison
	Validations  []ValidationResult

	Err *dial.ClassifiedError
}

func Run(ctx context.Context, in RunInput) (*Result, error) {
	conn, addr, state, dialErr := in.DialFn(in.Address, in.TLSConfig)
	if conn != nil {
		defer conn.Close()
	}

	if rejectErr := ech.RetryConfigs(dialErr); rejectErr != nil {
		return runRejected(ctx, in, rejectErr)
	}
	if dialErr != nil {
		classified := dial.Classify(dialErr)
		return &Result{Offered: in.Offer, Err: &classified}, nil
	}

	return &Result{
		Offered:        in.Offer,
		Accepted:       state.ECHAccepted,
		PeerAddr:       addrString(addr),
		NegotiatedALPN: state.NegotiatedProtocol,
		TLSVersion:     state.Version,
	}, nil
}

// ECH rejected, handle RetryConfigs when received
func runRejected(ctx context.Context, in RunInput, rejectErr *tls.ECHRejectionError) (*Result, error) {
	// Some implementations that do not support ECH send an empty ECH configurations.
	var retryConfigs goech.ECHConfigList
	if len(rejectErr.RetryConfigList) > 0 {
		var err error
		retryConfigs, err = goech.UnmarshalECHConfigList(rejectErr.RetryConfigList)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling server retry configs: %w", err)
		}
	}

	result := &Result{
		Offered:      in.Offer,
		Rejected:     true,
		RetryConfigs: retryConfigs,
	}

	if len(retryConfigs) == 0 {
		logrus.Warnf("%s rejected the offered ECH config without returning RetryConfigs", in.Address)
		return result, nil
	}
	logrus.Warnf("%s rejected the offered ECH config and returned RetryConfigs", in.Address)

	dnsList, found, matches := dnsrr.CompareAndLog(ctx, in.Target, in.DNSServer, retryConfigs)
	result.DNS = &DNSComparison{Found: found, Matches: matches, Configs: dnsList}

	switch {
	case in.ValidateAllConfigs:
		toValidate := retryConfigs
		max := in.MaxValidations
		if max <= 0 {
			max = DefaultMaxValidations
		}
		if len(toValidate) > max {
			toValidate = toValidate[:max]
		}
		result.Validations = ValidateConfigs(in.TLSConfig, in.Address, toValidate, in.DialFn)
	case in.ValidateConfig:
		result.Validations = ValidateConfigs(in.TLSConfig, in.Address, retryConfigs[:1], in.DialFn)
	}
	return result, nil
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
