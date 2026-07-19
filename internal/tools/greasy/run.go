package greasy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"

	"github.com/OmarTariq612/goech"
	"github.com/sirupsen/logrus"

	"github.com/jmuecke/echtools/pkg/dial"
	"github.com/jmuecke/echtools/pkg/ech"
	"github.com/jmuecke/echtools/pkg/echfmt"
	"github.com/jmuecke/echtools/pkg/probe"
)

func run(out io.Writer, o *options, target, address string, list goech.ECHConfigList, dialFn dial.Fn) error {
	ech.LogEchConfigs("Offering ECH config", list...)

	cfg, err := o.tls.TLS(target, list)
	if err != nil {
		return err
	}

	logrus.Debugf("offering ECH to %s (public name %q)", address, target)
	res, err := probe.Run(context.Background(), probe.RunInput{
		Target:    target,
		Address:   address,
		Offer:     list,
		TLSConfig: cfg,
		DialFn:    dialFn,
		DNSServer: o.dns.DNSServer,

		ValidateConfig:     o.validateConfig,
		ValidateAllConfigs: o.validateAllConfigs,
	})
	if err != nil {
		return err
	}

	switch {
	case res.Err != nil:
		return fmt.Errorf("%s: %s", res.Err.Kind, res.Err.Message)
	case res.Rejected:
		return renderRejected(out, o, address, res)
	default:
		return renderOutcome(out, o, address, res)
	}
}

// printStatus writes a one-line verdict to stdout for the human-readable
// formats; json and b64 carry the verdict in-band instead.
func printStatus(out io.Writer, o *options, line string) {
	if o.Format == echfmt.FormatText || o.Format == echfmt.FormatTable {
		fmt.Fprintln(out, line)
	}
}

// Different output when at least one connection failed
func renderRejected(out io.Writer, o *options, address string, res *probe.Result) error {
	ech.LogEchConfigs("Server RetryConfigs", res.RetryConfigs...)

	render := o.renderOptions()
	rejected := false
	render.ECHAccepted = &rejected
	if res.DNS != nil {
		render.DNS = &echfmt.DNSInfo{
			Found:   res.DNS.Found,
			Matches: res.DNS.Matches,
			Configs: echfmt.ToSerializableList(res.DNS.Configs),
		}
	}
	for _, v := range res.Validations {
		render.Validations = append(render.Validations, echfmt.ValidationInfo{
			Index:    v.Index,
			ConfigID: v.ConfigID,
			Accepted: v.Accepted,
			Error:    v.Err,
		})
	}

	printStatus(out, o, fmt.Sprintf("ECH rejected by %s (%d retry config(s) returned)", address, len(res.RetryConfigs)))
	if err := echfmt.Render(out, res.RetryConfigs, render); err != nil {
		return err
	}

	var failures int
	for _, v := range res.Validations {
		if !v.Accepted {
			failures++
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d retry config(s) failed ECH validation against %s", failures, len(res.Validations), address)
	}
	if o.requireConfig {
		return fmt.Errorf("ECH was rejected by %s", address)
	}
	return nil
}

func renderOutcome(out io.Writer, o *options, address string, res *probe.Result) error {
	peer := fmt.Sprintf("peer %s, %s", res.PeerAddr, tls.VersionName(res.TLSVersion))
	if res.NegotiatedALPN != "" {
		peer += ", ALPN " + res.NegotiatedALPN
	}
	if res.Accepted {
		logrus.Infof("ECH accepted by %s (%s)", address, res.PeerAddr)
		printStatus(out, o, fmt.Sprintf("ECH accepted by %s (%s)", address, peer))
	} else {
		logrus.Warnf("handshake with %s succeeded but ECH was not accepted", address)
		printStatus(out, o, fmt.Sprintf("ECH not accepted by %s: handshake succeeded without ECH (%s)", address, peer))
	}

	render := o.renderOptions()
	render.ECHAccepted = &res.Accepted
	render.Peer = &echfmt.PeerInfo{
		Address:        res.PeerAddr,
		NegotiatedALPN: res.NegotiatedALPN,
		TLSVersion:     tls.VersionName(res.TLSVersion),
	}
	if err := echfmt.Render(out, res.Offered, render); err != nil {
		return err
	}
	if o.requireConfig && !res.Accepted {
		return fmt.Errorf("ECH was not accepted by %s", address)
	}
	return nil
}
