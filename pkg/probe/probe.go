// Run ECH probing and determine success
package probe

import (
	"crypto/tls"
	"fmt"

	"github.com/OmarTariq612/goech"
	"github.com/sirupsen/logrus"

	"github.com/jmuecke/echtools/pkg/dial"
	"github.com/jmuecke/echtools/pkg/ech"
)

type ValidationResult struct {
	Index    int
	ConfigID uint8
	Accepted bool
	Err      string // "" on success
}

func AttemptECH(cfg *tls.Config, address string, config goech.ECHConfig, dialFn dial.Fn) error {
	attempt, err := ech.Replace(cfg, config)
	if err != nil {
		return err
	}
	conn, _, state, err := dialFn(address, attempt)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		return fmt.Errorf("handshake failed: %s", dial.DescribeError(err))
	}
	if !state.ECHAccepted {
		return fmt.Errorf("handshake completed but the server did not accept ECH")
	}
	return nil
}

func ValidateConfigs(cfg *tls.Config, address string, configs goech.ECHConfigList, dialFn dial.Fn) []ValidationResult {
	results := make([]ValidationResult, len(configs))
	for i, config := range configs {
		ech.LogEchConfigs(fmt.Sprintf("Validating RetryConfig #%d with a fresh handshake", i), config)
		err := AttemptECH(cfg, address, config, dialFn)
		results[i] = ValidationResult{Index: i, ConfigID: config.ConfigID, Accepted: err == nil}
		if err != nil {
			results[i].Err = err.Error()
			logrus.WithError(err).Errorf("RetryConfig #%d (config_id %d) failed validation against %s", i, config.ConfigID, address)
			continue
		}
		logrus.Infof("RetryConfig #%d (config_id %d) validated: ECH accepted by %s", i, config.ConfigID, address)
	}
	return results
}
