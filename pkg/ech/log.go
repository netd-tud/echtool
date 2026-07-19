package ech

import (
	"github.com/OmarTariq612/goech"
	"github.com/sirupsen/logrus"
)

func LogEchConfigs(label string, configs ...goech.ECHConfig) {
	logrus.Infof("%s (count=%d)", label, len(configs))
	for i, c := range configs {
		logrus.Infof("  [%d] %s", i, c.String())
	}
}
