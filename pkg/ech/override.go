package ech

import "github.com/OmarTariq612/goech"

type Overrides struct {
	PublicName    *string
	ConfigID      *uint8
	Version       *uint16
	MaxNameLength *uint8
	// CipherSuites, when non-nil, replaces the config's cipher suites. A nil slice
	// leaves them unchanged.
	CipherSuites []goech.HpkeSymmetricCipherSuite
}

func (o Overrides) Empty() bool {
	return o.PublicName == nil && o.ConfigID == nil && o.Version == nil &&
		o.MaxNameLength == nil && o.CipherSuites == nil
}

func (o Overrides) Apply(c goech.ECHConfig) goech.ECHConfig {
	if o.PublicName != nil {
		c.RawPublicName = []byte(*o.PublicName)
	}
	if o.ConfigID != nil {
		c.ConfigID = *o.ConfigID
	}
	if o.Version != nil {
		c.Version = *o.Version
	}
	if o.MaxNameLength != nil {
		c.MaxNameLength = *o.MaxNameLength
	}
	if o.CipherSuites != nil {
		c.CipherSuites = o.CipherSuites
	}
	return c
}

func (o Overrides) ApplyList(list goech.ECHConfigList) goech.ECHConfigList {
	if o.Empty() {
		return list
	}
	out := make(goech.ECHConfigList, len(list))
	for i, c := range list {
		out[i] = o.Apply(c)
	}
	return out
}
