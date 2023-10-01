package client

import (
	"context"
	"time"

	"github.com/Snawoot/dtlspipe/ciphers"
	"github.com/Snawoot/dtlspipe/util"
)

type Config struct {
	BindAddress    string
	RemoteAddress  string
	Timeout        time.Duration
	IdleTimeout    time.Duration
	BaseContext    context.Context
	PSKCallback    func([]byte) ([]byte, error)
	PSKIdentity    string
	MTU            int
	CipherSuites   ciphers.CipherList
	EllipticCurves ciphers.CurveList
	StaleMode      util.StaleMode
}

func (cfg *Config) populateDefaults() *Config {
	newCfg := new(Config)
	*newCfg = *cfg
	cfg = newCfg
	if cfg.BaseContext == nil {
		cfg.BaseContext = context.Background()
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 90 * time.Second
	}
	if cfg.CipherSuites == nil {
		cfg.CipherSuites = ciphers.DefaultCipherList
	}
	if cfg.EllipticCurves == nil {
		cfg.EllipticCurves = ciphers.DefaultCurveList
	}
	return cfg
}
