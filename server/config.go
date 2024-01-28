package server

import (
	"context"
	"net"
	"time"

	"github.com/SenseUnit/dtlspipe/ciphers"
	"github.com/SenseUnit/dtlspipe/util"
)

type Config struct {
	BindAddress     string
	RemoteAddress   string
	Timeout         time.Duration
	IdleTimeout     time.Duration
	BaseContext     context.Context
	PSKCallback     func([]byte) ([]byte, error)
	MTU             int
	SkipHelloVerify bool
	CipherSuites    ciphers.CipherList
	EllipticCurves  ciphers.CurveList
	StaleMode       util.StaleMode
	TimeLimitFunc   func() time.Duration
	AllowFunc       func(localAddr, remoteAddr net.Addr) bool
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
	if cfg.TimeLimitFunc == nil {
		cfg.TimeLimitFunc = util.FixedTimeLimitFunc(0)
	}
	if cfg.AllowFunc == nil {
		cfg.AllowFunc = util.AllowAllFunc
	}
	return cfg
}
