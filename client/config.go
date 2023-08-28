package client

import (
	"context"
	"time"
)

type Config struct {
	BindAddress   string
	RemoteAddress string
	Timeout       time.Duration
	IdleTimeout   time.Duration
	BaseContext   context.Context
	PSKCallback   func([]byte) ([]byte, error)
	PSKIdentity   string
	MTU           int
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
	return cfg
}
