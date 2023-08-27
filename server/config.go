package server

import (
	"context"
	"time"
)

type Config struct {
	BindAddress   string
	RemoteAddress string
	Password      string
	Timeout       time.Duration
	IdleTimeout   time.Duration
	BaseContext   context.Context
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
