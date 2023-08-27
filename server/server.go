package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/pion/dtls/v2"
)

type Server struct {
	listener    net.Listener
	rAddr       string
	psk         []byte
	timeout     time.Duration
	idleTimeout time.Duration
	baseCtx     context.Context
	cancelCtx   func()
}

func New(cfg *Config) (*Server, error) {
	cfg = cfg.populateDefaults()

	baseCtx, cancelCtx := context.WithCancel(cfg.BaseContext)

	srv := &Server{
		rAddr:       cfg.RemoteAddress,
		psk:         []byte(cfg.Password), // TODO: key derivation
		timeout:     cfg.Timeout,
		idleTimeout: cfg.IdleTimeout,
		baseCtx:     baseCtx,
		cancelCtx:   cancelCtx,
	}

	lAddrPort, err := netip.ParseAddrPort(cfg.BindAddress)
	if err != nil {
		cancelCtx()
		return nil, fmt.Errorf("can't parse bind address: %w", err)
	}

	dtlsConfig := &dtls.Config{
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM,
			dtls.TLS_PSK_WITH_AES_128_CCM_8,
			dtls.TLS_PSK_WITH_AES_256_CCM_8,
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CBC_SHA256,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ConnectContextMaker:  srv.contextMaker,
		PSK: func(hint []byte) ([]byte, error) {
			return []byte(cfg.Password), nil
		},
	}
	listener, err := dtls.Listen("udp", net.UDPAddrFromAddrPort(lAddrPort), dtlsConfig)
	if err != nil {
		cancelCtx()
		return nil, fmt.Errorf("server listen failed: %w", err)
	}

	srv.listener = listener

	return srv, nil
}

func (srv *Server) listen() {
	for srv.baseCtx.Err() == nil {
		conn, err := srv.listener.Accept()
		if err != nil {
			log.Printf("conn accept failed: %v", err)
			return
		}

		go srv.serve(conn)
	}
}

func (srv *Server) serve(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("Hello, World!"))
}

func (srv *Server) contextMaker() (context.Context, func()) {
	return context.WithTimeout(srv.baseCtx, srv.timeout)
}

func (srv *Server) Close() error {
	srv.cancelCtx()
	return srv.listener.Close()
}
