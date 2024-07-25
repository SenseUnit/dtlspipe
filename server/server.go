package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/SenseUnit/dtlspipe/util"
	"github.com/pion/dtls/v3"
)

const (
	Backlog = 1024
)

type Server struct {
	listener      net.Listener
	dialer        *net.Dialer
	dtlsConfig    *dtls.Config
	rAddr         string
	psk           func([]byte) ([]byte, error)
	timeout       time.Duration
	idleTimeout   time.Duration
	baseCtx       context.Context
	cancelCtx     func()
	staleMode     util.StaleMode
	workerWG      sync.WaitGroup
	timeLimitFunc func() time.Duration
	allowFunc     func(net.Addr) bool
}

func New(cfg *Config) (*Server, error) {
	cfg = cfg.populateDefaults()

	baseCtx, cancelCtx := context.WithCancel(cfg.BaseContext)

	srv := &Server{
		dialer:        new(net.Dialer),
		rAddr:         cfg.RemoteAddress,
		timeout:       cfg.Timeout,
		psk:           cfg.PSKCallback,
		idleTimeout:   cfg.IdleTimeout,
		baseCtx:       baseCtx,
		cancelCtx:     cancelCtx,
		staleMode:     cfg.StaleMode,
		timeLimitFunc: cfg.TimeLimitFunc,
		allowFunc:     cfg.AllowFunc,
	}

	lAddrPort, err := netip.ParseAddrPort(cfg.BindAddress)
	if err != nil {
		cancelCtx()
		return nil, fmt.Errorf("can't parse bind address: %w", err)
	}

	srv.dtlsConfig = &dtls.Config{
		ExtendedMasterSecret:    dtls.RequireExtendedMasterSecret,
		PSK:                     srv.psk,
		MTU:                     cfg.MTU,
		InsecureSkipVerifyHello: cfg.SkipHelloVerify,
		CipherSuites:            cfg.CipherSuites,
		EllipticCurves:          cfg.EllipticCurves,
		OnConnectionAttempt: func(a net.Addr) error {
			if !srv.allowFunc(a) {
				return fmt.Errorf("address %s was not allowed by limiter", a.String())
			}
			return nil
		},
	}
	srv.listener, err = dtls.Listen("udp", net.UDPAddrFromAddrPort(lAddrPort), srv.dtlsConfig)
	if err != nil {
		cancelCtx()
		return nil, fmt.Errorf("can't initialize DTLS listener: %w", err)
	}

	go srv.listen()

	return srv, nil
}

func (srv *Server) listen() {
	defer srv.Close()
	for srv.baseCtx.Err() == nil {
		conn, err := srv.listener.Accept()
		if err != nil {
			log.Printf("DTLS conn accept failed: %v", err)
			continue
		}

		srv.workerWG.Add(1)
		go func(conn net.Conn) {
			defer srv.workerWG.Done()
			defer conn.Close()
			srv.serve(conn)
		}(conn)
	}
}

func (srv *Server) serve(conn net.Conn) {
	log.Printf("[+] conn %s <=> %s", conn.LocalAddr(), conn.RemoteAddr())
	defer log.Printf("[-] conn %s <=> %s", conn.LocalAddr(), conn.RemoteAddr())
	defer conn.Close()

	if handshaker, ok := conn.(interface {
		HandshakeContext(context.Context) error
	}); ok {
		err := func() error {
			hsCtx, cancel := context.WithTimeout(srv.baseCtx, srv.timeout)
			defer cancel()
			return handshaker.HandshakeContext(hsCtx)
		}()
		if err != nil {
			log.Printf("handshake %s <=> %s failed: %v", conn.LocalAddr(), conn.RemoteAddr(), err)
			return
		}
	}

	ctx := srv.baseCtx
	tl := srv.timeLimitFunc()
	if tl != 0 {
		newCtx, cancel := context.WithTimeout(ctx, tl)
		defer cancel()
		ctx = newCtx
	}

	remoteConn, err := func() (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(ctx, srv.timeout)
		defer cancel()
		return srv.dialer.DialContext(dialCtx, "udp", srv.rAddr)
	}()
	if err != nil {
		log.Printf("remote dial failed: %v", err)
		return
	}
	defer remoteConn.Close()

	util.PairConn(ctx, conn, remoteConn, srv.idleTimeout, srv.staleMode)
}

func (srv *Server) Close() error {
	srv.cancelCtx()
	err := srv.listener.Close()
	srv.workerWG.Wait()
	return err
}
