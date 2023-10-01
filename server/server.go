package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Snawoot/dtlspipe/util"
	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	"github.com/pion/transport/v2/udp"
)

const (
	Backlog = 1024
)

type Server struct {
	listener    net.Listener
	dtlsConfig  *dtls.Config
	rAddr       string
	psk         func([]byte) ([]byte, error)
	timeout     time.Duration
	idleTimeout time.Duration
	baseCtx     context.Context
	cancelCtx   func()
	staleMode   util.StaleMode
	workerWG    sync.WaitGroup
	timeLimit   time.Duration
}

func New(cfg *Config) (*Server, error) {
	cfg = cfg.populateDefaults()

	baseCtx, cancelCtx := context.WithCancel(cfg.BaseContext)

	srv := &Server{
		rAddr:       cfg.RemoteAddress,
		timeout:     cfg.Timeout,
		psk:         cfg.PSKCallback,
		idleTimeout: cfg.IdleTimeout,
		baseCtx:     baseCtx,
		cancelCtx:   cancelCtx,
		staleMode:   cfg.StaleMode,
		timeLimit:   cfg.TimeLimit,
	}

	lAddrPort, err := netip.ParseAddrPort(cfg.BindAddress)
	if err != nil {
		cancelCtx()
		return nil, fmt.Errorf("can't parse bind address: %w", err)
	}

	srv.dtlsConfig = &dtls.Config{
		ExtendedMasterSecret:    dtls.RequireExtendedMasterSecret,
		ConnectContextMaker:     srv.contextMaker,
		PSK:                     srv.psk,
		MTU:                     cfg.MTU,
		InsecureSkipVerifyHello: cfg.SkipHelloVerify,
		CipherSuites:            cfg.CipherSuites,
		EllipticCurves:          cfg.EllipticCurves,
	}
	lc := udp.ListenConfig{
		AcceptFilter: func(packet []byte) bool {
			pkts, err := recordlayer.UnpackDatagram(packet)
			if err != nil || len(pkts) < 1 {
				return false
			}
			h := &recordlayer.Header{}
			if err := h.Unmarshal(pkts[0]); err != nil {
				return false
			}
			return h.ContentType == protocol.ContentTypeHandshake
		},
		Backlog: Backlog,
	}
	listener, err := lc.Listen("udp", net.UDPAddrFromAddrPort(lAddrPort))
	if err != nil {
		cancelCtx()
		return nil, fmt.Errorf("server listen failed: %w", err)
	}

	srv.listener = listener

	go srv.listen()

	return srv, nil
}

func (srv *Server) listen() {
	defer srv.Close()
	for srv.baseCtx.Err() == nil {
		conn, err := srv.listener.Accept()
		if err != nil {
			log.Printf("conn accept failed: %v", err)
			continue
		}

		srv.workerWG.Add(1)
		go func(conn net.Conn) {
			defer srv.workerWG.Done()
			defer conn.Close()
			conn, err := dtls.Server(conn, srv.dtlsConfig)
			if err != nil {
				log.Printf("DTLS accept error: %v", err)
				return
			}
			defer conn.Close()
			srv.serve(conn)
		}(conn)
	}
}

func (srv *Server) serve(conn net.Conn) {
	log.Printf("[+] conn %s <=> %s", conn.LocalAddr(), conn.RemoteAddr())
	defer log.Printf("[-] conn %s <=> %s", conn.LocalAddr(), conn.RemoteAddr())
	defer conn.Close()

	ctx := srv.baseCtx
	if srv.timeLimit != 0 {
		newCtx, cancel := context.WithTimeout(ctx, srv.timeLimit)
		defer cancel()
		ctx = newCtx
	}

	dialCtx, cancel := context.WithTimeout(ctx, srv.timeout)
	defer cancel()
	remoteConn, err := (&net.Dialer{}).DialContext(dialCtx, "udp", srv.rAddr)
	if err != nil {
		log.Printf("remote dial failed: %v", err)
		return
	}
	defer remoteConn.Close()

	util.PairConn(ctx, conn, remoteConn, srv.idleTimeout, srv.staleMode)
}

func (srv *Server) contextMaker() (context.Context, func()) {
	return context.WithTimeout(srv.baseCtx, srv.timeout)
}

func (srv *Server) Close() error {
	srv.cancelCtx()
	err := srv.listener.Close()
	srv.workerWG.Wait()
	return err
}
