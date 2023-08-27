package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	"github.com/pion/transport/v2/udp"
)

type Server struct {
	listener    net.Listener
	dtlsConfig  *dtls.Config
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
		timeout:     cfg.Timeout,
		psk:         cfg.PSK,
		idleTimeout: cfg.IdleTimeout,
		baseCtx:     baseCtx,
		cancelCtx:   cancelCtx,
	}

	lAddrPort, err := netip.ParseAddrPort(cfg.BindAddress)
	if err != nil {
		cancelCtx()
		return nil, fmt.Errorf("can't parse bind address: %w", err)
	}

	srv.dtlsConfig = &dtls.Config{
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
		PSK:                  srv.getPSK,
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

		go func(conn net.Conn) {
			conn, err := dtls.Server(conn, srv.dtlsConfig)
			if err != nil {
				log.Printf("DTLS accept error: %v", err)
				return
			}
			srv.serve(conn)
		}(conn)
	}
}

func (srv *Server) serve(conn net.Conn) {
	log.Printf("[+] conn %s <=> %s", conn.LocalAddr(), conn.RemoteAddr())
	defer log.Printf("[-] conn %s <=> %s", conn.LocalAddr(), conn.RemoteAddr())
	defer conn.Close()
	io.Copy(conn, conn)
}

func (srv *Server) contextMaker() (context.Context, func()) {
	return context.WithTimeout(srv.baseCtx, srv.timeout)
}

func (srv *Server) getPSK(hint []byte) ([]byte, error) {
	return srv.psk, nil
}

func (srv *Server) Close() error {
	srv.cancelCtx()
	return srv.listener.Close()
}
