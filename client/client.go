package client

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
	"github.com/pion/transport/v3/udp"
)

const (
	MaxPktBuf = 65536
	Backlog   = 1024
)

type Client struct {
	listener      net.Listener
	dtlsConfig    *dtls.Config
	remoteDialFn  func(context.Context) (net.PacketConn, net.Addr, error)
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

func New(cfg *Config) (*Client, error) {
	cfg = cfg.populateDefaults()

	baseCtx, cancelCtx := context.WithCancel(cfg.BaseContext)

	client := &Client{
		remoteDialFn:  cfg.RemoteDialFunc,
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

	client.dtlsConfig = &dtls.Config{
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		PSK:                  client.psk,
		PSKIdentityHint:      []byte(cfg.PSKIdentity),
		MTU:                  cfg.MTU,
		CipherSuites:         cfg.CipherSuites,
		EllipticCurves:       cfg.EllipticCurves,
	}
	lc := udp.ListenConfig{
		Backlog: Backlog,
	}
	listener, err := lc.Listen("udp", net.UDPAddrFromAddrPort(lAddrPort))
	if err != nil {
		cancelCtx()
		return nil, fmt.Errorf("client listen failed: %w", err)
	}

	client.listener = listener

	go client.listen()

	return client, nil
}

func (client *Client) listen() {
	defer client.Close()
	for client.baseCtx.Err() == nil {
		conn, err := client.listener.Accept()
		if err != nil {
			log.Printf("conn accept failed: %v", err)
			continue
		}

		if !client.allowFunc(conn.RemoteAddr()) {
			continue
		}

		client.workerWG.Add(1)
		go func(conn net.Conn) {
			defer client.workerWG.Done()
			defer conn.Close()
			client.serve(conn)
		}(conn)
	}
}

func (client *Client) serve(conn net.Conn) {
	log.Printf("[+] conn %s <=> %s", conn.LocalAddr(), conn.RemoteAddr())
	defer log.Printf("[-] conn %s <=> %s", conn.LocalAddr(), conn.RemoteAddr())
	defer conn.Close()

	ctx := client.baseCtx
	tl := client.timeLimitFunc()
	if tl != 0 {
		newCtx, cancel := context.WithTimeout(ctx, tl)
		defer cancel()
		ctx = newCtx
	}

	dialCtx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	remoteConn, remoteAddr, err := client.remoteDialFn(dialCtx)
	if err != nil {
		log.Printf("remote dial failed: %v", err)
		return
	}
	defer remoteConn.Close()

	dtlsConn, err := dtls.Client(remoteConn, remoteAddr, client.dtlsConfig)
	if err != nil {
		log.Printf("DTLS connection with remote server failed: %v", err)
		return
	}
	defer dtlsConn.Close()

	if err := dtlsConn.HandshakeContext(dialCtx); err != nil {
		log.Printf("DTLS handshake with remote server failed: %v", err)
		return
	}

	util.PairConn(ctx, conn, dtlsConn, client.idleTimeout, client.staleMode)
}

func (client *Client) Close() error {
	client.cancelCtx()
	err := client.listener.Close()
	client.workerWG.Wait()
	return err
}
