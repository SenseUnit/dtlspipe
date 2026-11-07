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
	"github.com/pion/dtls/v4"
	"github.com/pion/transport/v4/udp"
)

const (
	MaxPktBuf = 65536
	Backlog   = 1024
)

type Client struct {
	listener      net.Listener
	remoteDialFn  func(context.Context) (net.PacketConn, net.Addr, error)
	opts          []dtls.ClientOption
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
		idleTimeout:   cfg.IdleTimeout,
		baseCtx:       baseCtx,
		cancelCtx:     cancelCtx,
		staleMode:     cfg.StaleMode,
		timeLimitFunc: cfg.TimeLimitFunc,
		allowFunc:     cfg.AllowFunc,
		opts: []dtls.ClientOption{
			dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
			dtls.WithPSK(cfg.PSKCallback, nil),
			dtls.WithMTU(cfg.MTU),
			dtls.WithCipherSuites(cfg.CipherSuites...),
			dtls.WithEllipticCurves(cfg.EllipticCurves...),
		},
	}
	if cfg.EnableCID {
		client.opts = append(client.opts, dtls.WithConnectionID(dtls.OnlySendCIDGenerator(), dtls.CIDPathMigrationUnsafe))
	}

	lAddrPort, err := netip.ParseAddrPort(cfg.BindAddress)
	if err != nil {
		cancelCtx()
		return nil, fmt.Errorf("can't parse bind address: %w", err)
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

	remoteConn, err := func() (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(ctx, client.timeout)
		defer cancel()
		remoteConn, remoteAddr, err := client.remoteDialFn(dialCtx)
		if err != nil {
			return nil, fmt.Errorf("remote dial function failed: %w", err)
		}

		dtlsConn, err := dtls.Client(remoteConn, remoteAddr, client.opts...)
		if err != nil {
			remoteConn.Close()
			return nil, fmt.Errorf("DTLS connection with remote server failed: %w", err)
		}

		if err := dtlsConn.HandshakeContext(dialCtx); err != nil {
			dtlsConn.Close()
			remoteConn.Close()
			return nil, fmt.Errorf("DTLS handshake with remote server failed: %w", err)
		}

		return dtlsConn, nil
	}()
	if err != nil {
		log.Printf("remote dial failed: %v", err)
		return
	}
	defer remoteConn.Close()

	util.PairConn(ctx, conn, remoteConn, client.idleTimeout, client.staleMode)
}

func (client *Client) Close() error {
	client.cancelCtx()
	err := client.listener.Close()
	client.workerWG.Wait()
	return err
}
