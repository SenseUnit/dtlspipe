package util

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Snawoot/rlzone"
)

func GenPSK(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := crand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("random bytes generation failed: %w", err)
	}

	return b, nil
}

func GenPSKHex(length int) (string, error) {
	b, err := GenPSK(length)
	if err != nil {
		return "", fmt.Errorf("can't generate hex key: %w", err)
	}

	return hex.EncodeToString(b), nil
}

func PSKFromHex(input string) ([]byte, error) {
	return hex.DecodeString(input)
}

func isTimeout(err error) bool {
	if timeoutErr, ok := err.(interface {
		Timeout() bool
	}); ok {
		return timeoutErr.Timeout()
	}
	return false
}

func isTemporary(err error) bool {
	if timeoutErr, ok := err.(interface {
		Temporary() bool
	}); ok {
		return timeoutErr.Temporary()
	}
	return false
}

const (
	MaxPktBuf = 65536
)

func PairConn(ctx context.Context, left, right net.Conn, idleTimeout time.Duration, staleMode StaleMode) {
	var wg sync.WaitGroup
	tracker := newTracker(staleMode)

	copyDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			left.Close()
			right.Close()
		case <-copyDone:
		}
	}()
	defer close(copyDone)

	copier := func(dst, src net.Conn, label bool) {
		defer wg.Done()
		defer dst.Close()
		buf := make([]byte, MaxPktBuf)
		for {
			if err := src.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
				log.Printf("can't update deadline for connection: %v", err)
				break
			}

			n, err := src.Read(buf)
			if err != nil {
				if isTimeout(err) {
					// hit read deadline
					if tracker.handleTimeout(label) {
						// not stale conn
						continue
					} else {
						log.Printf("dropping stale connection %s <=> %s", src.LocalAddr(), src.RemoteAddr())
					}
				} else {
					// any other error
					if isTemporary(err) {
						log.Printf("ignoring temporary error during read from %s: %v", src.RemoteAddr(), err)
						continue
					}
					log.Printf("read from %s error: %v", src.RemoteAddr(), err)
				}
				break
			}

			tracker.notify(label)

			_, err = dst.Write(buf[:n])
			if err != nil {
				log.Printf("write to %s error: %v", dst.RemoteAddr(), err)
				break
			}
		}
	}

	wg.Add(2)
	go copier(left, right, false)
	go copier(right, left, true)
	wg.Wait()
}

func NetAddrToNetipAddrPort(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.AddrPort()
	case *net.TCPAddr:
		return v.AddrPort()
	}
	res, _ := netip.ParseAddrPort(a.String())
	return res
}

func AllowAllFunc(_, _ net.Addr) bool {
	return true
}

func AllowByRatelimit(z rlzone.Ratelimiter[netip.Addr]) func(net.Addr, net.Addr) bool {
	if z == nil {
		return AllowAllFunc
	}
	return func(_, remoteAddr net.Addr) bool {
		key := NetAddrToNetipAddrPort(remoteAddr).Addr()
		return z.Allow(key)
	}
}

func FixedTimeLimitFunc(d time.Duration) func() time.Duration {
	return func() time.Duration {
		return d
	}
}

func TimeLimitFunc(low, high time.Duration) func() time.Duration {
	if low > high {
		return TimeLimitFunc(high, low)
	}
	if low == high {
		return FixedTimeLimitFunc(low)
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var mux sync.Mutex
	delta := high - low
	return func() time.Duration {
		mux.Lock()
		defer mux.Unlock()
		return low + time.Duration(r.Int63n(int64(delta)))
	}
}

type DynDialer struct {
	dial func(context.Context, string, string) (net.Conn, error)
	ep   func() string
}

func NewDynDialer(ep func() string, dial func(context.Context, string, string) (net.Conn, error)) DynDialer {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return DynDialer{
		ep:   ep,
		dial: dial,
	}
}

func (d DynDialer) DialContext(ctx context.Context, network string) (net.Conn, error) {
	return d.dial(ctx, network, d.ep())
}
