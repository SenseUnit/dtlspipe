package addrgen

import (
	"math/big"
	"math/rand"
	"net/netip"
	"sync"
)

var rng = rand.New(rand.NewSource(time.UnixNano()))
var rngPool 

type AddrGetter interface {
	Addr() string
}

type AddrRange struct {
	startAddr netip.Addr
	size      *big.Int
}

type AddrSet struct {
	portBase   uint16
	portNum    uint16
	addrRanges []AddrGetter
}
