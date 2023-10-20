package addrgen

import (
	"math/big"
)

type AddrGetter interface {
	Addr() string
	Power() *big.Int
}

type AddrSet struct {
	portBase   uint16
	portNum    uint16
	addrRanges []AddrGetter
}
