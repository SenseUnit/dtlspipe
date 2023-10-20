package addrgen

import (
	"math/big"
	"math/rand"
	"net/netip"

	"github.com/Snawoot/dtlspipe/randpool"
)

type AddrRange struct {
	base *big.Int
	size *big.Int
}

var _ AddrGetter = &AddrRange{}

func NewAddrRange(start, end netip.Addr) *AddrRange {
	if end.Less(start) {
		return NewAddrRange(end, start)
	}

	base := new(big.Int)
	base.SetBytes(start.AsSlice())
	upper := new(big.Int)
	upper.SetBytes(end.AsSlice())

	size := new(big.Int)
	size.Sub(upper, base)
	size.Add(size, big.NewInt(1))

	return &AddrRange{
		base: base,
		size: size,
	}
}

func (ar *AddrRange) Addr() string {
	res := new(big.Int)
	randpool.Borrow(func(r *rand.Rand) {
		res.Rand(r, ar.size)
	})
	res.Add(ar.base, res)
	var resSlice [16]byte
	res.FillBytes(resSlice[:])
	resAddr, ok := netip.AddrFromSlice(resSlice[:])
	if !ok {
		panic("can't parse address from slice")
	}
	return resAddr.String()
}

func (ar *AddrRange) Power() *big.Int {
	res := new(big.Int)
	res.Set(ar.size)
	return res
}
