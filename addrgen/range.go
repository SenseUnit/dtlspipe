package addrgen

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net/netip"
	"strings"

	"github.com/SenseUnit/dtlspipe/randpool"
)

type AddrRange struct {
	base *big.Int
	size *big.Int
	v6   bool
}

var _ AddrGen = &AddrRange{}

func NewAddrRange(start, end netip.Addr) (*AddrRange, error) {
	if start.BitLen() != end.BitLen() {
		return nil, errors.New("addr bit length mismatch - one of them is IPv4, another is IPv6")
	}
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
		v6:   start.BitLen() == 128,
	}, nil
}

func NewAddrRangeFromPrefix(pfx netip.Prefix) (*AddrRange, error) {
	if !pfx.IsValid() {
		return nil, errors.New("invalid prefix")
	}
	pfx = pfx.Masked()
	addr := pfx.Addr()
	base := new(big.Int)
	base.SetBytes(addr.AsSlice())
	pfxPower := addr.BitLen() - pfx.Bits()
	size := big.NewInt(1)
	size.Lsh(size, uint(pfxPower))
	return &AddrRange{
		base: base,
		size: size,
		v6:   addr.BitLen() == 128,
	}, nil
}

func (ar *AddrRange) Addr() string {
	res := new(big.Int)
	randpool.Borrow(func(r *rand.Rand) {
		res.Rand(r, ar.size)
	})
	res.Add(ar.base, res)
	var resArr [16]byte
	resSlice := resArr[:]
	if !ar.v6 {
		resSlice = resSlice[:4]
	}
	res.FillBytes(resSlice)
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

func ParseAddrRangeSpec(spec string) (AddrGen, error) {
	switch {
	case strings.Contains(spec, "/"):
		pfx, err := netip.ParsePrefix(spec)
		if err != nil {
			return nil, fmt.Errorf("unable to parse prefix %q: %w", spec, err)
		}
		if pfx.IsSingleIP() {
			return SingleAddr(pfx.Addr().String()), nil
		}
		r, err := NewAddrRangeFromPrefix(pfx)
		if err != nil {
			return nil, fmt.Errorf("unable to parse range spec %q: %w", spec, err)
		}
		return r, nil
	case strings.Contains(spec, ".."):
		parts := strings.SplitN(spec, "..", 2)
		start, err := netip.ParseAddr(parts[0])
		if err != nil {
			return nil, fmt.Errorf("unable to parse addr %q: %w", parts[0], err)
		}
		end, err := netip.ParseAddr(parts[1])
		if err != nil {
			return nil, fmt.Errorf("unable to parse addr %q: %w", parts[1], err)
		}
		r, err := NewAddrRange(start, end)
		if err != nil {
			return nil, fmt.Errorf("invalid range spec %q: %w", spec, err)
		}
		return r, nil
	}
	return SingleAddr(spec), nil
}
