package addrgen

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type AddrGetter interface {
	Addr() string
	Power() *big.Int
}

type PortGetter interface {
	Port() uint16
	Power() uint16
}

type AddrSet struct {
	portRange  PortGetter
	addrRanges []AddrGetter
}

func ParseAddrSet(spec string) (*AddrSet, error) {
	lastColonIdx := strings.LastIndex(spec, ":")
	if lastColonIdx == -1 {
		return nil, errors.New("port specification not found - colon is missing")
	}
	addrPart := spec[:lastColonIdx]
	portPart := spec[lastColonIdx+1:]
	portRange, err := ParsePortRangeSpec(portPart)
	if err != nil {
		return nil, fmt.Errorf("unable to parse port part: %w", err)
	}

	terms := strings.Split(addrPart, ",")
	addrRanges := make([]AddrGetter, 0, len(terms))
	for _, addrRangeSpec := range terms {
		r, err := ParseAddrRangeSpec(addrRangeSpec)
		if err != nil {
			return nil, fmt.Errorf("addr range spec %q parse failed: %w", addrRangeSpec, err)
		}
		addrRanges = append(addrRanges, r)
	}
	return &AddrSet{
		portRange: portRange,
		addrRanges: addrRanges,
	}, nil
}
