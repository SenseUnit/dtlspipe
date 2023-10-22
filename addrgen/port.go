package addrgen

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/Snawoot/dtlspipe/randpool"
)

var _ PortGen = PortRange{}

type PortRange struct {
	portBase uint16
	portNum  uint16
}

func NewPortRange(start, end uint16) PortRange {
	if end < start {
		return NewPortRange(end, start)
	}
	return PortRange{
		portBase: start,
		portNum:  end - start + 1,
	}
}

func (p PortRange) Port() uint16 {
	var delta uint16
	randpool.Borrow(func(r *rand.Rand) {
		delta = uint16(r.Intn(int(p.portNum)))
	})
	return p.portBase + delta
}

func (p PortRange) Power() uint16 {
	return p.portNum
}

var _ PortGen = SinglePort(0)

type SinglePort uint16

func (p SinglePort) Port() uint16 {
	return uint16(p)
}

func (p SinglePort) Power() uint16 {
	return 1
}

func ParsePortRangeSpec(spec string) (PortGen, error) {
	parts := strings.SplitN(spec, "-", 2)
	switch len(parts) {
	case 1:
		port, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("unable to parse port specification %q: %w", parts[0], err)
		}
		return SinglePort(port), nil
	case 2:
		start, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("unable to parse port specification %q: %w", parts[0], err)
		}
		end, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("unable to parse port specification %q: %w", parts[1], err)
		}
		return NewPortRange(uint16(start), uint16(end)), nil
	}
	return nil, fmt.Errorf("unexpected number of components: %d", len(parts))
}
