package addrgen

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/Snawoot/dtlspipe/randpool"
)

type AddrGen interface {
	Addr() string
	Power() *big.Int
}

type PortGen interface {
	Port() uint16
	Power() uint16
}

type EndpointGen interface {
	Endpoint() string
	Power() *big.Int
}

var _ EndpointGen = &AddrSet{}

type AddrSet struct {
	portRange  PortGen
	addrRanges []AddrGen
	cumWeights []*big.Int
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
	addrRanges := make([]AddrGen, 0, len(terms))
	for _, addrRangeSpec := range terms {
		r, err := ParseAddrRangeSpec(addrRangeSpec)
		if err != nil {
			return nil, fmt.Errorf("addr range spec %q parse failed: %w", addrRangeSpec, err)
		}
		addrRanges = append(addrRanges, r)
	}
	if len(addrRanges) == 0 {
		return nil, errors.New("no valid address ranges specified")
	}

	cumWeights := make([]*big.Int, len(addrRanges))
	currSum := new(big.Int)
	for i, r := range addrRanges {
		currSum.Add(currSum, r.Power())
		cumWeights[i] = new(big.Int).Set(currSum)
	}
	return &AddrSet{
		portRange:  portRange,
		addrRanges: addrRanges,
		cumWeights: cumWeights,
	}, nil
}

func (as *AddrSet) Endpoint() string {
	port := as.portRange.Port()
	count := len(as.addrRanges)
	limit := as.cumWeights[count-1]
	random := new(big.Int)
	randpool.Borrow(func(r *rand.Rand) {
		random.Rand(r, limit)
	})
	idx, found := slices.BinarySearchFunc(as.cumWeights, random, func(elem, target *big.Int) int {
		return elem.Cmp(target)
	})
	if found {
		idx++
	}
	addr := as.addrRanges[idx].Addr()
	return net.JoinHostPort(addr, strconv.FormatUint(uint64(port), 10))
}

func (as *AddrSet) Power() *big.Int {
	power := big.NewInt(int64(as.portRange.Power()))
	power.Mul(power, as.cumWeights[len(as.addrRanges)-1])
	return power
}

var _ EndpointGen = EqualMultiEndpointGen(nil)
type EqualMultiEndpointGen []EndpointGen

func NewEqualMultiEndpointGen(gens ...EndpointGen) (EqualMultiEndpointGen, error) {
	if len(gens) < 1 {
		return nil, errors.New("no generators provides")
	}
	return EqualMultiEndpointGen(gens), nil
}

func EqualMultiEndpointGenFromSpecs(specs []string) (EqualMultiEndpointGen, error) {
	gens := make([]EndpointGen, 0, len(specs))
	for _, spec := range specs {
		g, err := ParseAddrSet(spec)
		if err != nil {
			return nil, fmt.Errorf("can't create endpoint gen from spec %q: %w", spec, err)
		}
		gens = append(gens, g)
	}
	return NewEqualMultiEndpointGen(gens...)
}

func (g EqualMultiEndpointGen) Endpoint() string {
	var ret string
	randpool.Borrow(func(r *rand.Rand) {
		ret = g[r.Intn(len(g))].Endpoint()
	})
	return ret
}

func (g EqualMultiEndpointGen) Power() *big.Int {
	sum := new(big.Int)
	for _, sg := range g {
		sum.Add(sum, sg.Power())
	}
	return sum
}

var _ EndpointGen = SingleEndpoint("")
type SingleEndpoint string

func (e SingleEndpoint) Endpoint() string {
	return string(e)
}

func (e SingleEndpoint) Power() *big.Int {
	return big.NewInt(1)
}
