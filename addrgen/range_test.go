package addrgen

import (
	"math/big"
	"net/netip"
	"testing"
)

func must[T any](x T, err error) T {
	if err != nil {
		panic(err)
	}
	return x
}

func TestAddrRangeSingle(t *testing.T) {
	for _, sample := range []string{"127.0.0.1", "0.0.0.0", "::1", "255.255.255.255", "::"} {
		a := netip.MustParseAddr(sample)
		r := must(NewAddrRange(a, a))
		if res := r.Addr(); res != sample {
			t.Errorf("expected: %q; got: %q", sample, res)
		}
	}
}

func TestAddrRangePower(t *testing.T) {
	r := must(NewAddrRange(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.10")))
	if res := r.Power(); big.NewInt(10).Cmp(res) != 0 {
		t.Errorf("expected: %s, got: %s", big.NewInt(10).String(), res.String())
	}
}
