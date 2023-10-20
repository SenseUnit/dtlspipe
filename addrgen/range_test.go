package addrgen

import (
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
