package addrgen

import (
	"math/big"
	"testing"
)

func TestSingleAddr(t *testing.T) {
	s := "example.com"
	if r := SingleAddr(s).Addr(); r != s {
		t.Errorf("expected: %q, got: %q", s, r)
	}
	if r := SingleAddr(s).Power(); big.NewInt(1).Cmp(r) != 0 {
		t.Errorf("expected: %s, got: %s", big.NewInt(1).String(), r)
	}
}
