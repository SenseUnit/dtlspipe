package addrgen

import (
	"strings"
	"testing"
)

func TestAddrGen1(t *testing.T) {
	g := must(ParseAddrSet("10.0.0.0/17,192.168.0.0..192.168.255.255:20000-50000"))
	var a, b int
	for i := 0; i < 100; i++ {
		s := g.Endpoint()
		switch {
		case strings.HasPrefix(s, "10.0."):
			a++
		case strings.HasPrefix(s, "192.168."):
			b++
		default:
			t.Errorf("unexpected value: %q", s)
		}
	}
	if a > b {
		t.Errorf("%d > %d", a, b)
	}
}
