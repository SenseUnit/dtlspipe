package addrgen

import (
	"math"
	"testing"
)

const testArraySize = 100
const testIterCount = 100000

func TestPortSimple(t *testing.T) {
	g := must(ParsePortRangeSpec("443"))
	for i := 0; i < 100; i++ {
		if p := g.Port(); p != 443 {
			t.Errorf("unexpected port value: %d", p)
		}
	}
}

func TestPortRange(t *testing.T) {
	var arr [testArraySize]int
	g := must(ParsePortRangeSpec("10000-20000"))

	for i := 0; i < testIterCount; i++ {
		p := g.Port()
		arr[p%testArraySize]++
	}

	sum := 0
	for i := 0; i < testArraySize; i++ {
		sum += int(arr[i])
	}
	if sum != testIterCount {
		t.Errorf("unexpected sum: %d", sum)
	}

	mx := float64(testIterCount) / float64(testArraySize)
	sigmaSquared := mx * float64(testArraySize-1) / float64(testArraySize)
	sigma := math.Sqrt(sigmaSquared)
	t.Logf("sigma = %.3f", sigma)
	t.Logf("5*sigma = %.3f", 5*sigma)

	for i := 0; i < testArraySize; i++ {
		if math.Abs(float64(arr[i])-mx) > 5*sigma {
			t.Errorf("arr[%d]=%d too far from mx=%.3f", i, arr[i], mx)
		}
	}
}
