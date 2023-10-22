package randpool

import (
	"math"
	"math/rand"
	"testing"
)

const testArraySize = 100
const testIterCount = 100000

func TestBorrow(t *testing.T) {
	var arr [testArraySize]int
	rp := New()
	rp.Borrow(func(r *rand.Rand) {
		for i := 0; i < testIterCount; i++ {
			arr[r.Intn(testArraySize)]++
		}
	})

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
