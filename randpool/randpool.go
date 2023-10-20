package randpool

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
)

type RandPool struct {
	pool sync.Pool
}

func MakeRand() *rand.Rand {
	var seedBuf [8]byte
	if _, err := crand.Read(seedBuf[:]); err != nil {
		panic(fmt.Errorf("crypto/rand.Read failed: %w", err))
	}
	uSeed := binary.BigEndian.Uint64(seedBuf[:])
	return rand.New(rand.NewSource(int64(uSeed)))
}

func poolMakeRand() any {
	return MakeRand()
}

func New() *RandPool {
	return &RandPool{
		pool: sync.Pool{
			New: poolMakeRand,
		},
	}
}

func (p *RandPool) Borrow(f func(*rand.Rand)) {
	rng := p.pool.Get().(*rand.Rand)
	defer p.pool.Put(rng)
	f(rng)
}
