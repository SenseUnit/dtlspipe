package util

import "sync/atomic"

type StaleMode int

const (
	BothStale = iota
	EitherStale
	LeftStale
	RightStale
)

type tracker struct {
	leftCounter     atomic.Int32
	rightCounter    atomic.Int32
	leftTimedOutAt  atomic.Int32
	rightTimedOutAt atomic.Int32
	staleFun        func() bool
}

func newTracker(staleMode StaleMode) *tracker {
	t := &tracker{}
	switch staleMode {
	case BothStale:
		t.staleFun = t.bothStale
	case EitherStale:
		t.staleFun = t.eitherStale
	case LeftStale:
		t.staleFun = t.leftStale
	case RightStale:
		t.staleFun = t.rightStale
	default:
		panic("unsupported stale mode")
	}
	return t
}

func (t *tracker) notify(isLeft bool) {
	if isLeft {
		t.leftCounter.Add(1)
	} else {
		t.rightCounter.Add(1)
	}
}

func (t *tracker) handleTimeout(isLeft bool) bool {
	if isLeft {
		t.leftTimedOutAt.Store(t.leftCounter.Load())
	} else {
		t.rightTimedOutAt.Store(t.rightCounter.Load())
	}
	return t.staleFun()
}

func (t *tracker) leftStale() bool {
	return t.leftCounter.Load() == t.leftTimedOutAt.Load()
}

func (t *tracker) rightStale() bool {
	return t.rightCounter.Load() == t.rightTimedOutAt.Load()
}

func (t *tracker) bothStale() bool {
	return t.leftStale() && t.rightStale()
}

func (t *tracker) eitherStale() bool {
	return t.leftStale() || t.rightStale()
}
