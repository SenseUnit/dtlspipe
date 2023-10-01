package util

import (
	"errors"
	"sync/atomic"
)

type StaleMode int

const (
	BothStale StaleMode = iota
	EitherStale
	LeftStale
	RightStale
)

func (m *StaleMode) String() string {
	if m == nil {
		return "<nil>"
	}
	switch *m {
	case BothStale:
		return "both"
	case EitherStale:
		return "either"
	case LeftStale:
		return "left"
	case RightStale:
		return "right"
	}
	return "<unknown>"
}

func (m *StaleMode) Set(val string) error {
	switch val {
	case "both":
		*m = BothStale
	case "either":
		*m = EitherStale
	case "left":
		*m = LeftStale
	case "right":
		*m = RightStale
	default:
		return errors.New("unknown stale mode")
	}
	return nil
}

type tracker struct {
	leftCounter     atomic.Int32
	rightCounter    atomic.Int32
	leftTimedOutAt  atomic.Int32
	rightTimedOutAt atomic.Int32
	staleFunc       func() bool
}

func newTracker(staleMode StaleMode) *tracker {
	t := &tracker{}
	switch staleMode {
	case BothStale:
		t.staleFunc = t.bothStale
	case EitherStale:
		t.staleFunc = t.eitherStale
	case LeftStale:
		t.staleFunc = t.leftStale
	case RightStale:
		t.staleFunc = t.rightStale
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
	return !t.staleFunc()
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
