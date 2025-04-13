package trickle

import "time"

// Timer represents a time.Timer equivalent.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// Clock provides an interface for time-related operations, allowing mocking.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
	Sleep(d time.Duration) // Added for potential future use or testing convenience
}

// realClock implements the Clock interface using the standard time package.
type realClock struct{}

func (c *realClock) Now() time.Time {
	return time.Now()
}

func (c *realClock) NewTimer(d time.Duration) Timer {
	return &realTimer{timer: time.NewTimer(d)}
}

func (c *realClock) Sleep(d time.Duration) {
	time.Sleep(d)
}

// realTimer wraps a standard time.Timer to implement the Timer interface.
type realTimer struct {
	timer *time.Timer
}

func (rt *realTimer) C() <-chan time.Time {
	return rt.timer.C
}

func (rt *realTimer) Stop() bool {
	return rt.timer.Stop()
}

func (rt *realTimer) Reset(d time.Duration) bool {
	return rt.timer.Reset(d)
}
