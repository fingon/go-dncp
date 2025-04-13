package timeish

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
	Sleep(d time.Duration)
}

// --- Real Implementation ---

// realClock implementation for Clock interface
type realClock struct{}

// NewRealClock creates a new clock using the real time.
func NewRealClock() Clock {
	return &realClock{}
}

func (c *realClock) Now() time.Time {
	return time.Now()
}

func (c *realClock) NewTimer(d time.Duration) Timer {
	// Need to implement Timer interface based on time.Timer
	return &realTimer{timer: time.NewTimer(d)}
}

func (c *realClock) Sleep(d time.Duration) {
	time.Sleep(d)
}

// realTimer wraps time.Timer to satisfy Timer
type realTimer struct {
	timer *time.Timer
}

func (rt *realTimer) C() <-chan time.Time {
	if rt.timer == nil {
		// Return a closed channel if timer is nil (e.g., after Stop)
		// This prevents blocking forever on nil channel read.
		ch := make(chan time.Time)
		close(ch)
		return ch
	}
	return rt.timer.C
}

func (rt *realTimer) Stop() bool {
	if rt.timer == nil {
		return false // Already stopped or never started
	}
	stopped := rt.timer.Stop()
	// Ensure the channel is drained if Stop returns false (timer already fired)
	if !stopped {
		// Drain the channel non-blockingly. If there's nothing there,
		// or if it's already closed, this does nothing.
		select {
		case <-rt.timer.C:
		default:
		}
	}
	// Setting timer to nil might be problematic if Reset is called later.
	// Let's rely on time.Timer's behavior. Stop prevents future sends.
	return stopped
}

func (rt *realTimer) Reset(d time.Duration) bool {
	if rt.timer == nil {
		rt.timer = time.NewTimer(d) // Re-create if stopped previously? Or error? Let's re-create.
		return true                 // Indicates it was reset (effectively)
	}
	// Ensure the channel is drained before resetting, similar to time.Timer.Reset documentation.
	if !rt.timer.Stop() {
		select {
		case <-rt.timer.C:
		default:
		}
	}
	return rt.timer.Reset(d)
}
