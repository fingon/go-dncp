package timeish

import (
	"sync"
	"time"
)

// --- Mock Clock Implementation ---

// MockTimer is the mock implementation of the Timer interface.
type MockTimer struct {
	c      chan time.Time
	stopCh chan struct{} // Channel to signal Stop() was called
	resetD time.Duration // Stores the duration passed to Reset
	mu     sync.Mutex
}

// NewMockTimer creates a new mock timer instance.
func NewMockTimer(d time.Duration) *MockTimer {
	return &MockTimer{
		c:      make(chan time.Time, 1), // Buffered to allow sending time without immediate receive
		stopCh: make(chan struct{}, 1),
		resetD: d, // Initial duration
	}
}

// C returns the timer channel.
func (m *MockTimer) C() <-chan time.Time {
	return m.c
}

// Stop simulates stopping the timer and returns true.
func (m *MockTimer) Stop() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Non-blocking send to signal stop
	select {
	case m.stopCh <- struct{}{}:
	default:
	}
	// In a real scenario, this would return if the timer was active.
	// For mock, we might not need complex state tracking, return true.
	return true
}

// Reset simulates resetting the timer with a new duration.
func (m *MockTimer) Reset(d time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetD = d
	// Drain any pending time signal if resetting
	select {
	case <-m.c:
	default:
	}
	// Similar to Stop, return true for simplicity.
	return true
}

// Tick manually triggers the timer's channel.
func (m *MockTimer) Tick(t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Non-blocking send
	select {
	case m.c <- t:
	default: // Avoid blocking if channel is full or receiver not ready
	}
}

// WasStopped checks if Stop was called on the timer.
func (m *MockTimer) WasStopped() bool {
	select {
	case <-m.stopCh:
		return true
	default:
		return false
	}
}

// GetResetDuration returns the last duration the timer was reset to.
func (m *MockTimer) GetResetDuration() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resetD
}

// MockClock is the mock implementation of the Clock interface.
type MockClock struct {
	currentTime time.Time
	timers      []*MockTimer // Keep track of created timers
	mu          sync.Mutex
}

// NewMockClock creates a new mock clock starting at a specific time.
func NewMockClock(start time.Time) *MockClock {
	return &MockClock{
		currentTime: start,
	}
}

// Now returns the current time of the mock clock.
func (m *MockClock) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentTime
}

// NewTimer creates a new mock timer associated with this clock.
func (m *MockClock) NewTimer(d time.Duration) Timer {
	m.mu.Lock()
	defer m.mu.Unlock()
	mt := NewMockTimer(d)
	m.timers = append(m.timers, mt)
	return mt
}

// Sleep advances the mock clock's time by the specified duration.
func (m *MockClock) Sleep(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentTime = m.currentTime.Add(d)
}

// Advance advances the mock clock's time by the specified duration.
// Note: This currently does the same as Sleep. Consider if different behavior is needed.
func (m *MockClock) Advance(d time.Duration) {
	m.mu.Lock()
	targetTime := m.currentTime.Add(d)
	m.currentTime = targetTime
	m.mu.Unlock()
}

// GetTimers returns a slice of all mock timers created by this clock.
func (m *MockClock) GetTimers() []*MockTimer {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy
	timersCopy := make([]*MockTimer, len(m.timers))
	copy(timersCopy, m.timers)
	return timersCopy
}
