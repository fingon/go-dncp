package timeish_test

import (
	"sync"
	"testing"
	"time"

	"github.com/fingon/go-dncp/timeish" // Import the package under test
	"gotest.tools/v3/assert"
)

// Test MockTimer functionality
func TestMockTimer(t *testing.T) {
	initialDuration := 100 * time.Millisecond
	mt := timeish.NewMockTimer(initialDuration)

	assert.Equal(t, initialDuration, mt.GetResetDuration(), "Initial duration mismatch")

	// Test C() returns a channel
	timerChan := mt.C()
	assert.Assert(t, timerChan != nil, "Timer channel should not be nil")

	// Test Tick() sends on the channel
	now := time.Now()
	mt.Tick(now)
	select {
	case receivedTime := <-timerChan:
		assert.Equal(t, now, receivedTime, "Received time mismatch")
	case <-time.After(10 * time.Millisecond):
		t.Fatal("Did not receive time on timer channel after Tick()")
	}

	// Test Reset() updates duration and drains channel
	mt.Tick(now.Add(1 * time.Second)) // Put something in channel
	resetDuration := 200 * time.Millisecond
	mt.Reset(resetDuration)
	assert.Equal(t, resetDuration, mt.GetResetDuration(), "Reset duration mismatch")
	// Check channel was drained (non-blocking read)
	select {
	case <-timerChan:
		t.Fatal("Timer channel should have been drained on Reset()")
	default:
		// Expected path
	}

	// Test Stop() signals and WasStopped() detects it
	assert.Assert(t, !mt.WasStopped(), "Timer should not report stopped initially")
	mt.Stop()
	// Allow a moment for the stop signal to propagate (though channel is buffered)
	time.Sleep(1 * time.Millisecond)
	assert.Assert(t, mt.WasStopped(), "Timer should report stopped after Stop()")

	// Test Stop() again (should be idempotent)
	mt.Stop()
	assert.Assert(t, mt.WasStopped(), "Timer should still report stopped")
}

// Test MockClock functionality
func TestMockClock(t *testing.T) {
	startTime := time.Unix(1700000000, 0)
	mc := timeish.NewMockClock(startTime)

	// Test Now()
	assert.Equal(t, startTime, mc.Now(), "Initial Now() time mismatch")

	// Test Sleep() / Advance()
	advanceDuration := 5 * time.Second
	mc.Sleep(advanceDuration)
	expectedTime := startTime.Add(advanceDuration)
	assert.Equal(t, expectedTime, mc.Now(), "Time after Sleep() mismatch")

	mc.Advance(advanceDuration)
	expectedTime = expectedTime.Add(advanceDuration)
	assert.Equal(t, expectedTime, mc.Now(), "Time after Advance() mismatch")

	// Test NewTimer()
	timerDuration := 1 * time.Minute
	timer := mc.NewTimer(timerDuration)
	assert.Assert(t, timer != nil, "NewTimer should return a non-nil timer")

	// Check if timer is tracked
	timers := mc.GetTimers()
	assert.Equal(t, 1, len(timers), "Expected 1 timer to be tracked")
	assert.Equal(t, timerDuration, timers[0].GetResetDuration(), "Tracked timer duration mismatch")

	// Test GetTimers() returns a copy
	timers[0] = timeish.NewMockTimer(99 * time.Second) // Modify the copy
	originalTimers := mc.GetTimers()
	assert.Equal(t, timerDuration, originalTimers[0].GetResetDuration(), "Original timer should not be affected by modifying the copy")

	// Test concurrent access (basic check)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		mc.Now()
		mc.NewTimer(1 * time.Second)
		mc.Sleep(1 * time.Millisecond)
	}()
	go func() {
		defer wg.Done()
		mc.Advance(500 * time.Millisecond)
		mc.GetTimers()
	}()
	wg.Wait()
	// No explicit assertion, just checking for race conditions with -race flag
}
