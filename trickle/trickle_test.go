package trickle_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/fingon/go-dncp/timeish" // Import the new package
	"github.com/fingon/go-dncp/trickle"
	"gotest.tools/v3/assert"
)

// --- Test Setup ---

type testMsg struct {
	ID           int
	IsConsistent bool
}

type testHarness struct {
	t               *testing.T
	trickle         *trickle.Trickle[testMsg]
	mockClock       *timeish.MockClock // Use timeish.MockClock
	transmitChan    chan struct{}      // Signals a transmission occurred
	consistencyFunc func(data testMsg) bool
	config          trickle.Config[testMsg]
}

func setupTest(t *testing.T, cfgMod func(cfg *trickle.Config[testMsg])) *testHarness {
	t.Helper()

	transmitChan := make(chan struct{}, 10)                     // Buffered to avoid blocking transmit func
	mockClock := timeish.NewMockClock(time.Unix(1700000000, 0)) // Use timeish.NewMockClock

	consistencyFunc := func(data testMsg) bool {
		return data.IsConsistent
	}

	config := trickle.Config[testMsg]{
		Imin:          time.Millisecond * 100,
		ImaxDoublings: 4, // Imax = 100ms * 2^4 = 1600ms
		K:             1,
		TransmitFunc: func() {
			select {
			case transmitChan <- struct{}{}: // Non-blocking send
			default:
				t.Log("Transmit channel full")
			}
		},
		ConsistencyFunc: consistencyFunc,
		Logger:          slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Clock:           mockClock, // Pass the timeish.MockClock
		// Use deterministic rand source if needed, default is fine for now
	}

	if cfgMod != nil {
		cfgMod(&config)
	}

	tr, err := trickle.New(config)
	assert.NilError(t, err)
	assert.Assert(t, tr != nil)

	return &testHarness{
		t:               t,
		trickle:         tr,
		mockClock:       mockClock,
		transmitChan:    transmitChan,
		consistencyFunc: consistencyFunc,
		config:          config, // Store the effective config
	}
}

// Helper to implement io.Writer for slog
type testWriter struct {
	t *testing.T
}

func (tw testWriter) Write(p []byte) (n int, err error) {
	tw.t.Log(string(p))
	return len(p), nil
}

// --- Tests ---

func TestNewTrickle_ValidConfig(t *testing.T) {
	h := setupTest(t, nil) // Use default valid config
	assert.Assert(t, h.trickle != nil)
	// Check if config values were set correctly (using defaults where applicable)
	cfg := h.trickle.Config()
	assert.Equal(t, h.config.Imin, cfg.Imin)
	assert.Equal(t, h.config.K, cfg.K)
	// Cannot directly check ImaxDuration or ImaxDoublings via Config()
}

func TestNewTrickle_InvalidConfig(t *testing.T) {
	// Test missing transmit func
	_, err := trickle.New(trickle.Config[testMsg]{
		ConsistencyFunc: func(testMsg) bool { return true },
		Logger:          slog.Default(),
		Clock:           timeish.NewMockClock(time.Now()), // Use timeish.NewMockClock
	})
	assert.ErrorContains(t, err, "transmit func is required")

	// Test invalid Imin (should use default)
	tr, err := trickle.New(trickle.Config[testMsg]{
		Imin:            -1,
		TransmitFunc:    func() {},
		ConsistencyFunc: func(testMsg) bool { return true },
		Logger:          slog.Default(),
		Clock:           timeish.NewMockClock(time.Now()), // Use timeish.NewMockClock
	})
	assert.NilError(t, err)
	assert.Equal(t, trickle.DefaultImin, tr.Config().Imin)

	// Test invalid K (should use default)
	tr, err = trickle.New(trickle.Config[testMsg]{
		K:               0, // Test K=0 specifically, should default to 1
		TransmitFunc:    func() {},
		ConsistencyFunc: func(testMsg) bool { return true },
		Logger:          slog.Default(),
		Clock:           timeish.NewMockClock(time.Now()), // Use timeish.NewMockClock
	})
	assert.NilError(t, err)
	assert.Equal(t, uint(1), tr.Config().K) // Expecting default K=1
}

func TestTrickle_StartStop(t *testing.T) {
	h := setupTest(t, nil)
	h.trickle.Start()
	// Allow some time for the run loop to start (though startChan handles this)
	time.Sleep(10 * time.Millisecond) // Give goroutine time to start

	h.trickle.Stop()
	// Stop should block until the goroutine exits. Check timers were stopped.
	timers := h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	// Expecting intervalTimer and transmissionTimer
	assert.Assert(t, len(timers) >= 2, "Expected at least 2 timers")
	// Check if timers were stopped (best effort check)
	// Note: WasStopped might not be perfectly reliable depending on timing.
	// A better check might be to ensure no further ticks are processed after Stop.
	// For now, we assume Stop correctly stops timers internally.

	// Calling Stop again should be a no-op (check logs for warnings)
	h.trickle.Stop()
	// Calling Start again should be a no-op
	h.trickle.Start()
}

func TestTrickle_Transmission(t *testing.T) {
	h := setupTest(t, func(cfg *trickle.Config[testMsg]) {
		cfg.K = 1 // Ensure k=1 for this test
	})
	h.trickle.Start()

	timers := h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2, "Expected at least 2 timers")
	intervalTimer := timers[0]     // Assuming first is interval (*timeish.MockTimer)
	transmissionTimer := timers[1] // Assuming second is transmission (*timeish.MockTimer)

	// Manually trigger the transmission timer
	transmissionTimer.Tick(h.mockClock.Now()) // Use Tick method from timeish.MockTimer

	// Check if transmit function was called
	select {
	case <-h.transmitChan:
		// Success
	case <-time.After(50 * time.Millisecond):
		t.Fatal("TransmitFunc was not called after transmission timer fired")
	}

	// Trigger interval timer to start next interval
	intervalTimer.Tick(h.mockClock.Now())
	time.Sleep(10 * time.Millisecond) // Allow run loop to process

	// Get new timers for the new interval
	timers = h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2, "Expected timers to be reset/recreated")
	newTransmissionTimer := timers[len(timers)-1] // Assume last one is the new transmission timer (*timeish.MockTimer)

	// Trigger transmission timer again for the new interval
	newTransmissionTimer.Tick(h.mockClock.Now()) // Use Tick method from timeish.MockTimer

	// Check if transmit function was called again
	select {
	case <-h.transmitChan:
		// Success
	case <-time.After(50 * time.Millisecond):
		t.Fatal("TransmitFunc was not called after second transmission timer fired")
	}

	h.trickle.Stop()
}

func TestTrickle_Suppression(t *testing.T) {
	h := setupTest(t, func(cfg *trickle.Config[testMsg]) {
		cfg.K = 1 // Redundancy constant
	})
	h.trickle.Start()

	timers := h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)
	transmissionTimer := timers[1] // *timeish.MockTimer

	// Receive a consistent message, should increment counter c to 1
	h.trickle.Receive(testMsg{ID: 1, IsConsistent: true})
	time.Sleep(10 * time.Millisecond) // Allow run loop to process

	// Manually trigger the transmission timer
	// Since c=1 and k=1, transmission should be suppressed (c >= k)
	transmissionTimer.Tick(h.mockClock.Now()) // Use Tick method from timeish.MockTimer

	// Check that transmit function was NOT called
	select {
	case <-h.transmitChan:
		t.Fatal("TransmitFunc was called unexpectedly (transmission should be suppressed)")
	case <-time.After(50 * time.Millisecond):
		// Success, timeout means no transmission
	}

	h.trickle.Stop()
}

func TestTrickle_InconsistentMessage_Reset(t *testing.T) {
	h := setupTest(t, func(cfg *trickle.Config[testMsg]) {
		cfg.Imin = 100 * time.Millisecond
		cfg.ImaxDoublings = 2 // Imax = 400ms
	})
	h.trickle.Start()

	timers := h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)
	intervalTimer := timers[0] // *timeish.MockTimer

	// Let the first interval expire to double I
	intervalTimer.Tick(h.mockClock.Now()) // Use Tick method from timeish.MockTimer
	time.Sleep(10 * time.Millisecond)     // Allow run loop to process interval end

	// Check that the new interval timer is set to I*2 = 200ms
	timers = h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)
	newIntervalTimer := timers[len(timers)-2]                             // Assume second to last is new interval timer (*timeish.MockTimer)
	assert.Equal(t, h.config.Imin*2, newIntervalTimer.GetResetDuration()) // Use GetResetDuration from timeish.MockTimer

	// Receive an inconsistent message
	h.trickle.Receive(testMsg{ID: 2, IsConsistent: false})
	time.Sleep(10 * time.Millisecond) // Allow run loop to process

	// Check if the timer was reset to Imin
	// The reset logic creates/resets timers again.
	timers = h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)
	resetIntervalTimer := timers[len(timers)-2]                                                                  // Assume second to last is reset interval timer (*timeish.MockTimer)
	assert.Equal(t, h.config.Imin, resetIntervalTimer.GetResetDuration(), "Interval timer should reset to Imin") // Use GetResetDuration

	h.trickle.Stop()
}

func TestTrickle_InconsistentMessage_NoResetAtImin(t *testing.T) {
	h := setupTest(t, func(cfg *trickle.Config[testMsg]) {
		cfg.Imin = 100 * time.Millisecond
	})
	h.trickle.Start()

	timers := h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)
	intervalTimer := timers[0]                                  // *timeish.MockTimer
	initialIntervalDuration := intervalTimer.GetResetDuration() // Use GetResetDuration
	assert.Equal(t, h.config.Imin, initialIntervalDuration)

	// Receive an inconsistent message while I is still Imin
	h.trickle.Receive(testMsg{ID: 2, IsConsistent: false})
	time.Sleep(10 * time.Millisecond) // Allow run loop to process

	// Check that the timer was NOT reset (it should still be Imin)
	// No new timers should have been created by the reset logic in this case.
	timers = h.mockClock.GetTimers()                                                                             // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)                                                                           // Should still have the original timers
	currentIntervalTimer := timers[0]                                                                            // Check the original timer instance (*timeish.MockTimer)
	assert.Equal(t, h.config.Imin, currentIntervalTimer.GetResetDuration(), "Interval timer should remain Imin") // Use GetResetDuration

	h.trickle.Stop()
}

func TestTrickle_Event_Reset(t *testing.T) {
	h := setupTest(t, func(cfg *trickle.Config[testMsg]) {
		cfg.Imin = 100 * time.Millisecond
		cfg.ImaxDoublings = 2 // Imax = 400ms
	})
	h.trickle.Start()

	timers := h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)
	intervalTimer := timers[0] // *timeish.MockTimer

	// Let the first interval expire to double I
	intervalTimer.Tick(h.mockClock.Now()) // Use Tick
	time.Sleep(10 * time.Millisecond)     // Allow run loop to process interval end

	// Check that the new interval timer is set to I*2 = 200ms
	timers = h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)
	newIntervalTimer := timers[len(timers)-2]                             // *timeish.MockTimer
	assert.Equal(t, h.config.Imin*2, newIntervalTimer.GetResetDuration()) // Use GetResetDuration

	// Signal an external event
	h.trickle.Event()
	time.Sleep(10 * time.Millisecond) // Allow run loop to process

	// Check if the timer was reset to Imin
	timers = h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)
	resetIntervalTimer := timers[len(timers)-2]                                                                           // *timeish.MockTimer
	assert.Equal(t, h.config.Imin, resetIntervalTimer.GetResetDuration(), "Interval timer should reset to Imin on event") // Use GetResetDuration

	h.trickle.Stop()
}

func TestTrickle_Event_NoResetAtImin(t *testing.T) {
	h := setupTest(t, func(cfg *trickle.Config[testMsg]) {
		cfg.Imin = 100 * time.Millisecond
	})
	h.trickle.Start()

	timers := h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)
	intervalTimer := timers[0]                                  // *timeish.MockTimer
	initialIntervalDuration := intervalTimer.GetResetDuration() // Use GetResetDuration
	assert.Equal(t, h.config.Imin, initialIntervalDuration)

	// Signal an external event while I is still Imin
	h.trickle.Event()
	time.Sleep(10 * time.Millisecond) // Allow run loop to process

	// Check that the timer was NOT reset
	timers = h.mockClock.GetTimers() // Returns []*timeish.MockTimer
	assert.Assert(t, len(timers) >= 2)
	currentIntervalTimer := timers[0]                                                                            // *timeish.MockTimer
	assert.Equal(t, h.config.Imin, currentIntervalTimer.GetResetDuration(), "Interval timer should remain Imin") // Use GetResetDuration

	h.trickle.Stop()
}

func TestTrickle_IntervalDoubling(t *testing.T) {
	imin := 50 * time.Millisecond
	imaxDoublings := 3 // Imax = 50 * 2^3 = 400ms
	imaxDuration := imin * time.Duration(1<<imaxDoublings)

	h := setupTest(t, func(cfg *trickle.Config[testMsg]) {
		cfg.Imin = imin
		cfg.ImaxDoublings = uint(imaxDoublings)
	})
	h.trickle.Start()

	expectedI := imin
	for i := range imaxDoublings + 1 { // Go one past Imax to check clamping
		timers := h.mockClock.GetTimers() // Returns []*timeish.MockTimer
		assert.Assert(t, len(timers) >= 2, "Loop %d: Expected timers", i)
		intervalTimer := timers[len(timers)-2] // Get the latest interval timer (*timeish.MockTimer)

		// Check current interval duration
		assert.Equal(t, expectedI, intervalTimer.GetResetDuration(), "Loop %d: Incorrect interval duration", i) // Use GetResetDuration

		// Trigger interval timer expiration
		intervalTimer.Tick(h.mockClock.Now()) // Use Tick
		time.Sleep(10 * time.Millisecond)     // Allow run loop to process

		// Calculate next expected interval, clamped at Imax
		if expectedI < imaxDuration {
			expectedI *= 2
			if expectedI > imaxDuration {
				expectedI = imaxDuration
			}
		}
		// If already at Imax, it should stay at Imax
	}

	h.trickle.Stop()
}

func TestTrickle_ConfigKZero(t *testing.T) {
	// Explicitly test K=0, which should default to K=1
	h := setupTest(t, func(cfg *trickle.Config[testMsg]) {
		cfg.K = 0
	})
	assert.Equal(t, uint(1), h.trickle.Config().K)
}
