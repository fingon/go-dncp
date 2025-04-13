package trickle

import (
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/fingon/go-dncp/timeish" // Import the new package
)

// Constants defining default Trickle parameters, based on RFC 6206 examples
// but should be configured based on specific protocol needs.
const (
	DefaultImin time.Duration = 100 * time.Millisecond // Example minimum interval
	DefaultImax uint          = 16                     // Example max doublings (Imax = Imin * 2^16)
	DefaultK    uint          = 1                      // Example redundancy constant
)

// Callback function type for when Trickle decides to transmit.
// The implementation should send the appropriate protocol message.
type TransmitFunc func()

// Callback function type to check if a received message is consistent.
// Takes message data of type M as input.
type ConsistencyFunc[M any] func(data M) bool

// Trickle implements the Trickle algorithm (RFC 6206) for messages of type M.
type Trickle[M any] struct {
	// --- Configuration Parameters (RFC 6206 Section 4.1) ---
	imin time.Duration // Minimum interval size
	imax time.Duration // Maximum interval size (calculated from Imin and Imax doublings)
	k    uint          // Redundancy constant

	// --- State Variables (RFC 6206 Section 4.1) ---
	i time.Duration // Current interval size
	c uint          // Counter for consistent messages in the current interval

	// --- Internal State ---
	transmitFunc    TransmitFunc       // Callback function for transmissions
	consistencyFunc ConsistencyFunc[M] // Callback function to check consistency
	logger          *slog.Logger
	clock           timeish.Clock // Use timeish.Clock

	intervalTimer     timeish.Timer // Use timeish.Timer
	transmissionTimer timeish.Timer // Use timeish.Timer

	// --- Communication Channels ---
	eventChan   chan struct{} // Channel to signal an external event causing a reset
	stopChan    chan struct{} // Channel to signal the Trickle instance to stop
	stoppedChan chan struct{} // Channel closed when the run loop has exited
	startChan   chan struct{} // Channel to signal the start of the run loop
	receiveChan chan M        // Channel for receiving external messages to check consistency

	// --- Synchronization ---
	mu    sync.Mutex // Protects access to state variables if needed (primarily for Stop)
	wg    sync.WaitGroup
	r     *rand.Rand // Source for random numbers
	state State      // Current state of the Trickle instance
}

// State represents the operational state of the Trickle instance.
type State int

const (
	// StateIdle means the Trickle instance is created but not running.
	StateIdle State = iota
	// StateRunning means the Trickle instance's main loop is active.
	StateRunning
	// StateStopped means the Trickle instance has been stopped.
	StateStopped
)

// Config holds the configuration for a Trickle instance handling messages of type M.
type Config[M any] struct {
	// Imin is the minimum interval size (RFC 6206 Section 4.1).
	// Must be greater than 0.
	Imin time.Duration
	// ImaxDoublings is the maximum number of doublings of Imin (RFC 6206 Section 4.1).
	// The actual maximum interval duration will be Imin * 2^ImaxDoublings.
	ImaxDoublings uint
	// K is the redundancy constant (RFC 6206 Section 4.1).
	// 0 is actually 1.
	K uint
	// TransmitFunc is called when Trickle decides a transmission should occur.
	TransmitFunc TransmitFunc
	// ConsistencyFunc is called to determine if a received message is consistent.
	ConsistencyFunc ConsistencyFunc[M]
	// Logger is the logger to use. If nil, a default logger is used.
	Logger *slog.Logger
	// RandSource is the source for random numbers. If nil, a new PCG source is used.
	RandSource rand.Source
	// Clock provides the time source. If nil, uses the real time.
	Clock timeish.Clock // Use timeish.Clock
}

// New creates a new Trickle instance for messages of type M.
// The instance needs to be started using the Start() method.
func New[M any](config Config[M]) (*Trickle[M], error) {
	if config.Imin <= 0 {
		config.Imin = DefaultImin
		slog.Warn("Trickle Imin invalid, using default", "imin", config.Imin)
	}
	if config.K == 0 {
		// RFC 6206 Section 6.5 recommendation for k=infinity
		//
		// But I think 1 is sane default
		config.K = 1
	} else if config.K < 1 {
		config.K = DefaultK
		slog.Warn("Trickle K invalid, using default", "k", config.K)
	}
	if config.TransmitFunc == nil {
		// Provide a default no-op function to avoid nil panics
		config.TransmitFunc = func() {}
		return nil, errors.New("transmit func is required")
	}
	if config.ConsistencyFunc == nil {
		// Provide a default consistency function (always inconsistent)
		config.ConsistencyFunc = func(_ M) bool { return false }
		slog.Warn("Trickle ConsistencyFunc is nil, all received messages will be treated as inconsistent")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Clock == nil {
		config.Clock = timeish.NewRealClock() // Use real time from timeish
	}
	if config.RandSource == nil {
		// Use a default source if none provided.
		now := config.Clock.Now()
		config.RandSource = rand.NewPCG(uint64(now.UnixNano()), uint64(now.UnixNano()/2))
	}

	imaxDuration := config.Imin * time.Duration(uint64(1)<<config.ImaxDoublings)

	t := &Trickle[M]{
		imin:            config.Imin,
		imax:            imaxDuration,
		k:               config.K,
		transmitFunc:    config.TransmitFunc,
		consistencyFunc: config.ConsistencyFunc,
		logger:          config.Logger.With("module", "trickle"),
		clock:           config.Clock,
		r:               rand.New(config.RandSource),
		state:           StateIdle,
		// consistentChan:   make(chan M), // Initialize if used
		// inconsistentChan: make(chan M), // Initialize if used
		eventChan:   make(chan struct{}, 1), // Buffered to avoid blocking external events
		stopChan:    make(chan struct{}),
		stoppedChan: make(chan struct{}),
		startChan:   make(chan struct{}),
		receiveChan: make(chan M),
	}

	t.logger.Info("Trickle instance created",
		"imin", t.imin,
		"imaxDoublings", config.ImaxDoublings,
		"imaxDuration", t.imax,
		"k", t.k)

	return t, nil
}

// Config returns a copy of the configuration parameters used by the instance.
// Note that ImaxDoublings is not stored directly, so it's omitted here.
// RandSource is also omitted.
func (t *Trickle[M]) Config() Config[M] {
	// Config values are immutable after New(), safe to read.
	return Config[M]{
		Imin:            t.imin,
		ImaxDoublings:   0, // Not stored directly
		K:               t.k,
		TransmitFunc:    t.transmitFunc,
		ConsistencyFunc: t.consistencyFunc,
		Logger:          t.logger,
		// RandSource not stored
	}
}

// Start begins the Trickle algorithm execution in a new goroutine.
func (t *Trickle[M]) Start() {
	t.mu.Lock()
	if t.state != StateIdle {
		t.mu.Unlock()
		t.logger.Warn("Trickle Start called on already started or stopped instance")
		return
	}
	t.state = StateRunning
	t.mu.Unlock()

	t.wg.Add(1)
	go t.run()
	// Wait for the run loop to signal it has started before returning.
	<-t.startChan
	t.logger.Info("Trickle instance started")
}

// Stop signals the Trickle algorithm goroutine to terminate and waits for it.
func (t *Trickle[M]) Stop() {
	t.mu.Lock()
	if t.state != StateRunning {
		t.mu.Unlock()
		t.logger.Warn("Trickle Stop called on non-running instance")
		return
	}
	// Signal stop
	close(t.stopChan)
	t.state = StateStopped // Mark as stopped immediately to prevent further signals
	t.mu.Unlock()

	// Wait for run loop to exit
	t.wg.Wait()
	t.logger.Info("Trickle instance stopped")
}

// Receive processes an incoming message of type M according to the Trickle algorithm rules.
// It checks the message consistency using the configured ConsistencyFunc.
// This method is safe to call from multiple goroutines.
func (t *Trickle[M]) Receive(data M) {
	t.mu.Lock()
	state := t.state
	t.mu.Unlock()

	if state != StateRunning {
		t.logger.Debug("Ignoring received message on non-running Trickle instance")
		return
	}

	// Send to the internal channel for processing by the run loop
	// Use a select to avoid blocking if the run loop is busy or stopping.
	select {
	case t.receiveChan <- data:
	case <-t.stopChan:
		t.logger.Debug("Ignoring received message as Trickle instance is stopping")
	default:
		// This case should ideally not happen with an unbuffered channel
		// if the run loop is actively selecting, but added for robustness.
		t.logger.Warn("Trickle receive channel busy, dropping message")
	}
}

// Event signals an external event that should reset the Trickle timer (RFC 6206, Step 6).
// This method is safe to call from multiple goroutines.
func (t *Trickle[M]) Event() {
	t.mu.Lock()
	state := t.state
	t.mu.Unlock()

	if state != StateRunning {
		t.logger.Debug("Ignoring external event on non-running Trickle instance")
		return
	}

	// Use non-blocking send because eventChan is buffered
	select {
	case t.eventChan <- struct{}{}:
		t.logger.Debug("External event signaled")
	default:
		t.logger.Debug("External event channel full or instance stopping, event ignored")
	}
}

// run is the main loop for the Trickle algorithm.
func (t *Trickle[M]) run() {
	defer t.wg.Done()
	defer close(t.stoppedChan) // Signal that the loop has exited

	// Rule 1: When the algorithm starts, set I to [Imin, Imax].
	// We choose Imin for the first interval for faster initial propagation.
	t.mu.Lock()
	t.i = t.imin
	t.mu.Unlock()
	t.startInterval()  // startInterval also locks/unlocks when accessing t.i
	close(t.startChan) // Signal that initialization is complete

	for {
		select {
		case <-t.intervalTimer.C():
			// Rule 5: When the interval I expires, double the interval length.
			t.mu.Lock()
			currentI := t.i // Read current value before doubling
			newI := currentI * 2
			if newI > t.imax {
				newI = t.imax
			}
			t.i = newI
			t.mu.Unlock()
			t.logger.Debug("Interval expired, doubling interval", "old_i", currentI, "new_i", newI)
			t.startInterval() // Start the next interval

		case <-t.transmissionTimer.C():
			// Rule 4: At time t, transmit if c < k.
			if t.c < t.k {
				t.logger.Debug("Transmission timer expired, transmitting", "c", t.c, "k", t.k)
				t.transmitFunc()
			} else {
				t.logger.Debug("Transmission timer expired, suppressed", "c", t.c, "k", t.k)
			}

		case data := <-t.receiveChan:
			// Process received message for consistency
			if t.consistencyFunc(data) {
				// Rule 3: Whenever Trickle hears a "consistent" transmission, increment c.
				t.c++
				t.logger.Debug("Consistent message received", "new_c", t.c)
			} else {
				// Rule 6: If Trickle hears an "inconsistent" transmission...
				t.logger.Debug("Inconsistent message received")
				if t.i > t.imin {
					// ...reset the Trickle timer (set I to Imin, start new interval).
					t.mu.Lock()
					oldI := t.i
					t.mu.Unlock()
					t.logger.Debug("Resetting timer due to inconsistency", "old_i", oldI, "new_i", t.imin)
					t.resetTimer() // resetTimer handles locking for setting t.i
				}
				// If I is already Imin, do nothing.
			}

		case <-t.eventChan:
			// Rule 6: Trickle can also reset its timer in response to external "events".
			t.logger.Debug("External event received")
			t.mu.Lock()
			currentI := t.i
			t.mu.Unlock()
			if currentI > t.imin {
				t.logger.Debug("Resetting timer due to external event", "old_i", currentI, "new_i", t.imin)
				t.resetTimer() // resetTimer handles locking for setting t.i
			}

		case <-t.stopChan:
			// Stop requested
			t.logger.Debug("Stop signal received, stopping timers and exiting run loop")
			if t.intervalTimer != nil {
				t.intervalTimer.Stop()
			}
			if t.transmissionTimer != nil {
				t.transmissionTimer.Stop()
			}
			return // Exit the loop
		}
	}
}

// resetTimer resets the Trickle interval to Imin and starts a new interval.
// Assumes timers are stopped or handles stopping them.
// Must be called from the run() goroutine.
func (t *Trickle[M]) resetTimer() {
	t.mu.Lock()
	t.i = t.imin
	t.mu.Unlock()
	t.startInterval() // startInterval handles its own locking for t.i access
}

// startInterval begins a new Trickle interval.
// It resets the counter c, calculates the transmission time t, and sets the timers.
// Must be called from the run() goroutine.
func (t *Trickle[M]) startInterval() {
	// Ensure previous timers are stopped before creating/resetting new ones.
	// Stop timers safely.
	if t.intervalTimer != nil {
		t.intervalTimer.Stop()
	}
	if t.transmissionTimer != nil {
		t.transmissionTimer.Stop()
	}

	// Rule 2: When an interval begins, reset c to 0.
	t.c = 0

	// Rule 2: Set t to a random point in [I/2, I).
	t.mu.Lock()
	currentI := t.i
	t.mu.Unlock()

	// Calculate random duration within the range [0, currentI/2).
	halfI := currentI / 2
	var randomOffset time.Duration
	if halfI > 0 {
		randomOffset = time.Duration(t.r.Int64N(int64(halfI)))
	}
	transmissionTime := halfI + randomOffset // t is now in [currentI/2, currentI)

	t.logger.Debug("Starting new interval", "i", currentI, "t", transmissionTime)

	// Set or reset the timers using the clock.
	if t.intervalTimer == nil {
		t.intervalTimer = t.clock.NewTimer(currentI)
	} else {
		t.intervalTimer.Reset(currentI)
	}

	if t.transmissionTimer == nil {
		t.transmissionTimer = t.clock.NewTimer(transmissionTime)
	} else {
		t.transmissionTimer.Reset(transmissionTime)
	}
}
