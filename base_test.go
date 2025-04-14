// This would be named dncp_test.go, except I don't want wildcards to
// include it in AI context.

package dncp_test

import (
	"crypto/sha256"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/fingon/go-dncp"
	"github.com/fingon/go-dncp/timeish"
	"github.com/fingon/go-dncp/trickle"
	"gotest.tools/v3/assert"
)

// --- Test Harness ---

type mockTransport struct {
	mu       sync.Mutex
	sentData map[string][][]byte // destination -> list of sent payloads
	t        *testing.T
}

func newMockTransport(t *testing.T) *mockTransport {
	return &mockTransport{
		sentData: make(map[string][][]byte),
		t:        t,
	}
}

func (m *mockTransport) SendFunc(destination string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sentData[destination] == nil {
		m.sentData[destination] = make([][]byte, 0, 1)
	}
	// Store a copy of the data
	m.sentData[destination] = append(m.sentData[destination], slices.Clone(data))
	m.t.Logf("MockTransport: Sent %d bytes to %s", len(data), destination)
	return nil
}

func (m *mockTransport) AddPeerFunc(localEndpointID dncp.EndpointIdentifier, peerNodeID dncp.NodeIdentifier, peerEndpointID dncp.EndpointIdentifier, peerAddress string) error {
	m.t.Logf("MockTransport: AddPeerFunc called - localEpID: %d, peerNodeID: %x, peerEpID: %d, addr: %s", localEndpointID, peerNodeID, peerEndpointID, peerAddress)
	// In a real scenario, this would establish connection. Mock does nothing.
	return nil
}

func (m *mockTransport) RemovePeerFunc(localEndpointID dncp.EndpointIdentifier, peerNodeID dncp.NodeIdentifier) error {
	m.t.Logf("MockTransport: RemovePeerFunc called - localEpID: %d, peerNodeID: %x", localEndpointID, peerNodeID)
	// In a real scenario, this would close connection. Mock does nothing.
	return nil
}

func (m *mockTransport) GetSentData(destination string) [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return copies
	var copies [][]byte
	for _, data := range m.sentData[destination] {
		copies = append(copies, slices.Clone(data))
	}
	return copies
}

func (m *mockTransport) ClearSentData() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentData = make(map[string][][]byte)
}

type testHarness struct {
	t         *testing.T
	dncp      *dncp.DNCP
	mockClock *timeish.MockClock
	transport *mockTransport
	profile   dncp.Profile
	nodeID    dncp.NodeIdentifier
}

// Helper to implement io.Writer for slog
type testWriter struct {
	t *testing.T
}

func (tw testWriter) Write(p []byte) (n int, err error) {
	tw.t.Log(string(p))
	return len(p), nil
}

func setupTest(t *testing.T, nodeID dncp.NodeIdentifier, profileMod func(p *dncp.Profile)) *testHarness {
	t.Helper()

	mockClock := timeish.NewMockClock(time.Unix(1700000000, 0))
	transport := newMockTransport(t)
	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if nodeID == nil {
		nodeID = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	}

	profile := dncp.Profile{
		NodeIdentifierLength: uint(len(nodeID)),
		HashFunction:         sha256.New,
		HashLength:           32,
		TrickleImin:          100 * time.Millisecond,
		TrickleImaxDoublings: 4, // Imax = 1600ms
		TrickleK:             1,
		KeepAliveInterval:    5 * time.Second, // Enable keep-alives for testing
		KeepAliveMultiplier:  3,
		UseDenseOptimization: false, // Default to off unless test enables it
		DensePeerThreshold:   0,
		Logger:               logger,
		Clock:                mockClock,
		NewTrickleInstanceFunc: func(transmitFunc trickle.TransmitFunc, consistencyFunc trickle.ConsistencyFunc[[]byte]) (*trickle.Trickle[[]byte], error) {
			cfg := trickle.Config[[]byte]{
				Imin:            100 * time.Millisecond, // Use profile values? Yes.
				ImaxDoublings:   4,
				K:               1,
				TransmitFunc:    transmitFunc,
				ConsistencyFunc: consistencyFunc,
				Logger:          logger.With("trickle", true),
				Clock:           mockClock,
			}
			return trickle.New(cfg)
		},
	}

	if profileMod != nil {
		profileMod(&profile)
	}

	d, err := dncp.New(nodeID, profile)
	assert.NilError(t, err)
	assert.Assert(t, d != nil)

	// Assign transport functions after New
	d.SendFunc = transport.SendFunc
	d.AddPeerFunc = transport.AddPeerFunc
	d.RemovePeerFunc = transport.RemovePeerFunc

	h := &testHarness{
		t:         t,
		dncp:      d,
		mockClock: mockClock,
		transport: transport,
		profile:   profile, // Store effective profile
		nodeID:    nodeID,
	}

	// Start background tasks
	h.dncp.Start()
	t.Cleanup(h.dncp.Stop) // Ensure Stop is called

	return h
}

// --- Tests ---

func TestNewDNCP(t *testing.T) {
	t.Run("Valid profile", func(t *testing.T) {
		h := setupTest(t, nil, nil) // Use defaults
		assert.Assert(t, h.dncp != nil)
	})

	t.Run("Nil Node ID", func(t *testing.T) {
		_, err := dncp.New(nil, dncp.Profile{NodeIdentifierLength: 8})
		assert.ErrorContains(t, err, "node ID cannot be empty")
	})

	t.Run("Node ID length mismatch", func(t *testing.T) {
		_, err := dncp.New([]byte{1, 2, 3}, dncp.Profile{NodeIdentifierLength: 8})
		assert.ErrorContains(t, err, "node ID length does not match profile")
	})

	t.Run("Profile defaults", func(t *testing.T) {
		// Test that defaults are applied correctly
		nodeID := []byte{1, 1, 1, 1, 1, 1, 1, 1}
		d, err := dncp.New(nodeID, dncp.Profile{
			NodeIdentifierLength: 8, // Only provide mandatory fields
			HashFunction:         sha256.New,
			HashLength:           32,
			TrickleImin:          100 * time.Millisecond,
			TrickleK:             1,
		})
		assert.NilError(t, err)
		assert.Assert(t, d != nil)
		// We can't easily inspect the internal profile, but check no error occurred.
	})
}

func TestEndpointManagement(t *testing.T) {
	h := setupTest(t, nil, nil)
	epID := dncp.EndpointIdentifier(1)
	ep := dncp.Endpoint{
		ID:               epID,
		TransportMode:    dncp.TransportModeMulticastUnicast, // Requires endpoint trickle
		InterfaceName:    "test0",
		LocalAddress:     "local:1234",
		MulticastAddress: "mcast:5678",
	}

	// Add Endpoint
	err := h.dncp.AddEndpoint(ep)
	assert.NilError(t, err)

	// Verify endpoint Trickle instance started (check logs or mock clock timers)
	timers := h.mockClock.GetTimers()
	assert.Assert(t, len(timers) >= 2, "Expected Trickle timers for endpoint") // Interval + Transmission

	// Add duplicate Endpoint
	err = h.dncp.AddEndpoint(ep)
	assert.ErrorContains(t, err, "endpoint with ID 1 already exists")

	// Add endpoint with reserved ID
	err = h.dncp.AddEndpoint(dncp.Endpoint{ID: dncp.ReservedEndpointIdentifier})
	assert.ErrorContains(t, err, "cannot use reserved endpoint identifier 0")

	// Remove Endpoint
	err = h.dncp.RemoveEndpoint(epID)
	assert.NilError(t, err)

	// Verify endpoint Trickle instance stopped (check logs or mock clock timers)
	// Note: MockClock doesn't track stopped timers explicitly in a simple way.
	// Rely on logs or absence of further ticks/transmissions.

	// Remove non-existent Endpoint
	err = h.dncp.RemoveEndpoint(epID)
	assert.ErrorContains(t, err, "endpoint with ID 1 not found")
}

func TestPublishData(t *testing.T) {
	h := setupTest(t, nil, nil)

	// Initial state (no data published yet)
	// TODO: Need a way to get current local NodeState easily

	// Publish some data
	testTLV, err := dncp.NewKeepAliveIntervalTLV(0, 1234*time.Millisecond) // Example TLV
	assert.NilError(t, err)
	newData := dncp.NodeData{
		dncp.TLVTypeKeepAliveInterval: []*dncp.TLV{testTLV},
	}

	err = h.dncp.PublishData(newData)
	assert.NilError(t, err)

	// TODO: Verify sequence number incremented
	// TODO: Verify local node hash updated
	// TODO: Verify network hash updated
	// TODO: Verify Trickle timers reset (check logs or mock clock timers)

	// Publish again (should increment sequence)
	err = h.dncp.PublishData(newData) // Publish same data again
	assert.NilError(t, err)
	// TODO: Verify sequence number incremented again
}

// TODO: Add tests for Peer Management (Add/RemovePeer)
// TODO: Add tests for TLV Handling (HandleReceivedTLVs)
// TODO: Add tests for Topology Updates (updateTopologyGraph)
// TODO: Add tests for Network Hash Calculation (calculateNetworkStateHash)
// TODO: Add tests for Keep-Alive Timeouts (checkPeerTimeouts)
// TODO: Add tests for Dense Mode Optimization
// TODO: Add tests for CompareSequenceNumbers
