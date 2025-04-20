package dncp

import (
	"bytes"
	"crypto/sha256" // Default hash, profile can override
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/fingon/go-dncp/timeish"
	"github.com/fingon/go-dncp/trickle"
)

// TransportMode represents the communication mode for an endpoint.
type TransportMode int

const (
	// TransportModeUnicast represents pure unicast communication.
	TransportModeUnicast TransportMode = iota
	// TransportModeMulticastUnicast represents both multicast and unicast communication.
	TransportModeMulticastUnicast
	// TransportModeMulticastListenUnicast represents multicast listening with unicast communication.
	TransportModeMulticastListenUnicast
)

// String returns a string representation of the TransportMode.
func (m TransportMode) String() string {
	switch m {
	case TransportModeUnicast:
		return "Unicast"
	case TransportModeMulticastUnicast:
		return "Multicast+Unicast"
	case TransportModeMulticastListenUnicast:
		return "MulticastListen+Unicast"
	default:
		return fmt.Sprintf("Unknown(%d)", int(m))
	}
}

// NodeIdentifier represents a unique identifier for a DNCP node.
// Its length is defined by the DNCP profile.
type NodeIdentifier []byte

// EndpointIdentifier represents a unique identifier for a DNCP endpoint within a node.
type EndpointIdentifier uint32

const (
	// ReservedEndpointIdentifier is the reserved value 0 for endpoint identifiers.
	ReservedEndpointIdentifier EndpointIdentifier = 0
	// DefaultNodeIdentifierLength is a common length, profile overrides.
	DefaultNodeIdentifierLength = 8
	// DefaultHashSize is the default size of the hash output in bytes (SHA-256 truncated).
	DefaultHashSize = 32 // SHA-256 full output
)

// HashFunc defines the interface for hash functions used by DNCP.
type HashFunc func() hash.Hash

// Profile holds the configuration parameters for a DNCP instance,
// as defined in RFC 7787 Section 9.
type Profile struct {
	// NodeIdentifierLength specifies the fixed length of node identifiers.
	NodeIdentifierLength uint
	// HashFunction provides the hash function (e.g., sha256.New).
	HashFunction HashFunc
	// HashLength specifies the number of bytes to use from the hash output.
	HashLength uint
	// TrickleImin is the minimum Trickle interval.
	TrickleImin time.Duration
	// TrickleImaxDoublings is the maximum number of Trickle interval doublings.
	TrickleImaxDoublings uint
	// TrickleK is the Trickle redundancy constant.
	TrickleK uint
	// KeepAliveInterval is the default interval for sending keep-alives. 0 disables.
	KeepAliveInterval time.Duration
	// KeepAliveMultiplier determines how many intervals can be missed before timeout.
	KeepAliveMultiplier uint
	// UseDenseOptimization specifies if the dense multicast optimization (Sec 6.2) is enabled.
	UseDenseOptimization bool
	// DensePeerThreshold is the number of peers on a multicast link above which
	// the dense optimization logic is triggered. Only used if UseDenseOptimization is true.
	// A value of 0 disables the threshold check.
	DensePeerThreshold uint
	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
	// Clock provides the time source. If nil, uses real time.
	Clock timeish.Clock // Use timeish.Clock
	// RandSource provides the random number source. If nil, a default is used.
	RandSource rand.Source // Use rand.Source interface from math/rand/v2

	// NewTrickleInstanceFunc creates a Trickle instance for an endpoint or peer.
	// The implementation should configure the TransmitFunc and ConsistencyFunc
	// based on the provided context (e.g., destination address).
	// The returned Trickle instance should *not* be started yet.
	NewTrickleInstanceFunc func(transmitFunc trickle.TransmitFunc, consistencyFunc trickle.ConsistencyFunc[[]byte]) (*trickle.Trickle[[]byte], error)
	// HandleCollisionFunc is an optional callback invoked when a collision for the local node ID is detected.
	HandleCollisionFunc func() error
}

// NodeData represents the set of TLVs published by a node.
// Stored as a map where each key maps to a slice of TLVMarshaler instances of that type.
type NodeData map[TLVType][]TLVMarshaler

// NodeState holds the state associated with a specific node in the DNCP network.
// RFC 7787 Section 2 & 5.
type NodeState struct {
	NodeID          NodeIdentifier
	SequenceNumber  uint32
	OriginationTime time.Time // Estimated time of publication
	Data            NodeData
	DataHash        []byte // Cached hash of the ordered NodeData TLVs

	// --- Internal state ---
	lastUpdateTime time.Time                                            // Local time when this state was last updated/validated
	isReachable    bool                                                 // Determined by topology graph traversal (Sec 4.6)
	publishedPeers map[EndpointIdentifier]map[string]EndpointIdentifier // Peers published by this node: localEndpoint -> peerNodeID (string key) -> peerEndpoint
}

// Peer represents a relationship with another DNCP node on a specific local endpoint.
// RFC 7787 Section 2 & 5.
type Peer struct {
	NodeID            NodeIdentifier
	EndpointID        EndpointIdentifier       // The peer's endpoint ID
	LocalEndpointID   EndpointIdentifier       // The local endpoint ID for this peer relationship
	Address           string                   // Transport address (e.g., "ip:port"), managed externally
	LastContact       time.Time                // Last time any valid message was received
	KeepAliveInterval time.Duration            // Peer's advertised keep-alive interval (0 if none/default)
	trickleInstance   *trickle.Trickle[[]byte] // Trickle state for unreliable unicast (if applicable)
}

// Endpoint represents a local DNCP communication endpoint.
// RFC 7787 Section 2 & 5.
type Endpoint struct {
	ID            EndpointIdentifier
	TransportMode TransportMode // Communication mode for this endpoint

	InterfaceName     string                   // e.g., "eth0"
	LocalAddress      string                   // Local address used by the endpoint
	MulticastAddress  string                   // Multicast address (if applicable)
	trickleInstance   *trickle.Trickle[[]byte] // Trickle state for multicast/endpoint
	peers             map[string]*Peer         // Peers discovered/configured on this endpoint, keyed by string(NodeID)
	highestNodeOnLink NodeIdentifier           // Node ID of the highest peer seen on this link (for dense mode)
	KeepAliveInterval time.Duration            // Specific keep-alive for this endpoint (0=use profile default)
}

// DNCP represents a single DNCP node instance.
type DNCP struct {
	profile *Profile
	nodeID  NodeIdentifier
	logger  *slog.Logger
	clock   timeish.Clock // Use timeish.Clock

	mu         sync.RWMutex          // Protects access to shared state (nodes, endpoints, etc.)
	nodes      map[string]*NodeState // All known nodes, keyed by string(NodeID)
	endpoints  map[EndpointIdentifier]*Endpoint
	localState *NodeState // This node's own state

	networkStateHash []byte // Cached current network state hash

	// --- Communication & Control ---
	stopChan chan struct{}
	wg       sync.WaitGroup

	// --- Transport Abstraction ---
	// SendFunc is called to send raw TLV data to a specific destination.
	// Destination format depends on the underlying transport (e.g., "udp:ip:port", "mcast:group:port", "tcp:connID").
	// The implementation must handle (un)marshalling TLVs.
	SendFunc func(destination string, data []byte) error
	// AddPeerFunc is called when a potential new peer is discovered (e.g., via multicast).
	// The implementation should establish unicast communication if needed.
	AddPeerFunc func(localEndpointID EndpointIdentifier, peerNodeID NodeIdentifier, peerEndpointID EndpointIdentifier, peerAddress string) error
	// RemovePeerFunc is called when a peer relationship should be terminated.
	RemovePeerFunc func(localEndpointID EndpointIdentifier, peerNodeID NodeIdentifier) error
	// HandleCollisionFunc is an optional callback invoked when a collision for the local node ID is detected.
	// If the callback returns an error, DNCP might propagate it (e.g., to signal a required restart).
	// If nil or returns nil, DNCP performs default behavior (republish).
	HandleCollisionFunc func() error

	// --- Internal State for Rate Limiting ---
	lastNetStateRequest map[string]map[string]time.Time // sourceAddr -> hex(hash) -> time
}

// GetNodeID returns the node identifier of this DNCP instance.
func (d *DNCP) GetNodeID() NodeIdentifier {
	return slices.Clone(d.nodeID)
}

// GetProfile returns a pointer to the profile configuration used by this instance.
// Note: Modifying the returned profile after initialization is not recommended.
func (d *DNCP) GetProfile() *Profile {
	// Profile is set at creation and assumed immutable afterwards.
	return d.profile
}

// New creates a new DNCP instance.
func New(nodeID NodeIdentifier, profile Profile) (*DNCP, error) {
	// --- Validate and Default Profile ---
	if len(nodeID) == 0 {
		return nil, errors.New("node ID cannot be empty")
	}
	if profile.NodeIdentifierLength == 0 {
		profile.NodeIdentifierLength = DefaultNodeIdentifierLength
		slog.Warn("DNCP Profile NodeIdentifierLength invalid, using default", "len", profile.NodeIdentifierLength)
	}
	if len(nodeID) != int(profile.NodeIdentifierLength) {
		return nil, errors.New("node ID length does not match profile")
	}
	if profile.HashFunction == nil {
		profile.HashFunction = sha256.New // Default to SHA-256
		slog.Warn("DNCP Profile HashFunction is nil, using default SHA-256")
	}
	if profile.HashLength == 0 {
		profile.HashLength = DefaultHashSize
		slog.Warn("DNCP Profile HashLength invalid, using default", "len", profile.HashLength)
	}
	// Check hash length vs actual hash output size? Maybe later.
	if profile.TrickleImin <= 0 {
		profile.TrickleImin = trickle.DefaultImin
		slog.Warn("DNCP Profile TrickleImin invalid, using default", "imin", profile.TrickleImin)
	}
	if profile.TrickleK == 0 {
		profile.TrickleK = trickle.DefaultK
		slog.Warn("DNCP Profile TrickleK invalid, using default", "k", profile.TrickleK)
	}
	// ImaxDoublings default is handled by Trickle New
	if profile.KeepAliveMultiplier == 0 && profile.KeepAliveInterval > 0 {
		profile.KeepAliveMultiplier = 3 // Default multiplier if keep-alives are enabled
		slog.Warn("DNCP Profile KeepAliveMultiplier is 0, using default", "mult", profile.KeepAliveMultiplier)
	}
	if profile.Logger == nil {
		profile.Logger = slog.Default()
	}
	if profile.Clock == nil {
		profile.Clock = timeish.NewRealClock() // Use real time from timeish
	}
	if profile.RandSource == nil {
		// Use a default source if none provided.
		now := profile.Clock.Now()
		profile.RandSource = rand.NewPCG(uint64(now.UnixNano()), uint64(now.UnixNano()/2))
		slog.Debug("DNCP Profile RandSource is nil, using default PCG source")
	}

	// --- Initialize DNCP Instance ---
	d := &DNCP{
		profile:   &profile, // Store a pointer to the validated profile
		nodeID:    slices.Clone(nodeID),
		logger:    profile.Logger.With("module", "dncp", "nodeID", fmt.Sprintf("%x", nodeID)), // Use fmt for hex
		clock:     profile.Clock,
		nodes:     make(map[string]*NodeState),
		endpoints: make(map[EndpointIdentifier]*Endpoint),
		stopChan:  make(chan struct{}),
		// HandleCollisionFunc is part of the profile struct now
		lastNetStateRequest: make(map[string]map[string]time.Time),
	}

	// Initialize local node state
	d.localState = &NodeState{
		NodeID:          d.nodeID,
		SequenceNumber:  0, // Or load from persistent storage
		OriginationTime: d.clock.Now(),
		Data:            make(NodeData),
		DataHash:        nil, // Calculated on first publish
		lastUpdateTime:  d.clock.Now(),
		isReachable:     true,                                                       // Local node is always reachable to itself
		publishedPeers:  make(map[EndpointIdentifier]map[string]EndpointIdentifier), // Use string key
	}
	d.nodes[string(d.nodeID)] = d.localState

	d.logger.Info("DNCP instance created")
	return d, nil
}

// Start activates the DNCP instance background processes (e.g., keep-alives, topology checks).
func (d *DNCP) Start() {
	d.logger.Info("Starting DNCP instance...")
	d.wg.Add(1)
	go d.runBackgroundTasks()
	d.logger.Info("DNCP instance started")
}

// Stop halts the DNCP instance and its background processes.
func (d *DNCP) Stop() {
	d.logger.Info("Stopping DNCP instance...")
	close(d.stopChan)
	d.wg.Wait()
	d.logger.Info("DNCP instance stopped")
}

// GetNodeData returns the NodeData for a specific node.
// This provides access to the TLVs published by the node.
func (d *DNCP) GetNodeData(nodeID NodeIdentifier) (NodeData, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	node, exists := d.nodes[string(nodeID)]
	if !exists {
		return nil, fmt.Errorf("node %x not found in DNCP network", nodeID)
	}

	if !node.isReachable {
		return nil, fmt.Errorf("node %x is not reachable", nodeID)
	}

	// Return a deep copy of the node data map and the marshaler slices
	dataCopy := make(NodeData, len(node.Data))
	for typ, marshalerSlice := range node.Data {
		// Clone the slice itself
		clonedSlice := make([]TLVMarshaler, len(marshalerSlice))
		copy(clonedSlice, marshalerSlice)
		// Note: This is a shallow copy of the marshalers within the slice.
		// If marshalers were mutable and modified elsewhere, this could be an issue.
		// Assuming marshalers are treated as immutable after creation/decoding.
		dataCopy[typ] = clonedSlice
	}

	return dataCopy, nil
}

// runBackgroundTasks handles periodic tasks like keep-alives and topology updates.
func (d *DNCP) runBackgroundTasks() {
	defer d.wg.Done()
	// Use profile's TrickleImin as a base interval for checks? Or a separate config?
	ticker := d.clock.NewTimer(d.profile.TrickleImin) // Example interval
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C():
			d.logger.Debug("Running periodic background tasks")
			// --- Keep-Alive Check ---
			if d.profile.KeepAliveInterval > 0 {
				d.checkPeerTimeouts()
			}

			// --- Topology Update ---
			if d.updateTopologyGraph() {
				d.logger.Info("Topology changed, recalculating network hash")
				if d.calculateNetworkStateHash() {
					d.logger.Info("Network state hash changed due to topology update")
					d.resetAllTrickle() // Signal inconsistency
				}
			}

			// Reset ticker for next interval
			ticker.Reset(d.profile.TrickleImin) // Reset with the same interval

		case <-d.stopChan:
			d.logger.Debug("Stopping background tasks")
			return
		}
	}
}

// PublishData updates the local node's published data.
// This triggers a sequence number increment, hash recalculation, and Trickle reset.
func (d *DNCP) PublishData(newData NodeData) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Increment sequence number (handle wrap-around conceptually via comparison)
	d.localState.SequenceNumber++
	d.localState.OriginationTime = d.clock.Now()
	// Deep clone the NodeData map
	clonedData := make(NodeData, len(newData))
	for typ, tlvSlice := range newData {
		clonedData[typ] = slices.Clone(tlvSlice) // Clone the slice for this type
	}
	d.localState.Data = clonedData
	d.localState.lastUpdateTime = d.clock.Now()

	// Recalculate local node data hash
	if err := d.calculateNodeDataHash(d.localState); err != nil {
		// This should ideally not happen if TLV encoding is correct
		d.logger.Error("Failed to calculate local node data hash", "err", err)
		// Revert sequence number? Or log and continue? For now, log.
		return fmt.Errorf("failed to calculate local node data hash: %w", err)
	}

	d.logger.Info("Local data updated", "seq", d.localState.SequenceNumber, "hash", hex.EncodeToString(d.localState.DataHash))

	// Recalculate network state hash
	if d.calculateNetworkStateHashLocked() {
		d.logger.Info("Network state hash changed due to local data update")
		d.resetAllTrickle() // Signal inconsistency
	}

	return nil
}

// HandleReceivedTLVs processes a buffer of received TLV data from a specific source.
// isMulticast indicates if the data arrived via a multicast transport.
// Returns an error if processing fails critically or if a collision requires application intervention.
func (d *DNCP) HandleReceivedTLVs(data []byte, sourceAddr string, receivedOnLocalEpID EndpointIdentifier, isMulticast bool) error {
	d.logger.Debug("Handling received data", "source", sourceAddr, "localEpID", receivedOnLocalEpID, "len", len(data), "isMulticast", isMulticast)
	reader := bytes.NewReader(data)

	// Need sender's NodeID and EndpointID for processing Peer TLVs etc.
	var senderNodeID NodeIdentifier
	senderEndpointID := ReservedEndpointIdentifier // Default to reserved, type inferred

	// Attempt to decode NodeEndpoint TLV first if required by transport (Sec 4.2)
	// Assuming datagram transport where it MUST be first if present.
	var tlvsToProcess []TLVMarshaler
	// Pass profile to Decode
	firstTLV, err := Decode(reader, d.profile)

	needsDenseCheck := false

	switch {
	case errors.Is(err, io.EOF):
		// Empty stream, nothing to do.
		d.logger.Debug("Received empty TLV data", "source", sourceAddr)
		return nil
	case errors.Is(err, io.ErrUnexpectedEOF):
		// Truncated stream during first TLV decode.
		d.logger.Warn("Truncated TLV stream", "source", sourceAddr, "err", err)
		return fmt.Errorf("truncated TLV stream from %s: %w", sourceAddr, err)
	case err != nil:
		// Other error decoding first TLV. Log and attempt DecodeAll from start.
		d.logger.Warn("Failed to decode first potential TLV, attempting DecodeAll", "source", sourceAddr, "err", err)
		_, _ = reader.Seek(0, io.SeekStart) // Reset reader
		// Fall through to DecodeAll below
	case firstTLV != nil && firstTLV.GetType() == TLVTypeNodeEndpoint:
		// Successfully decoded NodeEndpoint TLV first.
		// Type assert to access fields
		nodeEpTLV, ok := firstTLV.(*NodeEndpointTLV)
		if !ok {
			// This should not happen if GetType() returned TLVTypeNodeEndpoint
			d.logger.Error("Internal error: Failed type assertion for NodeEndpointTLV", "source", sourceAddr)
			return errors.New("internal error: failed type assertion for NodeEndpointTLV")
		}
		if err != nil {
			d.logger.Warn("Failed to decode NodeEndpoint TLV", "source", sourceAddr, "err", err)
			return fmt.Errorf("broken NodeEndpointTLV: %w", err)
		}
		senderNodeID = nodeEpTLV.NodeID
		senderEndpointID = nodeEpTLV.EndpointID
		d.logger.Debug("Decoded NodeEndpoint TLV", "source", sourceAddr, "senderNodeID", fmt.Sprintf("%x", senderNodeID), "senderEpID", senderEndpointID)

		// --- Dense Mode: Track Highest Node ID ---
		// Regardless of mode, track the highest node ID seen on the link via multicast.
		// This is needed to decide if *this* node should be the active one in dense mode.
		if isMulticast && d.profile.UseDenseOptimization {
			d.mu.Lock()
			if ep, ok := d.endpoints[receivedOnLocalEpID]; ok {
				// Update highestNodeOnLink if the sender is higher than the current highest (or if none is set)
				if ep.highestNodeOnLink == nil || bytes.Compare(senderNodeID, ep.highestNodeOnLink) > 0 {
					d.logger.Debug("New highest node ID detected on link", "localEpID", receivedOnLocalEpID, "newNodeID", fmt.Sprintf("%x", senderNodeID), "oldNodeID", fmt.Sprintf("%x", ep.highestNodeOnLink))
					ep.highestNodeOnLink = slices.Clone(senderNodeID) // Store a copy
					// If we are in listen mode, and the highest node changed, we need to re-evaluate
					if ep.TransportMode == TransportModeMulticastListenUnicast {
						needsDenseCheck = true
					}
				}
			}
			d.mu.Unlock()
		}

		// --- Process Peer Addition/Update (Sec 4.5) ---
		if isMulticast {
			if d.AddPeerFunc != nil {
				d.logger.Debug("Triggering AddPeerFunc for multicast discovery", "source", sourceAddr, "senderNodeID", fmt.Sprintf("%x", senderNodeID))
				// Call AddPeerFunc asynchronously? Or let the implementation decide? Let implementation decide for now.
				err := d.AddPeerFunc(receivedOnLocalEpID, senderNodeID, senderEndpointID, sourceAddr)
				if err != nil {
					d.logger.Error("AddPeerFunc callback failed", "source", sourceAddr, "err", err)
				}
			} else {
				d.logger.Debug("Received NodeEndpoint via multicast, but no AddPeerFunc configured", "source", sourceAddr)
			}
		} else {
			// Received via unicast, proceed with adding/updating the peer state and Peer TLV
			addPeerErr := d.AddOrUpdatePeer(receivedOnLocalEpID, senderNodeID, senderEndpointID, sourceAddr)
			if addPeerErr != nil {
				d.logger.Error("Failed to add/update peer from unicast NodeEndpoint TLV", "source", sourceAddr, "err", addPeerErr)
				// Continue processing other TLVs? Yes.
			}
		}
	case firstTLV != nil:
		// First TLV was valid but not NodeEndpoint. Reset reader and let DecodeAll handle it.
		_, _ = reader.Seek(0, io.SeekStart)
		// Fall through to DecodeAll below
	}

	// Decode all TLVs (either remaining or all if first failed/wasn't NodeEndpoint)
	// Pass profile to DecodeAll
	tlvsToProcess, err = DecodeAll(reader, d.profile)
	if err != nil {
		// Log error but process the TLVs that were decoded successfully before the error.
		d.logger.Warn("Error decoding TLV stream", "source", sourceAddr, "err", err)
		// Continue processing successfully decoded tlvsToProcess below.
	}

	if len(tlvsToProcess) == 0 {
		d.logger.Debug("No further TLVs to process", "source", sourceAddr)
		return nil
	}

	// Process decoded TLVs
	for _, tlvMarshaler := range tlvsToProcess {
		// processSingleTLV might return an error (e.g., collision)
		if err := d.processSingleTLV(tlvMarshaler, senderNodeID, senderEndpointID, sourceAddr, isMulticast); err != nil {
			// If a collision error occurs, stop processing further TLVs in this batch and return the error.
			d.logger.Error("Error processing TLV, stopping batch processing", "type", tlvMarshaler.GetType(), "err", err)
			return err // Propagate the error (e.g., CollisionRestartError)
		}
	}

	// Perform dense check if triggered by highest node ID change
	if needsDenseCheck {
		d.mu.Lock()
		if ep, ok := d.endpoints[receivedOnLocalEpID]; ok {
			if d.checkAndHandleDenseLink(ep) {
				// Mode changed, need to republish
				d.mu.Unlock() // Unlock before PublishData
				currentData := d.getLocalDataForPublishing()
				err := d.PublishData(currentData)
				d.mu.Lock() // Re-lock
				if err != nil {
					d.logger.Error("Failed to republish data after dense mode change", "localEpID", receivedOnLocalEpID, "err", err)
				}
			}
		}
		d.mu.Unlock()
	}

	return nil // Return nil if all TLVs processed successfully without critical errors
}
