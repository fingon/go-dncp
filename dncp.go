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
	"slices"
	"sync"
	"time"

	"github.com/fingon/go-dncp/timeish" // Import timeish
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
	RandSource *uint64 // Pointer to allow sharing if needed, or nil for default

	// NewTrickleInstanceFunc creates a Trickle instance for an endpoint or peer.
	// The implementation should configure the TransmitFunc and ConsistencyFunc
	// based on the provided context (e.g., destination address).
	// The returned Trickle instance should *not* be started yet.
	NewTrickleInstanceFunc func(transmitFunc trickle.TransmitFunc, consistencyFunc trickle.ConsistencyFunc[[]byte]) (*trickle.Trickle[[]byte], error)
}

// NodeData represents the set of TLVs published by a node.
// Stored as a map where each key maps to a slice of TLVs of that type.
// This allows multiple TLVs of the same type (e.g., Peer TLV).
type NodeData map[TLVType][]*TLV

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
	// RandSource default is handled by Trickle New

	// --- Initialize DNCP Instance ---
	d := &DNCP{
		profile:   &profile, // Store a pointer to the validated profile
		nodeID:    slices.Clone(nodeID),
		logger:    profile.Logger.With("module", "dncp", "nodeID", fmt.Sprintf("%x", nodeID)), // Use fmt for hex
		clock:     profile.Clock,
		nodes:     make(map[string]*NodeState),
		endpoints: make(map[EndpointIdentifier]*Endpoint),
		stopChan:  make(chan struct{}),
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

// --- Topology & Reachability (RFC 7787 Section 4.6) ---

// updateTopologyGraph recalculates node reachability based on published Peer TLVs.
// Returns true if any node's reachability status changed, false otherwise.
// Acquires and releases d.mu.Lock.
func (d *DNCP) updateTopologyGraph() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	changed := false
	now := d.clock.Now()
	maxAge := time.Duration(1<<32-1<<15) * time.Millisecond // Max age from RFC 7787 4.6

	// Mark all nodes initially as unreachable, except the local node
	for _, node := range d.nodes {
		if !bytes.Equal(node.NodeID, d.nodeID) {
			if node.isReachable { // Track changes
				changed = true
			}
			node.isReachable = false
		} else {
			node.isReachable = true // Local node always reachable
		}
		// Clear previous peer state derived from TLVs
		node.publishedPeers = make(map[EndpointIdentifier]map[string]EndpointIdentifier) // Use string key
	}

	// Populate publishedPeers map from current NodeData for all nodes
	for _, node := range d.nodes {
		if node.Data == nil {
			continue
		}
		// Iterate through all Peer TLVs published by the node
		peerTLVs, ok := node.Data[TLVTypePeer]
		if !ok {
			continue
		}
		for _, tlv := range peerTLVs {
			// No need to check type again, we fetched the slice for TLVTypePeer
			peerTLV, err := DecodePeerTLV(tlv, d.profile.NodeIdentifierLength)
			if err != nil {
				d.logger.Warn("Failed to decode Peer TLV during topology update", "nodeID", fmt.Sprintf("%x", node.NodeID), "err", err)
				continue
			}
			if _, ok := node.publishedPeers[peerTLV.LocalEndpointID]; !ok {
				node.publishedPeers[peerTLV.LocalEndpointID] = make(map[string]EndpointIdentifier)
			}
			// Use string conversion for the map key
			node.publishedPeers[peerTLV.LocalEndpointID][string(peerTLV.PeerNodeID)] = peerTLV.PeerEndpointID
		}
	}
	// Iteratively mark nodes as reachable
	madeProgress := true
	for madeProgress {
		madeProgress = false
		for _, candidateNode := range d.nodes {
			// Skip if already marked reachable or if it's the local node (already handled)
			if candidateNode.isReachable || bytes.Equal(candidateNode.NodeID, d.nodeID) {
				continue
			}

			// Check if any reachable node R has a bidirectional link to candidateNode N
			for _, reachableNode := range d.nodes {
				if !reachableNode.isReachable {
					continue // R must be reachable
				}

				// Check age of R's data (RFC 7787 Section 4.6)
				if now.Sub(reachableNode.OriginationTime) > maxAge {
					continue // R's data is too old
				}

				// Check if R publishes a Peer TLV for N
				foundRtoN := false
				var rEndpointID, nEndpointID EndpointIdentifier
				for rEpID, peersOnREp := range reachableNode.publishedPeers {
					// Use string conversion for the map key lookup
					if nEpID, ok := peersOnREp[string(candidateNode.NodeID)]; ok {
						foundRtoN = true
						rEndpointID = rEpID
						nEndpointID = nEpID
						break
					}
				}
				if !foundRtoN {
					continue // R does not publish N as a peer
				}

				// Check if N publishes a Peer TLV back to R using the same endpoints
				foundNtoR := false
				if peersOnNEp, ok := candidateNode.publishedPeers[nEndpointID]; ok {
					// Use string conversion for the map key lookup
					if rEpIDCheck, ok := peersOnNEp[string(reachableNode.NodeID)]; ok {
						if rEpIDCheck == rEndpointID {
							foundNtoR = true
						}
					}
				}

				if foundNtoR {
					// Bidirectional link found! Mark N as reachable.
					if !candidateNode.isReachable { // Track changes
						d.logger.Debug("Marking node reachable via topology", "nodeID", fmt.Sprintf("%x", candidateNode.NodeID), "viaNodeID", fmt.Sprintf("%x", reachableNode.NodeID))
						candidateNode.isReachable = true
						changed = true
						madeProgress = true
						break // Move to the next candidate node
					}
				}
			} // End loop through reachable nodes (R)
		} // End loop through candidate nodes (N)
	} // End iterative loop

	// Optional: Clean up unreachable nodes after a grace period?
	// for key, node := range d.nodes {
	// 	if !node.isReachable {
	// 		// delete(d.nodes, key)
	//      // changed = true // If cleanup counts as change
	// 	}
	// }

	return changed
} // Restore closing brace for updateTopologyGraph

// --- Local Data Management ---

// getLocalDataForPublishing constructs the NodeData map for the local node,
// including current Peer TLVs and KeepAlive TLVs.
// Assumes lock is held.
func (d *DNCP) getLocalDataForPublishing() NodeData {
	// Start with a deep copy of existing data
	localData := make(NodeData, len(d.localState.Data))
	for typ, tlvSlice := range d.localState.Data {
		localData[typ] = slices.Clone(tlvSlice) // Clone the slice
	}
	// Clear existing Peer and KeepAlive TLVs, they will be regenerated
	delete(localData, TLVTypePeer)
	delete(localData, TLVTypeKeepAliveInterval)

	// Add current Peer TLVs
	peerTLVs := make([]*TLV, 0) // Collect all peer TLVs first
	for localEpID, ep := range d.endpoints {
		for _, peer := range ep.peers {
			// Apply dense optimization filtering (RFC 7787 Section 6.2)
			// If this node is listening on a dense link, only publish the peer with the highest ID.
			if d.profile.UseDenseOptimization && ep.TransportMode == TransportModeMulticastListenUnicast {
				// highestNodeOnLink needs to be determined and set elsewhere based on received messages.
				if ep.highestNodeOnLink == nil || !bytes.Equal(peer.NodeID, ep.highestNodeOnLink) {
					d.logger.Debug("Dense optimization: Skipping peer TLV publication", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peer.NodeID))
					continue // Skip publishing Peer TLV for this peer
				}
				d.logger.Debug("Dense optimization: Publishing peer TLV for highest node", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peer.NodeID))
			}

			peerTLV, err := NewPeerTLV(peer.NodeID, peer.EndpointID, localEpID, d.profile.NodeIdentifierLength)
			if err != nil {
				d.logger.Error("Failed to create Peer TLV for publishing", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "err", err)
				continue // Skip this peer
			}
			peerTLVs = append(peerTLVs, peerTLV)
		}
	}
	if len(peerTLVs) > 0 {
		localData[TLVTypePeer] = peerTLVs
	}

	// Add KeepAlive TLVs if needed (profile default is probably good enough for now)
	// TODO: Implement KeepAlive TLV creation based on endpoint config

	return localData
}

// addLocalPeerTLV adds a Peer TLV to the local node's state.
// Returns true if the state was changed (TLV was added), false otherwise.
// Assumes lock is held.
func (d *DNCP) addLocalPeerTLV(localEpID EndpointIdentifier, peerNodeID NodeIdentifier, peerEpID EndpointIdentifier) bool {
	// Create the TLV
	newPeerTLV, err := NewPeerTLV(peerNodeID, peerEpID, localEpID, d.profile.NodeIdentifierLength)
	if err != nil {
		d.logger.Error("Failed to create Peer TLV for local state", "err", err)
		return false
	}

	// Check if an identical TLV already exists
	existingTLVs := d.localState.Data[TLVTypePeer]
	for _, existingTLV := range existingTLVs {
		// Compare contents (Type, Length, Value)
		if existingTLV.Type == newPeerTLV.Type &&
			existingTLV.Length == newPeerTLV.Length &&
			bytes.Equal(existingTLV.Value, newPeerTLV.Value) {
			d.logger.Debug("Identical Peer TLV already exists, not adding", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
			return false // No change
		}
	}

	// Append the new TLV
	d.localState.Data[TLVTypePeer] = append(existingTLVs, newPeerTLV)
	d.logger.Debug("Added Peer TLV to local state", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
	return true // State changed
}

// removeLocalPeerTLV removes a specific Peer TLV from the local node's state.
// Returns true if a TLV was removed, false otherwise.
// Assumes lock is held.
func (d *DNCP) removeLocalPeerTLV(localEpID EndpointIdentifier, peerNodeID NodeIdentifier, peerEpID EndpointIdentifier) bool {
	existingTLVs, exists := d.localState.Data[TLVTypePeer]
	if !exists || len(existingTLVs) == 0 {
		return false // Nothing to remove
	}

	foundIndex := -1
	for i, tlv := range existingTLVs {
		// Decode each TLV to compare details
		// Optimization: Could compare raw bytes if NewPeerTLV is deterministic
		decodedTLV, err := DecodePeerTLV(tlv, d.profile.NodeIdentifierLength)
		if err != nil {
			d.logger.Warn("Failed to decode Peer TLV during removal check", "err", err)
			continue // Skip this one
		}

		if decodedTLV.LocalEndpointID == localEpID &&
			bytes.Equal(decodedTLV.PeerNodeID, peerNodeID) &&
			decodedTLV.PeerEndpointID == peerEpID {
			foundIndex = i
			break
		}
	}

	if foundIndex != -1 {
		// Remove the element at foundIndex
		d.localState.Data[TLVTypePeer] = append(existingTLVs[:foundIndex], existingTLVs[foundIndex+1:]...)
		// If the slice becomes empty, remove the map entry
		if len(d.localState.Data[TLVTypePeer]) == 0 {
			delete(d.localState.Data, TLVTypePeer)
		}
		d.logger.Debug("Removed Peer TLV from local state", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
		return true // State changed
	}

	return false // Matching TLV not found
}

// removeLocalPeerTLVsForEndpoint removes all Peer TLVs associated with a specific local endpoint.
// Returns true if any TLVs were removed, false otherwise.
// Assumes lock is held.
func (d *DNCP) removeLocalPeerTLVsForEndpoint(localEpID EndpointIdentifier) bool {
	existingTLVs, exists := d.localState.Data[TLVTypePeer]
	if !exists || len(existingTLVs) == 0 {
		return false // Nothing to remove
	}

	originalLength := len(existingTLVs)
	newTLVs := make([]*TLV, 0, originalLength)

	for _, tlv := range existingTLVs {
		decodedTLV, err := DecodePeerTLV(tlv, d.profile.NodeIdentifierLength)
		if err != nil {
			d.logger.Warn("Failed to decode Peer TLV during endpoint removal check", "err", err)
			newTLVs = append(newTLVs, tlv) // Keep undecodable TLV? Or discard? Keep for now.
			continue
		}
		// Keep TLV only if it's NOT for the endpoint being removed
		if decodedTLV.LocalEndpointID != localEpID {
			newTLVs = append(newTLVs, tlv)
		}
	}

	if len(newTLVs) < originalLength {
		if len(newTLVs) == 0 {
			delete(d.localState.Data, TLVTypePeer)
		} else {
			d.localState.Data[TLVTypePeer] = newTLVs
		}
		d.logger.Debug("Removed Peer TLVs for local endpoint", "localEpID", localEpID, "removedCount", originalLength-len(newTLVs))
		return true // State changed
	}

	return false // No TLVs removed for this endpoint
}

// --- Trickle Integration Helpers ---

// requiresEndpointTrickle checks if the transport mode needs an endpoint-wide Trickle instance.
func requiresEndpointTrickle(mode TransportMode) bool {
	// Only Multicast+Unicast mode uses endpoint Trickle for multicast status updates
	return mode == TransportModeMulticastUnicast
}

// requiresPeerTrickle checks if the transport mode needs per-peer Trickle instances.
func requiresPeerTrickle(mode TransportMode) bool {
	// Only Unicast mode with unreliable transport needs per-peer Trickle
	// Assuming "Unicast" implies unreliable for this example. Profile needs to be clearer.
	return mode == TransportModeUnicast
}

// createEndpointTransmitFunc creates the TransmitFunc for an endpoint's Trickle instance.
func (d *DNCP) createEndpointTransmitFunc(ep *Endpoint) trickle.TransmitFunc {
	return func() {
		d.mu.RLock()
		// Include NodeEndpoint TLV before NetworkState TLV (Sec 4.2)
		nodeEpTLV, err := NewNodeEndpointTLV(d.nodeID, ep.ID, d.profile.NodeIdentifierLength)
		if err != nil {
			d.logger.Error("Failed to create NodeEndpoint TLV for Trickle transmit", "epID", ep.ID, "err", err)
			d.mu.RUnlock()
			return
		}
		netStateTLV, err := NewNetworkStateTLV(d.networkStateHash, d.profile.HashLength)
		if err != nil {
			d.logger.Error("Failed to create NetworkState TLV for Trickle transmit", "epID", ep.ID, "err", err)
			d.mu.RUnlock()
			return
		}
		d.mu.RUnlock() // Unlock before sending

		// Destination for endpoint Trickle is usually multicast address
		dest := ep.MulticastAddress // Assuming this field holds the correct destination string
		if dest == "" {
			d.logger.Warn("Cannot transmit endpoint Trickle, no multicast address configured", "epID", ep.ID)
			return
		}

		err = d.sendTLVs(dest, []*TLV{nodeEpTLV, netStateTLV})
		if err != nil {
			d.logger.Error("Failed Trickle transmission for endpoint", "epID", ep.ID, "dest", dest, "err", err)
		} else {
			d.logger.Debug("Sent Trickle update for endpoint", "epID", ep.ID, "dest", dest)
		}
	}
}

// createPeerTransmitFunc creates the TransmitFunc for a peer's Trickle instance.
func (d *DNCP) createPeerTransmitFunc(peer *Peer) trickle.TransmitFunc {
	return func() {
		d.mu.RLock()
		// Include NodeEndpoint TLV before NetworkState TLV (Sec 4.2)
		nodeEpTLV, err := NewNodeEndpointTLV(d.nodeID, peer.LocalEndpointID, d.profile.NodeIdentifierLength)
		if err != nil {
			d.logger.Error("Failed to create NodeEndpoint TLV for peer Trickle transmit", "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "err", err)
			d.mu.RUnlock()
			return
		}
		netStateTLV, err := NewNetworkStateTLV(d.networkStateHash, d.profile.HashLength)
		if err != nil {
			d.logger.Error("Failed to create NetworkState TLV for peer Trickle transmit", "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "err", err)
			d.mu.RUnlock()
			return
		}
		d.mu.RUnlock() // Unlock before sending

		dest := peer.Address // Destination for peer Trickle is the peer's unicast address
		if dest == "" {
			d.logger.Warn("Cannot transmit peer Trickle, no peer address known", "peerNodeID", fmt.Sprintf("%x", peer.NodeID))
			return
		}

		err = d.sendTLVs(dest, []*TLV{nodeEpTLV, netStateTLV})
		if err != nil {
			d.logger.Error("Failed Trickle transmission for peer", "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "dest", dest, "err", err)
		} else {
			d.logger.Debug("Sent Trickle update for peer", "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "dest", dest)
		}
	}
}

// createConsistencyFunc creates the ConsistencyFunc for Trickle instances.
// It checks if the received message (assumed to be NetworkState TLV) matches the local hash.
func (d *DNCP) createConsistencyFunc() trickle.ConsistencyFunc[[]byte] {
	return func(data []byte) bool {
		// data is the raw bytes received that *should* contain TLVs
		if data == nil {
			d.logger.Warn("Trickle consistency check received nil data")
			return false // Inconsistent if nil
		}

		// Use DecodeAll as the order isn't guaranteed.
		var receivedHash []byte
		reader := bytes.NewReader(data)
		decodedTLVs, err := DecodeAll(reader)
		if err != nil {
			// Log the error but still check if NetworkState was decoded before the error
			d.logger.Warn("Error decoding TLV stream in consistency check", "err", err)
		}

		// Find the NetworkState TLV among the decoded ones
		found := false
		for _, tlv := range decodedTLVs {
			if tlv.Type == TLVTypeNetworkState {
				netState, err := DecodeNetworkStateTLV(tlv, d.profile.HashLength)
				if err == nil {
					receivedHash = netState.NetworkStateHash
					found = true
					break // Found the first NetworkState TLV
				}
				d.logger.Warn("Failed to decode NetworkState TLV in consistency check", "err", err)
				// Continue searching in case there's another valid one? No, spec implies one.
				break
			}
		}

		if !found {
			d.logger.Debug("Trickle consistency check did not find a valid NetworkState TLV in received data")
			return false // Inconsistent if we can't find/decode the hash
		}

		d.mu.RLock()
		localHash := d.networkStateHash
		d.mu.RUnlock()

		consistent := bytes.Equal(receivedHash, localHash)
		d.logger.Debug("Trickle consistency check", "received", hex.EncodeToString(receivedHash), "local", hex.EncodeToString(localHash), "consistent", consistent)
		return consistent
	}
}

// --- Dense Multicast Optimization (RFC 7787 Section 6.2) ---

// checkAndHandleDenseLink evaluates the state of an endpoint and switches modes if necessary.
// Returns true if the mode was changed (indicating a republish might be needed), false otherwise.
// Assumes lock is held.
func (d *DNCP) checkAndHandleDenseLink(ep *Endpoint) bool {
	if !d.profile.UseDenseOptimization || ep.TransportMode == TransportModeUnicast {
		return false // Optimization not enabled or not applicable
	}

	highestPeer := d.findHighestPeerOnLink(ep) // Find current highest among connected peers
	isDense := d.profile.DensePeerThreshold > 0 && uint(len(ep.peers)) > d.profile.DensePeerThreshold
	isHighest := highestPeer == nil || bytes.Equal(d.nodeID, highestPeer.NodeID)

	modeChanged := false

	if isDense && !isHighest {
		// Condition to switch TO listen mode: Dense link, and we are NOT highest.
		if ep.TransportMode != TransportModeMulticastListenUnicast {
			d.logger.Info("Switching endpoint to MulticastListen+Unicast mode (dense link, not highest)", "localEpID", ep.ID, "highestNodeID", fmt.Sprintf("%x", highestPeer.NodeID))
			d.switchToListenMode(ep, highestPeer)
			modeChanged = true
		} else if !bytes.Equal(ep.highestNodeOnLink, highestPeer.NodeID) {
			// Already in listen mode, but highest node changed. Update connection.
			d.logger.Info("Updating highest node peer in MulticastListen+Unicast mode", "localEpID", ep.ID, "newHighestNodeID", fmt.Sprintf("%x", highestPeer.NodeID))
			// Stop old trickle, remove old peer (if different), add new peer, start new trickle.
			// This is complex, let's simplify: just update highestNodeOnLink and rely on normal peer add/remove?
			// For now, just update the stored highest ID. The filtering in getLocalDataForPublishing will use it.
			// A more robust implementation might explicitly manage the single peer connection here.
			ep.highestNodeOnLink = slices.Clone(highestPeer.NodeID)
			// We might need to trigger AddPeerFunc for the new highest node if we don't have a connection.
		}
	} else {
		// Condition to switch or stay in multicast mode: Link is not dense OR we are the highest node.
		if ep.TransportMode != TransportModeMulticastUnicast {
			d.logger.Info("Switching endpoint to Multicast+Unicast mode (not dense or is highest)", "localEpID", ep.ID)
			d.switchToMulticastMode(ep)
			modeChanged = true
		}
	}

	return modeChanged
}

// findHighestPeerOnLink finds the peer with the highest Node ID currently in the endpoint's peer list.
// Returns nil if no peers exist.
// Assumes lock is held.
func (d *DNCP) findHighestPeerOnLink(ep *Endpoint) *Peer {
	var highestPeer *Peer
	for _, peer := range ep.peers {
		if highestPeer == nil || bytes.Compare(peer.NodeID, highestPeer.NodeID) > 0 {
			highestPeer = peer
		}
	}
	return highestPeer
}

// switchToListenMode transitions the endpoint to MulticastListen+Unicast mode.
// Assumes lock is held.
func (d *DNCP) switchToListenMode(ep *Endpoint, highestPeer *Peer) {
	ep.TransportMode = TransportModeMulticastListenUnicast
	ep.highestNodeOnLink = slices.Clone(highestPeer.NodeID) // Store copy

	// Stop endpoint Trickle
	if ep.trickleInstance != nil {
		ep.trickleInstance.Stop()
		ep.trickleInstance = nil
		d.logger.Debug("Stopped endpoint Trickle for Listen mode", "localEpID", ep.ID)
	}

	// Remove all peers except the highest one and stop their Trickle instances
	peersToRemove := make([]NodeIdentifier, 0)
	for _, peer := range ep.peers {
		if !bytes.Equal(peer.NodeID, highestPeer.NodeID) {
			if peer.trickleInstance != nil {
				peer.trickleInstance.Stop()
				d.logger.Debug("Stopped peer Trickle instance for Listen mode", "localEpID", ep.ID, "peerNodeID", fmt.Sprintf("%x", peer.NodeID))
			}
			peersToRemove = append(peersToRemove, peer.NodeID) // Collect IDs to remove
		}
	}

	// Remove non-highest peers from the map
	for _, nodeIDToRemove := range peersToRemove {
		delete(ep.peers, string(nodeIDToRemove))
		d.logger.Debug("Removed non-highest peer for Listen mode", "localEpID", ep.ID, "peerNodeID", fmt.Sprintf("%x", nodeIDToRemove))
		// Also remove the corresponding Peer TLV from local data (will be handled by republish)
	}

	// Ensure per-peer Trickle is running for the highest peer if needed
	if highestPeer != nil && highestPeer.trickleInstance == nil && requiresPeerTrickle(ep.TransportMode) { // Check new mode
		transmitFunc := d.createPeerTransmitFunc(highestPeer)
		consistencyFunc := d.createConsistencyFunc()
		trickleInst, err := d.profile.NewTrickleInstanceFunc(transmitFunc, consistencyFunc)
		if err != nil {
			d.logger.Error("Failed to create Trickle instance for highest peer", "localEpID", ep.ID, "peerNodeID", fmt.Sprintf("%x", highestPeer.NodeID), "err", err)
		} else {
			highestPeer.trickleInstance = trickleInst
			highestPeer.trickleInstance.Start()
			d.logger.Info("Started Trickle instance for highest peer in Listen mode", "localEpID", ep.ID, "peerNodeID", fmt.Sprintf("%x", highestPeer.NodeID))
		}
	}
}

// switchToMulticastMode transitions the endpoint back to Multicast+Unicast mode.
// Assumes lock is held.
func (d *DNCP) switchToMulticastMode(ep *Endpoint) {
	ep.TransportMode = TransportModeMulticastUnicast
	ep.highestNodeOnLink = nil // Clear highest node tracking

	// Stop per-peer Trickle instances (should only be one for the previous highest)
	for _, peer := range ep.peers {
		if peer.trickleInstance != nil {
			peer.trickleInstance.Stop()
			peer.trickleInstance = nil
			d.logger.Debug("Stopped peer Trickle for Multicast mode", "localEpID", ep.ID, "peerNodeID", fmt.Sprintf("%x", peer.NodeID))
		}
	}

	// Start endpoint Trickle if needed
	if ep.trickleInstance == nil && requiresEndpointTrickle(ep.TransportMode) { // Check new mode
		transmitFunc := d.createEndpointTransmitFunc(ep)
		consistencyFunc := d.createConsistencyFunc()
		trickleInst, err := d.profile.NewTrickleInstanceFunc(transmitFunc, consistencyFunc)
		if err != nil {
			d.logger.Error("Failed to create Trickle instance for endpoint", "id", ep.ID, "err", err)
		} else {
			ep.trickleInstance = trickleInst
			ep.trickleInstance.Start()
			d.logger.Info("Started endpoint Trickle instance for Multicast mode", "id", ep.ID)
		}
	}

	// Peers will be re-added automatically as NodeEndpoint TLVs are received via multicast.
	// We might need to trigger AddPeerFunc for nodes we already know about?
	// For now, rely on receiving messages again.
}

// --- Trickle Integration ---

// resetAllTrickle signals inconsistency to all active Trickle instances.
// Assumes lock is held.
func (d *DNCP) resetAllTrickle() {
	d.logger.Debug("Resetting Trickle timers due to network state change")
	for _, ep := range d.endpoints {
		if ep.trickleInstance != nil {
			ep.trickleInstance.Event() // Signal external event (inconsistency)
		}
		for _, peer := range ep.peers {
			if peer.trickleInstance != nil {
				peer.trickleInstance.Event()
			}
		}
	}
}

// --- TLV Processing (RFC 7787 Section 4.4) ---

// HandleReceivedTLVs processes a buffer of received TLV data from a specific source.
// isMulticast indicates if the data arrived via a multicast transport.
func (d *DNCP) HandleReceivedTLVs(data []byte, sourceAddr string, receivedOnLocalEpID EndpointIdentifier, isMulticast bool) error {
	d.logger.Debug("Handling received data", "source", sourceAddr, "localEpID", receivedOnLocalEpID, "len", len(data), "isMulticast", isMulticast)
	reader := bytes.NewReader(data)

	// Need sender's NodeID and EndpointID for processing Peer TLVs etc.
	var senderNodeID NodeIdentifier
	senderEndpointID := ReservedEndpointIdentifier // Default to reserved, type inferred

	// Attempt to decode NodeEndpoint TLV first if required by transport (Sec 4.2)
	// Assuming datagram transport where it MUST be first if present.
	var tlvsToProcess []*TLV
	firstTLV, err := Decode(reader)

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
	case firstTLV != nil && firstTLV.Type == TLVTypeNodeEndpoint:
		// Successfully decoded NodeEndpoint TLV first.
		nodeEpTLV, err := DecodeNodeEndpointTLV(firstTLV, d.profile.NodeIdentifierLength)
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
	tlvsToProcess, err = DecodeAll(reader)
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
	for _, tlv := range tlvsToProcess {
		d.processSingleTLV(tlv, senderNodeID, senderEndpointID, sourceAddr, receivedOnLocalEpID)
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

	return nil // Return nil even if DecodeAll had errors, as some TLVs might have been processed
}

// processSingleTLV handles the logic for a single received TLV according to RFC 7787 Section 4.4.
// receivedOnLocalEpID is currently unused but kept for potential future transport needs.
func (d *DNCP) processSingleTLV(tlv *TLV, senderNodeID NodeIdentifier, senderEndpointID EndpointIdentifier, sourceAddr string, _ EndpointIdentifier) {
	d.logger.Debug("Processing TLV", "type", tlv.Type, "len", tlv.Length, "senderNodeID", fmt.Sprintf("%x", senderNodeID), "senderEpID", senderEndpointID, "source", sourceAddr)

	// MAY: Implement rate limiting for replies (e.g., Request Network State)

	switch tlv.Type {
	case TLVTypeRequestNetworkState:
		// Reply with Network State TLV and all Node State TLVs (headers only)
		d.logger.Debug("Received RequestNetworkState", "source", sourceAddr)
		d.sendFullNetworkState(sourceAddr)

	case TLVTypeRequestNodeState:
		reqNodeTLV, err := DecodeRequestNodeStateTLV(tlv, d.profile.NodeIdentifierLength)
		if err != nil {
			d.logger.Warn("Failed to decode RequestNodeState TLV", "source", sourceAddr, "err", err)
			return
		}
		d.logger.Debug("Received RequestNodeState", "source", sourceAddr, "reqNodeID", fmt.Sprintf("%x", reqNodeTLV.NodeID))
		d.sendNodeState(sourceAddr, reqNodeTLV.NodeID, true) // Include data

	case TLVTypeNetworkState:
		netStateTLV, err := DecodeNetworkStateTLV(tlv, d.profile.HashLength)
		if err != nil {
			d.logger.Warn("Failed to decode NetworkState TLV", "source", sourceAddr, "err", err)
			return
		}
		d.logger.Debug("Received NetworkState", "source", sourceAddr, "hash", hex.EncodeToString(netStateTLV.NetworkStateHash))
		// Pass senderNodeID for peer lookup
		d.handleNetworkStateTLV(netStateTLV, senderNodeID, sourceAddr)

	case TLVTypeNodeState:
		nodeStateTLV, err := DecodeNodeStateTLV(tlv, d.profile.NodeIdentifierLength, d.profile.HashLength)
		if err != nil {
			d.logger.Warn("Failed to decode NodeState TLV", "source", sourceAddr, "err", err)
			return
		}
		d.logger.Debug("Received NodeState", "source", sourceAddr, "nodeID", fmt.Sprintf("%x", nodeStateTLV.NodeID), "seq", nodeStateTLV.SequenceNumber, "hasData", nodeStateTLV.NodeData != nil)
		d.handleNodeStateTLV(nodeStateTLV, sourceAddr)

	case TLVTypeNodeEndpoint:
		// Already handled before DecodeAll, but log if seen again (shouldn't happen with current logic)
		d.logger.Debug("Received NodeEndpoint TLV (again?)", "source", sourceAddr)

	case TLVTypePeer, TLVTypeKeepAliveInterval, TLVTypeTrustVerdict:
		// These should only appear nested within NodeState TLV's NodeData field.
		// If received standalone, ignore them (RFC 7787 Section 7.3).
		d.logger.Warn("Received unexpected standalone TLV", "type", tlv.Type, "source", sourceAddr)

	default:
		// Ignore unknown TLV types (RFC 7787 Section 4.4)
		d.logger.Debug("Ignoring unknown TLV type", "type", tlv.Type, "source", sourceAddr)
	}
}

// handleNetworkStateTLV processes a received Network State TLV.
// senderNodeID is needed to update the correct peer's LastContact timestamp.
func (d *DNCP) handleNetworkStateTLV(netStateTLV *NetworkStateTLV, senderNodeID NodeIdentifier, sourceAddr string) {
	d.mu.RLock()
	localHash := d.networkStateHash
	d.mu.RUnlock()

	if !bytes.Equal(netStateTLV.NetworkStateHash, localHash) {
		d.logger.Info("Received different network state hash", "source", sourceAddr, "received", hex.EncodeToString(netStateTLV.NetworkStateHash), "local", hex.EncodeToString(localHash))
		// MAY: Implement rate limiting for requests
		// Reply with Request Network State TLV (Section 4.4)
		d.requestNetworkState(sourceAddr)
		// MAY also send local Network State TLV
		// d.sendNetworkState(sourceAddr)
	} else {
		d.logger.Debug("Received matching network state hash", "source", sourceAddr)
		// Update peer LastContact timestamp if keep-alives enabled (Sec 6.1.4)
		if d.profile.KeepAliveInterval > 0 && senderNodeID != nil {
			d.mu.Lock()
			found := false
			peerKey := string(senderNodeID)
			now := d.clock.Now()
			for _, ep := range d.endpoints {
				if peer, ok := ep.peers[peerKey]; ok {
					// Check if source address matches? Maybe not necessary if NodeID is unique.
					peer.LastContact = now
					d.logger.Debug("Updated peer LastContact from consistent NetworkState", "peerNodeID", fmt.Sprintf("%x", senderNodeID), "localEpID", ep.ID, "time", now)
					found = true
					break // Found the peer, no need to check other endpoints
				}
			}
			if !found {
				d.logger.Warn("Received consistent NetworkState, but could not find peer to update timestamp", "senderNodeID", fmt.Sprintf("%x", senderNodeID), "source", sourceAddr)
			}
			d.mu.Unlock()
		}
	}
}

// handleNodeStateTLV processes a received Node State TLV.
func (d *DNCP) handleNodeStateTLV(nodeStateTLV *NodeStateTLV, sourceAddr string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	nodeKey := string(nodeStateTLV.NodeID)
	localNodeState, exists := d.nodes[nodeKey]
	now := d.clock.Now()

	// Check if it's our own Node ID (Sec 4.4)
	if bytes.Equal(nodeStateTLV.NodeID, d.nodeID) {
		// Compare sequence numbers using wrapping comparison
		if CompareSequenceNumbers(nodeStateTLV.SequenceNumber, d.localState.SequenceNumber) > 0 ||
			(nodeStateTLV.SequenceNumber == d.localState.SequenceNumber && !bytes.Equal(nodeStateTLV.DataHash, d.localState.DataHash)) {
			d.logger.Warn("Received NodeState for local node with higher seq or different hash",
				"source", sourceAddr,
				"rcvd_seq", nodeStateTLV.SequenceNumber, "local_seq", d.localState.SequenceNumber,
				"rcvd_hash", hex.EncodeToString(nodeStateTLV.DataHash), "local_hash", hex.EncodeToString(d.localState.DataHash))
			// Republish local data with much higher sequence number
			// Need to unlock before calling PublishData
			d.mu.Unlock()
			// How much higher? RFC suggests +1000
			newSeq := nodeStateTLV.SequenceNumber + 1000 // Potential overflow handled by wrapping
			currentData := d.getLocalDataForPublishing() // Get current data before modifying sequence
			d.localState.SequenceNumber = newSeq - 1     // Set sequence so PublishData increments to newSeq
			err := d.PublishData(currentData)
			d.mu.Lock() // Re-lock
			if err != nil {
				d.logger.Error("Failed to republish local data after conflict", "err", err)
			}
		}
		return // Done processing local node state
	}

	// Processing state for a remote node
	// Processing state for a remote node
	action := decideNodeStateAction(localNodeState, nodeStateTLV, exists, d.logger)

	switch action {
	case actionIgnore:
		d.logger.Debug("Ignoring older/same NodeState", "nodeID", fmt.Sprintf("%x", nodeStateTLV.NodeID), "rcvd_seq", nodeStateTLV.SequenceNumber, "local_seq", localNodeState.SequenceNumber)
	case actionUpdateStoreHeader:
		d.logger.Debug("Storing NodeState header", "nodeID", fmt.Sprintf("%x", nodeStateTLV.NodeID), "seq", nodeStateTLV.SequenceNumber)
		d.storeNodeStateHeader(nodeStateTLV, now)
	case actionUpdateStoreHeaderRequestData:
		d.logger.Debug("Storing NodeState header and requesting data", "nodeID", fmt.Sprintf("%x", nodeStateTLV.NodeID), "seq", nodeStateTLV.SequenceNumber)
		d.storeNodeStateHeader(nodeStateTLV, now)
		d.requestNodeState(sourceAddr, nodeStateTLV.NodeID)
	case actionUpdateStoreData:
		d.logger.Debug("Attempting to store NodeState with data", "nodeID", fmt.Sprintf("%x", nodeStateTLV.NodeID), "seq", nodeStateTLV.SequenceNumber)
		if d.storeNodeStateWithData(nodeStateTLV, now) {
			// Data was stored successfully, check network hash and peer KA
			if d.calculateNetworkStateHashLocked() {
				d.logger.Info("Network state hash changed after receiving NodeState with data")
				d.resetAllTrickle()
			}
			// Update peer keep-alive interval if present in data
			// Need to fetch the newly stored state
			if storedNode, ok := d.nodes[nodeKey]; ok {
				d.updatePeerKeepAliveFromNodeData(storedNode)
			}
		}
	}
}

// --- Node State Handling Helpers ---

type nodeStateAction int

const (
	actionIgnore nodeStateAction = iota
	actionUpdateStoreHeader
	actionUpdateStoreHeaderRequestData
	actionUpdateStoreData
)

// decideNodeStateAction determines the action to take based on received vs local state.
// Does not require lock.
func decideNodeStateAction(localNodeState *NodeState, receivedTLV *NodeStateTLV, exists bool, logger *slog.Logger) nodeStateAction {
	if !exists {
		logger.Info("Discovered new node via NodeState", "nodeID", fmt.Sprintf("%x", receivedTLV.NodeID))
		if receivedTLV.NodeData == nil {
			return actionUpdateStoreHeaderRequestData
		}
		return actionUpdateStoreData
	}

	// Existing node, compare sequence numbers
	seqComparison := CompareSequenceNumbers(receivedTLV.SequenceNumber, localNodeState.SequenceNumber)

	switch {
	case seqComparison > 0:
		// Received state is newer
		logger.Debug("Received newer NodeState", "nodeID", fmt.Sprintf("%x", receivedTLV.NodeID), "rcvd_seq", receivedTLV.SequenceNumber, "local_seq", localNodeState.SequenceNumber)
		if receivedTLV.NodeData == nil {
			return actionUpdateStoreHeaderRequestData
		}
		return actionUpdateStoreData
	case seqComparison == 0 && !bytes.Equal(receivedTLV.DataHash, localNodeState.DataHash):
		// Same sequence number, different hash - potential inconsistency
		logger.Warn("Received NodeState with same sequence but different hash", "nodeID", fmt.Sprintf("%x", receivedTLV.NodeID), "seq", receivedTLV.SequenceNumber)
		if receivedTLV.NodeData == nil {
			// We have data locally, they don't. Maybe just store header? Or request their (potentially empty) data?
			// Let's store header and request their data to be sure.
			return actionUpdateStoreHeaderRequestData
		}
		// They have data, we might or might not. Update with their data.
		return actionUpdateStoreData
	default: // seqComparison < 0 or (seqComparison == 0 and hashes match)
		return actionIgnore
	}
}

// storeNodeStateHeader creates/updates the node state with header info only.
// Assumes lock is held.
func (d *DNCP) storeNodeStateHeader(nodeStateTLV *NodeStateTLV, now time.Time) {
	nodeKey := string(nodeStateTLV.NodeID)
	newNodeState := &NodeState{
		NodeID:          slices.Clone(nodeStateTLV.NodeID),
		SequenceNumber:  nodeStateTLV.SequenceNumber,
		DataHash:        slices.Clone(nodeStateTLV.DataHash),
		lastUpdateTime:  now,
		OriginationTime: now.Add(-time.Duration(nodeStateTLV.MillisecondsSinceOrigination) * time.Millisecond),
		isReachable:     false,                                                      // Reachability determined by topology update later
		publishedPeers:  make(map[EndpointIdentifier]map[string]EndpointIdentifier), // Will be populated by topology update
		// Data remains nil
	}
	d.nodes[nodeKey] = newNodeState
}

// storeNodeStateWithData attempts to decode, verify, and store node state including data.
// Returns true if successful, false otherwise.
// Assumes lock is held.
func (d *DNCP) storeNodeStateWithData(nodeStateTLV *NodeStateTLV, now time.Time) bool {
	nodeKey := string(nodeStateTLV.NodeID)
	newNodeState := &NodeState{
		NodeID:         slices.Clone(nodeStateTLV.NodeID),
		SequenceNumber: nodeStateTLV.SequenceNumber,
		// DataHash will be verified/set below
		lastUpdateTime:  now,
		OriginationTime: now.Add(-time.Duration(nodeStateTLV.MillisecondsSinceOrigination) * time.Millisecond),
		isReachable:     false,                                                      // Reachability determined by topology update later
		publishedPeers:  make(map[EndpointIdentifier]map[string]EndpointIdentifier), // Will be populated by topology update
	}

	// Decode nested TLVs
	decodedData, err := decodeNodeDataTLVs(nodeStateTLV.NodeData)
	if err != nil {
		d.logger.Warn("Failed to decode nested TLVs in received NodeState", "nodeID", fmt.Sprintf("%x", nodeStateTLV.NodeID), "err", err)
		return false // Ignore this update
	}
	newNodeState.Data = decodedData

	// Calculate hash of received data
	err = d.calculateNodeDataHash(newNodeState) // Modifies newNodeState.DataHash
	if err != nil {
		d.logger.Error("Failed to calculate hash for received node data", "nodeID", fmt.Sprintf("%x", nodeStateTLV.NodeID), "err", err)
		return false // Ignore this update
	}

	// Compare calculated hash with hash from TLV header
	if !bytes.Equal(newNodeState.DataHash, nodeStateTLV.DataHash) {
		d.logger.Warn("Received NodeState data hash mismatch", "nodeID", fmt.Sprintf("%x", nodeStateTLV.NodeID), "header_hash", hex.EncodeToString(nodeStateTLV.DataHash), "calc_hash", hex.EncodeToString(newNodeState.DataHash))
		return false // Ignore TLV (Sec 4.4)
	}

	// Hash matches, accept the data
	d.nodes[nodeKey] = newNodeState
	return true
}

// updatePeerKeepAliveFromNodeData checks NodeData for KeepAliveInterval TLVs
// and updates the corresponding peer's state.
// Assumes lock is held.
func (d *DNCP) updatePeerKeepAliveFromNodeData(nodeState *NodeState) {
	if nodeState.Data == nil {
		return
	}

	// Find the peer associated with this node state across all endpoints
	var peerRef *Peer
	var peerLocalEpID EndpointIdentifier
	nodeKey := string(nodeState.NodeID)

	for epID, ep := range d.endpoints {
		if peer, ok := ep.peers[nodeKey]; ok {
			peerRef = peer
			peerLocalEpID = epID
			break
		}
	}

	if peerRef == nil {
		// We know about the node state but don't have an active peer connection? Possible.
		return
	}

	// Check for KeepAliveInterval TLVs in the node's data
	kaTLVs, ok := nodeState.Data[TLVTypeKeepAliveInterval]
	foundSpecific := false
	specificInterval := time.Duration(0) // Default to 0 if no TLV found
	defaultInterval := time.Duration(0)

	if ok {
		for _, kaTLV := range kaTLVs {
			decodedKA, err := DecodeKeepAliveIntervalTLV(kaTLV)
			if err != nil {
				d.logger.Warn("Failed to decode KeepAliveInterval TLV from node data", "nodeID", fmt.Sprintf("%x", nodeState.NodeID), "err", err)
				continue
			}

			interval := time.Duration(decodedKA.Interval) * time.Millisecond
			if decodedKA.EndpointID == peerLocalEpID {
				// Found interval specific to the endpoint peer is on
				specificInterval = interval
				foundSpecific = true
				break // Specific endpoint ID always wins
			} else if decodedKA.EndpointID == ReservedEndpointIdentifier {
				// Found a default interval
				defaultInterval = interval
			}
		}
	}

	// Determine the effective interval (specific wins over default)
	effectiveInterval := defaultInterval
	if foundSpecific {
		effectiveInterval = specificInterval
	}

	// Update the peer's interval if it changed
	if peerRef.KeepAliveInterval != effectiveInterval {
		d.logger.Debug("Updating peer keep-alive interval",
			"peerNodeID", fmt.Sprintf("%x", peerRef.NodeID),
			"localEpID", peerLocalEpID,
			"oldInterval", peerRef.KeepAliveInterval,
			"newInterval", effectiveInterval,
			"source", map[bool]string{true: "specific TLV", false: "default TLV/none"}[foundSpecific])
		peerRef.KeepAliveInterval = effectiveInterval
	}
}

// --- Sending TLVs ---

// sendTLV encodes and sends a single TLV to the destination.
func (d *DNCP) sendTLV(destination string, tlv *TLV) error {
	var buf bytes.Buffer
	if err := tlv.Encode(&buf); err != nil {
		return fmt.Errorf("failed to encode TLV type %d: %w", tlv.Type, err)
	}
	if d.SendFunc == nil {
		return errors.New("SendFunc is not configured")
	}
	return d.SendFunc(destination, buf.Bytes())
}

// sendTLVs encodes and sends multiple TLVs together in one payload.
func (d *DNCP) sendTLVs(destination string, tlvs []*TLV) error {
	var buf bytes.Buffer
	for _, tlv := range tlvs {
		if err := tlv.Encode(&buf); err != nil {
			// Log error for the specific TLV but try to send the rest?
			// Or fail the whole batch? Fail batch for now.
			return fmt.Errorf("failed to encode TLV type %d in batch: %w", tlv.Type, err)
		}
	}
	if buf.Len() == 0 {
		return nil // Nothing to send
	}
	if d.SendFunc == nil {
		return errors.New("SendFunc is not configured")
	}
	return d.SendFunc(destination, buf.Bytes())
}

// requestNetworkState sends a Request Network State TLV.
func (d *DNCP) requestNetworkState(destination string) {
	tlv := &TLV{Type: TLVTypeRequestNetworkState, Length: 0, Value: []byte{}}
	err := d.sendTLV(destination, tlv)
	if err != nil {
		d.logger.Error("Failed to send RequestNetworkState", "destination", destination, "err", err)
	}
}

// requestNodeState sends a Request Node State TLV.
func (d *DNCP) requestNodeState(destination string, nodeID NodeIdentifier) {
	tlv, err := NewRequestNodeStateTLV(nodeID, d.profile.NodeIdentifierLength)
	if err != nil {
		d.logger.Error("Failed to create RequestNodeState TLV", "nodeID", fmt.Sprintf("%x", nodeID), "err", err)
		return
	}
	err = d.sendTLV(destination, tlv)
	if err != nil {
		d.logger.Error("Failed to send RequestNodeState", "destination", destination, "nodeID", fmt.Sprintf("%x", nodeID), "err", err)
	}
}

// sendNodeState sends the Node State TLV for a specific node.
func (d *DNCP) sendNodeState(destination string, nodeID NodeIdentifier, includeData bool) {
	d.mu.RLock()
	nodeState, exists := d.nodes[string(nodeID)]
	d.mu.RUnlock()

	if !exists {
		d.logger.Warn("Cannot send NodeState, node not found locally", "nodeID", fmt.Sprintf("%x", nodeID))
		return
	}

	// Need to lock to safely access nodeState fields while creating TLV
	d.mu.RLock()
	seq := nodeState.SequenceNumber
	hash := slices.Clone(nodeState.DataHash)
	msSinceOrigination := uint32(d.clock.Now().Sub(nodeState.OriginationTime).Milliseconds())
	var dataBytes []byte
	var dataBuf bytes.Buffer
	if includeData && nodeState.Data != nil {
		// Get all TLVs ordered correctly for encoding
		orderedTLVs := getOrderedTLVs(nodeState.Data)
		for _, dataTLV := range orderedTLVs {
			if err := dataTLV.Encode(&dataBuf); err != nil {
				d.logger.Error("Failed to encode nested TLV for NodeState data", "nodeID", fmt.Sprintf("%x", nodeID), "type", dataTLV.Type, "err", err)
				// Cannot send with data if any TLV fails encoding
				dataBytes = nil // Ensure dataBytes is nil if encoding fails
				break
			}
		}
		// Only assign dataBytes if encoding succeeded for all TLVs
		if dataBytes != nil {
			dataBytes = dataBuf.Bytes()
		}
	}
	d.mu.RUnlock() // Unlock after accessing nodeState data

	tlv, err := NewNodeStateTLV(nodeID, seq, msSinceOrigination, hash, dataBytes, d.profile.NodeIdentifierLength, d.profile.HashLength)
	if err != nil {
		d.logger.Error("Failed to create NodeState TLV", "nodeID", fmt.Sprintf("%x", nodeID), "err", err)
		return
	}

	err = d.sendTLV(destination, tlv)
	if err != nil {
		d.logger.Error("Failed to send NodeState", "destination", destination, "nodeID", fmt.Sprintf("%x", nodeID), "err", err)
	}
}

// sendFullNetworkState sends the Network State TLV followed by all known Node State TLVs (headers only).
func (d *DNCP) sendFullNetworkState(destination string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	tlvsToSend := make([]*TLV, 0, len(d.nodes)+1)

	// 1. Network State TLV
	netStateTLV, err := NewNetworkStateTLV(d.networkStateHash, d.profile.HashLength)
	if err != nil {
		d.logger.Error("Failed to create NetworkState TLV for full state send", "err", err)
		return // Cannot proceed without network state
	}
	tlvsToSend = append(tlvsToSend, netStateTLV)

	// 2. Node State TLVs (Headers Only)
	now := d.clock.Now()
	for _, nodeState := range d.nodes {
		// Check reachability? Spec doesn't explicitly say for replies, but seems logical.
		// Let's include all known nodes for now, as requested by RequestNetworkState spec.
		// if !nodeState.isReachable { continue }

		msSinceOrigination := uint32(now.Sub(nodeState.OriginationTime).Milliseconds())
		nodeTLV, err := NewNodeStateTLV(
			nodeState.NodeID,
			nodeState.SequenceNumber,
			msSinceOrigination,
			nodeState.DataHash,
			nil, // No data
			d.profile.NodeIdentifierLength,
			d.profile.HashLength,
		)
		if err != nil {
			d.logger.Error("Failed to create NodeState TLV header for full state send", "nodeID", fmt.Sprintf("%x", nodeState.NodeID), "err", err)
			continue // Skip this node
		}
		tlvsToSend = append(tlvsToSend, nodeTLV)
	}

	// Send all TLVs together
	err = d.sendTLVs(destination, tlvsToSend)
	if err != nil {
		d.logger.Error("Failed to send full network state", "destination", destination, "err", err)
	} else {
		d.logger.Debug("Sent full network state", "destination", destination, "num_nodes", len(tlvsToSend)-1)
	}
}
