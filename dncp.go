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
	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
	// Clock provides the time source. If nil, uses real time.
	Clock timeish.Clock // Use timeish.Clock
	// RandSource provides the random number source. If nil, a default is used.
	RandSource *uint64 // Pointer to allow sharing if needed, or nil for default
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
	EndpointID        EndpointIdentifier    // The peer's endpoint ID
	LocalEndpointID   EndpointIdentifier    // The local endpoint ID for this peer relationship
	Address           string                // Transport address (e.g., "ip:port"), managed externally
	LastContact       time.Time             // Last time any valid message was received
	KeepAliveInterval time.Duration         // Peer's advertised keep-alive interval (0 if none/default)
	trickleInstance   *trickle.Trickle[any] // Trickle state for unreliable unicast (if applicable)
}

// Endpoint represents a local DNCP communication endpoint.
// RFC 7787 Section 2 & 5.
type Endpoint struct {
	ID                EndpointIdentifier
	TransportMode     string                // e.g., "Multicast+Unicast", "Unicast", "MulticastListen+Unicast"
	InterfaceName     string                // e.g., "eth0"
	LocalAddress      string                // Local address used by the endpoint
	MulticastAddress  string                // Multicast address (if applicable)
	trickleInstance   *trickle.Trickle[any] // Trickle state for multicast/endpoint
	peers             map[string]*Peer      // Peers discovered/configured on this endpoint, keyed by string(NodeID)
	keepAliveInterval time.Duration         // Local keep-alive interval for this endpoint
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

// AddEndpoint configures a new local endpoint.
func (d *DNCP) AddEndpoint(ep Endpoint) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.endpoints[ep.ID]; exists {
		return fmt.Errorf("endpoint with ID %d already exists", ep.ID)
	}
	if ep.ID == ReservedEndpointIdentifier {
		return errors.New("cannot use reserved endpoint identifier 0")
	}
	if ep.peers == nil {
		ep.peers = make(map[string]*Peer)
	}
	// TODO: Initialize Trickle instance based on TransportMode

	d.endpoints[ep.ID] = &ep
	d.logger.Info("Added endpoint", "id", ep.ID, "mode", ep.TransportMode, "iface", ep.InterfaceName)
	return nil
}

// RemoveEndpoint removes a local endpoint.
func (d *DNCP) RemoveEndpoint(id EndpointIdentifier) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, exists := d.endpoints[id] // Use blank identifier as ep is not used below
	if !exists {
		return fmt.Errorf("endpoint with ID %d not found", id)
	}

	// TODO: Stop Trickle instance for the endpoint
	// TODO: Clean up peers associated with this endpoint? Or rely on timeout/transport signals?

	delete(d.endpoints, id)
	d.logger.Info("Removed endpoint", "id", id)

	// Update local Peer TLVs and republish if necessary
	if d.removeLocalPeerTLVsForEndpoint(id) {
		d.mu.Unlock() // Unlock before calling PublishData which locks
		// Need to reconstruct the current local data without the removed peers
		currentData := d.getLocalDataForPublishing()
		err := d.PublishData(currentData)
		d.mu.Lock() // Re-lock
		if err != nil {
			d.logger.Error("Failed to republish data after removing endpoint", "id", id, "err", err)
			// State might be inconsistent here
		}
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
	// NOTE: The duplicated block below was removed as part of the fix for the NodeData map change.
	// This section seems to be a leftover artifact. Removing the extra closing brace below.
	//				continue
	//			}
	//			if _, ok := node.publishedPeers[peerTLV.LocalEndpointID]; !ok {
	//				node.publishedPeers[peerTLV.LocalEndpointID] = make(map[string]EndpointIdentifier)
	//			}
	//			// Use string conversion for the map key
	//			node.publishedPeers[peerTLV.LocalEndpointID][string(peerTLV.PeerNodeID)] = peerTLV.PeerEndpointID
	//		}
	//	}
	//}

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

// --- Peer Management & Keep-Alives ---

// AddOrUpdatePeer adds a new peer or updates an existing one on a local endpoint.
// Called by the transport layer when a connection is established or a NodeEndpoint TLV is received.
func (d *DNCP) AddOrUpdatePeer(localEpID EndpointIdentifier, peerNodeID NodeIdentifier, peerEpID EndpointIdentifier, peerAddr string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ep, ok := d.endpoints[localEpID]
	if !ok {
		return fmt.Errorf("local endpoint %d not found", localEpID)
	}

	peer, exists := ep.peers[string(peerNodeID)]
	now := d.clock.Now()

	if !exists {
		peer = &Peer{
			NodeID:          slices.Clone(peerNodeID),
			EndpointID:      peerEpID,
			LocalEndpointID: localEpID,
			Address:         peerAddr,
			LastContact:     now,
			// KeepAliveInterval will be updated when NodeState is received
		}
		ep.peers[string(peerNodeID)] = peer
		d.logger.Info("Added new peer", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID), "peerEpID", peerEpID, "addr", peerAddr)
	} else {
		// Update existing peer info
		peer.EndpointID = peerEpID // Peer might change its endpoint ID?
		peer.Address = peerAddr
		peer.LastContact = now
		d.logger.Debug("Updated existing peer contact", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
	}

	// Update local Peer TLV for this new/updated peer relationship
	if d.addLocalPeerTLV(localEpID, peerNodeID, peerEpID) {
		d.mu.Unlock() // Unlock before calling PublishData
		// Need to reconstruct the current local data with the new peer
		currentData := d.getLocalDataForPublishing()
		err := d.PublishData(currentData)
		d.mu.Lock() // Re-lock
		if err != nil {
			d.logger.Error("Failed to republish data after adding/updating peer", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID), "err", err)
			// State might be inconsistent here
		}
	}

	return nil
}

// RemovePeer removes a peer relationship.
// Called by transport layer on disconnect or by keep-alive timeout.
func (d *DNCP) RemovePeer(localEpID EndpointIdentifier, peerNodeID NodeIdentifier) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ep, ok := d.endpoints[localEpID]
	if !ok {
		// Endpoint might have been removed already, not an error
		d.logger.Warn("Cannot remove peer, local endpoint not found", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
		return nil // Or return specific error? fmt.Errorf("local endpoint %d not found", localEpID)
	}

	peerKey := string(peerNodeID)
	peer, exists := ep.peers[peerKey]
	if !exists {
		// Peer might have been removed already, not an error
		d.logger.Warn("Cannot remove peer, peer not found on endpoint", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
		return nil
	}

	// TODO: Stop per-peer Trickle instance if applicable

	delete(ep.peers, peerKey)
	d.logger.Info("Removed peer", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))

	// Remove the corresponding Peer TLV from local data and republish
	if d.removeLocalPeerTLV(localEpID, peerNodeID, peer.EndpointID) {
		d.mu.Unlock() // Unlock before calling PublishData
		// Need to reconstruct the current local data without the removed peer
		currentData := d.getLocalDataForPublishing()
		err := d.PublishData(currentData)
		d.mu.Lock() // Re-lock
		if err != nil {
			d.logger.Error("Failed to republish data after removing peer", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID), "err", err)
			// State might be inconsistent here
		}
	}

	return nil
}

// checkPeerTimeouts iterates through peers and removes those that haven't been heard from.
// Assumes lock is held.
func (d *DNCP) checkPeerTimeouts() {
	now := d.clock.Now()
	peersToRemove := make(map[EndpointIdentifier][]NodeIdentifier) // localEpID -> list of peerNodeIDs

	for localEpID, ep := range d.endpoints {
		for _, peer := range ep.peers {
			keepAliveInterval := d.profile.KeepAliveInterval // Use profile default initially

			// Check if peer publishes a specific interval
			// TODO: When NodeData supports multiple TLVs, decode KeepAliveInterval TLV here
			//       and check if it applies to this peerLocalEpID or default (0).
			//       This check is currently done within updatePeerKeepAliveFromNodeData.

			// Use peer's specific interval if found and non-zero, else use local endpoint default
			// (Currently, peer.KeepAliveInterval is updated in updatePeerKeepAliveFromNodeData)
			if peer.KeepAliveInterval > 0 {
				keepAliveInterval = peer.KeepAliveInterval
			} else if ep.keepAliveInterval > 0 {
				keepAliveInterval = ep.keepAliveInterval
			}

			if keepAliveInterval > 0 { // Only timeout if keep-alives are expected
				timeoutDuration := time.Duration(d.profile.KeepAliveMultiplier) * keepAliveInterval
				if now.Sub(peer.LastContact) > timeoutDuration {
					d.logger.Info("Peer timed out", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "lastContact", peer.LastContact, "timeout", timeoutDuration)
					if _, ok := peersToRemove[localEpID]; !ok {
						peersToRemove[localEpID] = make([]NodeIdentifier, 0, 1)
					}
					peersToRemove[localEpID] = append(peersToRemove[localEpID], peer.NodeID)
				}
			}
		}
	}

	// Remove timed-out peers (unlocks/relocks internally via RemovePeer)
	if len(peersToRemove) > 0 {
		d.mu.Unlock() // Need to unlock before calling RemovePeer which locks
		for localEpID, nodeIDs := range peersToRemove {
			for _, peerNodeID := range nodeIDs {
				// RemovePeer handles logging and republishing
				if err := d.RemovePeer(localEpID, peerNodeID); err != nil {
					// Log error but continue trying to remove others
					d.logger.Error("Failed to remove timed-out peer", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID), "err", err)
				}
			}
		}
		d.mu.Lock() // Re-lock after processing removals
	}
}

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
			// TODO: Apply dense optimization filtering here if ep.isDense
			// if ep.isDense && !bytes.Equal(peer.NodeID, ep.highestNodeOnLink) { continue }

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

	// Add KeepAlive TLVs if needed
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
func (d *DNCP) HandleReceivedTLVs(data []byte, sourceAddr string, receivedOnLocalEpID EndpointIdentifier) error {
	d.logger.Debug("Handling received data", "source", sourceAddr, "localEpID", receivedOnLocalEpID, "len", len(data))
	reader := bytes.NewReader(data)

	// Need sender's NodeID and EndpointID for processing Peer TLVs etc.
	var senderNodeID NodeIdentifier
	senderEndpointID := ReservedEndpointIdentifier // Default to reserved, type inferred

	// Attempt to decode NodeEndpoint TLV first if required by transport (Sec 4.2)
	// Assuming datagram transport where it MUST be first if present.
	var tlvsToProcess []*TLV
	firstTLV, err := Decode(reader)

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
		nodeEpTLV, decodeErr := DecodeNodeEndpointTLV(firstTLV, d.profile.NodeIdentifierLength)
		if decodeErr != nil {
			d.logger.Warn("Failed to decode NodeEndpoint TLV", "source", sourceAddr, "err", decodeErr)
			// Proceed without sender info? Or discard? For now, proceed.
		} else {
			senderNodeID = nodeEpTLV.NodeID
			senderEndpointID = nodeEpTLV.EndpointID
			d.logger.Debug("Decoded NodeEndpoint TLV", "source", sourceAddr, "senderNodeID", fmt.Sprintf("%x", senderNodeID), "senderEpID", senderEndpointID)
			// Process peer addition/update based on NodeEndpoint TLV (Sec 4.5)
			addPeerErr := d.AddOrUpdatePeer(receivedOnLocalEpID, senderNodeID, senderEndpointID, sourceAddr) // Use sourceAddr directly for now
			if addPeerErr != nil {
				d.logger.Error("Failed to add/update peer from NodeEndpoint TLV", "source", sourceAddr, "err", addPeerErr)
				// Continue processing other TLVs? Yes.
			}
		}
		// NodeEndpoint TLV is processed, don't add it to tlvsToProcess.
		// Continue to DecodeAll for remaining TLVs.
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

	return nil // Return nil even if DecodeAll had errors, as some TLVs might have been processed
}

// processSingleTLV handles the logic for a single received TLV according to RFC 7787 Section 4.4.
// receivedOnLocalEpID is currently unused but kept for potential future transport needs.
func (d *DNCP) processSingleTLV(tlv *TLV, senderNodeID NodeIdentifier, senderEndpointID EndpointIdentifier, sourceAddr string, _ EndpointIdentifier) {
	d.logger.Debug("Processing TLV", "type", tlv.Type, "len", tlv.Length, "senderNodeID", fmt.Sprintf("%x", senderNodeID), "senderEpID", senderEndpointID, "source", sourceAddr)

	// TODO: Implement rate limiting for replies (e.g., Request Network State)

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
		d.handleNetworkStateTLV(netStateTLV, sourceAddr)

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
func (d *DNCP) handleNetworkStateTLV(netStateTLV *NetworkStateTLV, sourceAddr string) {
	d.mu.RLock()
	localHash := d.networkStateHash
	d.mu.RUnlock()

	if !bytes.Equal(netStateTLV.NetworkStateHash, localHash) {
		d.logger.Info("Received different network state hash", "source", sourceAddr, "received", hex.EncodeToString(netStateTLV.NetworkStateHash), "local", hex.EncodeToString(localHash))
		// TODO: Implement rate limiting for requests
		// Reply with Request Network State TLV (Section 4.4)
		d.requestNetworkState(sourceAddr)
		// MAY also send local Network State TLV
		// d.sendNetworkState(sourceAddr)
	} else {
		d.logger.Debug("Received matching network state hash", "source", sourceAddr)
		// TODO: Update peer LastContact timestamp if keep-alives enabled (Sec 6.1.4)
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
