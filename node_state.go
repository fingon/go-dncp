package dncp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

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
