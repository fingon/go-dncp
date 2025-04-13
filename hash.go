package dncp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
)

// calculateNodeDataHash calculates and updates the hash for a single node's data.
// Assumes node.Data is populated. Updates node.DataHash.
// MUST be called with d.mu held or on a non-shared NodeState before adding it.
func (d *DNCP) calculateNodeDataHash(node *NodeState) error {
	hasher := d.profile.HashFunction()
	orderedTLVs := getOrderedTLVs(node.Data)

	var buf bytes.Buffer
	for _, tlv := range orderedTLVs {
		// Encode TLV to buffer (including padding)
		buf.Reset()
		err := tlv.Encode(&buf)
		if err != nil {
			// Should not happen if TLV data is valid
			d.logger.Error("Failed to encode TLV for hashing", "nodeID", fmt.Sprintf("%x", node.NodeID), "tlvType", tlv.Type, "err", err)
			return fmt.Errorf("encoding TLV type %d for node %x failed: %w", tlv.Type, node.NodeID, err)
		}
		// Write encoded TLV (including padding) to hasher
		if _, err := hasher.Write(buf.Bytes()); err != nil {
			// Should not happen with standard hashers
			d.logger.Error("Failed to write TLV to hasher", "nodeID", fmt.Sprintf("%x", node.NodeID), "tlvType", tlv.Type, "err", err)
			return fmt.Errorf("writing TLV type %d for node %x to hasher failed: %w", tlv.Type, node.NodeID, err)
		}
	}

	fullHash := hasher.Sum(nil)
	node.DataHash = fullHash[:min(len(fullHash), int(d.profile.HashLength))] // Truncate hash
	return nil
}

// calculateNetworkStateHash calculates the overall network state hash based on
// all *bidirectionally reachable* nodes. Updates d.networkStateHash.
// Returns true if the hash changed, false otherwise.
// Acquires and releases d.mu.RLock.
func (d *DNCP) calculateNetworkStateHash() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.calculateNetworkStateHashLocked()
}

// calculateNetworkStateHashLocked is the internal implementation, assumes lock is held.
func (d *DNCP) calculateNetworkStateHashLocked() bool {
	hasher := d.profile.HashFunction()
	seqBuf := make([]byte, 4) // Buffer for sequence number

	// 1. Get all reachable nodes
	reachableNodes := make([]*NodeState, 0, len(d.nodes))
	for _, node := range d.nodes {
		if node.isReachable { // Only include reachable nodes
			reachableNodes = append(reachableNodes, node)
		}
	}

	// 2. Sort nodes by Node ID
	slices.SortFunc(reachableNodes, func(a, b *NodeState) int {
		return bytes.Compare(a.NodeID, b.NodeID)
	})

	// 3. Concatenate sequence number and node data hash for each node
	for _, node := range reachableNodes {
		// Write Sequence Number (Network Byte Order)
		binary.BigEndian.PutUint32(seqBuf, node.SequenceNumber)
		if _, err := hasher.Write(seqBuf); err != nil {
			d.logger.Error("Failed to write sequence number to network hasher", "nodeID", fmt.Sprintf("%x", node.NodeID), "err", err)
			// Consider this a fatal error?
			return false // Indicate no change, but log error
		}

		// Write Node Data Hash
		if _, err := hasher.Write(node.DataHash); err != nil {
			d.logger.Error("Failed to write node data hash to network hasher", "nodeID", fmt.Sprintf("%x", node.NodeID), "err", err)
			// Consider this a fatal error?
			return false // Indicate no change, but log error
		}
	}

	// 4. Calculate final hash and truncate
	fullHash := hasher.Sum(nil)
	newHash := fullHash[:min(len(fullHash), int(d.profile.HashLength))]

	// 5. Compare with old hash
	if !bytes.Equal(d.networkStateHash, newHash) {
		d.networkStateHash = newHash
		d.logger.Debug("Network state hash updated", "newHash", hex.EncodeToString(newHash))
		return true // Hash changed
	}

	return false // Hash did not change
}
