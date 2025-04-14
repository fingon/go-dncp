package dncp

import (
	"bytes"
	"fmt"
	"slices"
)

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

	// Add KeepAlive TLVs if specific endpoint intervals differ from profile default
	keepAliveTLVs := make([]*TLV, 0)
	profileDefaultKA := d.profile.KeepAliveInterval
	for epID, ep := range d.endpoints {
		// ep.KeepAliveInterval should be defaulted to profile value in AddEndpoint if initially 0
		if ep.KeepAliveInterval > 0 && ep.KeepAliveInterval != profileDefaultKA {
			kaTLV, err := NewKeepAliveIntervalTLV(epID, ep.KeepAliveInterval)
			if err != nil {
				d.logger.Error("Failed to create KeepAliveInterval TLV for publishing", "localEpID", epID, "interval", ep.KeepAliveInterval, "err", err)
				continue // Skip this one
			}
			keepAliveTLVs = append(keepAliveTLVs, kaTLV)
		}
	}
	if len(keepAliveTLVs) > 0 {
		localData[TLVTypeKeepAliveInterval] = keepAliveTLVs
	}

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
