package dncp

import (
	"bytes"
	"fmt"
	"slices"
)

// getLocalDataForPublishing constructs the NodeData map (map[TLVType][]TLVMarshaler)
// for the local node, including current Peer TLVs and KeepAlive TLVs.
// Assumes lock is held.
func (d *DNCP) getLocalDataForPublishing() NodeData {
	// Start with a deep copy of existing non-generated data?
	// Or assume localState.Data only holds non-generated TLVs?
	// Let's assume localState.Data holds application-specific TLVs,
	// and we add Peer/KeepAlive TLVs here.
	localData := make(NodeData) // Start fresh
	// Copy application-specific TLVs (if any were stored directly)
	for typ, marshalerSlice := range d.localState.Data {
		if typ != TLVTypePeer && typ != TLVTypeKeepAliveInterval {
			localData[typ] = slices.Clone(marshalerSlice) // Clone the slice
		}
	}

	// Add current Peer TLVs
	peerMarshalers := make([]TLVMarshaler, 0) // Collect all peer marshalers
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

			// Create PeerTLV struct instance
			peerMarshaler, err := NewPeerTLV(peer.NodeID, peer.EndpointID, localEpID)
			if err != nil {
				d.logger.Error("Failed to create Peer TLV for publishing", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "err", err)
				continue // Skip this peer
			}
			peerMarshalers = append(peerMarshalers, peerMarshaler)
		}
	}
	if len(peerMarshalers) > 0 {
		localData[TLVTypePeer] = peerMarshalers
	}

	// Add KeepAlive TLVs if specific endpoint intervals differ from profile default
	keepAliveMarshalers := make([]TLVMarshaler, 0)
	profileDefaultKA := d.profile.KeepAliveInterval
	for epID, ep := range d.endpoints {
		// ep.KeepAliveInterval should be defaulted to profile value in AddEndpoint if initially 0
		if ep.KeepAliveInterval > 0 && ep.KeepAliveInterval != profileDefaultKA {
			// Create KeepAliveIntervalTLV struct instance
			kaMarshaler, err := NewKeepAliveIntervalTLV(epID, ep.KeepAliveInterval)
			if err != nil {
				d.logger.Error("Failed to create KeepAliveInterval TLV for publishing", "localEpID", epID, "interval", ep.KeepAliveInterval, "err", err)
				continue // Skip this one
			}
			keepAliveMarshalers = append(keepAliveMarshalers, kaMarshaler)
		}
	}
	if len(keepAliveMarshalers) > 0 {
		localData[TLVTypeKeepAliveInterval] = keepAliveMarshalers
	}

	return localData
}

// addLocalPeerTLV adds a Peer TLV marshaler to the local node's state.
// Returns true if the state was changed (marshaler was added), false otherwise.
// Assumes lock is held.
func (d *DNCP) addLocalPeerTLV(localEpID EndpointIdentifier, peerNodeID NodeIdentifier, peerEpID EndpointIdentifier) bool {
	// Create the marshaler
	newPeerMarshaler, err := NewPeerTLV(peerNodeID, peerEpID, localEpID)
	if err != nil {
		d.logger.Error("Failed to create Peer TLV marshaler for local state", "err", err)
		return false
	}

	// Check if an identical marshaler already exists
	existingMarshalers := d.localState.Data[TLVTypePeer]
	for _, existingMarshaler := range existingMarshalers {
		// Type assert and compare fields
		if existingPeer, ok := existingMarshaler.(*PeerTLV); ok {
			if existingPeer.LocalEndpointID == newPeerMarshaler.LocalEndpointID &&
				existingPeer.PeerEndpointID == newPeerMarshaler.PeerEndpointID &&
				bytes.Equal(existingPeer.PeerNodeID, newPeerMarshaler.PeerNodeID) {
				d.logger.Debug("Identical Peer TLV already exists, not adding", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
				return false // No change
			}
		}
	}

	// Append the new marshaler
	d.localState.Data[TLVTypePeer] = append(existingMarshalers, newPeerMarshaler)
	d.logger.Debug("Added Peer TLV to local state", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
	return true // State changed
}

// removeLocalPeerTLV removes a specific Peer TLV marshaler from the local node's state.
// Returns true if a marshaler was removed, false otherwise.
// Assumes lock is held.
func (d *DNCP) removeLocalPeerTLV(localEpID EndpointIdentifier, peerNodeID NodeIdentifier, peerEpID EndpointIdentifier) bool {
	existingMarshalers, exists := d.localState.Data[TLVTypePeer]
	if !exists || len(existingMarshalers) == 0 {
		return false // Nothing to remove
	}

	foundIndex := -1
	for i, marshaler := range existingMarshalers {
		if peerTLV, ok := marshaler.(*PeerTLV); ok {
			if peerTLV.LocalEndpointID == localEpID &&
				bytes.Equal(peerTLV.PeerNodeID, peerNodeID) &&
				peerTLV.PeerEndpointID == peerEpID {
				foundIndex = i
				break
			}
		}
	}

	if foundIndex != -1 {
		// Remove the element at foundIndex
		d.localState.Data[TLVTypePeer] = append(existingMarshalers[:foundIndex], existingMarshalers[foundIndex+1:]...)
		// If the slice becomes empty, remove the map entry
		if len(d.localState.Data[TLVTypePeer]) == 0 {
			delete(d.localState.Data, TLVTypePeer)
		}
		d.logger.Debug("Removed Peer TLV from local state", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
		return true // State changed
	}

	return false // Matching marshaler not found
}

// removeLocalPeerTLVsForEndpoint removes all Peer TLV marshalers associated with a specific local endpoint.
// Returns true if any marshalers were removed, false otherwise.
// Assumes lock is held.
func (d *DNCP) removeLocalPeerTLVsForEndpoint(localEpID EndpointIdentifier) bool {
	existingMarshalers, exists := d.localState.Data[TLVTypePeer]
	if !exists || len(existingMarshalers) == 0 {
		return false // Nothing to remove
	}

	originalLength := len(existingMarshalers)
	newMarshalers := make([]TLVMarshaler, 0, originalLength)

	for _, marshaler := range existingMarshalers {
		if peerTLV, ok := marshaler.(*PeerTLV); ok {
			// Keep TLV only if it's NOT for the endpoint being removed
			if peerTLV.LocalEndpointID != localEpID {
				newMarshalers = append(newMarshalers, marshaler)
			}
		} else {
			// Keep non-PeerTLV marshalers if they somehow ended up here?
			newMarshalers = append(newMarshalers, marshaler)
		}
	}

	if len(newMarshalers) < originalLength {
		if len(newMarshalers) == 0 {
			delete(d.localState.Data, TLVTypePeer)
		} else {
			d.localState.Data[TLVTypePeer] = newMarshalers
		}
		d.logger.Debug("Removed Peer TLVs for local endpoint", "localEpID", localEpID, "removedCount", originalLength-len(newMarshalers))
		return true // State changed
	}

	return false // No TLVs removed for this endpoint
}
