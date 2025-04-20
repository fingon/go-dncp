package dncp

import (
	"bytes"
	"fmt"
	"slices"
)

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

		// Initialize per-peer Trickle if needed and not already existing
		if d.profile.NewTrickleInstanceFunc != nil && requiresPeerTrickle(ep.TransportMode) {
			transmitFunc := d.createPeerTransmitFunc(peer) // Pass peer context
			consistencyFunc := d.createConsistencyFunc()
			trickleInst, err := d.profile.NewTrickleInstanceFunc(transmitFunc, consistencyFunc)
			if err != nil {
				d.logger.Error("Failed to create Trickle instance for peer", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID), "err", err)
				// Continue without Trickle for this peer? Yes.
			} else {
				peer.trickleInstance = trickleInst
				peer.trickleInstance.Start()
				d.logger.Info("Started Trickle instance for peer", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
			}
		}
	} else {
		// Update existing peer info
		peer.EndpointID = peerEpID // Peer might change its endpoint ID?
		peer.Address = peerAddr
		peer.LastContact = now
		d.logger.Debug("Updated existing peer contact", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
	}

	// Update local Peer TLV for this new/updated peer relationship
	needsRepublish := d.addLocalPeerTLV(localEpID, peerNodeID, peerEpID)

	// Check if dense mode needs evaluation after adding/updating peer
	// This check should happen *after* the peer is added to ep.peers
	if d.profile.UseDenseOptimization && ep.TransportMode == TransportModeMulticastUnicast {
		// Check density and potentially switch modes (locks/unlocks internally)
		// checkAndHandleDenseLink will compare len(ep.peers) against threshold
		if d.checkAndHandleDenseLink(ep) {
			needsRepublish = true // Mode switch requires republish
		}
	}

	// Update local Peer TLV for this new/updated peer relationship and republish if needed
	if needsRepublish {
		d.mu.Unlock() // Unlock before calling PublishData
		// Need to reconstruct the current local data
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

	// Stop per-peer Trickle instance if applicable
	if peer.trickleInstance != nil {
		peer.trickleInstance.Stop()
		d.logger.Info("Stopped Trickle instance for peer", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))
	}

	delete(ep.peers, peerKey)
	d.logger.Info("Removed peer", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peerNodeID))

	// Check if dense mode needs evaluation after removing peer
	needsRepublish := d.removeLocalPeerTLV(localEpID, peerNodeID, peer.EndpointID)
	if d.profile.UseDenseOptimization {
		// If we were in listen mode and the highest node was removed, re-evaluate.
		// If we were in multicast mode and dropped below threshold, re-evaluate.
		if ep.TransportMode == TransportModeMulticastListenUnicast && bytes.Equal(peerNodeID, ep.highestNodeOnLink) {
			if d.checkAndHandleDenseLink(ep) {
				needsRepublish = true
			}
		} else if ep.TransportMode == TransportModeMulticastUnicast && d.profile.DensePeerThreshold > 0 && uint(len(ep.peers)) <= d.profile.DensePeerThreshold {
			// Dropped below threshold, check if we should switch back (though this is implicitly handled by checkAndHandleDenseLink finding self as highest)
			if d.checkAndHandleDenseLink(ep) {
				needsRepublish = true
			}
		}
	}

	// Remove the corresponding Peer TLV from local data and republish if needed
	if needsRepublish {
		d.mu.Unlock() // Unlock before calling PublishData
		// Need to reconstruct the current local data
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
