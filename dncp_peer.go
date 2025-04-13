package dncp

import (
	"bytes"
	"fmt"
	"slices"
	"time"
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

	// Check if dense mode needs evaluation after adding/updating peer
	needsRepublish := d.addLocalPeerTLV(localEpID, peerNodeID, peerEpID)
	if d.profile.UseDenseOptimization && ep.TransportMode == TransportModeMulticastUnicast && d.profile.DensePeerThreshold > 0 && uint(len(ep.peers)) > d.profile.DensePeerThreshold {
		// Check density and potentially switch modes (locks/unlocks internally)
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

// checkPeerTimeouts iterates through peers and removes those that haven't been heard from.
// Assumes lock is held.
func (d *DNCP) checkPeerTimeouts() {
	now := d.clock.Now()
	peersToRemove := make(map[EndpointIdentifier][]NodeIdentifier) // localEpID -> list of peerNodeIDs

	for localEpID, ep := range d.endpoints {
		for peerKey, peer := range ep.peers { // Use peerKey for node lookup
			// Determine the effective keep-alive interval for this peer relationship
			keepAliveInterval := d.profile.KeepAliveInterval // Start with profile default

			// Look up the peer's NodeState to find their published KeepAliveInterval TLVs
			peerNodeState, nodeExists := d.nodes[peerKey]
			if nodeExists && peerNodeState.Data != nil {
				kaTLVs, tlvsExist := peerNodeState.Data[TLVTypeKeepAliveInterval]
				if !tlvsExist {
					continue
				}
				foundSpecific := false
				specificInterval := time.Duration(0)
				defaultInterval := time.Duration(0)

				for _, kaTLV := range kaTLVs {
					decodedKA, err := DecodeKeepAliveIntervalTLV(kaTLV)
					if err != nil {
						d.logger.Warn("Failed to decode KeepAliveInterval TLV during timeout check", "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "err", err)
						continue
					}

					interval := time.Duration(decodedKA.Interval) * time.Millisecond
					if decodedKA.EndpointID == peer.LocalEndpointID {
						// Found interval specific to the endpoint this peer is on
						specificInterval = interval
						foundSpecific = true
						break // Specific endpoint ID always wins
					} else if decodedKA.EndpointID == ReservedEndpointIdentifier {
						// Found a default interval for the peer
						defaultInterval = interval
					}
				}

				// Determine the effective interval (specific wins over default)
				if foundSpecific {
					keepAliveInterval = specificInterval
				} else if defaultInterval > 0 { // Use default only if non-zero and no specific found
					keepAliveInterval = defaultInterval
				}
				// If neither specific nor default > 0 found, keepAliveInterval remains the profile default
			}

			// Now perform the timeout check using the determined interval
			if keepAliveInterval > 0 { // Only timeout if keep-alives are expected (interval > 0)
				timeoutDuration := time.Duration(d.profile.KeepAliveMultiplier) * keepAliveInterval
				if now.Sub(peer.LastContact) > timeoutDuration {
					d.logger.Info("Peer timed out", "localEpID", localEpID, "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "lastContact", peer.LastContact, "timeout", timeoutDuration, "intervalUsed", keepAliveInterval)
					if _, ok := peersToRemove[localEpID]; !ok {
						peersToRemove[localEpID] = make([]NodeIdentifier, 0, 1)
					}
					// Use peer.NodeID here, not peerKey
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
