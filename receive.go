package dncp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"
)

// processSingleTLV handles the logic for a single received TLVMarshaler according to RFC 7787 Section 4.4.
// It returns an error only if a critical issue occurs (like a collision requiring restart).
func (d *DNCP) processSingleTLV(tlv TLVMarshaler, senderNodeID NodeIdentifier, senderEndpointID EndpointIdentifier, sourceAddr string, isMulticast bool) error {
	tlvType := tlv.GetType() // Get type from the interface
	d.logger.Debug("Processing TLV", "type", tlvType, "senderNodeID", fmt.Sprintf("%x", senderNodeID), "senderEpID", senderEndpointID, "source", sourceAddr, "isMulticast", isMulticast)

	// --- Multicast Reply Delay (RFC 7787 Section 4.4) ---
	// If received via multicast, delay replies by random time in [0, Imin/2]
	// This is done by launching a goroutine for the actual sending function.
	maybeDelay := func(sendAction func()) {
		if isMulticast {
			delay := time.Duration(d.profile.RandSource.Uint64() % uint64(d.profile.TrickleImin/2))
			d.logger.Debug("Delaying multicast reply", "delay", delay, "source", sourceAddr)
			go func() {
				d.clock.Sleep(delay)
				sendAction()
			}()
		} else {
			sendAction() // Send immediately if unicast
		}
	}

	switch specificTLV := tlv.(type) {
	case *RequestNetworkStateTLV:
		d.logger.Debug("Received RequestNetworkState", "source", sourceAddr)
		maybeDelay(func() { d.sendFullNetworkState(sourceAddr) })

	case *RequestNodeStateTLV:
		d.logger.Debug("Received RequestNodeState", "source", sourceAddr, "reqNodeID", fmt.Sprintf("%x", specificTLV.NodeID))
		maybeDelay(func() { d.sendNodeState(sourceAddr, specificTLV.NodeID, true) }) // Include data

	case *NetworkStateTLV:
		d.logger.Debug("Received NetworkState", "source", sourceAddr, "hash", hex.EncodeToString(specificTLV.NetworkStateHash))
		// Pass senderNodeID for peer lookup
		d.handleNetworkStateTLV(specificTLV, senderNodeID, sourceAddr)

	case *NodeStateTLV:
		d.logger.Debug("Received NodeState", "source", sourceAddr, "nodeID", fmt.Sprintf("%x", specificTLV.NodeID), "seq", specificTLV.SequenceNumber, "hasData", len(specificTLV.GetSubTLVs()) > 0)
		// handleNodeStateTLV might return a collision error
		if err := d.handleNodeStateTLV(specificTLV, sourceAddr); err != nil {
			return err // Propagate collision error
		}

	case *NodeEndpointTLV:
		// Already handled before DecodeAll, but log if seen again (shouldn't happen with current logic)
		d.logger.Debug("Received NodeEndpoint TLV (again?)", "source", sourceAddr)

	case *PeerTLV, *KeepAliveIntervalTLV: // Add other nested-only types like TrustVerdict here
		// These should only appear nested within NodeState TLV's NodeData field.
		// If received standalone, ignore them (RFC 7787 Section 7.3).
		d.logger.Warn("Received unexpected standalone TLV", "type", tlvType, "source", sourceAddr)

	default:
		// Ignore unknown TLV types (RFC 7787 Section 4.4)
		// This case also handles TLV types registered by other modules (like shsp2 URLTLV)
		// that are not directly processed by the core DNCP logic here.
		d.logger.Debug("Ignoring/skipping TLV type", "type", tlvType, "source", sourceAddr)
	}
	return nil // No error occurred during processing this TLV
}

// isNetworkStateRequestAllowed checks if sending a RequestNetworkState to the source
// for the given hash is allowed based on rate limiting rules (RFC 7787 Section 4.4).
// It updates the rate-limiting state if the request is allowed.
// Acquires and releases d.mu.Lock.
func (d *DNCP) isNetworkStateRequestAllowed(sourceAddr string, receivedHash []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.clock.Now()
	hashHex := hex.EncodeToString(receivedHash)
	sourceRequests, sourceExists := d.lastNetStateRequest[sourceAddr]
	if !sourceExists {
		sourceRequests = make(map[string]time.Time)
		d.lastNetStateRequest[sourceAddr] = sourceRequests
	}

	lastRequestTime, hashRequested := sourceRequests[hashHex]
	requestAllowed := true
	if hashRequested && now.Sub(lastRequestTime) < d.profile.TrickleImin {
		requestAllowed = false
		d.logger.Debug("Rate limiting RequestNetworkState", "source", sourceAddr, "hash", hashHex, "timeSinceLast", now.Sub(lastRequestTime))
	}

	// Clean up old entries for this source to prevent map growth
	for h, t := range sourceRequests {
		if now.Sub(t) >= d.profile.TrickleImin {
			delete(sourceRequests, h)
		}
	}
	if len(sourceRequests) == 0 && sourceExists { // Delete map only if it existed before
		delete(d.lastNetStateRequest, sourceAddr)
	}

	if requestAllowed {
		sourceRequests[hashHex] = now // Record the time we are sending the request
	}

	return requestAllowed
}

// handleNetworkStateTLV processes a received Network State TLV struct.
// senderNodeID is needed to update the correct peer's LastContact timestamp.
func (d *DNCP) handleNetworkStateTLV(netStateTLV *NetworkStateTLV, senderNodeID NodeIdentifier, sourceAddr string) {
	d.mu.RLock()
	localHash := d.networkStateHash
	d.mu.RUnlock()

	if bytes.Equal(netStateTLV.NetworkStateHash, localHash) {
		// Hashes match
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
		return // Hashes matched, done.
	}

	// Hashes differ
	d.logger.Info("Received different network state hash", "source", sourceAddr, "received", hex.EncodeToString(netStateTLV.NetworkStateHash), "local", hex.EncodeToString(localHash))
	if d.isNetworkStateRequestAllowed(sourceAddr, netStateTLV.NetworkStateHash) {
		d.requestNetworkState(sourceAddr)
		// MAY also send local Network State TLV
		// d.sendNetworkState(sourceAddr)
	}
}

// handleLocalNodeCollision checks for and handles collisions with the local node ID based on a received NodeStateTLV struct.
// It calls the HandleCollisionFunc callback or performs the default republish action.
// Returns a specific error if the callback indicates a restart is needed, nil otherwise.
// Assumes d.mu is held, but unlocks/relocks around callbacks/PublishData.
func (d *DNCP) handleLocalNodeCollision(receivedNodeState *NodeStateTLV, sourceAddr string) error {
	// Compare sequence numbers using wrapping comparison
	if CompareSequenceNumbers(receivedNodeState.SequenceNumber, d.localState.SequenceNumber) > 0 ||
		(receivedNodeState.SequenceNumber == d.localState.SequenceNumber && !bytes.Equal(receivedNodeState.DataHash, d.localState.DataHash)) {
		d.logger.Error("Node ID collision detected!",
			"source", sourceAddr,
			"rcvd_seq", receivedNodeState.SequenceNumber, "local_seq", d.localState.SequenceNumber,
			"rcvd_hash", hex.EncodeToString(receivedNodeState.DataHash), "local_hash", hex.EncodeToString(d.localState.DataHash))

		// Call the collision handler if configured
		if d.profile.HandleCollisionFunc != nil { // Check profile for the func
			d.logger.Info("Calling HandleCollisionFunc callback")
			d.mu.Unlock() // Unlock before calling callback
			err := d.profile.HandleCollisionFunc()
			d.mu.Lock() // Re-lock (though instance might be stopped/replaced)
			if err != nil {
				// The callback returned an error. This might be the specific
				// collision error signaling a restart, or some other error.
				d.logger.Error("HandleCollisionFunc returned an error", "err", err)
				// Propagate the error up. The caller (handleNodeStateTLV) will handle it.
				return err
			}
			// Callback succeeded without error, assume it handled the collision internally (if possible).
			// Stop processing this TLV.
			return nil // No error to propagate, but collision was handled by callback.
		}

		// --- Default Behavior (No Handler or Handler Returned nil) ---
		// Republish local data with much higher sequence number (RFC 7787 Sec 4.4)
		d.logger.Warn("Node ID collision detected, but no specific handler action taken; republishing local state with higher sequence")
		d.mu.Unlock()                                     // Unlock before calling PublishData
		newSeq := receivedNodeState.SequenceNumber + 1000 // Potential overflow handled by wrapping
		currentData := d.getLocalDataForPublishing()      // Get current data before modifying sequence
		d.localState.SequenceNumber = newSeq - 1          // Set sequence so PublishData increments to newSeq
		err := d.PublishData(currentData)
		d.mu.Lock() // Re-lock
		if err != nil {
			d.logger.Error("Failed to republish local data after conflict", "err", err)
			// Return the error from PublishData? Or just log? Log for now.
			// Return nil because the *collision* was handled (by attempting republish).
			return nil
		}
		return nil // Collision handled (by republishing).
	}
	return nil // No collision detected.
}

// handleNodeStateTLV processes a received Node State TLV struct.
// Returns an error only if a collision requires application intervention.
func (d *DNCP) handleNodeStateTLV(receivedNodeState *NodeStateTLV, sourceAddr string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if it's our own Node ID (Sec 4.4)
	if bytes.Equal(receivedNodeState.NodeID, d.nodeID) {
		// handleLocalNodeCollision might return an error (e.g., CollisionRestartError)
		if err := d.handleLocalNodeCollision(receivedNodeState, sourceAddr); err != nil {
			return err // Propagate the error (e.g., restart required)
		}
		return nil // Collision handled internally or no collision, done.
	}

	// Processing state for a remote node
	nodeKey := string(receivedNodeState.NodeID)
	localNodeState, exists := d.nodes[nodeKey]
	now := d.clock.Now()
	action := decideNodeStateAction(localNodeState, receivedNodeState, exists, d.logger)

	switch action {
	case actionIgnore:
		d.logger.Debug("Ignoring older/same NodeState", "nodeID", fmt.Sprintf("%x", receivedNodeState.NodeID), "rcvd_seq", receivedNodeState.SequenceNumber, "local_seq", localNodeState.SequenceNumber)
	case actionUpdateStoreHeader:
		d.logger.Debug("Storing NodeState header", "nodeID", fmt.Sprintf("%x", receivedNodeState.NodeID), "seq", receivedNodeState.SequenceNumber)
		d.storeNodeStateHeader(receivedNodeState, now)
	case actionUpdateStoreHeaderRequestData:
		d.logger.Debug("Storing NodeState header and requesting data", "nodeID", fmt.Sprintf("%x", receivedNodeState.NodeID), "seq", receivedNodeState.SequenceNumber)
		d.storeNodeStateHeader(receivedNodeState, now)
		d.requestNodeState(sourceAddr, receivedNodeState.NodeID)
	case actionUpdateStoreData:
		d.logger.Debug("Attempting to store NodeState with data", "nodeID", fmt.Sprintf("%x", receivedNodeState.NodeID), "seq", receivedNodeState.SequenceNumber)
		if d.storeNodeStateWithData(receivedNodeState, now) {
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
	return nil // No error occurred that needs application intervention
}
