package dncp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"
)

// processSingleTLV handles the logic for a single received TLV according to RFC 7787 Section 4.4.
func (d *DNCP) processSingleTLV(tlv *TLV, senderNodeID NodeIdentifier, senderEndpointID EndpointIdentifier, sourceAddr string, isMulticast bool) {
	d.logger.Debug("Processing TLV", "type", tlv.Type, "len", tlv.Length, "senderNodeID", fmt.Sprintf("%x", senderNodeID), "senderEpID", senderEndpointID, "source", sourceAddr, "isMulticast", isMulticast)

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

	switch tlv.Type {
	case TLVTypeRequestNetworkState:
		d.logger.Debug("Received RequestNetworkState", "source", sourceAddr)
		maybeDelay(func() { d.sendFullNetworkState(sourceAddr) })

	case TLVTypeRequestNodeState:
		reqNodeTLV, err := DecodeRequestNodeStateTLV(tlv, d.profile.NodeIdentifierLength)
		if err != nil {
			d.logger.Warn("Failed to decode RequestNodeState TLV", "source", sourceAddr, "err", err)
			return
		}
		d.logger.Debug("Received RequestNodeState", "source", sourceAddr, "reqNodeID", fmt.Sprintf("%x", reqNodeTLV.NodeID))
		maybeDelay(func() { d.sendNodeState(sourceAddr, reqNodeTLV.NodeID, true) }) // Include data

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

// handleNetworkStateTLV processes a received Network State TLV.
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

// handleLocalNodeCollision checks for and handles collisions with the local node ID.
// It calls the HandleCollisionFunc callback or performs the default republish action.
// Returns true if a collision was detected and handled (processing should stop), false otherwise.
// Assumes d.mu is held, but unlocks/relocks around callbacks/PublishData.
func (d *DNCP) handleLocalNodeCollision(nodeStateTLV *NodeStateTLV, sourceAddr string) bool {
	// Compare sequence numbers using wrapping comparison
	if CompareSequenceNumbers(nodeStateTLV.SequenceNumber, d.localState.SequenceNumber) > 0 ||
		(nodeStateTLV.SequenceNumber == d.localState.SequenceNumber && !bytes.Equal(nodeStateTLV.DataHash, d.localState.DataHash)) {
		d.logger.Error("Node ID collision detected!",
			"source", sourceAddr,
			"rcvd_seq", nodeStateTLV.SequenceNumber, "local_seq", d.localState.SequenceNumber,
			"rcvd_hash", hex.EncodeToString(nodeStateTLV.DataHash), "local_hash", hex.EncodeToString(d.localState.DataHash))

		// Call the collision handler if configured
		if d.HandleCollisionFunc != nil {
			d.logger.Info("Calling HandleCollisionFunc callback")
			d.mu.Unlock() // Unlock before calling callback
			err := d.HandleCollisionFunc()
			d.mu.Lock() // Re-lock (though instance might be stopped/replaced)
			if err != nil {
				d.logger.Error("HandleCollisionFunc failed", "err", err)
				// Log and continue might lead to inconsistent state. Stop instance? For now, just log.
			}
			// Assume callback handles restart/stop, so return true to stop processing.
			return true
		}

		// Default behavior: Republish local data with much higher sequence number (RFC 7787 Sec 4.4)
		d.logger.Warn("No HandleCollisionFunc configured, republishing local state with higher sequence")
		d.mu.Unlock()                                // Unlock before calling PublishData
		newSeq := nodeStateTLV.SequenceNumber + 1000 // Potential overflow handled by wrapping
		currentData := d.getLocalDataForPublishing() // Get current data before modifying sequence
		d.localState.SequenceNumber = newSeq - 1     // Set sequence so PublishData increments to newSeq
		err := d.PublishData(currentData)
		d.mu.Lock() // Re-lock
		if err != nil {
			d.logger.Error("Failed to republish local data after conflict", "err", err)
		}
		return true // Collision handled (by republishing), stop processing.
	}
	return false // No collision detected or handled.
}

// handleNodeStateTLV processes a received Node State TLV.
func (d *DNCP) handleNodeStateTLV(nodeStateTLV *NodeStateTLV, sourceAddr string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if it's our own Node ID (Sec 4.4)
	if bytes.Equal(nodeStateTLV.NodeID, d.nodeID) {
		if d.handleLocalNodeCollision(nodeStateTLV, sourceAddr) {
			return // Collision detected and handled, stop processing this TLV.
		}
		return // No collision, done processing local node state.
	}

	// Processing state for a remote node
	nodeKey := string(nodeStateTLV.NodeID)
	localNodeState, exists := d.nodes[nodeKey]
	now := d.clock.Now()
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
