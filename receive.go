package dncp

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

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
