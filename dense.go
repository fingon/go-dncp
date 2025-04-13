package dncp

import (
	"bytes"
	"fmt"
	"slices"
)

// Dense Multicast Optimization (RFC 7787 Section 6.2)

// checkAndHandleDenseLink evaluates the state of an endpoint and switches modes if necessary.
// Returns true if the mode was changed (indicating a republish might be needed), false otherwise.
// Assumes lock is held.
func (d *DNCP) checkAndHandleDenseLink(ep *Endpoint) bool {
	if !d.profile.UseDenseOptimization || ep.TransportMode == TransportModeUnicast {
		return false // Optimization not enabled or not applicable
	}

	highestPeer := d.findHighestPeerOnLink(ep) // Find current highest among connected peers
	isDense := d.profile.DensePeerThreshold > 0 && uint(len(ep.peers)) > d.profile.DensePeerThreshold
	isHighest := highestPeer == nil || bytes.Equal(d.nodeID, highestPeer.NodeID)

	modeChanged := false

	if isDense && !isHighest {
		// Condition to switch TO listen mode: Dense link, and we are NOT highest.
		if ep.TransportMode != TransportModeMulticastListenUnicast {
			d.logger.Info("Switching endpoint to MulticastListen+Unicast mode (dense link, not highest)", "localEpID", ep.ID, "highestNodeID", fmt.Sprintf("%x", highestPeer.NodeID))
			d.switchToListenMode(ep, highestPeer)
			modeChanged = true
		} else if !bytes.Equal(ep.highestNodeOnLink, highestPeer.NodeID) {
			// Already in listen mode, but highest node changed. Update connection.
			d.logger.Info("Updating highest node peer in MulticastListen+Unicast mode", "localEpID", ep.ID, "newHighestNodeID", fmt.Sprintf("%x", highestPeer.NodeID))
			// Stop old trickle, remove old peer (if different), add new peer, start new trickle.
			// This is complex, let's simplify: just update highestNodeOnLink and rely on normal peer add/remove?
			// For now, just update the stored highest ID. The filtering in getLocalDataForPublishing will use it.
			// A more robust implementation might explicitly manage the single peer connection here.
			ep.highestNodeOnLink = slices.Clone(highestPeer.NodeID)
			// We might need to trigger AddPeerFunc for the new highest node if we don't have a connection.
		}
	} else {
		// Condition to switch or stay in multicast mode: Link is not dense OR we are the highest node.
		if ep.TransportMode != TransportModeMulticastUnicast {
			d.logger.Info("Switching endpoint to Multicast+Unicast mode (not dense or is highest)", "localEpID", ep.ID)
			d.switchToMulticastMode(ep)
			modeChanged = true
		}
	}

	return modeChanged
}

// findHighestPeerOnLink finds the peer with the highest Node ID currently in the endpoint's peer list.
// Returns nil if no peers exist.
// Assumes lock is held.
func (d *DNCP) findHighestPeerOnLink(ep *Endpoint) *Peer {
	var highestPeer *Peer
	for _, peer := range ep.peers {
		if highestPeer == nil || bytes.Compare(peer.NodeID, highestPeer.NodeID) > 0 {
			highestPeer = peer
		}
	}
	return highestPeer
}

// switchToListenMode transitions the endpoint to MulticastListen+Unicast mode.
// Assumes lock is held.
func (d *DNCP) switchToListenMode(ep *Endpoint, highestPeer *Peer) {
	ep.TransportMode = TransportModeMulticastListenUnicast
	ep.highestNodeOnLink = slices.Clone(highestPeer.NodeID) // Store copy

	// Stop endpoint Trickle
	if ep.trickleInstance != nil {
		ep.trickleInstance.Stop()
		ep.trickleInstance = nil
		d.logger.Debug("Stopped endpoint Trickle for Listen mode", "localEpID", ep.ID)
	}

	// Remove all peers except the highest one and stop their Trickle instances
	peersToRemove := make([]NodeIdentifier, 0)
	for _, peer := range ep.peers {
		if !bytes.Equal(peer.NodeID, highestPeer.NodeID) {
			if peer.trickleInstance != nil {
				peer.trickleInstance.Stop()
				d.logger.Debug("Stopped peer Trickle instance for Listen mode", "localEpID", ep.ID, "peerNodeID", fmt.Sprintf("%x", peer.NodeID))
			}
			peersToRemove = append(peersToRemove, peer.NodeID) // Collect IDs to remove
		}
	}

	// Remove non-highest peers from the map
	for _, nodeIDToRemove := range peersToRemove {
		delete(ep.peers, string(nodeIDToRemove))
		d.logger.Debug("Removed non-highest peer for Listen mode", "localEpID", ep.ID, "peerNodeID", fmt.Sprintf("%x", nodeIDToRemove))
		// Also remove the corresponding Peer TLV from local data (will be handled by republish)
	}

	// Ensure per-peer Trickle is running for the highest peer if needed
	if highestPeer != nil && highestPeer.trickleInstance == nil && requiresPeerTrickle(ep.TransportMode) { // Check new mode
		transmitFunc := d.createPeerTransmitFunc(highestPeer)
		consistencyFunc := d.createConsistencyFunc()
		trickleInst, err := d.profile.NewTrickleInstanceFunc(transmitFunc, consistencyFunc)
		if err != nil {
			d.logger.Error("Failed to create Trickle instance for highest peer", "localEpID", ep.ID, "peerNodeID", fmt.Sprintf("%x", highestPeer.NodeID), "err", err)
		} else {
			highestPeer.trickleInstance = trickleInst
			highestPeer.trickleInstance.Start()
			d.logger.Info("Started Trickle instance for highest peer in Listen mode", "localEpID", ep.ID, "peerNodeID", fmt.Sprintf("%x", highestPeer.NodeID))
		}
	}
}

// switchToMulticastMode transitions the endpoint back to Multicast+Unicast mode.
// Assumes lock is held.
func (d *DNCP) switchToMulticastMode(ep *Endpoint) {
	ep.TransportMode = TransportModeMulticastUnicast
	ep.highestNodeOnLink = nil // Clear highest node tracking

	// Stop per-peer Trickle instances (should only be one for the previous highest)
	for _, peer := range ep.peers {
		if peer.trickleInstance != nil {
			peer.trickleInstance.Stop()
			peer.trickleInstance = nil
			d.logger.Debug("Stopped peer Trickle for Multicast mode", "localEpID", ep.ID, "peerNodeID", fmt.Sprintf("%x", peer.NodeID))
		}
	}

	// Start endpoint Trickle if needed
	if ep.trickleInstance == nil && requiresEndpointTrickle(ep.TransportMode) { // Check new mode
		transmitFunc := d.createEndpointTransmitFunc(ep)
		consistencyFunc := d.createConsistencyFunc()
		trickleInst, err := d.profile.NewTrickleInstanceFunc(transmitFunc, consistencyFunc)
		if err != nil {
			d.logger.Error("Failed to create Trickle instance for endpoint", "id", ep.ID, "err", err)
		} else {
			ep.trickleInstance = trickleInst
			ep.trickleInstance.Start()
			d.logger.Info("Started endpoint Trickle instance for Multicast mode", "id", ep.ID)
		}
	}

	// Peers will be re-added automatically as NodeEndpoint TLVs are received via multicast.
	// We might need to trigger AddPeerFunc for nodes we already know about?
	// For now, rely on receiving messages again.
}
