package dncp

import (
	"fmt"
	"time"
)

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
