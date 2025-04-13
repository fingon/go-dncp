package dncp

import (
	"bytes"
	"fmt"
	"time"
)

// Topology & Reachability (RFC 7787 Section 4.6)

// updateTopologyGraph recalculates node reachability based on published Peer TLVs.
// Returns true if any node's reachability status changed, false otherwise.
// Acquires and releases d.mu.Lock.
func (d *DNCP) updateTopologyGraph() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	changed := false
	now := d.clock.Now()
	maxAge := time.Duration(1<<32-1<<15) * time.Millisecond // Max age from RFC 7787 4.6

	// Mark all nodes initially as unreachable, except the local node
	for _, node := range d.nodes {
		if !bytes.Equal(node.NodeID, d.nodeID) {
			if node.isReachable { // Track changes
				changed = true
			}
			node.isReachable = false
		} else {
			node.isReachable = true // Local node always reachable
		}
		// Clear previous peer state derived from TLVs
		node.publishedPeers = make(map[EndpointIdentifier]map[string]EndpointIdentifier) // Use string key
	}

	// Populate publishedPeers map from current NodeData for all nodes
	for _, node := range d.nodes {
		if node.Data == nil {
			continue
		}
		// Iterate through all Peer TLVs published by the node
		peerTLVs, ok := node.Data[TLVTypePeer]
		if !ok {
			continue
		}
		for _, tlv := range peerTLVs {
			// No need to check type again, we fetched the slice for TLVTypePeer
			peerTLV, err := DecodePeerTLV(tlv, d.profile.NodeIdentifierLength)
			if err != nil {
				d.logger.Warn("Failed to decode Peer TLV during topology update", "nodeID", fmt.Sprintf("%x", node.NodeID), "err", err)
				continue
			}
			if _, ok := node.publishedPeers[peerTLV.LocalEndpointID]; !ok {
				node.publishedPeers[peerTLV.LocalEndpointID] = make(map[string]EndpointIdentifier)
			}
			// Use string conversion for the map key
			node.publishedPeers[peerTLV.LocalEndpointID][string(peerTLV.PeerNodeID)] = peerTLV.PeerEndpointID
		}
	}
	// Iteratively mark nodes as reachable
	madeProgress := true
	for madeProgress {
		madeProgress = false
		for _, candidateNode := range d.nodes {
			// Skip if already marked reachable or if it's the local node (already handled)
			if candidateNode.isReachable || bytes.Equal(candidateNode.NodeID, d.nodeID) {
				continue
			}

			// Check if any reachable node R has a bidirectional link to candidateNode N
			for _, reachableNode := range d.nodes {
				if !reachableNode.isReachable {
					continue // R must be reachable
				}

				// Check age of R's data (RFC 7787 Section 4.6)
				if now.Sub(reachableNode.OriginationTime) > maxAge {
					continue // R's data is too old
				}

				// Check if R publishes a Peer TLV for N
				foundRtoN := false
				var rEndpointID, nEndpointID EndpointIdentifier
				for rEpID, peersOnREp := range reachableNode.publishedPeers {
					// Use string conversion for the map key lookup
					if nEpID, ok := peersOnREp[string(candidateNode.NodeID)]; ok {
						foundRtoN = true
						rEndpointID = rEpID
						nEndpointID = nEpID
						break
					}
				}
				if !foundRtoN {
					continue // R does not publish N as a peer
				}

				// Check if N publishes a Peer TLV back to R using the same endpoints
				foundNtoR := false
				if peersOnNEp, ok := candidateNode.publishedPeers[nEndpointID]; ok {
					// Use string conversion for the map key lookup
					if rEpIDCheck, ok := peersOnNEp[string(reachableNode.NodeID)]; ok {
						if rEpIDCheck == rEndpointID {
							foundNtoR = true
						}
					}
				}

				if foundNtoR {
					// Bidirectional link found! Mark N as reachable.
					if !candidateNode.isReachable { // Track changes
						d.logger.Debug("Marking node reachable via topology", "nodeID", fmt.Sprintf("%x", candidateNode.NodeID), "viaNodeID", fmt.Sprintf("%x", reachableNode.NodeID))
						candidateNode.isReachable = true
						changed = true
						madeProgress = true
						break // Move to the next candidate node
					}
				}
			} // End loop through reachable nodes (R)
		} // End loop through candidate nodes (N)
	} // End iterative loop

	// Optional: Clean up unreachable nodes after a grace period?
	// for key, node := range d.nodes {
	// 	if !node.isReachable {
	// 		// delete(d.nodes, key)
	//      // changed = true // If cleanup counts as change
	// 	}
	// }

	return changed
} // Restore closing brace for updateTopologyGraph
