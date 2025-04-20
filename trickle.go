package dncp

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/fingon/go-dncp/trickle"
)

// Trickle Integration Helpers
// requiresEndpointTrickle checks if the transport mode needs an endpoint-wide Trickle instance.
func requiresEndpointTrickle(mode TransportMode) bool {
	// Only Multicast+Unicast mode uses endpoint Trickle for multicast status updates
	return mode == TransportModeMulticastUnicast
}

// requiresPeerTrickle checks if the transport mode needs per-peer Trickle instances.
func requiresPeerTrickle(mode TransportMode) bool {
	// Only Unicast mode with unreliable transport needs per-peer Trickle
	// Assuming "Unicast" implies unreliable for this example. Profile needs to be clearer.
	return mode == TransportModeUnicast
}

// createEndpointTransmitFunc creates the TransmitFunc for an endpoint's Trickle instance.
func (d *DNCP) createEndpointTransmitFunc(ep *Endpoint) trickle.TransmitFunc {
	return func() {
		d.mu.RLock()
		// Include NodeEndpoint TLV before NetworkState TLV (Sec 4.2)
		nodeEpMarshaler, err := NewNodeEndpointTLV(d.nodeID, ep.ID) // No length needed
		if err != nil {
			d.logger.Error("Failed to create NodeEndpoint TLV for Trickle transmit", "epID", ep.ID, "err", err)
			d.mu.RUnlock()
			return
		}
		netStateMarshaler, err := NewNetworkStateTLV(d.networkStateHash) // No length needed
		if err != nil {
			d.logger.Error("Failed to create NetworkState TLV for Trickle transmit", "epID", ep.ID, "err", err)
			d.mu.RUnlock()
			return
		}
		d.mu.RUnlock() // Unlock before sending

		// Destination for endpoint Trickle is usually multicast address
		dest := ep.MulticastAddress // Assuming this field holds the correct destination string
		if dest == "" {
			d.logger.Warn("Cannot transmit endpoint Trickle, no multicast address configured", "epID", ep.ID)
			return
		}

		// Send the marshalers
		err = d.sendTLVs(dest, []TLVMarshaler{nodeEpMarshaler, netStateMarshaler})
		if err != nil {
			d.logger.Error("Failed Trickle transmission for endpoint", "epID", ep.ID, "dest", dest, "err", err)
		} else {
			d.logger.Debug("Sent Trickle update for endpoint", "epID", ep.ID, "dest", dest)
		}
	}
}

// createPeerTransmitFunc creates the TransmitFunc for a peer's Trickle instance.
func (d *DNCP) createPeerTransmitFunc(peer *Peer) trickle.TransmitFunc {
	return func() {
		d.mu.RLock()
		// Include NodeEndpoint TLV before NetworkState TLV (Sec 4.2)
		nodeEpMarshaler, err := NewNodeEndpointTLV(d.nodeID, peer.LocalEndpointID) // No length needed
		if err != nil {
			d.logger.Error("Failed to create NodeEndpoint TLV for peer Trickle transmit", "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "err", err)
			d.mu.RUnlock()
			return
		}
		netStateMarshaler, err := NewNetworkStateTLV(d.networkStateHash) // No length needed
		if err != nil {
			d.logger.Error("Failed to create NetworkState TLV for peer Trickle transmit", "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "err", err)
			d.mu.RUnlock()
			return
		}
		d.mu.RUnlock() // Unlock before sending

		dest := peer.Address // Destination for peer Trickle is the peer's unicast address
		if dest == "" {
			d.logger.Warn("Cannot transmit peer Trickle, no peer address known", "peerNodeID", fmt.Sprintf("%x", peer.NodeID))
			return
		}

		// Send the marshalers
		err = d.sendTLVs(dest, []TLVMarshaler{nodeEpMarshaler, netStateMarshaler})
		if err != nil {
			d.logger.Error("Failed Trickle transmission for peer", "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "dest", dest, "err", err)
		} else {
			d.logger.Debug("Sent Trickle update for peer", "peerNodeID", fmt.Sprintf("%x", peer.NodeID), "dest", dest)
		}
	}
}

// createConsistencyFunc creates the ConsistencyFunc for Trickle instances.
// It checks if the received message (assumed to be NetworkState TLV) matches the local hash.
func (d *DNCP) createConsistencyFunc() trickle.ConsistencyFunc[[]byte] {
	return func(data []byte) bool {
		// data is the raw bytes received that *should* contain TLVs
		if data == nil {
			d.logger.Warn("Trickle consistency check received nil data")
			return false // Inconsistent if nil
		}

		// Use DecodeAll with profile context.
		var receivedHash []byte
		reader := bytes.NewReader(data)
		decodedMarshalers, err := DecodeAll(reader, d.profile)
		if err != nil {
			// Log the error but still check if NetworkState was decoded before the error
			d.logger.Warn("Error decoding TLV stream in consistency check", "err", err)
		}

		// Find the NetworkState TLV among the decoded ones
		found := false
		for _, marshaler := range decodedMarshalers {
			if netStateTLV, ok := marshaler.(*NetworkStateTLV); ok {
				// Successfully decoded and type asserted
				receivedHash = netStateTLV.NetworkStateHash
				found = true
				break // Found the NetworkState TLV
			}
		}

		if !found {
			d.logger.Debug("Trickle consistency check did not find a valid NetworkState TLV in received data")
			return false // Inconsistent if we can't find/decode the hash
		}

		d.mu.RLock()
		localHash := d.networkStateHash
		d.mu.RUnlock()

		consistent := bytes.Equal(receivedHash, localHash)
		d.logger.Debug("Trickle consistency check", "received", hex.EncodeToString(receivedHash), "local", hex.EncodeToString(localHash), "consistent", consistent)
		return consistent
	}
}

// resetAllTrickle signals inconsistency to all active Trickle instances.
// Assumes lock is held.
func (d *DNCP) resetAllTrickle() {
	d.logger.Debug("Resetting Trickle timers due to network state change")
	for _, ep := range d.endpoints {
		if ep.trickleInstance != nil {
			ep.trickleInstance.Event() // Signal external event (inconsistency)
		}
		for _, peer := range ep.peers {
			if peer.trickleInstance != nil {
				peer.trickleInstance.Event()
			}
		}
	}
}
