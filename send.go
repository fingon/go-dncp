package dncp

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
)

// sendTLV encodes and sends a single TLV to the destination.
func (d *DNCP) sendTLV(destination string, tlv *TLV) error {
	var buf bytes.Buffer
	if err := tlv.Encode(&buf); err != nil {
		return fmt.Errorf("failed to encode TLV type %d: %w", tlv.Type, err)
	}
	if d.SendFunc == nil {
		return errors.New("SendFunc is not configured")
	}
	return d.SendFunc(destination, buf.Bytes())
}

// sendTLVs encodes and sends multiple TLVs together in one payload.
func (d *DNCP) sendTLVs(destination string, tlvs []*TLV) error {
	var buf bytes.Buffer
	for _, tlv := range tlvs {
		if err := tlv.Encode(&buf); err != nil {
			// Log error for the specific TLV but try to send the rest?
			// Or fail the whole batch? Fail batch for now.
			return fmt.Errorf("failed to encode TLV type %d in batch: %w", tlv.Type, err)
		}
	}
	if buf.Len() == 0 {
		return nil // Nothing to send
	}
	if d.SendFunc == nil {
		return errors.New("SendFunc is not configured")
	}
	return d.SendFunc(destination, buf.Bytes())
}

// requestNetworkState sends a Request Network State TLV.
func (d *DNCP) requestNetworkState(destination string) {
	tlv := &TLV{Type: TLVTypeRequestNetworkState, Length: 0, Value: []byte{}}
	err := d.sendTLV(destination, tlv)
	if err != nil {
		d.logger.Error("Failed to send RequestNetworkState", "destination", destination, "err", err)
	}
}

// requestNodeState sends a Request Node State TLV.
func (d *DNCP) requestNodeState(destination string, nodeID NodeIdentifier) {
	tlv, err := NewRequestNodeStateTLV(nodeID, d.profile.NodeIdentifierLength)
	if err != nil {
		d.logger.Error("Failed to create RequestNodeState TLV", "nodeID", fmt.Sprintf("%x", nodeID), "err", err)
		return
	}
	err = d.sendTLV(destination, tlv)
	if err != nil {
		d.logger.Error("Failed to send RequestNodeState", "destination", destination, "nodeID", fmt.Sprintf("%x", nodeID), "err", err)
	}
}

// sendNodeState sends the Node State TLV for a specific node.
func (d *DNCP) sendNodeState(destination string, nodeID NodeIdentifier, includeData bool) {
	d.mu.RLock()
	nodeState, exists := d.nodes[string(nodeID)]
	d.mu.RUnlock()

	if !exists {
		d.logger.Warn("Cannot send NodeState, node not found locally", "nodeID", fmt.Sprintf("%x", nodeID))
		return
	}

	// Need to lock to safely access nodeState fields while creating TLV
	d.mu.RLock()
	seq := nodeState.SequenceNumber
	hash := slices.Clone(nodeState.DataHash)
	msSinceOrigination := uint32(d.clock.Now().Sub(nodeState.OriginationTime).Milliseconds())
	var dataBytes []byte
	var dataBuf bytes.Buffer
	if includeData && nodeState.Data != nil {
		// Get all TLVs ordered correctly for encoding
		orderedTLVs := getOrderedTLVs(nodeState.Data)
		for _, dataTLV := range orderedTLVs {
			if err := dataTLV.Encode(&dataBuf); err != nil {
				d.logger.Error("Failed to encode nested TLV for NodeState data", "nodeID", fmt.Sprintf("%x", nodeID), "type", dataTLV.Type, "err", err)
				// Cannot send with data if any TLV fails encoding
				dataBytes = nil // Ensure dataBytes is nil if encoding fails
				break
			}
		}
		// Only assign dataBytes if encoding succeeded for all TLVs
		if dataBytes != nil {
			dataBytes = dataBuf.Bytes()
		}
	}
	d.mu.RUnlock() // Unlock after accessing nodeState data

	tlv, err := NewNodeStateTLV(nodeID, seq, msSinceOrigination, hash, dataBytes, d.profile.NodeIdentifierLength, d.profile.HashLength)
	if err != nil {
		d.logger.Error("Failed to create NodeState TLV", "nodeID", fmt.Sprintf("%x", nodeID), "err", err)
		return
	}

	err = d.sendTLV(destination, tlv)
	if err != nil {
		d.logger.Error("Failed to send NodeState", "destination", destination, "nodeID", fmt.Sprintf("%x", nodeID), "err", err)
	}
}

// sendFullNetworkState sends the Network State TLV followed by all known Node State TLVs (headers only).
func (d *DNCP) sendFullNetworkState(destination string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	tlvsToSend := make([]*TLV, 0, len(d.nodes)+1)

	// 1. Network State TLV
	netStateTLV, err := NewNetworkStateTLV(d.networkStateHash, d.profile.HashLength)
	if err != nil {
		d.logger.Error("Failed to create NetworkState TLV for full state send", "err", err)
		return // Cannot proceed without network state
	}
	tlvsToSend = append(tlvsToSend, netStateTLV)

	// 2. Node State TLVs (Headers Only)
	now := d.clock.Now()
	for _, nodeState := range d.nodes {
		// Check reachability? Spec doesn't explicitly say for replies, but seems logical.
		// Let's include all known nodes for now, as requested by RequestNetworkState spec.
		// if !nodeState.isReachable { continue }

		msSinceOrigination := uint32(now.Sub(nodeState.OriginationTime).Milliseconds())
		nodeTLV, err := NewNodeStateTLV(
			nodeState.NodeID,
			nodeState.SequenceNumber,
			msSinceOrigination,
			nodeState.DataHash,
			nil, // No data
			d.profile.NodeIdentifierLength,
			d.profile.HashLength,
		)
		if err != nil {
			d.logger.Error("Failed to create NodeState TLV header for full state send", "nodeID", fmt.Sprintf("%x", nodeState.NodeID), "err", err)
			continue // Skip this node
		}
		tlvsToSend = append(tlvsToSend, nodeTLV)
	}

	// Send all TLVs together
	err = d.sendTLVs(destination, tlvsToSend)
	if err != nil {
		d.logger.Error("Failed to send full network state", "destination", destination, "err", err)
	} else {
		d.logger.Debug("Sent full network state", "destination", destination, "num_nodes", len(tlvsToSend)-1)
	}
}
