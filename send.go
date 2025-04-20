package dncp

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
)

// sendTLV encodes and sends a single TLVMarshaler to the destination.
func (d *DNCP) sendTLV(destination string, tlv TLVMarshaler) error {
	var buf bytes.Buffer
	if err := Encode(tlv, &buf); err != nil { // Use the generic Encode function
		return fmt.Errorf("failed to encode TLV type %d: %w", tlv.GetType(), err)
	}
	if d.SendFunc == nil {
		return errors.New("SendFunc is not configured")
	}
	return d.SendFunc(destination, buf.Bytes())
}

// sendTLVs encodes and sends multiple TLVMarshalers together in one payload.
func (d *DNCP) sendTLVs(destination string, tlvs []TLVMarshaler) error {
	var buf bytes.Buffer
	for _, tlv := range tlvs {
		if err := Encode(tlv, &buf); err != nil { // Use the generic Encode function
			// Log error for the specific TLV but try to send the rest?
			// Or fail the whole batch? Fail batch for now.
			return fmt.Errorf("failed to encode TLV type %d in batch: %w", tlv.GetType(), err)
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

// requestNetworkState sends a Request Network State TLV struct.
func (d *DNCP) requestNetworkState(destination string) {
	// Create the specific TLV struct instance
	tlv := &RequestNetworkStateTLV{BaseTLV: BaseTLV{TLVType: TLVTypeRequestNetworkState}}
	err := d.sendTLV(destination, tlv) // Pass the TLVMarshaler
	if err != nil {
		d.logger.Error("Failed to send RequestNetworkState", "destination", destination, "err", err)
	}
}

// requestNodeState sends a Request Node State TLV struct.
func (d *DNCP) requestNodeState(destination string, nodeID NodeIdentifier) {
	// Create the specific TLV struct instance
	tlv, err := NewRequestNodeStateTLV(nodeID) // No length needed here
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
	var nestedTLVs []TLVMarshaler
	var err error
	if includeData && nodeState.Data != nil {
		// Get all TLVMarshalers ordered correctly for encoding
		// Note: getOrderedTLVs now returns []TLVMarshaler
		nestedTLVs, err = getOrderedTLVs(nodeState.Data)
	}
	d.mu.RUnlock() // Unlock after accessing nodeState data
	if err != nil {
		d.logger.Error("getOrderedTLVs failed", "err", err)
		return
	}

	// Create the specific TLV struct instance
	tlv, err := NewNodeStateTLV(nodeID, seq, msSinceOrigination, hash, nestedTLVs) // Pass marshalers directly
	if err != nil {
		d.logger.Error("Failed to create NodeState TLV", "nodeID", fmt.Sprintf("%x", nodeID), "err", err)
		return
	}

	err = d.sendTLV(destination, tlv)
	if err != nil {
		d.logger.Error("Failed to send NodeState", "destination", destination, "nodeID", fmt.Sprintf("%x", nodeID), "err", err)
	}
}

// sendFullNetworkState sends the Network State TLV struct followed by all known Node State TLV structs (headers only).
func (d *DNCP) sendFullNetworkState(destination string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	tlvsToSend := make([]TLVMarshaler, 0, len(d.nodes)+1)

	// 1. Network State TLV
	netStateTLV, err := NewNetworkStateTLV(d.networkStateHash) // No length needed
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
		// Create NodeStateTLV struct with nil NestedTLVs
		nodeTLV, err := NewNodeStateTLV(
			nodeState.NodeID,
			nodeState.SequenceNumber,
			msSinceOrigination,
			nodeState.DataHash,
			nil, // No nested TLVs
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
