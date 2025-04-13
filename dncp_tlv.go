package dncp

import (
	"encoding/binary"
	"fmt"
	"slices"
	"time"
)

// --- Specific TLV Structs and Constructors/Decoders ---

// --- Request TLVs (Section 7.1) ---

// RequestNetworkStateTLV corresponds to TLV Type 1. It has no value.
type RequestNetworkStateTLV struct{} // No fields needed

// NewRequestNetworkStateTLV creates a new Request Network State TLV.
func NewRequestNetworkStateTLV() *TLV {
	return &TLV{Type: TLVTypeRequestNetworkState, Length: 0, Value: []byte{}}
}

// DecodeRequestNetworkStateTLV validates a generic TLV as RequestNetworkState.
func DecodeRequestNetworkStateTLV(tlv *TLV) (*RequestNetworkStateTLV, error) {
	if tlv.Type != TLVTypeRequestNetworkState {
		return nil, fmt.Errorf("invalid type for RequestNetworkState: %d", tlv.Type)
	}
	if tlv.Length != 0 {
		return nil, fmt.Errorf("%w: expected length 0 for RequestNetworkState, got %d", ErrInvalidTLVLength, tlv.Length)
	}
	return &RequestNetworkStateTLV{}, nil
}

// RequestNodeStateTLV corresponds to TLV Type 2.
type RequestNodeStateTLV struct {
	NodeID NodeIdentifier
}

// NewRequestNodeStateTLV creates a new Request Node State TLV.
func NewRequestNodeStateTLV(nodeID NodeIdentifier, expectedLen uint) (*TLV, error) {
	if len(nodeID) != int(expectedLen) {
		return nil, fmt.Errorf("%w: invalid NodeID length %d for profile length %d", ErrInvalidTLVLength, len(nodeID), expectedLen)
	}
	return &TLV{
		Type:   TLVTypeRequestNodeState,
		Length: uint16(len(nodeID)),
		Value:  slices.Clone(nodeID),
	}, nil
}

// DecodeRequestNodeStateTLV decodes the Request Node State TLV value.
func DecodeRequestNodeStateTLV(tlv *TLV, expectedLen uint) (*RequestNodeStateTLV, error) {
	if tlv.Type != TLVTypeRequestNodeState {
		return nil, fmt.Errorf("invalid type for RequestNodeState: %d", tlv.Type)
	}
	if tlv.Length != uint16(expectedLen) {
		return nil, fmt.Errorf("%w: expected length %d for RequestNodeState, got %d", ErrInvalidTLVLength, expectedLen, tlv.Length)
	}
	if len(tlv.Value) != int(expectedLen) {
		// This check should be redundant if Encode/Decode work correctly, but good practice.
		return nil, fmt.Errorf("%w: internal inconsistency, value length %d != header length %d", ErrInvalidTLVLength, len(tlv.Value), tlv.Length)
	}
	return &RequestNodeStateTLV{
		NodeID: slices.Clone(tlv.Value),
	}, nil
}

// --- Data TLVs (Section 7.2) ---

// NodeEndpointTLV corresponds to TLV Type 3.
type NodeEndpointTLV struct {
	NodeID     NodeIdentifier
	EndpointID EndpointIdentifier
}

// NewNodeEndpointTLV creates a new Node Endpoint TLV.
func NewNodeEndpointTLV(nodeID NodeIdentifier, endpointID EndpointIdentifier, nodeIDLen uint) (*TLV, error) {
	if len(nodeID) != int(nodeIDLen) {
		return nil, fmt.Errorf("%w: invalid NodeID length %d for profile length %d", ErrInvalidTLVLength, len(nodeID), nodeIDLen)
	}
	valueLen := int(nodeIDLen) + 4 // NodeID + EndpointID (uint32)
	value := make([]byte, valueLen)
	copy(value[0:nodeIDLen], nodeID)
	binary.BigEndian.PutUint32(value[nodeIDLen:valueLen], uint32(endpointID))

	return &TLV{
		Type:   TLVTypeNodeEndpoint,
		Length: uint16(valueLen),
		Value:  value,
	}, nil
}

// DecodeNodeEndpointTLV decodes the Node Endpoint TLV value.
func DecodeNodeEndpointTLV(tlv *TLV, nodeIDLen uint) (*NodeEndpointTLV, error) {
	if tlv.Type != TLVTypeNodeEndpoint {
		return nil, fmt.Errorf("invalid type for NodeEndpoint: %d", tlv.Type)
	}
	expectedLen := nodeIDLen + 4
	if tlv.Length != uint16(expectedLen) {
		return nil, fmt.Errorf("%w: expected length %d for NodeEndpoint, got %d", ErrInvalidTLVLength, expectedLen, tlv.Length)
	}
	if uint(len(tlv.Value)) != expectedLen {
		return nil, fmt.Errorf("%w: internal inconsistency, value length %d != header length %d", ErrInvalidTLVLength, len(tlv.Value), tlv.Length)
	}

	return &NodeEndpointTLV{
		NodeID:     slices.Clone(tlv.Value[0:nodeIDLen]),
		EndpointID: EndpointIdentifier(binary.BigEndian.Uint32(tlv.Value[nodeIDLen:expectedLen])),
	}, nil
}

// NetworkStateTLV corresponds to TLV Type 4.
type NetworkStateTLV struct {
	NetworkStateHash []byte
}

// NewNetworkStateTLV creates a new Network State TLV.
func NewNetworkStateTLV(hash []byte, hashLen uint) (*TLV, error) {
	if len(hash) != int(hashLen) {
		return nil, fmt.Errorf("%w: invalid hash length %d for profile length %d", ErrInvalidTLVLength, len(hash), hashLen)
	}
	return &TLV{
		Type:   TLVTypeNetworkState,
		Length: uint16(len(hash)),
		Value:  slices.Clone(hash),
	}, nil
}

// DecodeNetworkStateTLV decodes the Network State TLV value.
func DecodeNetworkStateTLV(tlv *TLV, hashLen uint) (*NetworkStateTLV, error) {
	if tlv.Type != TLVTypeNetworkState {
		return nil, fmt.Errorf("invalid type for NetworkState: %d", tlv.Type)
	}
	if tlv.Length != uint16(hashLen) {
		return nil, fmt.Errorf("%w: expected length %d for NetworkState hash, got %d", ErrInvalidTLVLength, hashLen, tlv.Length)
	}
	if uint(len(tlv.Value)) != hashLen {
		return nil, fmt.Errorf("%w: internal inconsistency, value length %d != header length %d", ErrInvalidTLVLength, len(tlv.Value), tlv.Length)
	}
	return &NetworkStateTLV{
		NetworkStateHash: slices.Clone(tlv.Value),
	}, nil
}

// NodeStateTLV corresponds to TLV Type 5.
type NodeStateTLV struct {
	NodeID                       NodeIdentifier
	SequenceNumber               uint32
	MillisecondsSinceOrigination uint32
	DataHash                     []byte
	NodeData                     []byte // Optional raw bytes of nested TLVs
}

// NewNodeStateTLV creates a new Node State TLV.
// nodeData should be the already encoded byte stream of nested TLVs, or nil.
func NewNodeStateTLV(nodeID NodeIdentifier, seqNum, msSinceOrig uint32, dataHash, nodeData []byte, nodeIDLen, hashLen uint) (*TLV, error) {
	if len(nodeID) != int(nodeIDLen) {
		return nil, fmt.Errorf("%w: invalid NodeID length %d for profile length %d", ErrInvalidTLVLength, len(nodeID), nodeIDLen)
	}
	if len(dataHash) != int(hashLen) {
		return nil, fmt.Errorf("%w: invalid DataHash length %d for profile length %d", ErrInvalidTLVLength, len(dataHash), hashLen)
	}

	fixedPartLen := int(nodeIDLen) + 4 + 4 + int(hashLen) // NodeID + SeqNum + MsSinceOrig + DataHash
	valueLen := fixedPartLen + len(nodeData)
	if valueLen > MaxTLVValueLength {
		return nil, fmt.Errorf("%w: total NodeState value length %d exceeds maximum %d", ErrInvalidTLVLength, valueLen, MaxTLVValueLength)
	}

	value := make([]byte, valueLen)
	offset := 0
	copy(value[offset:offset+int(nodeIDLen)], nodeID)
	offset += int(nodeIDLen)
	binary.BigEndian.PutUint32(value[offset:offset+4], seqNum)
	offset += 4
	binary.BigEndian.PutUint32(value[offset:offset+4], msSinceOrig)
	offset += 4
	copy(value[offset:offset+int(hashLen)], dataHash)
	offset += int(hashLen)
	if len(nodeData) > 0 {
		copy(value[offset:], nodeData)
	}

	return &TLV{
		Type:   TLVTypeNodeState,
		Length: uint16(valueLen),
		Value:  value,
	}, nil
}

// DecodeNodeStateTLV decodes the Node State TLV value.
// The NodeData field remains as raw bytes for further decoding if needed.
func DecodeNodeStateTLV(tlv *TLV, nodeIDLen, hashLen uint) (*NodeStateTLV, error) {
	if tlv.Type != TLVTypeNodeState {
		return nil, fmt.Errorf("invalid type for NodeState: %d", tlv.Type)
	}
	fixedPartLen := int(nodeIDLen) + 4 + 4 + int(hashLen)
	if tlv.Length < uint16(fixedPartLen) {
		return nil, fmt.Errorf("%w: length %d too short for NodeState fixed fields (%d)", ErrInvalidTLVLength, tlv.Length, fixedPartLen)
	}
	if len(tlv.Value) != int(tlv.Length) {
		return nil, fmt.Errorf("%w: internal inconsistency, value length %d != header length %d", ErrInvalidTLVLength, len(tlv.Value), tlv.Length)
	}

	offset := 0
	nodeID := slices.Clone(tlv.Value[offset : offset+int(nodeIDLen)])
	offset += int(nodeIDLen)
	seqNum := binary.BigEndian.Uint32(tlv.Value[offset : offset+4])
	offset += 4
	msSinceOrig := binary.BigEndian.Uint32(tlv.Value[offset : offset+4])
	offset += 4
	dataHash := slices.Clone(tlv.Value[offset : offset+int(hashLen)])
	offset += int(hashLen)

	var nodeData []byte
	if offset < len(tlv.Value) {
		nodeData = slices.Clone(tlv.Value[offset:])
	}

	return &NodeStateTLV{
		NodeID:                       nodeID,
		SequenceNumber:               seqNum,
		MillisecondsSinceOrigination: msSinceOrig,
		DataHash:                     dataHash,
		NodeData:                     nodeData,
	}, nil
}

// --- Data TLVs within Node State TLV (Section 7.3) ---

// PeerTLV corresponds to TLV Type 8.
type PeerTLV struct {
	PeerNodeID      NodeIdentifier
	PeerEndpointID  EndpointIdentifier
	LocalEndpointID EndpointIdentifier // Renamed from "(Local) Endpoint Identifier" for clarity
}

// NewPeerTLV creates a new Peer TLV.
func NewPeerTLV(peerNodeID NodeIdentifier, peerEpID, localEpID EndpointIdentifier, nodeIDLen uint) (*TLV, error) {
	if len(peerNodeID) != int(nodeIDLen) {
		return nil, fmt.Errorf("%w: invalid PeerNodeID length %d for profile length %d", ErrInvalidTLVLength, len(peerNodeID), nodeIDLen)
	}
	valueLen := int(nodeIDLen) + 4 + 4 // PeerNodeID + PeerEpID + LocalEpID
	value := make([]byte, valueLen)
	offset := 0
	copy(value[offset:offset+int(nodeIDLen)], peerNodeID)
	offset += int(nodeIDLen)
	binary.BigEndian.PutUint32(value[offset:offset+4], uint32(peerEpID))
	offset += 4
	binary.BigEndian.PutUint32(value[offset:offset+4], uint32(localEpID))

	return &TLV{
		Type:   TLVTypePeer,
		Length: uint16(valueLen),
		Value:  value,
	}, nil
}

// DecodePeerTLV decodes the Peer TLV value.
func DecodePeerTLV(tlv *TLV, nodeIDLen uint) (*PeerTLV, error) {
	if tlv.Type != TLVTypePeer {
		return nil, fmt.Errorf("invalid type for Peer: %d", tlv.Type)
	}
	expectedLen := nodeIDLen + 4 + 4
	if tlv.Length != uint16(expectedLen) {
		return nil, fmt.Errorf("%w: expected length %d for Peer, got %d", ErrInvalidTLVLength, expectedLen, tlv.Length)
	}
	if uint(len(tlv.Value)) != expectedLen {
		return nil, fmt.Errorf("%w: internal inconsistency, value length %d != header length %d", ErrInvalidTLVLength, len(tlv.Value), tlv.Length)
	}

	offset := 0
	peerNodeID := slices.Clone(tlv.Value[offset : offset+int(nodeIDLen)])
	offset += int(nodeIDLen)
	peerEpID := EndpointIdentifier(binary.BigEndian.Uint32(tlv.Value[offset : offset+4]))
	offset += 4
	localEpID := EndpointIdentifier(binary.BigEndian.Uint32(tlv.Value[offset : offset+4]))

	return &PeerTLV{
		PeerNodeID:      peerNodeID,
		PeerEndpointID:  peerEpID,
		LocalEndpointID: localEpID,
	}, nil
}

// KeepAliveIntervalTLV corresponds to TLV Type 9.
type KeepAliveIntervalTLV struct {
	EndpointID EndpointIdentifier // 0 means default for all endpoints without specific TLV
	Interval   uint32             // Interval in milliseconds, 0 means no keep-alives sent
}

// NewKeepAliveIntervalTLV creates a new Keep-Alive Interval TLV.
func NewKeepAliveIntervalTLV(endpointID EndpointIdentifier, interval time.Duration) (*TLV, error) {
	valueLen := 4 + 4 // EndpointID + Interval
	value := make([]byte, valueLen)
	intervalMs := uint32(interval.Milliseconds())
	// Check for potential overflow if interval is huge? Milliseconds should fit uint32 for ~49 days.
	if interval > 0 && intervalMs == 0 {
		return nil, fmt.Errorf("interval %v too small, results in 0 milliseconds", interval)
	}
	if interval < 0 {
		return nil, fmt.Errorf("interval %v cannot be negative", interval)
	}

	binary.BigEndian.PutUint32(value[0:4], uint32(endpointID))
	binary.BigEndian.PutUint32(value[4:8], intervalMs)

	return &TLV{
		Type:   TLVTypeKeepAliveInterval,
		Length: uint16(valueLen),
		Value:  value,
	}, nil
}

// DecodeKeepAliveIntervalTLV decodes the Keep-Alive Interval TLV value.
func DecodeKeepAliveIntervalTLV(tlv *TLV) (*KeepAliveIntervalTLV, error) {
	if tlv.Type != TLVTypeKeepAliveInterval {
		return nil, fmt.Errorf("invalid type for KeepAliveInterval: %d", tlv.Type)
	}
	expectedLen := 4 + 4
	if tlv.Length != uint16(expectedLen) {
		// Allow >= 8 for potential sub-TLVs? Spec says "Length: >= 8"
		// Let's stick to exact length for now unless sub-TLVs are defined.
		// if tlv.Length < uint16(expectedLen) {
		return nil, fmt.Errorf("%w: expected length %d for KeepAliveInterval, got %d", ErrInvalidTLVLength, expectedLen, tlv.Length)
		// }
	}
	if len(tlv.Value) < expectedLen { // Check value buffer has enough bytes
		return nil, fmt.Errorf("%w: internal inconsistency, value length %d < expected length %d", ErrInvalidTLVLength, len(tlv.Value), expectedLen)
	}

	endpointID := EndpointIdentifier(binary.BigEndian.Uint32(tlv.Value[0:4]))
	intervalMs := binary.BigEndian.Uint32(tlv.Value[4:8])

	return &KeepAliveIntervalTLV{
		EndpointID: endpointID,
		Interval:   intervalMs,
	}, nil
}
