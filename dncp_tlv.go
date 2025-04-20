package dncp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// --- Initialization: Register Standard TLV Types ---

func init() {
	RegisterTLVType(TLVTypeRequestNetworkState, func() TLVMarshaler {
		return &RequestNetworkStateTLV{BaseTLV: BaseTLV{TLVType: TLVTypeRequestNetworkState}}
	})
	RegisterTLVType(TLVTypeRequestNodeState, func() TLVMarshaler { return &RequestNodeStateTLV{BaseTLV: BaseTLV{TLVType: TLVTypeRequestNodeState}} })
	RegisterTLVType(TLVTypeNodeEndpoint, func() TLVMarshaler { return &NodeEndpointTLV{BaseTLV: BaseTLV{TLVType: TLVTypeNodeEndpoint}} })
	RegisterTLVType(TLVTypeNetworkState, func() TLVMarshaler { return &NetworkStateTLV{BaseTLV: BaseTLV{TLVType: TLVTypeNetworkState}} })
	RegisterTLVType(TLVTypeNodeState, func() TLVMarshaler { return &NodeStateTLV{BaseTLV: BaseTLV{TLVType: TLVTypeNodeState}} })
	RegisterTLVType(TLVTypePeer, func() TLVMarshaler { return &PeerTLV{BaseTLV: BaseTLV{TLVType: TLVTypePeer}} })
	RegisterTLVType(TLVTypeKeepAliveInterval, func() TLVMarshaler { return &KeepAliveIntervalTLV{BaseTLV: BaseTLV{TLVType: TLVTypeKeepAliveInterval}} })
	// Register TLVTypeTrustVerdict later if implemented
}

// --- Request TLVs (Section 7.1) ---

// RequestNetworkStateTLV corresponds to TLV Type 1. It has no value.
type RequestNetworkStateTLV struct {
	BaseTLV
}

// EncodeValue returns an empty byte slice as this TLV has no specific fields.
func (t *RequestNetworkStateTLV) EncodeValue() ([]byte, error) {
	return []byte{}, nil
}

// DecodeValue consumes 0 bytes as this TLV has no specific fields.
func (t *RequestNetworkStateTLV) DecodeValue([]byte, *Profile) (int, error) {
	// We expect Decode to handle sub-TLVs if len(value) > 0
	return 0, nil
}

// RequestNodeStateTLV corresponds to TLV Type 2.
type RequestNodeStateTLV struct {
	BaseTLV
	NodeID NodeIdentifier
}

// NewRequestNodeStateTLV creates a new Request Node State TLV instance.
func NewRequestNodeStateTLV(nodeID NodeIdentifier) (*RequestNodeStateTLV, error) {
	// Length validation happens during encoding or based on profile during decoding
	return &RequestNodeStateTLV{
		BaseTLV: BaseTLV{TLVType: TLVTypeRequestNodeState},
		NodeID:  slices.Clone(nodeID),
	}, nil
}

// EncodeValue returns the NodeID bytes.
// Note: Length validation against profile should happen in the caller if needed,
// or rely on the Decode side validation. For simplicity, encode what's given.
func (t *RequestNodeStateTLV) EncodeValue() ([]byte, error) {
	return slices.Clone(t.NodeID), nil // Return only the NodeID bytes
}

// DecodeValue decodes the NodeID, validating length against the profile, and returns consumed bytes.
func (t *RequestNodeStateTLV) DecodeValue(value []byte, profile *Profile) (int, error) {
	if profile == nil {
		return 0, errors.New("profile is required for decoding RequestNodeStateTLV")
	}
	expectedLen := int(profile.NodeIdentifierLength)
	if len(value) < expectedLen { // Check if enough bytes exist for NodeID
		return 0, fmt.Errorf("%w: expected at least %d bytes for RequestNodeState NodeID, got %d", ErrInvalidTLVLength, expectedLen, len(value))
	}
	if expectedLen == 0 {
		return 0, fmt.Errorf("%w: NodeIdentifierLength cannot be zero in profile", ErrInvalidTLVLength)
	}
	t.NodeID = slices.Clone(value[0:expectedLen])
	// Sub-TLVs might follow, so we only return the consumed length for NodeID
	return expectedLen, nil
}

// --- Data TLVs (Section 7.2) ---

// NodeEndpointTLV corresponds to TLV Type 3.
type NodeEndpointTLV struct {
	BaseTLV
	NodeID     NodeIdentifier
	EndpointID EndpointIdentifier
}

// NewNodeEndpointTLV creates a new Node Endpoint TLV instance.
func NewNodeEndpointTLV(nodeID NodeIdentifier, endpointID EndpointIdentifier) (*NodeEndpointTLV, error) {
	return &NodeEndpointTLV{
		BaseTLV:    BaseTLV{TLVType: TLVTypeNodeEndpoint},
		NodeID:     slices.Clone(nodeID),
		EndpointID: endpointID,
	}, nil
}

// EncodeValue encodes NodeID and EndpointID.
func (t *NodeEndpointTLV) EncodeValue() ([]byte, error) {
	// Length validation against profile should happen elsewhere if needed.
	nodeIDLen := len(t.NodeID) // Use actual length of stored NodeID
	valueLen := nodeIDLen + 4  // NodeID + EndpointID (uint32)
	value := make([]byte, valueLen)
	copy(value[0:nodeIDLen], t.NodeID)
	binary.BigEndian.PutUint32(value[nodeIDLen:valueLen], uint32(t.EndpointID))
	return value, nil // Return only the bytes for NodeID and EndpointID
}

// DecodeValue decodes NodeID and EndpointID, validating length, and returns consumed bytes.
func (t *NodeEndpointTLV) DecodeValue(value []byte, profile *Profile) (int, error) {
	if profile == nil {
		return 0, errors.New("profile is required for decoding NodeEndpointTLV")
	}
	nodeIDLen := int(profile.NodeIdentifierLength)
	expectedLen := nodeIDLen + 4
	if len(value) < expectedLen { // Check if enough bytes exist for fixed fields
		return 0, fmt.Errorf("%w: expected at least %d bytes for NodeEndpoint, got %d", ErrInvalidTLVLength, expectedLen, len(value))
	}
	t.NodeID = slices.Clone(value[0:nodeIDLen])
	t.EndpointID = EndpointIdentifier(binary.BigEndian.Uint32(value[nodeIDLen:expectedLen]))
	// Sub-TLVs might follow
	return expectedLen, nil
}

// NetworkStateTLV corresponds to TLV Type 4.
type NetworkStateTLV struct {
	BaseTLV
	NetworkStateHash []byte
}

// NewNetworkStateTLV creates a new Network State TLV instance.
func NewNetworkStateTLV(hash []byte) (*NetworkStateTLV, error) {
	return &NetworkStateTLV{
		BaseTLV:          BaseTLV{TLVType: TLVTypeNetworkState},
		NetworkStateHash: slices.Clone(hash),
	}, nil
}

// EncodeValue returns the NetworkStateHash bytes.
func (t *NetworkStateTLV) EncodeValue() ([]byte, error) {
	// Length validation against profile should happen elsewhere if needed.
	return slices.Clone(t.NetworkStateHash), nil // Return only the hash bytes
}

// DecodeValue decodes the NetworkStateHash, validating length, and returns consumed bytes.
func (t *NetworkStateTLV) DecodeValue(value []byte, profile *Profile) (int, error) {
	if profile == nil {
		return 0, errors.New("profile is required for decoding NetworkStateTLV")
	}
	hashLen := int(profile.HashLength)
	if len(value) < hashLen { // Check if enough bytes exist for hash
		return 0, fmt.Errorf("%w: expected at least %d bytes for NetworkState hash, got %d", ErrInvalidTLVLength, hashLen, len(value))
	}
	t.NetworkStateHash = slices.Clone(value[0:hashLen])
	// Sub-TLVs might follow
	return hashLen, nil
}

// NodeStateTLV corresponds to TLV Type 5.
type NodeStateTLV struct {
	BaseTLV
	NodeID                       NodeIdentifier
	SequenceNumber               uint32
	MillisecondsSinceOrigination uint32
	DataHash                     []byte
	// NestedTLVs are stored in BaseTLV.SubTLVs
}

// NewNodeStateTLV creates a new Node State TLV instance.
// nestedTLVs are the TLVs representing the Node Data, which will be stored in BaseTLV.SubTLVs.
func NewNodeStateTLV(nodeID NodeIdentifier, seqNum, msSinceOrig uint32, dataHash []byte, nestedTLVs []TLVMarshaler) (*NodeStateTLV, error) {
	// Length validation happens during encoding/decoding based on profile
	t := &NodeStateTLV{
		BaseTLV:                      BaseTLV{TLVType: TLVTypeNodeState},
		NodeID:                       slices.Clone(nodeID),
		SequenceNumber:               seqNum,
		MillisecondsSinceOrigination: msSinceOrig,
		DataHash:                     slices.Clone(dataHash),
	}
	// Set sub-TLVs (Node Data) using the BaseTLV method
	if err := t.SetSubTLVs(nestedTLVs); err != nil {
		// Should not happen with BaseTLV implementation
		return nil, err
	}
	return t, nil
}

// EncodeValue encodes only the fixed fields (NodeID, SeqNum, MsSinceOrig, DataHash).
// The nested Node Data TLVs are handled by the generic Encode function via GetSubTLVs().
func (t *NodeStateTLV) EncodeValue() ([]byte, error) {
	// Length validation against profile should happen elsewhere if needed.
	nodeIDLen := len(t.NodeID)
	hashLen := len(t.DataHash)
	fixedPartLen := nodeIDLen + 4 + 4 + hashLen

	value := make([]byte, fixedPartLen)
	offset := 0
	copy(value[offset:offset+nodeIDLen], t.NodeID)
	offset += nodeIDLen
	binary.BigEndian.PutUint32(value[offset:offset+4], t.SequenceNumber)
	offset += 4
	binary.BigEndian.PutUint32(value[offset:offset+4], t.MillisecondsSinceOrigination)
	offset += 4
	copy(value[offset:offset+hashLen], t.DataHash)
	// Do NOT encode nested TLVs here, generic Encode handles BaseTLV.SubTLVs

	return value, nil
}

// DecodeValue decodes the fixed fields and returns the number of bytes consumed.
// The nested Node Data TLVs are handled by the generic Decode function.
func (t *NodeStateTLV) DecodeValue(value []byte, profile *Profile) (int, error) {
	if profile == nil {
		return 0, errors.New("profile is required for decoding NodeStateTLV")
	}
	nodeIDLen := int(profile.NodeIdentifierLength)
	hashLen := int(profile.HashLength)
	fixedPartLen := nodeIDLen + 4 + 4 + hashLen
	if len(value) < fixedPartLen {
		return 0, fmt.Errorf("%w: length %d too short for NodeState fixed fields (%d)", ErrInvalidTLVLength, len(value), fixedPartLen)
	}

	offset := 0
	t.NodeID = slices.Clone(value[offset : offset+nodeIDLen])
	offset += nodeIDLen
	t.SequenceNumber = binary.BigEndian.Uint32(value[offset : offset+4])
	offset += 4
	t.MillisecondsSinceOrigination = binary.BigEndian.Uint32(value[offset : offset+4])
	offset += 4
	t.DataHash = slices.Clone(value[offset : offset+hashLen])
	offset += hashLen

	// Do NOT decode nested TLVs here, generic Decode handles them based on remaining length
	return offset, nil // Return bytes consumed by fixed fields
}

// --- Data TLVs within Node State TLV (Section 7.3) ---

// PeerTLV corresponds to TLV Type 8.
type PeerTLV struct {
	BaseTLV
	PeerNodeID      NodeIdentifier
	PeerEndpointID  EndpointIdentifier
	LocalEndpointID EndpointIdentifier // Renamed from "(Local) Endpoint Identifier" for clarity
}

// NewPeerTLV creates a new Peer TLV instance.
func NewPeerTLV(peerNodeID NodeIdentifier, peerEpID, localEpID EndpointIdentifier) (*PeerTLV, error) {
	return &PeerTLV{
		BaseTLV:         BaseTLV{TLVType: TLVTypePeer},
		PeerNodeID:      slices.Clone(peerNodeID),
		PeerEndpointID:  peerEpID,
		LocalEndpointID: localEpID,
	}, nil
}

// EncodeValue encodes the Peer TLV fields.
func (t *PeerTLV) EncodeValue() ([]byte, error) {
	// Length validation against profile should happen elsewhere if needed.
	nodeIDLen := len(t.PeerNodeID)
	valueLen := nodeIDLen + 4 + 4 // PeerNodeID + PeerEpID + LocalEpID
	value := make([]byte, valueLen)
	offset := 0
	copy(value[offset:offset+nodeIDLen], t.PeerNodeID)
	offset += nodeIDLen
	binary.BigEndian.PutUint32(value[offset:offset+4], uint32(t.PeerEndpointID))
	offset += 4
	binary.BigEndian.PutUint32(value[offset:offset+4], uint32(t.LocalEndpointID))
	return value, nil // Return only the bytes for the specific fields
}

// DecodeValue decodes the Peer TLV fields, validating length, and returns consumed bytes.
func (t *PeerTLV) DecodeValue(value []byte, profile *Profile) (int, error) {
	if profile == nil {
		return 0, errors.New("profile is required for decoding PeerTLV")
	}
	nodeIDLen := int(profile.NodeIdentifierLength)
	expectedLen := nodeIDLen + 4 + 4
	if len(value) < expectedLen { // Check if enough bytes exist for fixed fields
		return 0, fmt.Errorf("%w: expected at least %d bytes for Peer, got %d", ErrInvalidTLVLength, expectedLen, len(value))
	}

	offset := 0
	t.PeerNodeID = slices.Clone(value[offset : offset+nodeIDLen])
	offset += nodeIDLen
	t.PeerEndpointID = EndpointIdentifier(binary.BigEndian.Uint32(value[offset : offset+4]))
	offset += 4
	t.LocalEndpointID = EndpointIdentifier(binary.BigEndian.Uint32(value[offset : offset+4]))
	offset += 4
	// Sub-TLVs might follow
	return offset, nil
}

// KeepAliveIntervalTLV corresponds to TLV Type 9.
// This TLV type *can* have sub-TLVs according to RFC 7787 Section 7.
type KeepAliveIntervalTLV struct {
	BaseTLV
	EndpointID EndpointIdentifier // 0 means default for all endpoints without specific TLV
	IntervalMs uint32             // Interval in milliseconds, 0 means no keep-alives sent
	// SubTLVs are stored in BaseTLV.SubTLVs
}

// NewKeepAliveIntervalTLV creates a new Keep-Alive Interval TLV instance.
// Any subTLVs should be set using SetSubTLVs().
func NewKeepAliveIntervalTLV(endpointID EndpointIdentifier, interval time.Duration) (*KeepAliveIntervalTLV, error) {
	intervalMs := uint32(interval.Milliseconds())
	if interval > 0 && intervalMs == 0 {
		return nil, fmt.Errorf("interval %v too small, results in 0 milliseconds", interval)
	}
	if interval < 0 {
		return nil, fmt.Errorf("interval %v cannot be negative", interval)
	}
	return &KeepAliveIntervalTLV{
		BaseTLV:    BaseTLV{TLVType: TLVTypeKeepAliveInterval},
		EndpointID: endpointID,
		IntervalMs: intervalMs,
	}, nil
}

// EncodeValue encodes only the fixed fields (EndpointID, IntervalMs).
// Sub-TLVs are handled by the generic Encode function.
func (t *KeepAliveIntervalTLV) EncodeValue() ([]byte, error) {
	fixedPartLen := 4 + 4 // EndpointID + Interval
	value := make([]byte, fixedPartLen)
	binary.BigEndian.PutUint32(value[0:4], uint32(t.EndpointID))
	binary.BigEndian.PutUint32(value[4:8], t.IntervalMs)
	return value, nil
}

// DecodeValue decodes the fixed fields and returns the number of bytes consumed.
// Sub-TLVs are handled by the generic Decode function.
func (t *KeepAliveIntervalTLV) DecodeValue(value []byte, _ *Profile) (int, error) {
	// Profile is not strictly needed here but kept for interface consistency
	fixedPartLen := 4 + 4
	if len(value) < fixedPartLen {
		return 0, fmt.Errorf("%w: expected at least %d bytes for KeepAliveInterval, got %d", ErrInvalidTLVLength, fixedPartLen, len(value))
	}

	t.EndpointID = EndpointIdentifier(binary.BigEndian.Uint32(value[0:4]))
	t.IntervalMs = binary.BigEndian.Uint32(value[4:8])

	// Sub-TLVs might follow
	return fixedPartLen, nil
}

// Helper to get interval as time.Duration
func (t *KeepAliveIntervalTLV) Interval() time.Duration {
	return time.Duration(t.IntervalMs) * time.Millisecond
}
