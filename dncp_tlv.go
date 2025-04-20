package dncp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

// EncodeValue returns an empty byte slice as this TLV has no value.
func (t *RequestNetworkStateTLV) EncodeValue() ([]byte, error) {
	return []byte{}, nil
}

// DecodeValue does nothing as this TLV has no value. The profile arg is ignored.
func (t *RequestNetworkStateTLV) DecodeValue(value []byte, _ *Profile) error {
	if len(value) != 0 {
		return fmt.Errorf("%w: expected length 0 for RequestNetworkState, got %d", ErrInvalidTLVLength, len(value))
	}
	return nil
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
	return slices.Clone(t.NodeID), nil
}

// DecodeValue decodes the NodeID from the value bytes, validating length against the profile.
func (t *RequestNodeStateTLV) DecodeValue(value []byte, profile *Profile) error {
	if profile == nil {
		return errors.New("profile is required for decoding RequestNodeStateTLV")
	}
	expectedLen := profile.NodeIdentifierLength
	if len(value) != int(expectedLen) {
		return fmt.Errorf("%w: expected length %d for RequestNodeState, got %d", ErrInvalidTLVLength, expectedLen, len(value))
	}
	if len(value) == 0 {
		return fmt.Errorf("%w: value cannot be empty for RequestNodeState", ErrInvalidTLVLength)
	}
	t.NodeID = slices.Clone(value)
	return nil
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
	return value, nil
}

// DecodeValue decodes NodeID and EndpointID, validating length against the profile.
func (t *NodeEndpointTLV) DecodeValue(value []byte, profile *Profile) error {
	if profile == nil {
		return errors.New("profile is required for decoding NodeEndpointTLV")
	}
	nodeIDLen := profile.NodeIdentifierLength
	expectedLen := int(nodeIDLen) + 4
	if len(value) != expectedLen {
		return fmt.Errorf("%w: expected length %d for NodeEndpoint, got %d", ErrInvalidTLVLength, expectedLen, len(value))
	}
	t.NodeID = slices.Clone(value[0:nodeIDLen])
	t.EndpointID = EndpointIdentifier(binary.BigEndian.Uint32(value[nodeIDLen:expectedLen]))
	return nil
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
	return slices.Clone(t.NetworkStateHash), nil
}

// DecodeValue decodes the NetworkStateHash, validating length against the profile.
func (t *NetworkStateTLV) DecodeValue(value []byte, profile *Profile) error {
	if profile == nil {
		return errors.New("profile is required for decoding NetworkStateTLV")
	}
	hashLen := profile.HashLength
	if len(value) != int(hashLen) {
		return fmt.Errorf("%w: expected length %d for NetworkState hash, got %d", ErrInvalidTLVLength, hashLen, len(value))
	}
	t.NetworkStateHash = slices.Clone(value)
	return nil
}

// NodeStateTLV corresponds to TLV Type 5.
type NodeStateTLV struct {
	BaseTLV
	NodeID                       NodeIdentifier
	SequenceNumber               uint32
	MillisecondsSinceOrigination uint32
	DataHash                     []byte
	NestedTLVs                   []TLVMarshaler // Decoded nested TLVs
}

// NewNodeStateTLV creates a new Node State TLV instance.
// nestedTLVs should be the list of TLVMarshaler instances to include.
func NewNodeStateTLV(nodeID NodeIdentifier, seqNum, msSinceOrig uint32, dataHash []byte, nestedTLVs []TLVMarshaler) (*NodeStateTLV, error) {
	// Length validation happens during encoding/decoding based on profile
	return &NodeStateTLV{
		BaseTLV:                      BaseTLV{TLVType: TLVTypeNodeState},
		NodeID:                       slices.Clone(nodeID),
		SequenceNumber:               seqNum,
		MillisecondsSinceOrigination: msSinceOrig,
		DataHash:                     slices.Clone(dataHash),
		NestedTLVs:                   nestedTLVs, // Store the slice directly
	}, nil
}

// EncodeValue encodes the fixed fields and the nested TLVs.
func (t *NodeStateTLV) EncodeValue() ([]byte, error) {
	// Length validation against profile should happen elsewhere if needed.
	nodeIDLen := len(t.NodeID)
	hashLen := len(t.DataHash)
	fixedPartLen := nodeIDLen + 4 + 4 + hashLen // NodeID + SeqNum + MsSinceOrig + DataHash

	// Encode nested TLVs, sort them by binary representation, then concatenate
	var nestedBytes []byte
	if len(t.NestedTLVs) > 0 {
		// Create temporary structure to hold encoded TLVs for sorting
		encodedNested := make([]encodedTLV, 0, len(t.NestedTLVs))
		var encBuf bytes.Buffer
		for _, nestedTLV := range t.NestedTLVs {
			encBuf.Reset()
			if err := Encode(nestedTLV, &encBuf); err != nil {
				return nil, fmt.Errorf("failed to encode nested TLV type %d for sorting: %w", nestedTLV.GetType(), err)
			}
			encodedNested = append(encodedNested, encodedTLV{
				marshaler: nestedTLV,
				encoded:   slices.Clone(encBuf.Bytes()),
			})
		}

		// Sort based on encoded binary content
		slices.SortFunc(encodedNested, func(a, b encodedTLV) int {
			return bytes.Compare(a.encoded, b.encoded)
		})

		// Concatenate sorted encoded TLVs
		var finalNestedBuf bytes.Buffer
		for _, et := range encodedNested {
			if _, err := finalNestedBuf.Write(et.encoded); err != nil {
				// Should not happen with bytes.Buffer
				return nil, fmt.Errorf("failed to write sorted nested TLV type %d to buffer: %w", et.marshaler.GetType(), err)
			}
		}
		nestedBytes = finalNestedBuf.Bytes()
	}

	valueLen := fixedPartLen + len(nestedBytes)

	// Create final value buffer
	value := make([]byte, valueLen)
	offset := 0
	copy(value[offset:offset+nodeIDLen], t.NodeID)
	offset += nodeIDLen
	binary.BigEndian.PutUint32(value[offset:offset+4], t.SequenceNumber)
	offset += 4
	binary.BigEndian.PutUint32(value[offset:offset+4], t.MillisecondsSinceOrigination)
	offset += 4
	copy(value[offset:offset+hashLen], t.DataHash)
	offset += hashLen
	if len(nestedBytes) > 0 {
		copy(value[offset:], nestedBytes)
	}

	return value, nil
}

// DecodeValue decodes the fixed fields and attempts to decode nested TLVs using the profile context.
func (t *NodeStateTLV) DecodeValue(value []byte, profile *Profile) error {
	if profile == nil {
		return errors.New("profile is required for decoding NodeStateTLV")
	}
	nodeIDLen := profile.NodeIdentifierLength
	hashLen := profile.HashLength
	fixedPartLen := int(nodeIDLen) + 4 + 4 + int(hashLen)
	if len(value) < fixedPartLen {
		return fmt.Errorf("%w: length %d too short for NodeState fixed fields (%d)", ErrInvalidTLVLength, len(value), fixedPartLen)
	}

	offset := 0
	t.NodeID = slices.Clone(value[offset : offset+int(nodeIDLen)])
	offset += int(nodeIDLen)
	t.SequenceNumber = binary.BigEndian.Uint32(value[offset : offset+4])
	offset += 4
	t.MillisecondsSinceOrigination = binary.BigEndian.Uint32(value[offset : offset+4])
	offset += 4
	t.DataHash = slices.Clone(value[offset : offset+int(hashLen)])
	offset += int(hashLen)

	// Decode nested TLVs if present
	if offset < len(value) {
		nestedBytes := value[offset:]
		nestedReader := bytes.NewReader(nestedBytes)
		// Pass profile to DecodeAll for nested decoding
		decodedNested, err := DecodeAll(nestedReader, profile)
		if err != nil && !errors.Is(err, io.EOF) { // EOF is expected if DecodeAll reads everything
			return fmt.Errorf("failed to decode nested TLVs: %w", err)
		}
		// Check if all bytes were consumed
		if nestedReader.Len() > 0 {
			return fmt.Errorf("trailing data (%d bytes) after decoding nested TLVs", nestedReader.Len())
		}
		t.NestedTLVs = decodedNested
	} else {
		t.NestedTLVs = nil // No nested data
	}

	return nil
}

// GetSubTLVs returns the decoded nested TLVs.
func (t *NodeStateTLV) GetSubTLVs() []TLVMarshaler {
	return t.NestedTLVs
}

// SetSubTLVs sets the nested TLVs.
func (t *NodeStateTLV) SetSubTLVs(subTLVs []TLVMarshaler) error {
	t.NestedTLVs = subTLVs
	return nil
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
	return value, nil
}

// DecodeValue decodes the Peer TLV fields, validating length against the profile.
func (t *PeerTLV) DecodeValue(value []byte, profile *Profile) error {
	if profile == nil {
		return errors.New("profile is required for decoding PeerTLV")
	}
	nodeIDLen := profile.NodeIdentifierLength
	expectedLen := int(nodeIDLen) + 4 + 4
	if len(value) != expectedLen {
		return fmt.Errorf("%w: expected length %d for Peer, got %d", ErrInvalidTLVLength, expectedLen, len(value))
	}

	offset := 0
	t.PeerNodeID = slices.Clone(value[offset : offset+int(nodeIDLen)])
	offset += int(nodeIDLen)
	t.PeerEndpointID = EndpointIdentifier(binary.BigEndian.Uint32(value[offset : offset+4]))
	offset += 4
	t.LocalEndpointID = EndpointIdentifier(binary.BigEndian.Uint32(value[offset : offset+4]))
	return nil
}

// KeepAliveIntervalTLV corresponds to TLV Type 9.
// This TLV type *can* have sub-TLVs according to RFC 7787 Section 7.
type KeepAliveIntervalTLV struct {
	BaseTLV
	EndpointID EndpointIdentifier // 0 means default for all endpoints without specific TLV
	IntervalMs uint32             // Interval in milliseconds, 0 means no keep-alives sent
	SubTLVs    []TLVMarshaler     // Optional nested TLVs
}

// NewKeepAliveIntervalTLV creates a new Keep-Alive Interval TLV instance.
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
		// SubTLVs initialized to nil
	}, nil
}

// EncodeValue encodes the fixed fields and any nested SubTLVs.
func (t *KeepAliveIntervalTLV) EncodeValue() ([]byte, error) {
	fixedPartLen := 4 + 4 // EndpointID + Interval
	fixedValue := make([]byte, fixedPartLen)
	binary.BigEndian.PutUint32(fixedValue[0:4], uint32(t.EndpointID))
	binary.BigEndian.PutUint32(fixedValue[4:8], t.IntervalMs)

	// Encode sub-TLVs if present
	if len(t.SubTLVs) == 0 {
		return fixedValue, nil
	}

	var subTLVBuf bytes.Buffer
	for _, subTLV := range t.SubTLVs {
		if err := Encode(subTLV, &subTLVBuf); err != nil {
			return nil, fmt.Errorf("failed to encode sub-TLV type %d for KeepAliveInterval: %w", subTLV.GetType(), err)
		}
	}
	subTLVBytes := subTLVBuf.Bytes()

	// Concatenate fixed part and encoded sub-TLVs
	finalValue := make([]byte, 0, fixedPartLen+len(subTLVBytes))
	finalValue = append(finalValue, fixedValue...)
	finalValue = append(finalValue, subTLVBytes...)
	return finalValue, nil
}

// DecodeValue decodes the fixed fields and attempts to decode sub-TLVs using the profile context.
func (t *KeepAliveIntervalTLV) DecodeValue(value []byte, profile *Profile) error {
	if profile == nil {
		return errors.New("profile is required for decoding KeepAliveIntervalTLV")
	}
	fixedPartLen := 4 + 4
	if len(value) < fixedPartLen {
		return fmt.Errorf("%w: expected length >= %d for KeepAliveInterval, got %d", ErrInvalidTLVLength, fixedPartLen, len(value))
	}

	t.EndpointID = EndpointIdentifier(binary.BigEndian.Uint32(value[0:4]))
	t.IntervalMs = binary.BigEndian.Uint32(value[4:8])

	// Decode sub-TLVs if present
	if len(value) > fixedPartLen {
		subTLVBytes := value[fixedPartLen:]
		subReader := bytes.NewReader(subTLVBytes)
		// Pass profile to DecodeAll for sub-TLVs
		decodedSubTLVs, err := DecodeAll(subReader, profile)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to decode sub-TLVs for KeepAliveInterval: %w", err)
		}
		if subReader.Len() > 0 {
			return fmt.Errorf("trailing data (%d bytes) after decoding sub-TLVs for KeepAliveInterval", subReader.Len())
		}
		t.SubTLVs = decodedSubTLVs
	} else {
		t.SubTLVs = nil
	}
	return nil
}

// GetSubTLVs returns the decoded sub-TLVs.
func (t *KeepAliveIntervalTLV) GetSubTLVs() []TLVMarshaler {
	return t.SubTLVs
}

// SetSubTLVs sets the sub-TLVs.
func (t *KeepAliveIntervalTLV) SetSubTLVs(subTLVs []TLVMarshaler) error {
	t.SubTLVs = subTLVs
	return nil
}

// Helper to get interval as time.Duration
func (t *KeepAliveIntervalTLV) Interval() time.Duration {
	return time.Duration(t.IntervalMs) * time.Millisecond
}
