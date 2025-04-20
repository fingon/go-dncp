package dncp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// TLVType represents the type of a DNCP TLV.
// Use exported constants like TLVTypeRequestNetworkState etc.
type TLVType uint16

// Standard DNCP TLV Types (RFC 7787 Section 11).
const (
	TLVTypeRequestNetworkState TLVType = 1
	TLVTypeRequestNodeState    TLVType = 2
	TLVTypeNodeEndpoint        TLVType = 3
	TLVTypeNetworkState        TLVType = 4
	TLVTypeNodeState           TLVType = 5
	// 6, 7 Reserved
	TLVTypePeer              TLVType = 8
	TLVTypeKeepAliveInterval TLVType = 9
	TLVTypeTrustVerdict      TLVType = 10
	// 11-31 Unassigned
	// 32-511 Reserved for per-DNCP profile use
	// 512-767 Unassigned
	// 768-1023 Reserved for Private Use
	// 1024-65535 Reserved for future use
)

// TlvHeaderSize is the fixed size of the TLV header (Type + Length).
const TlvHeaderSize = 4 // 2 bytes for Type, 2 bytes for Length

// MaxTLVValueLength is the maximum length of the Value field in a TLV.
// A single TLV's value cannot exceed this.
const MaxTLVValueLength = 65535 - TlvHeaderSize

// ErrInvalidTLVLength indicates a TLV record has an invalid length.
var ErrInvalidTLVLength = errors.New("invalid TLV length")

// ErrBufferTooSmall indicates the provided buffer is too small for the operation.
var ErrBufferTooSmall = errors.New("buffer too small")

// ErrNestedEncode indicates an error occurred while encoding nested TLVs.
var ErrUnknownTLVType = errors.New("unknown TLV type")

// TLVMarshaler defines the interface for specific TLV types.
type TLVMarshaler interface {
	// GetType returns the TLV type code.
	GetType() TLVType
	// EncodeValue encodes the specific TLV's fields into a byte slice representing the Value part.
	// It should return the raw value bytes *without* header or padding.
	EncodeValue() ([]byte, error)
	// DecodeValue decodes the specific TLV's fields from the provided Value byte slice.
	// The input slice contains only the Value part (no header or padding).
	// The profile provides context like expected lengths.
	// Returns the number of bytes consumed from the value slice by this TLV's specific fields.
	DecodeValue(value []byte, profile *Profile) (consumedBytes int, err error)
	// GetSubTLVs returns any nested TLVs contained within this TLV.
	GetSubTLVs() []TLVMarshaler
	// SetSubTLVs sets the nested TLVs for this TLV.
	// Returns an error if the TLV type does not support nesting.
	SetSubTLVs(subTLVs []TLVMarshaler) error
}

// BaseTLV provides common fields and helper methods for TLV implementations.
// It should be embedded in specific TLV structs.
type BaseTLV struct {
	TLVType TLVType
	SubTLVs []TLVMarshaler // Holds any decoded sub-TLVs
}

// GetType returns the TLV type code.
func (b *BaseTLV) GetType() TLVType {
	return b.TLVType
}

// GetSubTLVs returns the decoded sub-TLVs.
func (b *BaseTLV) GetSubTLVs() []TLVMarshaler {
	return b.SubTLVs
}

// SetSubTLVs sets the decoded sub-TLVs.
func (b *BaseTLV) SetSubTLVs(subTLVs []TLVMarshaler) error {
	b.SubTLVs = subTLVs
	return nil
}

// --- TLV Registry ---

// tlvFactory is a function that creates a new instance of a specific TLVMarshaler.
type tlvFactory func() TLVMarshaler

var (
	registry = make(map[TLVType]tlvFactory)
	regMux   sync.RWMutex
)

// RegisterTLVType registers a factory function for a specific TLV type.
// This should be called during initialization (e.g., in init() functions).
func RegisterTLVType(tlvType TLVType, factory tlvFactory) {
	regMux.Lock()
	defer regMux.Unlock()
	if _, exists := registry[tlvType]; exists {
		// Allow re-registration? Or panic? Panic for now to catch issues early.
		panic(fmt.Sprintf("TLV type %d already registered", tlvType))
	}
	registry[tlvType] = factory
}

// newTLVInstance creates a new TLVMarshaler instance for the given type using the registry.
func newTLVInstance(tlvType TLVType) (TLVMarshaler, error) {
	regMux.RLock()
	factory, exists := registry[tlvType]
	regMux.RUnlock()
	if !exists {
		// Allow unknown TLVs? For now, return error.
		// Could potentially return a generic "UnknownTLV" type.
		return nil, fmt.Errorf("%w: %d", ErrUnknownTLVType, tlvType)
	}
	return factory(), nil
}

// --- Generic Encoding/Decoding ---

// Encode encodes a TLVMarshaler into the provided writer.
// It handles the header, calls EncodeValue for specific fields, encodes SubTLVs, and adds padding.
func Encode(tlv TLVMarshaler, w io.Writer) error {
	// 1. Encode specific value fields
	specificValueBytes, err := tlv.EncodeValue()
	if err != nil {
		return fmt.Errorf("failed to encode specific value for TLV type %d: %w", tlv.GetType(), err)
	}

	// 2. Encode SubTLVs if present
	var subTLVBytes []byte
	subTLVs := tlv.GetSubTLVs()
	if len(subTLVs) > 0 {
		var subBuf bytes.Buffer
		for _, sub := range subTLVs {
			if err := Encode(sub, &subBuf); err != nil { // Recursive call to handle sub-sub-TLVs etc.
				return fmt.Errorf("failed to encode sub-TLV type %d for TLV type %d: %w", sub.GetType(), tlv.GetType(), err)
			}
		}
		subTLVBytes = subBuf.Bytes()
	}

	// 3. Combine specific value and sub-TLVs
	combinedValueBytes := make([]byte, 0, len(specificValueBytes)+len(subTLVBytes))
	combinedValueBytes = append(combinedValueBytes, specificValueBytes...)
	combinedValueBytes = append(combinedValueBytes, subTLVBytes...)

	// 4. Calculate total length and padding
	totalValueLen := uint16(len(combinedValueBytes))
	if totalValueLen > MaxTLVValueLength {
		return fmt.Errorf("%w: total value length %d (specific + sub-TLVs) exceeds maximum %d for TLV type %d",
			ErrInvalidTLVLength, totalValueLen, MaxTLVValueLength, tlv.GetType())
	}
	paddingLen := (4 - (int(totalValueLen) % 4)) % 4

	// 5. Write Header
	header := make([]byte, TlvHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], uint16(tlv.GetType()))
	binary.BigEndian.PutUint16(header[2:4], totalValueLen) // Length field is total value length
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("failed to write TLV header type %d: %w", tlv.GetType(), err)
	}

	// 6. Write Combined Value
	if totalValueLen > 0 {
		if _, err := w.Write(combinedValueBytes); err != nil {
			return fmt.Errorf("failed to write TLV combined value type %d: %w", tlv.GetType(), err)
		}
	}

	// 7. Write Padding
	if paddingLen > 0 {
		padding := make([]byte, paddingLen) // Padding bytes are zero
		if _, err := w.Write(padding); err != nil {
			return fmt.Errorf("failed to write TLV padding type %d: %w", tlv.GetType(), err)
		}
	}

	return nil
}

// Decode decodes a single TLV from the provided reader using the registry.
// It requires the DNCP profile for context. Handles decoding of sub-TLVs if present.
// Returns io.EOF if the reader is empty or contains insufficient data for a header.
// Returns io.ErrUnexpectedEOF if the value, sub-TLVs, or padding cannot be fully read.
func Decode(r io.Reader, profile *Profile) (TLVMarshaler, error) {
	if profile == nil {
		return nil, errors.New("decode requires a non-nil profile")
	}
	header := make([]byte, TlvHeaderSize)
	nRead, err := io.ReadFull(r, header)
	if err != nil {
		if errors.Is(err, io.EOF) && nRead == 0 {
			return nil, io.EOF // Clean EOF at the start
		}
		return nil, fmt.Errorf("failed to read TLV header (read %d bytes): %w", nRead, io.ErrUnexpectedEOF)
	}

	tlvType := TLVType(binary.BigEndian.Uint16(header[0:2]))
	totalValueLen := binary.BigEndian.Uint16(header[2:4]) // This is the length of specific value + sub-TLVs

	if totalValueLen > MaxTLVValueLength {
		return nil, fmt.Errorf("%w: declared length %d exceeds maximum %d for TLV type %d",
			ErrInvalidTLVLength, totalValueLen, MaxTLVValueLength, tlvType)
	}

	// Create instance using registry
	tlvInstance, err := newTLVInstance(tlvType)
	if err != nil {
		// Read and discard the value and padding for unknown types before returning error
		bytesToDiscard := int(totalValueLen) + (4-(int(totalValueLen)%4))%4
		if bytesToDiscard > 0 {
			if _, discardErr := io.CopyN(io.Discard, r, int64(bytesToDiscard)); discardErr != nil {
				return nil, fmt.Errorf("failed to discard value/padding for unknown TLV type %d: %w (original error: %v)", tlvType, discardErr, err)
			}
		}
		return nil, fmt.Errorf("cannot create instance for TLV type %d: %w", tlvType, err)
	}

	// Read the entire value section (specific fields + sub-TLVs)
	fullValueBytes := make([]byte, totalValueLen)
	if totalValueLen > 0 {
		nRead, err = io.ReadFull(r, fullValueBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read TLV full value (type %d, expected %d, read %d): %w",
				tlvType, totalValueLen, nRead, io.ErrUnexpectedEOF)
		}
	}

	// Read and discard padding bytes for the *total* value length
	paddingLen := (4 - (int(totalValueLen) % 4)) % 4
	if paddingLen > 0 {
		paddingBuf := make([]byte, paddingLen)
		nRead, err = io.ReadFull(r, paddingBuf)
		if err != nil {
			return nil, fmt.Errorf("failed to read TLV padding (type %d, expected %d, read %d): %w",
				tlvType, paddingLen, nRead, io.ErrUnexpectedEOF)
		}
	}

	// Decode the specific fields using the type's method, passing the full value buffer
	consumedBytes, err := tlvInstance.DecodeValue(fullValueBytes, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to decode specific value for TLV type %d: %w", tlvType, err)
	}

	// Check if bytes were consumed correctly
	if consumedBytes < 0 || consumedBytes > int(totalValueLen) {
		return nil, fmt.Errorf("invalid consumed bytes count %d returned by DecodeValue for TLV type %d (total value len %d)",
			consumedBytes, tlvType, totalValueLen)
	}

	// Decode sub-TLVs if there are remaining bytes
	if consumedBytes < int(totalValueLen) {
		subTLVBytes := fullValueBytes[consumedBytes:]
		subReader := bytes.NewReader(subTLVBytes)
		decodedSubTLVs, err := DecodeAll(subReader, profile) // Recursive call
		if err != nil && !errors.Is(err, io.EOF) {           // EOF is okay if DecodeAll reads everything
			return nil, fmt.Errorf("failed to decode sub-TLVs for TLV type %d: %w", tlvType, err)
		}
		// Check if all sub-TLV bytes were consumed
		if subReader.Len() > 0 {
			return nil, fmt.Errorf("trailing data (%d bytes) after decoding sub-TLVs for TLV type %d", subReader.Len(), tlvType)
		}
		// Set the decoded sub-TLVs on the main TLV instance
		if err := tlvInstance.SetSubTLVs(decodedSubTLVs); err != nil {
			// This error might occur if the base SetSubTLVs wasn't overridden correctly,
			// but the default BaseTLV implementation now handles it.
			return nil, fmt.Errorf("failed to set sub-TLVs for TLV type %d: %w", tlvType, err)
		}
	}

	return tlvInstance, nil
}

// DecodeAll decodes all TLVs from the reader until EOF, using the provided profile context.
func DecodeAll(r io.Reader, profile *Profile) ([]TLVMarshaler, error) {
	if profile == nil {
		return nil, errors.New("decodeAll requires a non-nil profile")
	}
	var tlvs []TLVMarshaler
	for {
		tlv, err := Decode(r, profile)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // Normal end of stream
			}
			// Return other errors, potentially wrapping them for context
			return tlvs, fmt.Errorf("error decoding TLV stream: %w", err) // Return partially decoded TLVs and the error
		}
		tlvs = append(tlvs, tlv)
	}
	return tlvs, nil
}
