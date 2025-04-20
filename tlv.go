package dncp

import (
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
	DecodeValue(value []byte, profile *Profile) error
	// GetSubTLVs returns any nested TLVs contained within this TLV.
	// Returns nil if the TLV type does not support nesting or has no nested TLVs.
	GetSubTLVs() []TLVMarshaler
	// SetSubTLVs sets the nested TLVs for this TLV.
	// Returns an error if the TLV type does not support nesting.
	SetSubTLVs(subTLVs []TLVMarshaler) error
}

// BaseTLV provides common fields and helper methods for TLV implementations.
// It should be embedded in specific TLV structs.
type BaseTLV struct {
	TLVType TLVType
}

// GetType returns the TLV type code.
func (b *BaseTLV) GetType() TLVType {
	return b.TLVType
}

// GetSubTLVs provides a default implementation for TLVs that don't support nesting.
func (b *BaseTLV) GetSubTLVs() []TLVMarshaler {
	return nil
}

// SetSubTLVs provides a default implementation for TLVs that don't support nesting.
func (b *BaseTLV) SetSubTLVs(_ []TLVMarshaler) error {
	return fmt.Errorf("TLV type %d does not support nested TLVs", b.TLVType)
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
// It handles the header, calls the specific EncodeValue method, and adds padding.
func Encode(tlv TLVMarshaler, w io.Writer) error {
	valueBytes, err := tlv.EncodeValue()
	if err != nil {
		return fmt.Errorf("failed to encode value for TLV type %d: %w", tlv.GetType(), err)
	}

	valueLen := uint16(len(valueBytes))
	if valueLen > MaxTLVValueLength {
		return fmt.Errorf("%w: value length %d exceeds maximum %d for TLV type %d",
			ErrInvalidTLVLength, valueLen, MaxTLVValueLength, tlv.GetType())
	}

	// Calculate padding length
	paddingLen := (4 - (int(valueLen) % 4)) % 4

	// Write Header
	header := make([]byte, TlvHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], uint16(tlv.GetType()))
	binary.BigEndian.PutUint16(header[2:4], valueLen) // Length field is *value* length
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("failed to write TLV header type %d: %w", tlv.GetType(), err)
	}

	// Write Value
	if valueLen > 0 {
		if _, err := w.Write(valueBytes); err != nil {
			return fmt.Errorf("failed to write TLV value type %d: %w", tlv.GetType(), err)
		}
	}

	// Write Padding
	if paddingLen > 0 {
		padding := make([]byte, paddingLen) // Padding bytes are zero
		if _, err := w.Write(padding); err != nil {
			return fmt.Errorf("failed to write TLV padding type %d: %w", tlv.GetType(), err)
		}
	}

	return nil
}

// Decode decodes a single TLV from the provided reader using the registry.
// It requires the DNCP profile to provide context (e.g., expected lengths) for decoding specific TLV types.
// Returns io.EOF if the reader is empty or contains insufficient data for a header.
// Returns io.ErrUnexpectedEOF if the value or padding cannot be fully read.
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
		// Treat partial read or EOF after partial read as UnexpectedEOF
		return nil, fmt.Errorf("failed to read TLV header (read %d bytes): %w", nRead, io.ErrUnexpectedEOF)
	}

	tlvType := TLVType(binary.BigEndian.Uint16(header[0:2]))
	valueLen := binary.BigEndian.Uint16(header[2:4])

	// Validate length
	if valueLen > MaxTLVValueLength {
		return nil, fmt.Errorf("%w: declared length %d exceeds maximum %d for TLV type %d",
			ErrInvalidTLVLength, valueLen, MaxTLVValueLength, tlvType)
	}

	// Create instance using registry
	tlvInstance, err := newTLVInstance(tlvType)
	if err != nil {
		// Handle unknown type - skip or error? Error for now.
		// To skip, we would read and discard valueLen + padding bytes.
		return nil, fmt.Errorf("cannot create instance for TLV type %d: %w", tlvType, err)
	}

	// Read value bytes
	valueBytes := make([]byte, valueLen)
	if valueLen > 0 {
		nRead, err = io.ReadFull(r, valueBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read TLV value (type %d, expected %d, read %d): %w",
				tlvType, valueLen, nRead, io.ErrUnexpectedEOF)
		}
	}

	// Read and discard padding bytes
	paddingLen := (4 - (int(valueLen) % 4)) % 4
	if paddingLen > 0 {
		paddingBuf := make([]byte, paddingLen)
		nRead, err = io.ReadFull(r, paddingBuf)
		if err != nil {
			return nil, fmt.Errorf("failed to read TLV padding (type %d, expected %d, read %d): %w",
				tlvType, paddingLen, nRead, io.ErrUnexpectedEOF)
		}
		// Could optionally check if padding bytes are zero here.
	}

	// Decode the value using the specific type's method, passing the profile
	if err := tlvInstance.DecodeValue(valueBytes, profile); err != nil {
		return nil, fmt.Errorf("failed to decode value for TLV type %d: %w", tlvType, err)
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
