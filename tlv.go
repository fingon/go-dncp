package dncp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

// TLV represents a single Type-Length-Value object as defined in RFC 7787 Section 7.
type TLV struct {
	Type   TLVType
	Length uint16 // Length of the Value field only (excluding padding)
	Value  []byte // The raw value bytes
	// SubTLVs are not explicitly modeled here; they are part of the Value.
}

// TlvHeaderSize is the fixed size of the TLV header (Type + Length).
const TlvHeaderSize = 4 // 2 bytes for Type, 2 bytes for Length

// MaxTLVValueLength is derived from the maximum node data size (64KB).
// A single TLV's value cannot exceed this.
const MaxTLVValueLength = 65535 - TlvHeaderSize

// ErrInvalidTLVLength indicates a TLV record has an invalid length.
var ErrInvalidTLVLength = errors.New("invalid TLV length")

// ErrBufferTooSmall indicates the provided buffer is too small for the operation.
var ErrBufferTooSmall = errors.New("buffer too small")

// Encode encodes the TLV into the provided writer.
// It handles padding to the next 4-byte boundary.
func (t *TLV) Encode(w io.Writer) error {
	// Validate length before encoding
	if len(t.Value) != int(t.Length) {
		return fmt.Errorf("%w: value length %d does not match header length %d",
			ErrInvalidTLVLength, len(t.Value), t.Length)
	}

	header := make([]byte, TlvHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], uint16(t.Type))
	binary.BigEndian.PutUint16(header[2:4], t.Length)

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("failed to write TLV header: %w", err)
	}

	if len(t.Value) > 0 {
		if _, err := w.Write(t.Value); err != nil {
			return fmt.Errorf("failed to write TLV value: %w", err)
		}
	}

	// Calculate padding required to reach a 4-byte boundary
	paddingLen := (4 - (int(t.Length) % 4)) % 4
	if paddingLen > 0 {
		padding := make([]byte, paddingLen) // Padding bytes are zero
		if _, err := w.Write(padding); err != nil {
			return fmt.Errorf("failed to write TLV padding: %w", err)
		}
	}

	return nil
}

// Decode decodes a single TLV from the provided reader.
// It reads the header, value, and consumes any required padding bytes.
// Returns io.EOF if the reader is empty or contains insufficient data for a header.
// Returns io.ErrUnexpectedEOF if the value or padding cannot be fully read
// according to the length specified in the header.
func Decode(r io.Reader) (*TLV, error) {
	header := make([]byte, TlvHeaderSize)
	nRead, err := io.ReadFull(r, header)
	if err != nil {
		// Handle EOF cases specifically
		if errors.Is(err, io.EOF) {
			// Clean EOF only if 0 bytes were read. Otherwise, it's unexpected.
			if nRead == 0 {
				return nil, io.EOF
			}
			err = io.ErrUnexpectedEOF // Treat partial read + EOF as UnexpectedEOF
		}
		// Wrap other errors or UnexpectedEOF
		return nil, fmt.Errorf("failed to read TLV header (read %d bytes): %w", nRead, err)
	}

	tlvType := TLVType(binary.BigEndian.Uint16(header[0:2]))
	length := binary.BigEndian.Uint16(header[2:4])

	// Validate length against maximum possible value length
	if length > MaxTLVValueLength {
		return nil, fmt.Errorf("%w: declared length %d exceeds maximum possible %d",
			ErrInvalidTLVLength, length, MaxTLVValueLength)
	}

	// Read value bytes
	value := make([]byte, length)
	if length > 0 {
		nRead, err = io.ReadFull(r, value)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF // EOF during value read is always unexpected
			}
			return nil, fmt.Errorf("failed to read TLV value (expected %d bytes, read %d): %w",
				length, nRead, err)
		}
	}

	// Calculate and consume padding bytes
	paddingLen := (4 - (int(length) % 4)) % 4
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		nRead, err = io.ReadFull(r, padding)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF // EOF during padding read is always unexpected
			}
			return nil, fmt.Errorf("failed to read TLV padding (expected %d bytes, read %d): %w",
				paddingLen, nRead, err)
		}
		// Optional: Verify padding is all zeros
		// for _, b := range padding {
		// 	if b != 0 {
		// 		// Log warning? Return error? Profile specific? For now, just note.
		// 		// return nil, fmt.Errorf("invalid TLV padding: non-zero byte found")
		// 	}
		// }
	}

	// Successfully read header, value, and padding
	return &TLV{
		Type:   tlvType,
		Length: length,
		Value:  value,
	}, nil
}

// DecodeAll decodes all TLVs from the reader until EOF.
func DecodeAll(r io.Reader) ([]*TLV, error) {
	var tlvs []*TLV
	for {
		tlv, err := Decode(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // Normal end of stream
			}
			// Return other errors, potentially wrapping them for context
			return nil, fmt.Errorf("error decoding TLV stream: %w", err)
		}
		tlvs = append(tlvs, tlv)
	}
	// Decode handles EOF correctly if the stream is initially empty.
	return tlvs, nil
}
