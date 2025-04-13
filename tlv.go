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
	Length uint16 // Length of the Value field only
	Value  []byte
	// SubTLVs are not explicitly modeled here yet but could be parsed from Value.
}

// TlvHeaderSize is the fixed size of the TLV header (Type + Length).
const TlvHeaderSize = 4 // 2 bytes for Type, 2 bytes for Length

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
// Returns io.ErrUnexpectedEOF if the value or padding cannot be fully read according
// to the length specified in the header.
func Decode(r io.Reader) (*TLV, error) {
	header := make([]byte, TlvHeaderSize)
	n, err := io.ReadFull(r, header)
	if err != nil {
		// If we read 0 bytes and hit EOF, it's a clean EOF.
		// If we read > 0 bytes but < header size and hit EOF, it's UnexpectedEOF.
		// If any other error occurs, return it wrapped.
		if errors.Is(err, io.EOF) && n == 0 {
			return nil, io.EOF // Clean EOF at the very beginning
		}
		if errors.Is(err, io.ErrUnexpectedEOF) || (errors.Is(err, io.EOF) && n > 0) {
			// Not enough bytes for a full header
			return nil, fmt.Errorf("failed to read full TLV header (read %d bytes): %w", n, io.ErrUnexpectedEOF)
		}
		// Other read errors
		return nil, fmt.Errorf("failed to read TLV header: %w", err)
	}

	tlvType := TLVType(binary.BigEndian.Uint16(header[0:2]))
	length := binary.BigEndian.Uint16(header[2:4])

	// Basic sanity check for length. RFC 7787 Section 8 limits Node Data Items
	// (which contain TLVs) to 65535 bytes total. A single TLV's value length
	// must be less than that.
	const maxTLVPossibleLength = 65535 - TlvHeaderSize
	if length > maxTLVPossibleLength {
		// This TLV claims a length that's impossible within the protocol limits.
		return nil, fmt.Errorf("%w: declared length %d exceeds maximum possible %d",
			ErrInvalidTLVLength, length, maxTLVPossibleLength)
	}

	value := make([]byte, length)
	if length > 0 {
		n, err = io.ReadFull(r, value)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// Indicate unexpected EOF if value couldn't be fully read
				return nil, fmt.Errorf("failed to read TLV value (expected %d bytes, read %d): %w",
					length, n, io.ErrUnexpectedEOF)
			}
			return nil, fmt.Errorf("failed to read TLV value: %w", err)
		}
	}

	// Calculate and consume padding
	paddingLen := (4 - (int(length) % 4)) % 4
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		n, err = io.ReadFull(r, padding)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// Indicate unexpected EOF if padding couldn't be fully read
				return nil, fmt.Errorf("failed to read TLV padding (expected %d bytes, read %d): %w",
					paddingLen, n, io.ErrUnexpectedEOF)
			}
			// Return the specific padding read error
			return nil, fmt.Errorf("failed to read TLV padding: %w", err)
		}
		// RFC 7787 Section 7: "padding bytes with a value of zero"
		// Currently, we don't enforce this strictly, just consume them.
		// for _, b := range padding {
		// 	if b != 0 {
		// 		// Log warning? Return error? Profile specific? For now, just note.
		// 		// return nil, fmt.Errorf("invalid TLV padding: non-zero byte found")
		// 	}
		// }
	}

	// If we've reached here, all parts (header, value, padding) were read successfully.
	return &TLV{
		Type:   tlvType, // Use the tlvType read at the beginning
		Length: length,  // Use the length read at the beginning
		Value:  value,   // Use the value read earlier
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
	// Check if any TLVs were decoded if EOF was the first result?
	// No, Decode handles EOF correctly if the stream is empty.
	return tlvs, nil
}
