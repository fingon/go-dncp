package dncp_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/fingon/go-dncp" // Use alias if package name is dncp
	"gotest.tools/v3/assert"
)

func TestTLVEncodeDecode(t *testing.T) {
	testCases := []struct {
		name        string
		tlv         *dncp.TLV
		expectedLen int // Expected total encoded length including padding
	}{
		{
			name: "Zero length value",
			tlv: &dncp.TLV{
				Type:   dncp.TLVTypeRequestNetworkState,
				Length: 0,
				Value:  []byte{},
			},
			expectedLen: 4, // Header only
		},
		{
			name: "1 byte value (needs 3 padding)",
			tlv: &dncp.TLV{
				Type:   dncp.TLVTypeNodeEndpoint,
				Length: 1,
				Value:  []byte{0xAA},
			},
			expectedLen: 8, // 4 header + 1 value + 3 padding
		},
		{
			name: "2 byte value (needs 2 padding)",
			tlv: &dncp.TLV{
				Type:   dncp.TLVTypeNetworkState,
				Length: 2,
				Value:  []byte{0xBB, 0xCC},
			},
			expectedLen: 8, // 4 header + 2 value + 2 padding
		},
		{
			name: "3 byte value (needs 1 padding)",
			tlv: &dncp.TLV{
				Type:   dncp.TLVTypeNodeState,
				Length: 3,
				Value:  []byte{0xDD, 0xEE, 0xFF},
			},
			expectedLen: 8, // 4 header + 3 value + 1 padding
		},
		{
			name: "4 byte value (no padding needed)",
			tlv: &dncp.TLV{
				Type:   dncp.TLVTypePeer,
				Length: 4,
				Value:  []byte{0x11, 0x22, 0x33, 0x44},
			},
			expectedLen: 8, // 4 header + 4 value
		},
		{
			name: "Longer value (multiple of 4)",
			tlv: &dncp.TLV{
				Type:   dncp.TLVTypeKeepAliveInterval,
				Length: 8,
				Value:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			expectedLen: 12, // 4 header + 8 value
		},
		{
			name: "Longer value (not multiple of 4)",
			tlv: &dncp.TLV{
				Type:   dncp.TLVTypeTrustVerdict,
				Length: 6,
				Value:  []byte{9, 8, 7, 6, 5, 4},
			},
			expectedLen: 12, // 4 header + 6 value + 2 padding
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Encode
			err := tc.tlv.Encode(&buf)
			assert.NilError(t, err, "Encode failed")
			assert.Equal(t, tc.expectedLen, buf.Len(), "Encoded length mismatch")

			// Decode
			decodedTLV, err := dncp.Decode(&buf)
			assert.NilError(t, err, "Decode failed")

			// Verify
			assert.DeepEqual(t, tc.tlv, decodedTLV)
			assert.Equal(t, 0, buf.Len(), "Buffer should be empty after decoding") // Ensure padding was consumed
		})
	}
}

func TestDecodeAll(t *testing.T) {
	tlv1 := &dncp.TLV{Type: 1, Length: 1, Value: []byte{0x01}}                   // Encodes to 8 bytes
	tlv2 := &dncp.TLV{Type: 2, Length: 4, Value: []byte{0x02, 0x03, 0x04, 0x05}} // Encodes to 8 bytes
	tlv3 := &dncp.TLV{Type: 3, Length: 0, Value: []byte{}}                       // Encodes to 4 bytes

	var buf bytes.Buffer
	err := tlv1.Encode(&buf)
	assert.NilError(t, err)
	err = tlv2.Encode(&buf)
	assert.NilError(t, err)
	err = tlv3.Encode(&buf)
	assert.NilError(t, err)

	expectedTotalLen := 20 // 8 + 8 + 4
	assert.Equal(t, expectedTotalLen, buf.Len())

	decodedTLVs, err := dncp.DecodeAll(&buf)
	assert.NilError(t, err, "DecodeAll failed")
	assert.Equal(t, 3, len(decodedTLVs), "Incorrect number of TLVs decoded")
	assert.Equal(t, 0, buf.Len(), "Buffer should be empty after DecodeAll")

	assert.DeepEqual(t, tlv1, decodedTLVs[0])
	assert.DeepEqual(t, tlv2, decodedTLVs[1])
	assert.DeepEqual(t, tlv3, decodedTLVs[2])
}

func TestDecodeErrors(t *testing.T) {
	t.Run("Empty reader", func(t *testing.T) {
		_, err := dncp.Decode(bytes.NewReader([]byte{}))
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("Incomplete header", func(t *testing.T) {
		_, err := dncp.Decode(bytes.NewReader([]byte{0x00, 0x01, 0x00})) // 3 bytes only
		assert.ErrorContains(t, err, "failed to read full TLV header")
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("Truncated value", func(t *testing.T) {
		// Header declares length 4, but only 2 bytes follow
		header := []byte{0x00, 0x08, 0x00, 0x04} // Type 8, Length 4
		value := []byte{0xAA, 0xBB}
		data := make([]byte, 0, len(header)+len(value))
		data = append(data, header...)
		data = append(data, value...)
		_, err := dncp.Decode(bytes.NewReader(data))
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
		assert.ErrorContains(t, err, "failed to read TLV value")
	})

	t.Run("Truncated padding", func(t *testing.T) {
		// Header declares length 1 (needs 3 padding), but only 2 padding bytes follow
		header := []byte{0x00, 0x03, 0x00, 0x01} // Type 3, Length 1
		value := []byte{0xCC}
		padding := []byte{0x00, 0x00} // Missing one padding byte
		data := make([]byte, 0, len(header)+len(value)+len(padding))
		data = append(data, header...)
		data = append(data, value...)
		data = append(data, padding...)
		_, err := dncp.Decode(bytes.NewReader(data))
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
		assert.ErrorContains(t, err, "failed to read TLV padding")
	})

	t.Run("Excessive length", func(t *testing.T) {
		// Header declares length 65535 (using max uint16 conceptually)
		// We test against our internal maxReasonableLength
		headerLarge := []byte{0x00, 0x01, 0xFF, 0xFF} // Type 1, Length 65535
		_, err := dncp.Decode(bytes.NewReader(headerLarge))
		assert.ErrorContains(t, err, "invalid TLV length")
		assert.ErrorContains(t, err, "exceeds maximum possible")
	})

	// Note: Non-zero padding bytes are currently ignored, not causing an error.
	t.Run("Non-zero padding", func(t *testing.T) {
		// Header: Type 1, Length 1. Value: 0xAA. Padding: 0x00, 0x00, 0x01 (invalid)
		data := []byte{0x00, 0x01, 0x00, 0x01, 0xAA, 0x00, 0x00, 0x01}
		tlv, err := dncp.Decode(bytes.NewReader(data))
		assert.NilError(t, err) // Currently no error for non-zero padding
		assert.Assert(t, tlv != nil)
		assert.Equal(t, dncp.TLVType(1), tlv.Type)
		assert.Equal(t, uint16(1), tlv.Length)
		assert.DeepEqual(t, []byte{0xAA}, tlv.Value)
	})
}

func TestDecodeAllErrors(t *testing.T) {
	tlv1 := &dncp.TLV{Type: 1, Length: 1, Value: []byte{0x01}} // Valid

	var buf bytes.Buffer
	err := tlv1.Encode(&buf) // Encode valid TLV (8 bytes)
	assert.NilError(t, err)

	// Add corrupted data (incomplete header)
	buf.Write([]byte{0x00, 0x02, 0x00}) // 3 bytes only

	_, err = dncp.DecodeAll(&buf)
	assert.ErrorContains(t, err, "error decoding TLV stream")
	// Check underlying error is EOF/UnexpectedEOF from the failed Decode attempt
	assert.Assert(t, errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF))
}

func TestEncodeErrors(t *testing.T) {
	t.Run("Length mismatch", func(t *testing.T) {
		tlv := &dncp.TLV{
			Type:   1,
			Length: 5, // Incorrect length
			Value:  []byte{1, 2, 3, 4},
		}
		var buf bytes.Buffer
		err := tlv.Encode(&buf)
		assert.ErrorIs(t, err, dncp.ErrInvalidTLVLength)
		assert.ErrorContains(t, err, "value length 4 does not match header length 5")
	})

	t.Run("Write header error", func(t *testing.T) {
		tlv := &dncp.TLV{Type: 1, Length: 0, Value: []byte{}}
		writer := &failingWriter{failOn: "header"} // Use the package-level type
		err := tlv.Encode(writer)
		assert.ErrorContains(t, err, "failed to write TLV header")
	})

	t.Run("Write value error", func(t *testing.T) {
		tlv := &dncp.TLV{Type: 1, Length: 1, Value: []byte{1}}
		writer := &failingWriter{failOn: "value"}
		err := tlv.Encode(writer)
		assert.ErrorContains(t, err, "failed to write TLV value")
	})

	t.Run("Write padding error", func(t *testing.T) {
		tlv := &dncp.TLV{Type: 1, Length: 1, Value: []byte{1}} // Needs padding
		writer := &failingWriter{failOn: "padding"}
		err := tlv.Encode(writer)
		assert.ErrorContains(t, err, "failed to write TLV padding")
	})
}

// Mock writer to simulate write errors
type failingWriter struct {
	written int
	failOn  string // "header", "value", "padding"
}

func (fw *failingWriter) Write(p []byte) (n int, err error) {
	// Determine the expected write stage based on bytes already written
	isHeaderWrite := fw.written == 0
	isValueWrite := fw.written == dncp.TlvHeaderSize
	// Padding write happens after header and potential value bytes
	// This check is approximate and assumes a TLV that requires padding for the "padding" case.
	isPaddingWrite := fw.written > dncp.TlvHeaderSize

	// Check for failure conditions
	if fw.failOn == "header" && isHeaderWrite {
		return 0, errors.New("simulated: failed to write header")
	}
	if fw.failOn == "value" && isValueWrite {
		return 0, errors.New("simulated: failed to write value")
	}
	if fw.failOn == "padding" && isPaddingWrite {
		// This condition might trigger prematurely if value write is chunked,
		// but for Encode's current behavior, it should work.
		return 0, errors.New("simulated: failed to write padding")
	}

	// If no failure condition met, proceed with tracking written bytes
	fw.written += len(p)
	return len(p), nil
}
