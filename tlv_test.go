package dncp_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/fingon/go-dncp"
	"gotest.tools/v3/assert"
)

// Helper function to create a dummy profile for testing Decode
func createTestProfile() *dncp.Profile {
	return &dncp.Profile{
		NodeIdentifierLength: 8,
		HashLength:           32,
		// Other fields can be zero/nil for basic TLV decoding tests
	}
}

func TestTLVMarshalerEncodeDecode(t *testing.T) {
	profile := createTestProfile()
	nodeID := dncp.NodeIdentifier{1, 2, 3, 4, 5, 6, 7, 8}
	hash := []byte{0: 0xAA, 31: 0xBB} // 32 bytes

	testCases := []struct {
		name        string
		marshaler   dncp.TLVMarshaler
		expectedLen int // Expected total encoded length including padding
		verifyFunc  func(t *testing.T, decoded dncp.TLVMarshaler)
	}{
		{
			name:        "RequestNetworkState",
			marshaler:   &dncp.RequestNetworkStateTLV{BaseTLV: dncp.BaseTLV{TLVType: dncp.TLVTypeRequestNetworkState}},
			expectedLen: 4, // Header only
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				_, ok := decoded.(*dncp.RequestNetworkStateTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
			},
		},
		{
			name:        "RequestNodeState",
			marshaler:   dncpNewRequestNodeStateTLVMust(nodeID),
			expectedLen: 4 + 8, // Header + 8 byte NodeID
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				tlv, ok := decoded.(*dncp.RequestNodeStateTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
				assert.DeepEqual(t, nodeID, tlv.NodeID)
			},
		},
		{
			name:        "NodeEndpoint",
			marshaler:   dncpNewNodeEndpointTLVMust(nodeID, 123),
			expectedLen: 4 + 8 + 4, // Header + NodeID + EndpointID
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				tlv, ok := decoded.(*dncp.NodeEndpointTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
				assert.DeepEqual(t, nodeID, tlv.NodeID)
				assert.Equal(t, dncp.EndpointIdentifier(123), tlv.EndpointID)
			},
		},
		{
			name:        "NetworkState",
			marshaler:   dncpNewNetworkStateTLVMust(hash),
			expectedLen: 4 + 32, // Header + Hash
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				tlv, ok := decoded.(*dncp.NetworkStateTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
				assert.DeepEqual(t, hash, tlv.NetworkStateHash)
			},
		},
		{
			name:        "KeepAliveInterval (no sub-TLVs)",
			marshaler:   dncpNewKeepAliveIntervalTLVMust(5, 1500*time.Millisecond),
			expectedLen: 4 + 4 + 4, // Header + EpID + Interval
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				tlv, ok := decoded.(*dncp.KeepAliveIntervalTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
				assert.Equal(t, dncp.EndpointIdentifier(5), tlv.EndpointID)
				assert.Equal(t, uint32(1500), tlv.IntervalMs)
				assert.Assert(t, tlv.GetSubTLVs() == nil)
			},
		},
		// Add NodeState test case separately due to complexity
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Encode
			err := dncp.Encode(tc.marshaler, &buf)
			assert.NilError(t, err, "Encode failed")
			assert.Equal(t, tc.expectedLen, buf.Len(), "Encoded length mismatch")

			// Decode
			decodedTLV, err := dncp.Decode(&buf, profile)
			assert.NilError(t, err, "Decode failed")

			// Verify Type and specific fields using verifyFunc
			assert.Equal(t, tc.marshaler.GetType(), decodedTLV.GetType(), "Decoded TLV type mismatch")
			tc.verifyFunc(t, decodedTLV)
			assert.Equal(t, 0, buf.Len(), "Buffer should be empty after decoding") // Ensure padding was consumed
		})
	}
}

func TestNodeStateEncodeDecode(t *testing.T) {
	profile := createTestProfile()
	nodeID := dncp.NodeIdentifier{1, 2, 3, 4, 5, 6, 7, 8}
	hash := []byte{0: 0xAA, 31: 0xBB} // 32 bytes
	seq := uint32(100)
	ms := uint32(5000)

	// Nested TLVs
	nestedPeer := dncpNewPeerTLVMust([]byte{8, 7, 6, 5, 4, 3, 2, 1}, 1, 2)
	nestedKA := dncpNewKeepAliveIntervalTLVMust(0, 10*time.Second)

	testCases := []struct {
		name        string
		nestedTLVs  []dncp.TLVMarshaler
		expectedLen int
	}{
		{
			name:       "No nested TLVs",
			nestedTLVs: nil,
			// Header(4) + NodeID(8) + Seq(4) + Ms(4) + Hash(32) = 52
			expectedLen: 52,
		},
		{
			name:       "With nested TLVs",
			nestedTLVs: []dncp.TLVMarshaler{nestedPeer, nestedKA},
			// 52 (base) + Peer(4+8+4+4=20) + KA(4+4+4=12) = 84
			expectedLen: 84,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			marshaler, err := dncp.NewNodeStateTLV(nodeID, seq, ms, hash, tc.nestedTLVs)
			assert.NilError(t, err)

			var buf bytes.Buffer
			err = dncp.Encode(marshaler, &buf)
			assert.NilError(t, err, "Encode failed")
			assert.Equal(t, tc.expectedLen, buf.Len(), "Encoded length mismatch")

			decodedTLV, err := dncp.Decode(&buf, profile)
			assert.NilError(t, err, "Decode failed")
			assert.Equal(t, 0, buf.Len(), "Buffer should be empty after decoding")

			// Verify
			tlv, ok := decodedTLV.(*dncp.NodeStateTLV)
			assert.Assert(t, ok, "Decoded type mismatch")
			assert.Equal(t, dncp.TLVTypeNodeState, tlv.GetType())
			assert.DeepEqual(t, nodeID, tlv.NodeID)
			assert.Equal(t, seq, tlv.SequenceNumber)
			assert.Equal(t, ms, tlv.MillisecondsSinceOrigination)
			assert.DeepEqual(t, hash, tlv.DataHash)

			// Verify nested TLVs
			decodedNested := tlv.GetSubTLVs()
			assert.Equal(t, len(tc.nestedTLVs), len(decodedNested), "Nested TLV count mismatch")
			if len(tc.nestedTLVs) > 0 {
				// Note: Order might change due to sorting during encoding/hashing,
				// so direct comparison by index might fail if getOrderedTLVs is used.
				// For this test, assume EncodeValue encodes in the order provided.
				// A more robust test would check for presence regardless of order.
				assert.DeepEqual(t, tc.nestedTLVs[0], decodedNested[0])
				assert.DeepEqual(t, tc.nestedTLVs[1], decodedNested[1])
			}
		})
	}
}

func TestDecodeAllMarshalers(t *testing.T) {
	profile := createTestProfile()
	tlv1 := dncpNewRequestNetworkStateTLVMust()
	tlv2 := dncpNewRequestNodeStateTLVMust([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	tlv3 := dncpNewNodeEndpointTLVMust([]byte{8, 7, 6, 5, 4, 3, 2, 1}, 99)

	var buf bytes.Buffer
	err := dncp.Encode(tlv1, &buf)
	assert.NilError(t, err)
	err = dncp.Encode(tlv2, &buf)
	assert.NilError(t, err)
	err = dncp.Encode(tlv3, &buf)
	assert.NilError(t, err)

	expectedTotalLen := 4 + (4 + 8) + (4 + 8 + 4) // 4 + 12 + 16 = 32
	assert.Equal(t, expectedTotalLen, buf.Len())

	decodedTLVs, err := dncp.DecodeAll(&buf, profile)
	assert.NilError(t, err, "DecodeAll failed")
	assert.Equal(t, 3, len(decodedTLVs), "Decoded TLV count mismatch")
	// Simple type check for now
	assert.Equal(t, dncp.TLVTypeRequestNetworkState, decodedTLVs[0].GetType())
	assert.Equal(t, dncp.TLVTypeRequestNodeState, decodedTLVs[1].GetType())
	assert.Equal(t, dncp.TLVTypeNodeEndpoint, decodedTLVs[2].GetType())
	assert.Equal(t, 0, buf.Len(), "Buffer should be empty after DecodeAll")
}

func TestDecodeMarshalerErrors(t *testing.T) {
	profile := createTestProfile()

	t.Run("Empty reader", func(t *testing.T) {
		_, err := dncp.Decode(bytes.NewReader([]byte{}), profile)
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("Nil profile", func(t *testing.T) {
		_, err := dncp.Decode(bytes.NewReader([]byte{0, 1, 0, 0}), nil)
		assert.ErrorContains(t, err, "requires a non-nil profile")
	})

	t.Run("Incomplete header", func(t *testing.T) {
		_, err := dncp.Decode(bytes.NewReader([]byte{0x00, 0x01, 0x00}), profile) // 3 bytes only
		assert.ErrorContains(t, err, "failed to read TLV header")
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("Truncated value", func(t *testing.T) {
		// Header: Type 8 (Peer), Length 16 (8+4+4), but only 10 bytes follow
		header := []byte{0x00, 0x08, 0x00, 0x10}
		value := []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0} // Missing 6 bytes
		data := bytes.Join([][]byte{header, value}, nil)
		_, err := dncp.Decode(bytes.NewReader(data), profile)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
		assert.ErrorContains(t, err, "failed to read TLV value")
	})

	t.Run("Excessive length", func(t *testing.T) {
		headerLarge := []byte{0x00, 0x01, 0xFF, 0xFF} // Type 1, Length 65535
		_, err := dncp.Decode(bytes.NewReader(headerLarge), profile)
		assert.ErrorContains(t, err, "invalid TLV length")
		assert.ErrorContains(t, err, "exceeds maximum")
	})

	t.Run("Unknown TLV Type", func(t *testing.T) {
		headerUnknown := []byte{0xFF, 0xFF, 0x00, 0x00} // Type 65535, Length 0
		_, err := dncp.Decode(bytes.NewReader(headerUnknown), profile)
		assert.ErrorIs(t, err, dncp.ErrUnknownTLVType)
	})

	t.Run("DecodeValue Error", func(t *testing.T) {
		// Encode a valid NodeEndpoint header but with wrong length value bytes
		header := []byte{0x00, 0x03, 0x00, 0x05} // Type 3, Length 5 (invalid for NodeEndpoint with NodeIDLen=8)
		value := []byte{1, 2, 3, 4, 5}
		padding := []byte{0, 0, 0} // Add padding for length 5
		data := bytes.Join([][]byte{header, value, padding}, nil)
		_, err := dncp.Decode(bytes.NewReader(data), profile)
		assert.ErrorContains(t, err, "failed to decode value") // Error comes from NodeEndpointTLV.DecodeValue
		assert.ErrorIs(t, err, dncp.ErrInvalidTLVLength)
	})
}

func TestDecodeAllMarshalerErrors(t *testing.T) {
	profile := createTestProfile()
	tlv1 := dncpNewRequestNetworkStateTLVMust() // Valid

	var buf bytes.Buffer
	err := dncp.Encode(tlv1, &buf) // Encode valid TLV (4 bytes)
	assert.NilError(t, err)

	// Add corrupted data (incomplete header)
	buf.Write([]byte{0x00, 0x02, 0x00}) // 3 bytes only

	_, err = dncp.DecodeAll(&buf, profile)
	assert.ErrorContains(t, err, "error decoding TLV stream")
	// Check underlying error is EOF/UnexpectedEOF from the failed Decode attempt
	assert.Assert(t, errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF))
}

// --- Mocking Helpers ---

// Helper to must-create TLVs for tests
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func dncpNewRequestNetworkStateTLVMust() *dncp.RequestNetworkStateTLV {
	return &dncp.RequestNetworkStateTLV{BaseTLV: dncp.BaseTLV{TLVType: dncp.TLVTypeRequestNetworkState}}
}

func dncpNewRequestNodeStateTLVMust(nodeID dncp.NodeIdentifier) *dncp.RequestNodeStateTLV {
	return must(dncp.NewRequestNodeStateTLV(nodeID))
}

func dncpNewNodeEndpointTLVMust(nodeID dncp.NodeIdentifier, epID dncp.EndpointIdentifier) *dncp.NodeEndpointTLV {
	return must(dncp.NewNodeEndpointTLV(nodeID, epID))
}

func dncpNewNetworkStateTLVMust(hash []byte) *dncp.NetworkStateTLV {
	return must(dncp.NewNetworkStateTLV(hash))
}

func dncpNewPeerTLVMust(peerNodeID dncp.NodeIdentifier, peerEpID, localEpID dncp.EndpointIdentifier) *dncp.PeerTLV {
	return must(dncp.NewPeerTLV(peerNodeID, peerEpID, localEpID))
}

func dncpNewKeepAliveIntervalTLVMust(epID dncp.EndpointIdentifier, interval time.Duration) *dncp.KeepAliveIntervalTLV {
	return must(dncp.NewKeepAliveIntervalTLV(epID, interval))
}
