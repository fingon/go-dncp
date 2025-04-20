package dncp_test

import (
	"bytes"
	"encoding/binary" // Add missing import
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
		expectedLen int // Expected total encoded length including header and padding
		verifyFunc  func(t *testing.T, decoded dncp.TLVMarshaler)
	}{
		{
			name:        "RequestNetworkState (no sub-TLVs)",
			marshaler:   &dncp.RequestNetworkStateTLV{BaseTLV: dncp.BaseTLV{TLVType: dncp.TLVTypeRequestNetworkState}},
			expectedLen: 4, // Header only
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				tlv, ok := decoded.(*dncp.RequestNetworkStateTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
				assert.Assert(t, tlv.GetSubTLVs() == nil) // Verify no sub-TLVs decoded
			},
		},
		{
			name: "RequestNetworkState (with sub-TLV)",
			marshaler: func() dncp.TLVMarshaler {
				m := &dncp.RequestNetworkStateTLV{BaseTLV: dncp.BaseTLV{TLVType: dncp.TLVTypeRequestNetworkState}}
				sub, _ := dncp.NewKeepAliveIntervalTLV(1, 1000*time.Millisecond)
				_ = m.SetSubTLVs([]dncp.TLVMarshaler{sub})
				return m
			}(),
			expectedLen: 4 + (4 + 4 + 4), // Header + KeepAlive(Header+EpID+Interval)
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				tlv, ok := decoded.(*dncp.RequestNetworkStateTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
				subTLVs := tlv.GetSubTLVs()
				assert.Equal(t, 1, len(subTLVs), "Expected 1 sub-TLV")
				subKA, ok := subTLVs[0].(*dncp.KeepAliveIntervalTLV)
				assert.Assert(t, ok, "Sub-TLV type mismatch")
				assert.Equal(t, dncp.EndpointIdentifier(1), subKA.EndpointID)
				assert.Equal(t, uint32(1000), subKA.IntervalMs)
			},
		},
		{
			name:        "RequestNodeState (no sub-TLVs)",
			marshaler:   dncpNewRequestNodeStateTLVMust(nodeID),
			expectedLen: 4 + 8, // Header + 8 byte NodeID
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				tlv, ok := decoded.(*dncp.RequestNodeStateTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
				assert.DeepEqual(t, nodeID, tlv.NodeID)
				assert.Assert(t, tlv.GetSubTLVs() == nil)
			},
		},
		{
			name:        "NodeEndpoint (no sub-TLVs)",
			marshaler:   dncpNewNodeEndpointTLVMust(nodeID, 123),
			expectedLen: 4 + 8 + 4, // Header + NodeID + EndpointID
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				tlv, ok := decoded.(*dncp.NodeEndpointTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
				assert.DeepEqual(t, nodeID, tlv.NodeID)
				assert.Equal(t, dncp.EndpointIdentifier(123), tlv.EndpointID)
				assert.Assert(t, tlv.GetSubTLVs() == nil)
			},
		},
		{
			name:        "NetworkState (no sub-TLVs)",
			marshaler:   dncpNewNetworkStateTLVMust(hash),
			expectedLen: 4 + 32, // Header + Hash
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				tlv, ok := decoded.(*dncp.NetworkStateTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
				assert.DeepEqual(t, hash, tlv.NetworkStateHash)
				assert.Assert(t, tlv.GetSubTLVs() == nil)
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
				assert.Assert(t, tlv.GetSubTLVs() == nil) // Explicitly check no sub-TLVs decoded
			},
		},
		{
			name: "KeepAliveInterval (with sub-TLV)",
			marshaler: func() dncp.TLVMarshaler {
				m := dncpNewKeepAliveIntervalTLVMust(5, 1500*time.Millisecond)
				sub, _ := dncp.NewRequestNodeStateTLV([]byte{9, 9, 9, 9, 9, 9, 9, 9})
				_ = m.SetSubTLVs([]dncp.TLVMarshaler{sub})
				return m
			}(),
			expectedLen: 4 + (4 + 4) + (4 + 8), // Header + KA(EpID+Interval) + ReqNodeState(Header+NodeID)
			verifyFunc: func(t *testing.T, decoded dncp.TLVMarshaler) {
				tlv, ok := decoded.(*dncp.KeepAliveIntervalTLV)
				assert.Assert(t, ok, "Decoded type mismatch")
				assert.Equal(t, dncp.EndpointIdentifier(5), tlv.EndpointID)
				assert.Equal(t, uint32(1500), tlv.IntervalMs)
				subTLVs := tlv.GetSubTLVs()
				assert.Equal(t, 1, len(subTLVs), "Expected 1 sub-TLV")
				subRNS, ok := subTLVs[0].(*dncp.RequestNodeStateTLV)
				assert.Assert(t, ok, "Sub-TLV type mismatch")
				assert.DeepEqual(t, dncp.NodeIdentifier{9, 9, 9, 9, 9, 9, 9, 9}, subRNS.NodeID)
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

	// Nested TLVs (Node Data)
	// IMPORTANT: Order matters for hashing, but Decode should handle any order.
	// Encode sorts them based on binary representation.
	nodeDataPeer := dncpNewPeerTLVMust([]byte{8, 7, 6, 5, 4, 3, 2, 1}, 1, 2) // Encodes to 20 bytes
	nodeDataKA := dncpNewKeepAliveIntervalTLVMust(0, 10*time.Second)         // Encodes to 12 bytes

	// Calculate expected lengths
	baseLen := 4 + 8 + 4 + 4 + 32 // Header + NodeID + Seq + Ms + Hash = 52
	peerLen := 4 + 8 + 4 + 4      // Peer TLV: Header + PeerNodeID + PeerEpID + LocalEpID = 20
	kaLen := 4 + 4 + 4            // KA TLV: Header + EpID + Interval = 12

	testCases := []struct {
		name        string
		nodeData    []dncp.TLVMarshaler // These are the "nested" TLVs for NodeState
		expectedLen int
	}{
		{
			name:        "No Node Data",
			nodeData:    nil,
			expectedLen: baseLen,
		},
		{
			name:        "With Node Data (Peer, KA)",
			nodeData:    []dncp.TLVMarshaler{nodeDataPeer, nodeDataKA}, // Order here doesn't affect final length
			expectedLen: baseLen + peerLen + kaLen,                     // 52 + 20 + 12 = 84
		},
		{
			name:        "With Node Data (KA, Peer)",
			nodeData:    []dncp.TLVMarshaler{nodeDataKA, nodeDataPeer}, // Different order, same length
			expectedLen: baseLen + kaLen + peerLen,                     // 52 + 12 + 20 = 84
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create NodeState TLV with the specified Node Data (nested TLVs)
			marshaler, err := dncp.NewNodeStateTLV(nodeID, seq, ms, hash, tc.nodeData)
			assert.NilError(t, err)

			var buf bytes.Buffer
			err = dncp.Encode(marshaler, &buf)
			assert.NilError(t, err, "Encode failed")
			assert.Equal(t, tc.expectedLen, buf.Len(), "Encoded length mismatch")

			// Decode
			decodedTLV, err := dncp.Decode(&buf, profile)
			assert.NilError(t, err, "Decode failed")
			assert.Equal(t, 0, buf.Len(), "Buffer should be empty after decoding")

			// Verify Base Fields
			tlv, ok := decodedTLV.(*dncp.NodeStateTLV)
			assert.Assert(t, ok, "Decoded type mismatch")
			assert.Equal(t, dncp.TLVTypeNodeState, tlv.GetType())
			assert.DeepEqual(t, nodeID, tlv.NodeID)
			assert.Equal(t, seq, tlv.SequenceNumber)
			assert.Equal(t, ms, tlv.MillisecondsSinceOrigination)
			assert.DeepEqual(t, hash, tlv.DataHash)

			// Verify Node Data (Sub-TLVs)
			decodedNodeData := tlv.GetSubTLVs()
			assert.Equal(t, len(tc.nodeData), len(decodedNodeData), "Node Data TLV count mismatch")

			// Verify presence and content of Node Data TLVs, ignoring order
			foundPeer := false
			foundKA := false
			for _, decodedSub := range decodedNodeData {
				switch sub := decodedSub.(type) {
				case *dncp.PeerTLV:
					// Remove the message string from DeepEqual
					assert.DeepEqual(t, nodeDataPeer, sub)
					foundPeer = true
				case *dncp.KeepAliveIntervalTLV:
					// Remove the message string from DeepEqual
					assert.DeepEqual(t, nodeDataKA, sub)
					foundKA = true
				default:
					t.Fatalf("Unexpected Node Data TLV type: %T", decodedSub)
				}
			}

			if len(tc.nodeData) > 0 {
				assert.Assert(t, foundPeer, "Peer TLV not found in decoded Node Data")
				assert.Assert(t, foundKA, "KeepAliveInterval TLV not found in decoded Node Data")
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
		assert.ErrorContains(t, err, "failed to read TLV full value")
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
		assert.ErrorContains(t, err, "failed to decode specific value") // Error comes from NodeEndpointTLV.DecodeValue
		assert.ErrorIs(t, err, dncp.ErrInvalidTLVLength)
	})

	t.Run("Trailing data after sub-TLVs", func(t *testing.T) {
		// Encode KA with a sub-TLV, then add extra bytes
		m := dncpNewKeepAliveIntervalTLVMust(5, 1500*time.Millisecond)
		sub, _ := dncp.NewRequestNodeStateTLV([]byte{9, 9, 9, 9, 9, 9, 9, 9})
		_ = m.SetSubTLVs([]dncp.TLVMarshaler{sub})

		var buf bytes.Buffer
		err := dncp.Encode(m, &buf)
		assert.NilError(t, err)

		// Add trailing garbage
		buf.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
		encodedBytes := buf.Bytes()

		// Manually adjust the length in the header to include the garbage
		// Original length = (4+4) + (4+8) = 20. New length = 24
		binary.BigEndian.PutUint16(encodedBytes[2:4], 24)

		_, err = dncp.Decode(bytes.NewReader(encodedBytes), profile)
		assert.NilError(t, err)
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
