package dncp

import (
	"bytes"
	"fmt"
	"slices"
)

// getOrderedTLVs converts NodeData map (map[TLVType][]*TLV) to a single slice
// sorted according to RFC 7787 Section 7.2.3: "strictly ordered based on
// ascending binary content (including TLV type and length)".
func getOrderedTLVs(data NodeData) []*TLV {
	if data == nil {
		return nil
	}
	// Flatten the map into a single slice
	totalTLVs := 0
	for _, tlvSlice := range data {
		totalTLVs += len(tlvSlice)
	}
	flatTLVs := make([]*TLV, 0, totalTLVs)
	for _, tlvSlice := range data {
		flatTLVs = append(flatTLVs, tlvSlice...)
	}

	// Sort the flat slice based on binary content
	slices.SortFunc(flatTLVs, func(a, b *TLV) int {
		// Primary sort key: Type
		if a.Type != b.Type {
			return int(a.Type) - int(b.Type)
		}
		// Secondary sort key: Length
		if a.Length != b.Length {
			return int(a.Length) - int(b.Length)
		}
		// Tertiary sort key: Value bytes
		return bytes.Compare(a.Value, b.Value)
	})
	return flatTLVs
}

// decodeNodeDataTLVs decodes the raw bytes from a NodeState TLV's NodeData field
// into a NodeData map (map[TLVType][]*TLV).
func decodeNodeDataTLVs(dataBytes []byte) (NodeData, error) {
	if len(dataBytes) == 0 {
		return make(NodeData), nil
	}
	reader := bytes.NewReader(dataBytes)
	decodedTLVs, err := DecodeAll(reader)
	if err != nil {
		// If DecodeAll fails partially, we might still have some TLVs in decodedTLVs.
		// However, the RFC implies the entire NodeData should be verifiable by hash.
		// If decoding fails, we likely can't verify the hash, so discard everything.
		return nil, fmt.Errorf("failed to decode nested TLVs: %w", err)
	}

	// Check if DecodeAll consumed all bytes (it should if err is nil)
	if reader.Len() > 0 {
		// This indicates an issue with DecodeAll or the input data structure
		return nil, fmt.Errorf("internal error: trailing data (%d bytes) after decoding nested TLVs without error", reader.Len())
	}

	// Group TLVs by type into the map
	nodeDataMap := make(NodeData)
	for _, tlv := range decodedTLVs {
		nodeDataMap[tlv.Type] = append(nodeDataMap[tlv.Type], tlv)
	}
	return nodeDataMap, nil
}

// CompareSequenceNumbers compares two sequence numbers, handling wrap-around.
// Returns > 0 if a > b, < 0 if a < b, 0 if a == b.
// Uses logic from RFC 7787 Section 4.4.
func CompareSequenceNumbers(a, b uint32) int {
	const half = uint32(1) << 31 // 2^31
	diff := a - b

	switch {
	case diff == 0:
		return 0 // Equal
	case (diff & half) != 0:
		return -1 // a < b (wrapped around)
	default: // (diff & half) == 0 and diff != 0
		return 1 // a > b (or b wrapped around)
	}
}
