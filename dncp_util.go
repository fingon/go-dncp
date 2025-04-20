package dncp

import (
	"bytes"
	"fmt"
	"slices"
)

// encodedTLV holds a marshaler and its encoded binary representation for sorting.
type encodedTLV struct {
	marshaler TLVMarshaler
	encoded   []byte
}

// getOrderedTLVs converts NodeData map (map[TLVType][]TLVMarshaler) to a single slice
// sorted according to RFC 7787 Section 7.2.3: "strictly ordered based on
// ascending binary content". This requires encoding each TLV first.
// Returns an error if any TLV fails to encode.
func getOrderedTLVs(data NodeData) ([]TLVMarshaler, error) {
	if data == nil {
		return nil, nil
	}

	// Flatten the map into a single slice and encode each TLV
	totalTLVs := 0
	for _, marshalerSlice := range data {
		totalTLVs += len(marshalerSlice)
	}
	flatEncodedTLVs := make([]encodedTLV, 0, totalTLVs)
	var buf bytes.Buffer
	for _, marshalerSlice := range data {
		for _, marshaler := range marshalerSlice {
			buf.Reset()
			err := Encode(marshaler, &buf) // Use generic Encode
			if err != nil {
				return nil, fmt.Errorf("failed to encode TLV type %d for sorting: %w", marshaler.GetType(), err)
			}
			flatEncodedTLVs = append(flatEncodedTLVs, encodedTLV{
				marshaler: marshaler,
				encoded:   slices.Clone(buf.Bytes()), // Store encoded bytes
			})
		}
	}

	// Sort the flat slice based on encoded binary content
	slices.SortFunc(flatEncodedTLVs, func(a, b encodedTLV) int {
		return bytes.Compare(a.encoded, b.encoded)
	})

	// Extract the sorted marshalers
	sortedMarshalers := make([]TLVMarshaler, totalTLVs)
	for i, et := range flatEncodedTLVs {
		sortedMarshalers[i] = et.marshaler
	}
	return sortedMarshalers, nil
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
