package shsp2

import (
	"fmt"
	"log/slog"

	"github.com/fingon/go-dncp"
	"github.com/fingon/go-dncp/timeish"
	"github.com/fingon/go-dncp/trickle"
)

// URLTLV represents the value of the URL TLV.
type URLTLV struct {
	URL string // Variable length URL string
}

// NewURLTLV creates a new DNCP TLV containing the URL string.
func NewURLTLV(url string) (*dncp.TLV, error) {
	value := []byte(url)
	if len(value) > int(dncp.MaxTLVValueLength) {
		return nil, fmt.Errorf("%w: URL length %d exceeds maximum TLV value length %d", dncp.ErrInvalidTLVLength, len(value), dncp.MaxTLVValueLength)
	}
	return &dncp.TLV{
		Type:   TLVTypeURL,
		Length: uint16(len(value)),
		Value:  value,
	}, nil
}

// DecodeURLTLV decodes the URL string from a DNCP TLV.
func DecodeURLTLV(tlv *dncp.TLV) (*URLTLV, error) {
	if tlv.Type != TLVTypeURL {
		return nil, fmt.Errorf("invalid type for URL: %d", tlv.Type)
	}
	// Length check is implicitly handled by TLV decoding itself.
	// We just need to ensure Value length matches header Length.
	if len(tlv.Value) != int(tlv.Length) {
		return nil, fmt.Errorf("%w: internal inconsistency, value length %d != header length %d", dncp.ErrInvalidTLVLength, len(tlv.Value), tlv.Length)
	}
	url := string(tlv.Value)
	return &URLTLV{URL: url}, nil
}

// NewSHSP2Profile creates a DNCP profile configured according to the SHSP2 specification.
func NewSHSP2Profile(logger *slog.Logger, clock timeish.Clock) dncp.Profile {
	if logger == nil {
		logger = slog.Default()
	}
	if clock == nil {
		clock = timeish.NewRealClock()
	}

	// Define the function to create Trickle instances for this profile.
	newTrickleFunc := func(transmitFunc trickle.TransmitFunc, consistencyFunc trickle.ConsistencyFunc[[]byte]) (*trickle.Trickle[[]byte], error) {
		// For SHSP2, we use the provided transmitFunc directly
		// The DNCP implementation will handle including NodeEndpoint and NetworkState TLVs
		// URL TLVs will be included by the endpoint implementation
		trickleConfig := trickle.Config[[]byte]{
			Imin:            SHSP2TrickleImin,
			ImaxDoublings:   SHSP2TrickleImaxDoublings,
			K:               SHSP2TrickleK,
			TransmitFunc:    transmitFunc,
			ConsistencyFunc: consistencyFunc,
			Logger:          logger.With("subsystem", "trickle"),
			Clock:           clock,
		}
		return trickle.New(trickleConfig)
	}

	return dncp.Profile{
		NodeIdentifierLength: SHSP2NodeIdentifierLength,
		HashFunction:         SHSP2HashFunction,
		HashLength:           SHSP2HashLength,
		TrickleImin:          SHSP2TrickleImin,
		TrickleImaxDoublings: SHSP2TrickleImaxDoublings,
		TrickleK:             SHSP2TrickleK,
		KeepAliveInterval:    SHSP2KeepAliveInterval,
		KeepAliveMultiplier:  SHSP2KeepAliveMultiplier,
		UseDenseOptimization: true, // Spec says "if there are more than 2 nodes on the link, dense mode should be used"
		DensePeerThreshold:   SHSP2DensePeerThreshold,
		Logger:               logger,
		Clock:                clock,
		// RandSource: Use default
		NewTrickleInstanceFunc: newTrickleFunc,
		// HandleCollisionFunc: Application should provide an implementation.
		// Per SHSP2 spec, the handler should generate a new random Node ID
		// (SHSP2NodeIdentifierLength bytes) and likely trigger a restart
		// of the DNCP instance with the new ID. Returning an error from
		// the handler can signal the need for a restart.
		HandleCollisionFunc: nil,
	}
}
