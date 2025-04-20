package shsp2

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"

	"github.com/fingon/go-dncp"
	"github.com/fingon/go-dncp/timeish"
	"github.com/fingon/go-dncp/trickle"
)

// CollisionRestartError indicates a node ID collision occurred and provides a suggested new ID.
// The application should handle this by stopping the current DNCP instance and creating
// a new one with the NewNodeID.
type CollisionRestartError struct {
	SuggestedNewNodeID dncp.NodeIdentifier
}

func (e CollisionRestartError) Error() string {
	return "a node identifier collision occurred"
}

// --- SHSP2 Specific TLV ---

// URLTLV corresponds to TLV Type 768.
type URLTLV struct {
	dncp.BaseTLV
	URL string // Variable length URL string
}

func init() {
	dncp.RegisterTLVType(TLVTypeURL, func() dncp.TLVMarshaler { return &URLTLV{BaseTLV: dncp.BaseTLV{TLVType: TLVTypeURL}} })
}

// NewURLTLV creates a new URL TLV instance.
func NewURLTLV(url string) (*URLTLV, error) {
	// Basic validation could be added here (e.g., check if parseable)
	return &URLTLV{
		BaseTLV: dncp.BaseTLV{TLVType: TLVTypeURL},
		URL:     url,
	}, nil
}

// EncodeValue returns the URL string as bytes.
func (t *URLTLV) EncodeValue() ([]byte, error) {
	return []byte(t.URL), nil
}

// DecodeValue decodes the URL string from the value bytes.
// The profile argument is ignored for this simple TLV type.
func (t *URLTLV) DecodeValue(value []byte, _ *dncp.Profile) error {
	t.URL = string(value)
	return nil
}

// --- SHSP2 Profile ---

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
		// HandleCollisionFunc: Assign the SHSP2-specific handler.
		HandleCollisionFunc: handleSHSP2Collision,
	}
}

// generateNewSHSP2NodeID creates a new random 4-byte Node ID.
func generateNewSHSP2NodeID() (dncp.NodeIdentifier, error) {
	newNodeID := make(dncp.NodeIdentifier, SHSP2NodeIdentifierLength)
	_, err := rand.Read(newNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random node ID: %w", err)
	}
	return newNodeID, nil
}

// handleSHSP2Collision is the callback for the DNCP profile.
// It generates a new random Node ID and returns a specific error
// signaling that the application needs to restart the DNCP instance.
func handleSHSP2Collision() error {
	slog.Warn("SHSP2 Node ID collision detected!") // Use default logger temporarily
	newNodeID, err := generateNewSHSP2NodeID()
	if err != nil {
		// Log the error but return a generic collision error if generation fails?
		// Or return the underlying error? Let's return the specific error without a suggestion.
		slog.Error("Failed to generate new Node ID during collision handling", "err", err)
		// Return a generic error that doesn't include a new ID
		return errors.New("node ID collision detected, but failed to generate new ID")
	}
	slog.Warn("Suggesting application restart DNCP with new Node ID", "newNodeID", fmt.Sprintf("%x", newNodeID))
	return CollisionRestartError{SuggestedNewNodeID: newNodeID}
}
