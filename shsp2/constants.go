package shsp2

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/fingon/go-dncp"
)

const (
	// SHSP2ProfileName is the name for this profile.
	SHSP2ProfileName = "SHSP2"
	// SHSP2NodeIdentifierLength is 32 bits (4 bytes) as specified in the spec.
	SHSP2NodeIdentifierLength uint = 4
	// SHSP2TrickleImin is 200 ms.
	SHSP2TrickleImin = 200 * time.Millisecond
	// SHSP2TrickleImaxDoublings is 7.
	SHSP2TrickleImaxDoublings uint = 7
	// SHSP2TrickleK is 1.
	SHSP2TrickleK uint = 1
	// SHSP2KeepAliveInterval derived from Trickle Imax (0.2 * 2^7 = 25.6s).
	// RFC 7787 Section 1.1: "If keep-alives are used, A_NC_I is the minimum
	// of the computed A_NC_I and the keep-alive interval."
	// Using the max trickle interval seems reasonable.
	SHSP2KeepAliveInterval = SHSP2TrickleImin * (1 << SHSP2TrickleImaxDoublings) // 25.6 seconds
	// SHSP2KeepAliveMultiplier is the default multiplier (e.g., 3).
	SHSP2KeepAliveMultiplier uint = 3
	// SHSP2DensePeerThreshold is 2 (dense mode if > 2 nodes) as specified in the spec.
	SHSP2DensePeerThreshold uint = 2
	// SHSP2HashFunction is SHA-256.
	// SHSP2HashLength is the full SHA-256 length.
	SHSP2HashLength = 32
)

var SHSP2HashFunction = sha256.New

// SHSP2MulticastAddress is the link-local scope multicast address from spec: "ff02::1:0:42"
const SHSP2MulticastAddress = "ff02::1:0:42"

// SHSP2MulticastPort is the UDP port for multicast from spec: 53923
const SHSP2MulticastPort = 53923

// SHSP2MulticastDestination is the string representation for SendFunc.
var SHSP2MulticastDestination = fmt.Sprintf("udp:[%s]:%d", SHSP2MulticastAddress, SHSP2MulticastPort)

// SHSP2HTTPEndpoint is the HTTP endpoint path used for SHSP2 protocol requests
const SHSP2HTTPEndpoint = "/shsp2"

// TLV types specific to SHSP2
const (
	// TLVTypeURL is the TLV type for URL information (type 768 per spec)
	TLVTypeURL dncp.TLVType = 768
)
