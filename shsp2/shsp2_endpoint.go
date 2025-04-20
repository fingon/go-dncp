package shsp2

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fingon/go-dncp"
)

// Endpoint manages the SHSP2 specific interactions for a DNCP node,
// including HTTP server/client logic and multicast communication.
type Endpoint struct {
	dncpInstance *dncp.DNCP
	logger       *slog.Logger
	config       EndpointConfig

	mu          sync.RWMutex
	httpServers []*http.Server
	httpClient  *http.Client
	listenerWg  sync.WaitGroup // Wait group for HTTP server listeners
	stopChan    chan struct{}  // Channel to signal shutdown

	localURLs []string // URLs this endpoint listens on

	// Multicast related fields
	multicastConn *net.UDPConn   // UDP connection for multicast
	multicastAddr *net.UDPAddr   // Multicast address to send to
	multicastWg   sync.WaitGroup // Wait group for multicast listener
}

// EndpointConfig holds configuration for the SHSP2 endpoint.
type EndpointConfig struct {
	InterfaceName    string                  // Network interface name (e.g., "eth0")
	ListenPorts      []uint16                // Ports to listen on for HTTP requests
	EndpointID       dncp.EndpointIdentifier // DNCP endpoint identifier for this endpoint
	MulticastPort    uint16                  // Port for multicast UDP (default: 53923 per spec)
	MulticastAddress string                  // Multicast address (default: ff02::1:0:42 per spec)
	// Add other config like TLS settings if needed later
}

// NewEndpoint creates and initializes a new SHSP2 endpoint manager.
func NewEndpoint(dncpInstance *dncp.DNCP, config EndpointConfig, logger *slog.Logger) (*Endpoint, error) {
	if dncpInstance == nil {
		return nil, errors.New("DNCP instance cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	if len(config.ListenPorts) == 0 {
		// Default to a random port if none specified
		config.ListenPorts = []uint16{0} // Port 0 means system will assign a random available port
		logger.Info("No listen ports specified, using random port")
	}

	// Set default multicast values if not specified
	if config.MulticastPort == 0 {
		config.MulticastPort = SHSP2MulticastPort
	}
	if config.MulticastAddress == "" {
		config.MulticastAddress = SHSP2MulticastAddress
	}

	ep := &Endpoint{
		dncpInstance: dncpInstance,
		logger:       logger.With("module", "shsp2_endpoint", "iface", config.InterfaceName),
		config:       config,
		httpClient: &http.Client{
			// Configure timeouts for HTTP requests
			Timeout: 10 * time.Second,
		},
		stopChan: make(chan struct{}),
	}

	return ep, nil
}

// Start activates the SHSP2 endpoint: starts the HTTP server(s), multicast listener, and publishes URLs.
func (ep *Endpoint) Start() error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if len(ep.httpServers) > 0 || ep.multicastConn != nil {
		return errors.New("SHSP2 endpoint already started")
	}

	ep.logger.Info("Starting SHSP2 endpoint...")

	listenAddrs, err := ep.getListenAddrs()
	if err != nil {
		return fmt.Errorf("failed to get listen addresses: %w", err)
	}
	if len(listenAddrs) == 0 {
		return fmt.Errorf("no suitable IPv6 global addresses found on interface %s", ep.config.InterfaceName)
	}

	// Start HTTP servers
	var generatedURLs []string
	mux := http.NewServeMux()
	// Register the /shsp2 endpoint as specified in the SHSP2 spec
	mux.HandleFunc(SHSP2HTTPEndpoint, ep.handleSHSP2Request)
	// Also handle root for convenience
	mux.HandleFunc("/", ep.handleDefaultRequest)

	for _, port := range ep.config.ListenPorts {
		for _, addr := range listenAddrs {
			listenAddrStr := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
			urlStr := fmt.Sprintf("http://%s:%d", addr.String(), port)

			ep.logger.Info("Preparing HTTP server", "url", urlStr, "listenAddr", listenAddrStr)
			generatedURLs = append(generatedURLs, urlStr)

			listener, err := net.Listen("tcp4", listenAddrStr)
			if err != nil {
				// Clean up already started listeners if one fails
				ep.stopHTTPServersLocked()
				return fmt.Errorf("failed to listen on %s: %w", listenAddrStr, err)
			}

			server := &http.Server{
				Addr:    listenAddrStr,
				Handler: mux,
				// TODO: Add timeouts (ReadTimeout, WriteTimeout, IdleTimeout)
			}
			ep.httpServers = append(ep.httpServers, server)

			ep.listenerWg.Add(1)
			go func(l net.Listener, s *http.Server, u string) {
				defer ep.listenerWg.Done()
				ep.logger.Info("HTTP server listening", "url", u)
				err := s.Serve(l)
				// Log error unless it's the expected server closed error during shutdown
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					ep.logger.Error("HTTP server error", "url", u, "err", err)
				} else {
					ep.logger.Info("HTTP server stopped", "url", u)
				}
			}(listener, server, urlStr)
		}
	}

	ep.localURLs = generatedURLs
	ep.logger.Info("Successfully started HTTP servers", "count", len(ep.httpServers))

	// Start multicast listener
	if err := ep.startMulticastLocked(); err != nil {
		ep.logger.Error("Failed to start multicast listener", "err", err)
		ep.stopHTTPServersLocked() // Clean up HTTP servers
		return fmt.Errorf("failed to start multicast listener: %w", err)
	}

	// Publish the generated URLs via DNCP
	if err := ep.publishLocalURLsLocked(); err != nil {
		// Log error but continue running the servers? Or stop? Stop for now.
		ep.logger.Error("Failed to publish initial URLs via DNCP", "err", err)
		ep.stopMulticastLocked()
		ep.stopHTTPServersLocked() // Ensure servers are stopped if publish fails
		return fmt.Errorf("failed to publish initial URLs: %w", err)
	}

	// Send initial multicast announcement
	if err := ep.sendMulticastAnnouncementLocked(); err != nil {
		ep.logger.Error("Failed to send initial multicast announcement", "err", err)
		// Continue anyway, as this is not fatal
	}

	ep.logger.Info("SHSP2 endpoint started successfully")
	return nil
}

// Stop shuts down the HTTP server(s), multicast listener, and cleans up resources.
func (ep *Endpoint) Stop() {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if len(ep.httpServers) == 0 && ep.multicastConn == nil {
		ep.logger.Info("SHSP2 endpoint already stopped or not started")
		return
	}

	ep.logger.Info("Stopping SHSP2 endpoint...")
	close(ep.stopChan) // Signal goroutines relying on stopChan

	// Remove URL TLVs from DNCP before stopping servers
	if err := ep.unpublishLocalURLsLocked(); err != nil {
		ep.logger.Error("Failed to unpublish URLs via DNCP during stop", "err", err)
		// Continue stopping anyway
	}

	ep.stopMulticastLocked()
	ep.stopHTTPServersLocked()
	ep.localURLs = nil
	ep.logger.Info("SHSP2 endpoint stopped")
}

// SendRequestToNode finds the target node's URL via DNCP and sends an HTTP request.
// According to the spec, unicast should use only IPv6 global addresses for HTTP requests.
func (ep *Endpoint) SendRequestToNode(targetNodeID dncp.NodeIdentifier, method, path string, body io.Reader) (*http.Response, error) {
	ep.logger.Debug("Sending request to node", "targetNodeID", fmt.Sprintf("%x", targetNodeID), "method", method, "path", path)

	// Find the URL TLVs for the target node
	urlTLVs, err := ep.findNodeURLs(targetNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to find URLs for node %x: %w", targetNodeID, err)
	}

	if len(urlTLVs) == 0 {
		return nil, fmt.Errorf("node %x has not published any URL TLVs", targetNodeID)
	}

	var lastErr error
	for _, tlv := range urlTLVs {
		decodedURL, ok := tlv.(*URLTLV)
		if !ok {
			ep.logger.Warn("Wrong type in URLTLV")
			continue
		}

		// Construct the full request URL
		// Need to handle potential relative paths correctly
		baseURL, err := url.Parse(decodedURL.URL)
		if err != nil {
			ep.logger.Warn("Failed to parse base URL from peer TLV", "targetNodeID", fmt.Sprintf("%x", targetNodeID), "url", decodedURL.URL, "err", err)
			lastErr = fmt.Errorf("invalid base URL '%s': %w", decodedURL.URL, err)
			continue
		}

		// According to the spec, the /shsp2 endpoint is used with POST requests
		if path != SHSP2HTTPEndpoint && !strings.HasSuffix(path, SHSP2HTTPEndpoint) {
			path = SHSP2HTTPEndpoint
		}

		// Ensure path starts with "/"
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		targetURL := baseURL.JoinPath(path) // Use JoinPath for correct handling

		ep.logger.Debug("Attempting HTTP request", "url", targetURL.String())
		req, err := http.NewRequest(method, targetURL.String(), body)
		if err != nil {
			ep.logger.Error("Failed to create HTTP request object", "url", targetURL.String(), "err", err)
			lastErr = fmt.Errorf("failed creating request for %s: %w", targetURL.String(), err)
			continue // Try next URL if available
		}

		// Set content type for binary DNCP TLV sequences
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/octet-stream")
		}

		resp, err := ep.httpClient.Do(req)
		if err != nil {
			ep.logger.Warn("HTTP request failed", "url", targetURL.String(), "err", err)
			lastErr = fmt.Errorf("request to %s failed: %w", targetURL.String(), err)
			// Potentially retry or try next URL? For now, try next.
			continue
		}

		// Success! Return the response.
		ep.logger.Debug("HTTP request successful", "url", targetURL.String(), "status", resp.Status)
		return resp, nil
	}

	// If loop finishes without success
	if lastErr != nil {
		return nil, fmt.Errorf("failed to send request to node %x after trying all URLs: %w", targetNodeID, lastErr)
	}
	// This case should only happen if urlTLVs was empty, which is checked earlier.
	return nil, fmt.Errorf("failed to send request to node %x (no valid URLs?)", targetNodeID)
}

// GetLocalURLs returns the list of URLs this endpoint is currently listening on.
func (ep *Endpoint) GetLocalURLs() []string {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return slices.Clone(ep.localURLs)
}

// GetLocalURLTLVs returns the URL TLV marshalers for this endpoint's URLs.
// This might be used by external logic if needed.
func (ep *Endpoint) GetLocalURLTLVs() []dncp.TLVMarshaler {
	ep.mu.RLock()
	defer ep.mu.RUnlock()

	marshalers := make([]dncp.TLVMarshaler, 0, len(ep.localURLs))
	for _, urlStr := range ep.localURLs {
		marshaler, err := NewURLTLV(urlStr)
		if err != nil {
			ep.logger.Error("Failed to create URL TLV marshaler", "url", urlStr, "err", err)
			continue
		}
		marshalers = append(marshalers, marshaler)
	}
	return marshalers
}

// SendMulticastAnnouncement sends a multicast announcement with this node's URLs.
// This can be called externally to trigger an announcement, e.g., when URLs change.
func (ep *Endpoint) SendMulticastAnnouncement() error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	return ep.sendMulticastAnnouncementLocked()
}
