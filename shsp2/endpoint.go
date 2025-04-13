package shsp2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/fingon/go-dncp"
)

// stopHTTPServersLocked stops all running HTTP servers. Assumes lock is held.
func (ep *Endpoint) stopHTTPServersLocked() {
	ep.logger.Debug("Stopping HTTP servers...", "count", len(ep.httpServers))
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Graceful shutdown timeout
	defer cancel()

	var wg sync.WaitGroup
	for _, server := range ep.httpServers {
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			ep.logger.Debug("Shutting down server", "addr", s.Addr)
			if err := s.Shutdown(shutdownCtx); err != nil {
				ep.logger.Error("HTTP server shutdown error", "addr", s.Addr, "err", err)
			}
		}(server)
	}
	wg.Wait() // Wait for Shutdown calls to complete

	// Wait for the Serve goroutines to finish
	ep.listenerWg.Wait()
	ep.httpServers = nil // Clear the list
	ep.logger.Debug("All HTTP servers stopped")
}

// getListenAddrs finds suitable IPv4 addresses on the configured interface.
// According to the spec, unicast should use only IPv4 addresses.
func (ep *Endpoint) getListenAddrs() ([]net.IP, error) {
	iface, err := net.InterfaceByName(ep.config.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("could not find interface %s: %w", ep.config.InterfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("could not get addresses for interface %s: %w", ep.config.InterfaceName, err)
	}

	var ipAddrs []net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Check if it's IPv4 and not loopback
		// The spec states: "The unicast should use only IPv4 addresses."
		if ip.To4() != nil && !ip.IsLoopback() && !ip.IsMulticast() {
			ipAddrs = append(ipAddrs, ip.To4())
		}
	}
	return ipAddrs, nil
}

// publishLocalURLsLocked generates URL TLVs for the listening URLs and updates DNCP. Assumes lock is held.
func (ep *Endpoint) publishLocalURLsLocked() error {
	if len(ep.localURLs) == 0 {
		ep.logger.Warn("No local URLs generated, cannot publish")
		// Is this an error? Maybe not, could be transient.
		// Let's ensure existing URL TLVs are removed if any.
		return ep.unpublishLocalURLsLocked()
	}

	urlTLVs := make([]*dncp.TLV, 0, len(ep.localURLs))
	for _, urlStr := range ep.localURLs {
		tlv, err := NewURLTLV(urlStr)
		if err != nil {
			// Should not happen if URL generation is correct
			ep.logger.Error("Failed to create URL TLV", "url", urlStr, "err", err)
			continue // Skip this URL
		}
		urlTLVs = append(urlTLVs, tlv)
	}

	if len(urlTLVs) == 0 {
		ep.logger.Error("Failed to create any valid URL TLVs")
		return errors.New("failed to create any valid URL TLVs")
	}

	ep.logger.Info("Publishing local URLs via DNCP", "count", len(urlTLVs))
	// Create new NodeData with URL TLVs
	newData := make(dncp.NodeData)
	// Add URL TLVs
	newData[TLVTypeURL] = urlTLVs
	return ep.dncpInstance.PublishData(newData)
}

// unpublishLocalURLsLocked removes URL TLVs from DNCP. Assumes lock is held.
func (ep *Endpoint) unpublishLocalURLsLocked() error {
	ep.logger.Info("Unpublishing local URLs via DNCP")
	// Create empty NodeData without URL TLVs
	newData := make(dncp.NodeData)
	// Publish empty data to effectively remove URL TLVs
	return ep.dncpInstance.PublishData(newData)
}

// handleDefaultRequest is a placeholder HTTP handler for the root path.
func (ep *Endpoint) handleDefaultRequest(w http.ResponseWriter, r *http.Request) {
	ep.logger.Debug("Received HTTP request to root", "method", r.Method, "url", r.URL.String(), "remote", r.RemoteAddr)
	fmt.Fprintf(w, "Hello from SHSP2 node\nUse %s endpoint for SHSP2 protocol requests\n", SHSP2HTTPEndpoint)
}

// handleSHSP2Request handles the /shsp2 endpoint as defined in the spec.
// It accepts POST requests with binary DNCP TLV sequences and responds with binary TLVs if needed.
// According to the spec: "The /shsp2 endpoint is used with POST requests to send binary DNCP TLV sequences,
// as well as receive them in the body (if any response is produced)."
func (ep *Endpoint) handleSHSP2Request(w http.ResponseWriter, r *http.Request) {
	ep.logger.Debug("Received SHSP2 request", "method", r.Method, "url", r.URL.String(), "remote", r.RemoteAddr)

	// According to spec, we only handle POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body which should contain binary DNCP TLVs
	body, err := io.ReadAll(r.Body)
	if err != nil {
		ep.logger.Error("Failed to read request body", "err", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	if len(body) == 0 {
		ep.logger.Warn("Empty request body")
		http.Error(w, "Empty request body", http.StatusBadRequest)
		return
	}

	// Process the received TLVs
	// This will handle the TLVs according to DNCP rules
	// We use a fake source address since this is over HTTP
	sourceAddr := r.RemoteAddr
	localEpID := ep.config.EndpointID // Use the endpoint ID from config

	// Process the TLVs and collect any response TLVs
	responseTLVs, err := ep.processSHSP2TLVs(body, sourceAddr, localEpID)
	if err != nil {
		ep.logger.Error("Failed to process SHSP2 TLVs", "err", err)
		http.Error(w, fmt.Sprintf("Failed to process TLVs: %v", err), http.StatusInternalServerError)
		return
	}

	if len(responseTLVs) == 0 {
		// No response needed, just return 200 OK
		w.WriteHeader(http.StatusOK)
		return
	}

	// If there are response TLVs, encode and send them
	w.Header().Set("Content-Type", "application/octet-stream")
	var buf bytes.Buffer
	for _, tlv := range responseTLVs {
		if err := tlv.Encode(&buf); err != nil {
			ep.logger.Error("Failed to encode response TLV", "err", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	}
	_, err = w.Write(buf.Bytes())
	if err != nil {
		ep.logger.Error("Failed to write response ", "err", err)
	}
}

// processSHSP2TLVs handles the TLVs received in an SHSP2 HTTP request.
// It returns any TLVs that should be sent back in the response.
func (ep *Endpoint) processSHSP2TLVs(data []byte, sourceAddr string, localEpID dncp.EndpointIdentifier) ([]*dncp.TLV, error) {
	// Use the DNCP instance to process the TLVs
	// This will handle standard DNCP TLVs like Request Network State, etc.
	err := ep.dncpInstance.HandleReceivedTLVs(data, sourceAddr, localEpID, false) // isMulticast=false
	if err != nil {
		return nil, fmt.Errorf("error handling TLVs: %w", err)
	}

	// For now, we don't generate any response TLVs directly but
	// instead make requests in other direction.
	return nil, nil
}

// findNodeURLs attempts to find URL TLVs for a specific node in the DNCP network.
// This is a helper method to work around the lack of direct access to node data.
func (ep *Endpoint) findNodeURLs(targetNodeID dncp.NodeIdentifier) ([]*dncp.TLV, error) {
	// Get the node data from DNCP
	nodeData, err := ep.dncpInstance.GetNodeData(targetNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get node data for %x: %w", targetNodeID, err)
	}

	// Extract URL TLVs from the node data
	urlTLVs, ok := nodeData[TLVTypeURL]
	if !ok || len(urlTLVs) == 0 {
		return nil, fmt.Errorf("node %x has not published any URL TLVs", targetNodeID)
	}

	ep.logger.Debug("Found URL TLVs for node", "targetNodeID", fmt.Sprintf("%x", targetNodeID), "count", len(urlTLVs))
	return urlTLVs, nil
}

// startMulticastLocked initializes and starts the multicast listener.
// Assumes lock is held.
func (ep *Endpoint) startMulticastLocked() error {
	iface, err := net.InterfaceByName(ep.config.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", ep.config.InterfaceName, err)
	}

	// Parse the multicast address
	multicastAddr, err := net.ResolveUDPAddr("udp6",
		net.JoinHostPort(ep.config.MulticastAddress, strconv.Itoa(int(ep.config.MulticastPort))))
	if err != nil {
		return fmt.Errorf("failed to resolve multicast address %s:%d: %w",
			ep.config.MulticastAddress, ep.config.MulticastPort, err)
	}
	ep.multicastAddr = multicastAddr

	// Create a UDP socket for listening
	listenAddr := &net.UDPAddr{
		IP:   net.IPv6unspecified,
		Port: int(ep.config.MulticastPort),
	}
	conn, err := net.ListenUDP("udp6", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}

	// For multicast, we need to close the previous connection and create a new one
	// that's specifically set up for multicast
	conn.Close()

	// Create a UDP socket for multicast
	conn, err = net.ListenMulticastUDP("udp6", iface, &net.UDPAddr{
		IP:   multicastAddr.IP,
		Port: multicastAddr.Port,
	})
	if err != nil {
		return fmt.Errorf("failed to join multicast group: %w", err)
	}

	ep.multicastConn = conn
	ep.logger.Info("Joined multicast group", "address", multicastAddr.String(), "interface", iface.Name)

	// Start the multicast listener goroutine
	ep.multicastWg.Add(1)
	go ep.multicastListener()

	return nil
}

// stopMulticastLocked stops the multicast listener and cleans up resources.
// Assumes lock is held.
func (ep *Endpoint) stopMulticastLocked() {
	if ep.multicastConn != nil {
		ep.logger.Debug("Closing multicast connection")
		ep.multicastConn.Close()
		ep.multicastConn = nil

		// Wait for the listener goroutine to exit
		ep.multicastWg.Wait()
		ep.logger.Debug("Multicast listener stopped")
	}
}

// multicastListener is a goroutine that listens for incoming multicast messages.
func (ep *Endpoint) multicastListener() {
	defer ep.multicastWg.Done()

	buffer := make([]byte, 4096) // Buffer for incoming packets

	ep.logger.Info("Multicast listener started")

	for {
		// Check if we should stop
		select {
		case <-ep.stopChan:
			ep.logger.Debug("Multicast listener received stop signal")
			return
		default:
			// Continue processing
		}

		// Set read deadline to allow periodic checking of stopChan
		err := ep.multicastConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if err != nil {
			ep.logger.Error("Error setting deadline", "err", err)
			return
		}

		n, src, err := ep.multicastConn.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// This is just the timeout we set, continue
				continue
			}

			// Check if connection was closed (during shutdown)
			if errors.Is(err, net.ErrClosed) {
				ep.logger.Debug("Multicast connection closed")
				return
			}

			ep.logger.Error("Error reading from multicast socket", "err", err)
			continue
		}

		// Process the received multicast packet
		ep.handleMulticastPacket(buffer[:n], src)
	}
}

// handleMulticastPacket processes a received multicast packet.
func (ep *Endpoint) handleMulticastPacket(data []byte, src *net.UDPAddr) {
	ep.logger.Debug("Received multicast packet", "from", src.String(), "size", len(data))

	// Process the TLVs in the packet
	// According to the spec, multicast should contain TLV 768 (URL TLV)
	reader := bytes.NewReader(data)
	tlvs, err := dncp.DecodeAll(reader)
	if err != nil {
		ep.logger.Error("Failed to decode TLVs from multicast packet", "err", err)
		return
	}

	// Extract source node information and URL TLVs
	var sourceNodeID dncp.NodeIdentifier
	var urlTLVs []*dncp.TLV

	for _, tlv := range tlvs {
		switch tlv.Type {
		case dncp.TLVTypeNodeEndpoint:
			// Extract node ID from NodeEndpoint TLV
			// For SHSP2, we know the node ID length is 4 bytes (32 bits) per spec
			if len(tlv.Value) >= 4 { // Minimum size for NodeEndpoint TLV
				sourceNodeID = tlv.Value[:SHSP2NodeIdentifierLength]
			}
		case TLVTypeURL:
			urlTLVs = append(urlTLVs, tlv)
		}
	}

	if len(sourceNodeID) == 0 {
		ep.logger.Warn("Received multicast packet without valid NodeEndpoint TLV")
		return
	}

	if len(urlTLVs) == 0 {
		ep.logger.Warn("Received multicast packet without URL TLVs",
			"sourceNodeID", fmt.Sprintf("%x", sourceNodeID))
		return
	}

	// Log the URLs received
	for _, tlv := range urlTLVs {
		urlTLV, err := DecodeURLTLV(tlv)
		if err != nil {
			ep.logger.Warn("Failed to decode URL TLV", "err", err)
			continue
		}
		ep.logger.Debug("Received URL in multicast",
			"sourceNodeID", fmt.Sprintf("%x", sourceNodeID),
			"url", urlTLV.URL)
	}

	// Pass the TLVs to DNCP for processing
	// Use a fake source address since this is over multicast
	sourceAddr := src.String()
	localEpID := ep.config.EndpointID

	err = ep.dncpInstance.HandleReceivedTLVs(data, sourceAddr, localEpID, true) // isMulticast=true
	if err != nil {
		ep.logger.Error("Failed to process multicast TLVs", "err", err)
	}
}

// sendMulticastAnnouncementLocked sends a multicast announcement with this node's URLs.
// Assumes lock is held.
func (ep *Endpoint) sendMulticastAnnouncementLocked() error {
	if ep.multicastConn == nil || ep.multicastAddr == nil {
		return errors.New("multicast connection not initialized")
	}

	if len(ep.localURLs) == 0 {
		ep.logger.Warn("No local URLs to announce via multicast")
		return nil
	}

	// Create a buffer to hold the TLVs
	var buf bytes.Buffer

	// Add NodeEndpoint TLV first (required by DNCP for datagrams)
	// We need to create a NodeEndpoint TLV with our node ID
	nodeID := ep.dncpInstance.GetNodeID()

	// Create NodeEndpoint TLV using the helper method
	nodeEndpointTLV, err := dncp.NewNodeEndpointTLV(nodeID, ep.config.EndpointID, SHSP2NodeIdentifierLength)
	if err != nil {
		return fmt.Errorf("failed to create NodeEndpoint TLV: %w", err)
	}
	if err := nodeEndpointTLV.Encode(&buf); err != nil {
		return fmt.Errorf("failed to encode NodeEndpoint TLV: %w", err)
	}

	// Add URL TLVs
	for _, urlStr := range ep.localURLs {
		urlTLV, err := NewURLTLV(urlStr)
		if err != nil {
			ep.logger.Warn("Failed to create URL TLV for multicast", "url", urlStr, "err", err)
			continue
		}

		if err := urlTLV.Encode(&buf); err != nil {
			ep.logger.Warn("Failed to encode URL TLV for multicast", "url", urlStr, "err", err)
			continue
		}
	}

	// Send the multicast packet
	_, err = ep.multicastConn.WriteToUDP(buf.Bytes(), ep.multicastAddr)
	if err != nil {
		return fmt.Errorf("failed to send multicast announcement: %w", err)
	}

	ep.logger.Info("Sent multicast announcement",
		"address", ep.multicastAddr.String(),
		"urlCount", len(ep.localURLs))

	return nil
}
