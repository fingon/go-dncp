package dncp

import (
	"errors"
	"fmt"
)

// AddEndpoint configures a new local endpoint.
func (d *DNCP) AddEndpoint(ep Endpoint) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.endpoints[ep.ID]; exists {
		return fmt.Errorf("endpoint with ID %d already exists", ep.ID)
	}
	if ep.ID == ReservedEndpointIdentifier {
		return errors.New("cannot use reserved endpoint identifier 0")
	}
	if ep.peers == nil {
		ep.peers = make(map[string]*Peer)
	}

	// Initialize Trickle instance based on TransportMode
	if d.profile.NewTrickleInstanceFunc != nil && requiresEndpointTrickle(ep.TransportMode) {
		transmitFunc := d.createEndpointTransmitFunc(&ep)
		consistencyFunc := d.createConsistencyFunc()

		trickleInst, err := d.profile.NewTrickleInstanceFunc(transmitFunc, consistencyFunc)
		if err != nil {
			d.logger.Error("Failed to create Trickle instance for endpoint", "id", ep.ID, "err", err)
			// Proceed without Trickle? Or return error? Return error for now.
			return fmt.Errorf("failed to create Trickle instance for endpoint %d: %w", ep.ID, err)
		}
		ep.trickleInstance = trickleInst
		ep.trickleInstance.Start()
		d.logger.Info("Started Trickle instance for endpoint", "id", ep.ID)
	}

	d.endpoints[ep.ID] = &ep
	d.logger.Info("Added endpoint", "id", ep.ID, "mode", ep.TransportMode, "iface", ep.InterfaceName)
	return nil
}

// RemoveEndpoint removes a local endpoint.
func (d *DNCP) RemoveEndpoint(id EndpointIdentifier) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ep, exists := d.endpoints[id]
	if !exists {
		return fmt.Errorf("endpoint with ID %d not found", id)
	}

	// Stop Trickle instance for the endpoint
	if ep.trickleInstance != nil {
		ep.trickleInstance.Stop()
		d.logger.Info("Stopped Trickle instance for endpoint", "id", id)
	}

	// TODO: Clean up peers associated with this endpoint? Or rely on timeout/transport signals?

	delete(d.endpoints, id)
	d.logger.Info("Removed endpoint", "id", id)

	// Update local Peer TLVs and republish if necessary
	if d.removeLocalPeerTLVsForEndpoint(id) {
		d.mu.Unlock() // Unlock before calling PublishData which locks
		// Need to reconstruct the current local data without the removed peers
		currentData := d.getLocalDataForPublishing()
		err := d.PublishData(currentData)
		d.mu.Lock() // Re-lock
		if err != nil {
			d.logger.Error("Failed to republish data after removing endpoint", "id", id, "err", err)
			// State might be inconsistent here
		}
	}
	return nil
}
