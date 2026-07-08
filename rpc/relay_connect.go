// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"sync"

	"github.com/diodechain/diode_client/util"
)

// relayTarget is one relay candidate in try order. Client is set when the relay is
// already connected; otherwise only NodeID is known and a background dial is needed.
type relayTarget struct {
	NodeID util.Address
	Client *Client
}

// orderedRelayTargets deduplicates serverIDs and splits them into connected clients
// versus node IDs that still need a dial, preserving the original try order.
func orderedRelayTargets(getClient func(util.Address) *Client, serverIDs []util.Address) []relayTarget {
	seen := make(map[util.Address]bool, len(serverIDs))
	targets := make([]relayTarget, 0, len(serverIDs))
	for _, nodeID := range serverIDs {
		if nodeID == (util.Address{}) || seen[nodeID] {
			continue
		}
		seen[nodeID] = true
		target := relayTarget{NodeID: nodeID, Client: getClient(nodeID)}
		targets = append(targets, target)
	}
	return targets
}

type portOpenFunc func(client *Client) (*ConnectedPort, error)
type startRelayConnectFunc func(nodeID util.Address)
type waitRelayConnectFunc func(nodeID util.Address) (*Client, error)

// tryPortOpenOnRelays attempts portopen on already-connected relays first. Background
// dials for pending relays are started immediately so they overlap with the fast path.
// The first successful portopen wins; otherwise every attempt must fail before returning.
func tryPortOpenOnRelays(
	targets []relayTarget,
	startBackground startRelayConnectFunc,
	waitRelay waitRelayConnectFunc,
	createPort portOpenFunc,
) (*ConnectedPort, []error) {
	for _, target := range targets {
		if target.Client == nil {
			startBackground(target.NodeID)
		}
	}

	var (
		errs    []error
		pending []util.Address
	)
	for _, target := range targets {
		if target.Client != nil {
			conn, err := createPort(target.Client)
			if err == nil {
				return conn, nil
			}
			errs = append(errs, err)
			continue
		}
		pending = append(pending, target.NodeID)
	}
	if len(pending) == 0 {
		return nil, errs
	}

	type attemptResult struct {
		conn *ConnectedPort
		err  error
	}
	results := make(chan attemptResult, len(pending))
	var wg sync.WaitGroup
	for _, nodeID := range pending {
		wg.Add(1)
		go func(nodeID util.Address) {
			defer wg.Done()
			client, err := waitRelay(nodeID)
			if err != nil {
				results <- attemptResult{err: err}
				return
			}
			conn, err := createPort(client)
			results <- attemptResult{conn: conn, err: err}
		}(nodeID)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if result.conn != nil {
			return result.conn, nil
		}
		if result.err != nil {
			errs = append(errs, result.err)
		}
	}
	return nil, errs
}

// trackPendingRelay records a relay that should be dialed in the background and later
// waited on when connected relays are exhausted.
func trackPendingRelay(pending *[]util.Address, seen map[util.Address]bool, getClient func(util.Address) *Client, startBackground func(util.Address), nodeID util.Address) {
	if nodeID == (util.Address{}) || seen[nodeID] {
		return
	}
	seen[nodeID] = true
	if getClient(nodeID) != nil {
		return
	}
	startBackground(nodeID)
	*pending = append(*pending, nodeID)
}
