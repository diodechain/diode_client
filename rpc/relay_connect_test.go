// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/diodechain/diode_client/util"
)

func mustTestAddress(t *testing.T, hex string) util.Address {
	t.Helper()
	addr, err := util.DecodeAddress(hex)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestOrderedRelayTargets(t *testing.T) {
	t.Parallel()

	a := mustTestAddress(t, "0xceca2f8cf1983b4cf0c1ba51fd382c2bc37aba58")
	b := mustTestAddress(t, "0x68e0bafdda9ef323f692fc080d612718c941d120")
	c := mustTestAddress(t, "0x7e4cd38d266902444dc9c8f7c0aa716a32497d0b")
	connected := &Client{serverID: a}

	targets := orderedRelayTargets(func(id util.Address) *Client {
		if id == a {
			return connected
		}
		return nil
	}, []util.Address{a, b, a, c, b})

	if len(targets) != 3 {
		t.Fatalf("len(targets) = %d, want 3", len(targets))
	}
	if targets[0].NodeID != a || targets[0].Client != connected {
		t.Fatalf("targets[0] = %+v, want connected relay a", targets[0])
	}
	if targets[1].NodeID != b || targets[1].Client != nil {
		t.Fatalf("targets[1] = %+v, want pending relay b", targets[1])
	}
	if targets[2].NodeID != c || targets[2].Client != nil {
		t.Fatalf("targets[2] = %+v, want pending relay c", targets[2])
	}
}

func TestTrackPendingRelay(t *testing.T) {
	t.Parallel()

	node := mustTestAddress(t, "0xceca2f8cf1983b4cf0c1ba51fd382c2bc37aba58")
	var started []util.Address
	pending := make([]util.Address, 0)
	seen := make(map[util.Address]bool)

	trackPendingRelay(&pending, seen, func(util.Address) *Client { return nil }, func(id util.Address) {
		started = append(started, id)
	}, node)
	trackPendingRelay(&pending, seen, func(util.Address) *Client { return nil }, func(id util.Address) {
		started = append(started, id)
	}, node)

	if len(pending) != 1 || pending[0] != node {
		t.Fatalf("pending = %#v, want single node", pending)
	}
	if len(started) != 1 || started[0] != node {
		t.Fatalf("started = %#v, want single background dial", started)
	}
}

func TestTryPortOpenOnRelays_connectedBeforePending(t *testing.T) {
	t.Parallel()

	connectedID := mustTestAddress(t, "0xceca2f8cf1983b4cf0c1ba51fd382c2bc37aba58")
	pendingID := mustTestAddress(t, "0x68e0bafdda9ef323f692fc080d612718c941d120")
	connected := &Client{serverID: connectedID}
	pending := &Client{serverID: pendingID}
	wantConn := &ConnectedPort{client: pending}

	var (
		mu         sync.Mutex
		callOrder  []string
		started    []util.Address
		waitCalled bool
	)

	targets := orderedRelayTargets(func(id util.Address) *Client {
		if id == connectedID {
			return connected
		}
		return nil
	}, []util.Address{connectedID, pendingID})

	conn, errs := tryPortOpenOnRelays(
		targets,
		func(nodeID util.Address) {
			mu.Lock()
			started = append(started, nodeID)
			mu.Unlock()
		},
		func(nodeID util.Address) (*Client, error) {
			mu.Lock()
			waitCalled = true
			callOrder = append(callOrder, "wait:"+nodeID.HexString())
			mu.Unlock()
			if nodeID == pendingID {
				return pending, nil
			}
			return nil, fmt.Errorf("missing relay %s", nodeID.HexString())
		},
		func(client *Client) (*ConnectedPort, error) {
			mu.Lock()
			defer mu.Unlock()
			if client == connected {
				callOrder = append(callOrder, "port:"+connectedID.HexString())
				return nil, errors.New("connected relay failed")
			}
			if client == pending {
				callOrder = append(callOrder, "port:"+pendingID.HexString())
				return wantConn, nil
			}
			return nil, fmt.Errorf("unexpected client %s", client.serverID.HexString())
		},
	)

	if conn != wantConn {
		t.Fatalf("conn = %p, want %p", conn, wantConn)
	}
	if len(errs) != 0 {
		t.Fatalf("errs = %#v, want none when pending relay succeeds", errs)
	}
	if !waitCalled {
		t.Fatal("expected waitRelay to run for pending relay")
	}
	if len(started) != 1 || started[0] != pendingID {
		t.Fatalf("started = %#v, want background dial for pending relay only", started)
	}
	if len(callOrder) < 3 || callOrder[0] != "port:"+connectedID.HexString() || callOrder[1] != "wait:"+pendingID.HexString() {
		t.Fatalf("callOrder = %#v, want connected portopen before pending wait", callOrder)
	}
}

func TestTryPortOpenOnRelays_connectedFailuresOnly(t *testing.T) {
	t.Parallel()

	connectedID := mustTestAddress(t, "0xceca2f8cf1983b4cf0c1ba51fd382c2bc37aba58")
	connected := &Client{serverID: connectedID}
	targets := orderedRelayTargets(func(id util.Address) *Client {
		if id == connectedID {
			return connected
		}
		return nil
	}, []util.Address{connectedID})

	conn, errs := tryPortOpenOnRelays(
		targets,
		func(util.Address) {},
		func(util.Address) (*Client, error) {
			t.Fatal("waitRelay should not run when there are no pending relays")
			return nil, nil
		},
		func(*Client) (*ConnectedPort, error) {
			return nil, errors.New("connected relay failed")
		},
	)
	if conn != nil {
		t.Fatalf("conn = %p, want nil", conn)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %#v, want one connected-relay error", errs)
	}
}

func TestTryPortOpenOnRelays_firstPendingSuccessWins(t *testing.T) {
	t.Parallel()

	firstID := mustTestAddress(t, "0xceca2f8cf1983b4cf0c1ba51fd382c2bc37aba58")
	secondID := mustTestAddress(t, "0x68e0bafdda9ef323f692fc080d612718c941d120")
	first := &Client{serverID: firstID}
	second := &Client{serverID: secondID}
	wantConn := &ConnectedPort{client: first}

	targets := orderedRelayTargets(func(util.Address) *Client { return nil }, []util.Address{firstID, secondID})
	conn, errs := tryPortOpenOnRelays(
		targets,
		func(util.Address) {},
		func(nodeID util.Address) (*Client, error) {
			switch nodeID {
			case firstID:
				return first, nil
			case secondID:
				return second, nil
			default:
				return nil, fmt.Errorf("unknown relay %s", nodeID.HexString())
			}
		},
		func(client *Client) (*ConnectedPort, error) {
			if client == first {
				return wantConn, nil
			}
			return nil, errors.New("second relay failed")
		},
	)

	if conn != wantConn {
		t.Fatalf("conn = %p, want %p", conn, wantConn)
	}
	if len(errs) != 0 {
		t.Fatalf("errs = %#v, want none on success", errs)
	}
}

func TestTryPortOpenOnRelays_failsAfterAllPendingFail(t *testing.T) {
	t.Parallel()

	firstID := mustTestAddress(t, "0xceca2f8cf1983b4cf0c1ba51fd382c2bc37aba58")
	secondID := mustTestAddress(t, "0x68e0bafdda9ef323f692fc080d612718c941d120")

	targets := orderedRelayTargets(func(util.Address) *Client { return nil }, []util.Address{firstID, secondID})
	conn, errs := tryPortOpenOnRelays(
		targets,
		func(util.Address) {},
		func(nodeID util.Address) (*Client, error) {
			return nil, fmt.Errorf("dial failed %s", nodeID.HexString())
		},
		func(*Client) (*ConnectedPort, error) {
			t.Fatal("createPort should not run when all dials fail")
			return nil, nil
		},
	)

	if conn != nil {
		t.Fatalf("conn = %p, want nil", conn)
	}
	if len(errs) != 2 {
		t.Fatalf("len(errs) = %d, want 2 pending dial failures", len(errs))
	}
}
