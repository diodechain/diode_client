package rpc

import (
	"math/big"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
)

func TestBetterDeviceTicketPrefersTicketsWithAlternateRoutes(t *testing.T) {
	fallback := util.Address{1}
	current := &edge.DeviceTicket{
		ServerID:   util.Address{2},
		TotalBytes: big.NewInt(100),
	}
	candidate := &edge.DeviceTicket{
		ServerID:   util.Address{3},
		LocalAddr:  append([]byte{1}, fallback[:]...),
		TotalBytes: big.NewInt(50),
	}

	if !betterDeviceTicket(candidate, current) {
		t.Fatal("expected ticket with an alternate route to be preferred")
	}
}

func TestBetterDeviceTicketPrefersHigherUsageWithinSameRouteCount(t *testing.T) {
	current := &edge.DeviceTicket{
		ServerID:   util.Address{1},
		TotalBytes: big.NewInt(100),
	}
	candidate := &edge.DeviceTicket{
		ServerID:   util.Address{2},
		TotalBytes: big.NewInt(101),
	}

	if !betterDeviceTicket(candidate, current) {
		t.Fatal("expected higher-usage ticket to be preferred")
	}
}

func TestResolverBetterDeviceTicketPrefersLowerRankedFirstRoute(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)
	now := time.Now()

	fastServer := util.Address{1}
	slowServer := util.Address{2}
	fallbackServer := util.Address{3}

	cm.srv.Call(func() {
		fastCandidate := cm.ensureCandidateLocked("fast:41046")
		fastCandidate.nodeID = fastServer
		fastCandidate.hasNodeID = true
		fastCandidate.validated = true
		fastCandidate.configured = true
		fastCandidate.hasLatency = true
		fastCandidate.latencyEWMA = 10
		fastCandidate.lastSuccess = now

		slowCandidate := cm.ensureCandidateLocked("slow:41046")
		slowCandidate.nodeID = slowServer
		slowCandidate.hasNodeID = true
		slowCandidate.validated = true
		slowCandidate.configured = true
		slowCandidate.hasLatency = true
		slowCandidate.latencyEWMA = 50
		slowCandidate.lastSuccess = now
	})

	resolver := &Resolver{clientManager: cm}
	current := &edge.DeviceTicket{
		ServerID:   fastServer,
		TotalBytes: big.NewInt(100),
	}
	candidate := &edge.DeviceTicket{
		ServerID:   slowServer,
		LocalAddr:  append([]byte{1}, fallbackServer[:]...),
		TotalBytes: big.NewInt(200),
	}

	if resolver.betterDeviceTicket(candidate, current) {
		t.Fatal("expected lower-ranked first route to beat route count and usage")
	}
}
