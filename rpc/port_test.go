// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"testing"
)

func getPorts(length int) []int {
	port := NewPortService()
	ports := make([]int, length)
	for i := 0; i < length; i++ {
		ports[i] = port.Available()
	}
	return ports
}

func TestPort(t *testing.T) {
	ports := getPorts(10)
	portsMap := make(map[int]bool)
	for _, p := range ports {
		portsMap[p] = true
	}
	if len(portsMap) != len(ports) {
		t.Fatalf("Should not return same port")
	}
}
