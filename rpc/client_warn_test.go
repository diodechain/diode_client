// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"sync"
	"testing"
)

func TestHostFailureAlreadyWarned(t *testing.T) {
	t.Parallel()

	hostFailureWarned = sync.Map{}
	hosts := []string{
		"diode://0x1350d3b501d6842ed881b59de4b95b27372bfae8@as2.prenet.diode.io:41046",
		"AS2.prenet.diode.io:41046",
	}
	if hostFailureAlreadyWarned(hosts[0], "connect") {
		t.Fatal("first warning should be new")
	}
	if !hostFailureAlreadyWarned(hosts[1], "connect") {
		t.Fatal("normalized duplicate host should be suppressed")
	}
	if hostFailureAlreadyWarned(hosts[0], "start") {
		t.Fatal("different kind should be new")
	}
}
