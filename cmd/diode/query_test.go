package main

import (
	"strings"
	"testing"

	"github.com/diodechain/diode_client/config"
)

func TestQueryHandlerRequiresAddress(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	origCfg := config.AppConfig
	config.AppConfig = cfg
	t.Cleanup(func() {
		config.AppConfig = origCfg
	})

	err := queryHandler()
	if err == nil {
		t.Fatal("queryHandler() error = nil, want missing address error")
	}
	if !strings.Contains(err.Error(), "requires -address") {
		t.Fatalf("queryHandler() error = %q, want missing address error", err.Error())
	}
	statusErr, ok := err.(interface{ Status() int })
	if !ok {
		t.Fatalf("queryHandler() error type %T does not expose Status()", err)
	}
	if statusErr.Status() != 2 {
		t.Fatalf("queryHandler() status = %d, want 2", statusErr.Status())
	}
}
