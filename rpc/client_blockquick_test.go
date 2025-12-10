package rpc

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
)

func TestEnsureBlockquickWindowRetriesOnValidationError(t *testing.T) {
	withTempDB(t, func() {
		cfg := &config.Config{
			BlockquickDowngrade: false,
			LogDateTime:         true,
			ResolveCacheTime:    time.Minute,
		}

		logger, err := config.NewLogger(cfg)
		if err != nil {
			t.Fatalf("failed to create logger: %v", err)
		}
		cfg.Logger = &logger

		origAppConfig := config.AppConfig
		config.AppConfig = cfg
		defer func() { config.AppConfig = origAppConfig }()

		cm := NewClientManager(cfg)
		client := NewClient("testhost", cm, cfg, cm.GetPool())

		var calls int32
		client.validateNetworkFn = func() error {
			n := atomic.AddInt32(&calls, 1)
			if n < 3 {
				return fmt.Errorf("%s 100 < 200", blockquickValidationError)
			}
			return nil
		}

		if err := client.ensureBlockquickWindow(); err != nil {
			t.Fatalf("expected ensureBlockquickWindow to succeed, got %v", err)
		}

		if got := atomic.LoadInt32(&calls); got < 3 {
			t.Fatalf("expected validateNetwork to be retried, got %d calls", got)
		}
	})
}
