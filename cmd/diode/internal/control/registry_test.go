package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diodechain/diode_client/config"
)

type fakeDB struct {
	values map[string][]byte
}

func newFakeDB() *fakeDB {
	return &fakeDB{values: map[string][]byte{}}
}

func (db *fakeDB) Get(key string) ([]byte, error) {
	return db.values[key], nil
}

func (db *fakeDB) Put(key string, value []byte) error {
	cp := make([]byte, len(value))
	copy(cp, value)
	db.values[key] = cp
	return nil
}

func (db *fakeDB) Del(key string) error {
	delete(db.values, key)
	return nil
}

func (db *fakeDB) List() []string {
	keys := make([]string, 0, len(db.values))
	for key := range db.values {
		keys = append(keys, key)
	}
	return keys
}

func TestApplyJoinPropertiesExpandsExtraConfigAndDefaults(t *testing.T) {
	registry := NewRegistry(DefaultDescriptors())
	cfg := &config.Config{}
	err := ApplyJoinProperties(registry, &ApplyContext{
		Surface:               SurfaceJoin,
		Config:                cfg,
		DefaultRemoteRPCAddrs: []string{"eu1.prenet.diode.io:41046"},
	}, map[string]string{
		"bind":         "1234:svc-1:80",
		"extra_config": `{"api":true,"apiaddr":"localhost:7777","debug":true}`,
	})
	if err != nil {
		t.Fatalf("ApplyJoinProperties() error = %v", err)
	}
	if !cfg.EnableAPIServer {
		t.Fatalf("expected api enabled from extra_config")
	}
	if cfg.APIServerAddr != "localhost:7777" {
		t.Fatalf("expected apiaddr to apply, got %q", cfg.APIServerAddr)
	}
	if !cfg.Debug {
		t.Fatalf("expected debug enabled from extra_config")
	}
	if len(cfg.RemoteRPCAddrs) != 1 || cfg.RemoteRPCAddrs[0] != "eu1.prenet.diode.io:41046" {
		t.Fatalf("expected missing diodeaddrs to restore defaults, got %#v", cfg.RemoteRPCAddrs)
	}
	if len(cfg.SBinds) != 1 || cfg.SBinds[0] != "1234:svc-1:80" {
		t.Fatalf("expected bind to apply, got %#v", cfg.SBinds)
	}
}

func TestApplyJoinPropertiesEmptyBindClearsExistingBinds(t *testing.T) {
	registry := NewRegistry(DefaultDescriptors())
	cfg := &config.Config{
		SBinds: config.StringValues{"1234:svc-1:80"},
		Binds:  []config.Bind{{LocalPort: 1234, To: "svc-1", ToPort: 80, Protocol: config.TLSProtocol}},
	}
	err := ApplyJoinProperties(registry, &ApplyContext{
		Surface:               SurfaceJoin,
		Config:                cfg,
		DefaultRemoteRPCAddrs: []string{"eu1.prenet.diode.io:41046"},
	}, map[string]string{
		"bind": "",
	})
	if err != nil {
		t.Fatalf("ApplyJoinProperties() error = %v", err)
	}
	if len(cfg.SBinds) != 0 || len(cfg.Binds) != 0 {
		t.Fatalf("expected empty bind to clear existing binds, got %#v / %#v", cfg.SBinds, cfg.Binds)
	}
	if len(cfg.RemoteRPCAddrs) != 1 || cfg.RemoteRPCAddrs[0] != "eu1.prenet.diode.io:41046" {
		t.Fatalf("expected missing diodeaddrs to restore defaults, got %#v", cfg.RemoteRPCAddrs)
	}
}

func TestRegistryConfigDBKeysSetListDelete(t *testing.T) {
	registry := NewRegistry(DefaultDescriptors())
	cfg := &config.Config{}
	db := newFakeDB()
	privPEM, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "staticserver", "test.key"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	batch := NewBatch(SurfaceConfig)
	batch.Add("fleet", "0x1111111111111111111111111111111111111111")
	batch.Add("last_update_at", "42")
	if err := registry.AddByAlias(batch, "private", string(privPEM)); err != nil {
		t.Fatalf("AddByAlias(private) error = %v", err)
	}
	if err := registry.Apply(&ApplyContext{Surface: SurfaceConfig, Config: cfg, DB: db}, batch); err != nil {
		t.Fatalf("Apply(config set) error = %v", err)
	}

	entries, err := registry.ExportConfig(&ApplyContext{Surface: SurfaceConfig, Config: cfg, DB: db}, true)
	if err != nil {
		t.Fatalf("ExportConfig() error = %v", err)
	}
	got := map[string]string{}
	for _, entry := range entries {
		got[entry.Key] = entry.Value
	}
	if got["fleet"] != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("expected fleet in config export, got %#v", got)
	}
	if got["last_update_at"] != "42" {
		t.Fatalf("expected last_update_at in config export, got %#v", got)
	}
	if !strings.HasPrefix(got["private"], "0x") {
		t.Fatalf("expected private key export in unsafe mode, got %#v", got)
	}

	deleteBatch := NewBatch(SurfaceConfig)
	deleteBatch.Delete("fleet")
	deleteBatch.Delete("last_update_at")
	if err := registry.DeleteByAlias(deleteBatch, "private"); err != nil {
		t.Fatalf("DeleteByAlias(private) error = %v", err)
	}
	if err := registry.Apply(&ApplyContext{Surface: SurfaceConfig, Config: cfg, DB: db}, deleteBatch); err != nil {
		t.Fatalf("Apply(config delete) error = %v", err)
	}
	if len(db.List()) != 0 {
		t.Fatalf("expected all managed db keys deleted, got %#v", db.List())
	}
}

func TestExportOpaqueDBEntriesIncludesLegacyKeys(t *testing.T) {
	db := newFakeDB()
	if err := db.Put("legacy_key", []byte("legacy-value")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	entries := ExportOpaqueDBEntries(&ApplyContext{Surface: SurfaceConfig, DB: db}, map[string]bool{
		"private":        true,
		"fleet":          true,
		"last_update_at": true,
	})
	if len(entries) != 1 {
		t.Fatalf("expected one opaque entry, got %#v", entries)
	}
	if entries[0].Key != "legacy_key" {
		t.Fatalf("unexpected opaque key %#v", entries)
	}
	if entries[0].Value == "" {
		t.Fatalf("expected opaque value to be exported")
	}
}
