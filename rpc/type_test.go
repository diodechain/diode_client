package rpc

import (
	"path/filepath"
	"testing"

	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/util"
)

func withTempDB(t *testing.T, fn func()) {
	t.Helper()
	dir := t.TempDir()
	dbFile := filepath.Join(dir, "test.db")

	original := db.DB
	testDB, err := db.OpenFile(dbFile, false)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	db.DB = testDB
	t.Cleanup(func() {
		testDB.Close()
		db.DB = original
	})

	fn()
}

func TestRestoreLastValidFromCombinedRecord(t *testing.T) {
	withTempDB(t, func() {
		var hash crypto.Sha3
		for i := range hash {
			hash[i] = byte(i)
		}
		persistLastValidRecord(12345, hash)

		// Legacy keys may get out of sync; ensure restore ignores them.
		if err := db.DB.Put(lvbnKey, util.DecodeUintToBytes(1)); err != nil {
			t.Fatalf("failed to corrupt lvbn: %v", err)
		}
		var other crypto.Sha3
		if err := db.DB.Put(lvbhKey, other[:]); err != nil {
			t.Fatalf("failed to corrupt lvbh: %v", err)
		}

		bn, bh := restoreLastValid()
		if bn != 12345 {
			t.Fatalf("expected 12345, got %d", bn)
		}
		if bh != hash {
			t.Fatalf("unexpected hash %x", bh)
		}
	})
}

func TestRestoreLastValidFromLegacyKeys(t *testing.T) {
	withTempDB(t, func() {
		var hash crypto.Sha3
		for i := range hash {
			hash[i] = byte(255 - i)
		}
		if err := db.DB.Put(lvbnKey, util.DecodeUintToBytes(777)); err != nil {
			t.Fatalf("failed to write lvbn: %v", err)
		}
		if err := db.DB.Put(lvbhKey, hash[:]); err != nil {
			t.Fatalf("failed to write lvbh: %v", err)
		}

		bn, bh := restoreLastValid()
		if bn != 777 {
			t.Fatalf("expected 777, got %d", bn)
		}
		if bh != hash {
			t.Fatalf("unexpected hash %x", bh)
		}

		payload, err := db.DB.Get(lastValidRecordKey)
		if err != nil {
			t.Fatalf("expected combined record, got error: %v", err)
		}
		if len(payload) != lastValidRecordSize {
			t.Fatalf("unexpected combined record size %d", len(payload))
		}
	})
}

func TestRestoreLastValidInvalidCombinedRecord(t *testing.T) {
	withTempDB(t, func() {
		if err := db.DB.Put(lastValidRecordKey, []byte{1, 2, 3}); err != nil {
			t.Fatalf("failed to write invalid record: %v", err)
		}

		bn, bh := restoreLastValid()
		expectedBN, expectedHash := defaultLastValidRecord.bn, defaultLastValidRecord.hash
		if bn != expectedBN {
			t.Fatalf("expected default block %d, got %d", expectedBN, bn)
		}
		if bh != expectedHash {
			t.Fatalf("expected default hash %x, got %x", expectedHash, bh)
		}

		if _, err := db.DB.Get(lastValidRecordKey); err == nil {
			t.Fatalf("invalid combined key should be removed")
		}
	})
}
