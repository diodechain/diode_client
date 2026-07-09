package rpc

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/util"
)

func TestNormalizePrivatePEM_piFixture(t *testing.T) {
	t.Parallel()

	pemBytes := mustDBPrivateKey(t, filepath.Join("..", "pi.db"))
	before := clientPubkeyFromPEM(t, pemBytes)

	normalized, err := crypto.NormalizePrivatePEM(pemBytes)
	if err != nil {
		t.Fatalf("NormalizePrivatePEM: %v", err)
	}
	if bytes.Equal(pemBytes, normalized) {
		t.Fatal("expected explicit-curve PEM to be rewritten")
	}

	block, _ := pem.Decode(normalized)
	if block == nil {
		t.Fatal("normalized pem is invalid")
	}
	if !crypto.PrivateDERUsesNamedCurve(block.Bytes) {
		t.Fatal("expected normalized PEM to use named-curve encoding")
	}
	if len(block.Bytes) > 150 {
		t.Fatalf("expected compact DER, got %d bytes", len(block.Bytes))
	}

	after := clientPubkeyFromPEM(t, normalized)
	if util.PubkeyToAddress(before) != util.PubkeyToAddress(after) {
		t.Fatalf("address changed during normalization: %x -> %x", util.PubkeyToAddress(before), util.PubkeyToAddress(after))
	}
}

func TestNormalizePrivatePEM_namedCurveUnchanged(t *testing.T) {
	t.Parallel()

	pemBytes := mustDBPrivateKey(t, filepath.Join("..", "wallet1.db"))
	normalized, err := crypto.NormalizePrivatePEM(pemBytes)
	if err != nil {
		t.Fatalf("NormalizePrivatePEM: %v", err)
	}
	if !bytes.Equal(pemBytes, normalized) {
		t.Fatal("expected named-curve PEM to remain unchanged")
	}
}

func TestNormalizePrivatePEM_shortScalar(t *testing.T) {
	t.Parallel()

	scalar32 := []byte{
		0x00, 0x26, 0xf4, 0x2f, 0x9a, 0x52, 0xfa, 0xed,
		0x4b, 0xd0, 0xd6, 0x7f, 0x0e, 0x76, 0x24, 0xfa,
		0x4f, 0x49, 0xf6, 0xfb, 0x77, 0x4b, 0xd7, 0x25,
		0xef, 0x36, 0x52, 0xdc, 0x94, 0xf5, 0x65, 0x7a,
	}
	der, err := asn1.Marshal(cryptoECPrivateKey{Version: 1, PrivateKey: scalar32[1:]})
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if ValidatePrivatePEM(pemBytes) {
		t.Fatal("expected strict validation to fail before normalization")
	}

	normalized, err := crypto.NormalizePrivatePEM(pemBytes)
	if err != nil {
		t.Fatalf("NormalizePrivatePEM: %v", err)
	}
	if !ValidatePrivatePEM(normalized) {
		t.Fatal("expected normalized PEM to validate")
	}
}

func TestEnsurePrivatePEM_normalizesExplicitCurve(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	orig := mustDBPrivateKey(t, filepath.Join("..", "pi.db"))
	database, err := db.OpenFile(dbPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Put("private", orig); err != nil {
		t.Fatal(err)
	}

	db.DB = database
	defer func() { db.DB = nil }()

	normalized := EnsurePrivatePEM()
	if bytes.Equal(orig, normalized) {
		t.Fatal("expected EnsurePrivatePEM to normalize explicit-curve key")
	}
	if !ValidatePrivatePEM(normalized) {
		t.Fatal("expected normalized key to validate")
	}

	stored, err := database.Get("private")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, normalized) {
		t.Fatal("expected normalized key to be persisted")
	}
}

type cryptoECPrivateKey struct {
	Version    int
	PrivateKey []byte
}

func mustDBPrivateKey(t *testing.T, dbPath string) []byte {
	t.Helper()
	if _, err := os.Stat(dbPath); err != nil {
		t.Skipf("%s unavailable: %v", dbPath, err)
	}
	database, err := db.OpenFile(dbPath, false)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	key, err := database.Get("private")
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	return key
}

func clientPubkeyFromPEM(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("invalid pem")
	}
	priv, err := crypto.DerToECDSA(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub := crypto.MarshalPubkey(&priv.PublicKey)
	if pub == nil {
		t.Fatal("invalid public key")
	}
	return pub
}
