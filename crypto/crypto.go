package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/diodechain/diode_client/crypto/secp256k1"
	"golang.org/x/crypto/sha3"
)

const ecPrivKeyVersion = 1

var (
	secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	// Secp256k1NamedCurveOID is the ASN.1 OID for the secp256k1 named curve (1.3.132.0.10).
	Secp256k1NamedCurveOID = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

// Sha3 hash
type Sha3 [32]byte

func (s Sha3) String() string {
	return hex.EncodeToString(s[:])
}

var errInvalidPubkey = errors.New("invalid secp256k1 public key")

// ECPEMPrivateKey openssl ec pem private key
// see (maybe): https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
type ECPEMPrivateKey struct {
	E1      *big.Int
	KeyInfo struct {
		KeyType   asn1.ObjectIdentifier
		CurveName asn1.ObjectIdentifier
	}
	KeyData []byte
}

// ECPublicKey ec public key format
// see (maybe): https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
type ECPublicKey struct {
	Algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters []byte `asn1:"optional"`
	}
	PublicKey asn1.BitString
}

// ECPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//
//	RFC 5915
//	SEC1 - http://www.secg.org/sec1-v2.pdf
//
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ECPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// S256 returns an instance of the secp256k1 curve.
func S256() elliptic.Curve {
	return secp256k1.S256()
}

// PemToECDSA creates a private key with the given openssl pem encoded value.
// TODO: check key type and curve name
func PemToECDSA(pem []byte) (*ecdsa.PrivateKey, error) {
	var privKey ECPEMPrivateKey
	if _, err := asn1.Unmarshal(pem, &privKey); err != nil {
		log.Fatal(err)
		// return nil, err
	}
	return DerToECDSA(privKey.KeyData)
}

// DerToECDSA creates a private key with the given der encoded D value.
func DerToECDSA(derD []byte) (*ecdsa.PrivateKey, error) {
	var privKey ECPrivateKey
	if _, err := asn1.Unmarshal(derD, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}
	return toECDSA(privKey.PrivateKey, true)
}

// PrivateDERUsesNamedCurve reports whether der is an SEC1 ECPrivateKey using the secp256k1 named-curve OID.
func PrivateDERUsesNamedCurve(der []byte) bool {
	var raw ECPrivateKey
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return false
	}
	return raw.NamedCurveOID.Equal(Secp256k1NamedCurveOID)
}

// NormalizePrivatePEM re-encodes a secp256k1 private key PEM to named-curve SEC1 format.
// Relays expect the compact SPKI produced from that encoding during the TLS handshake.
// Keys already in named-curve form are returned unchanged.
func NormalizePrivatePEM(pemBytes []byte) ([]byte, error) {
	if pemBytes == nil {
		return nil, errors.New("empty private key pem")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Bytes == nil {
		return nil, errors.New("invalid private key pem")
	}
	if PrivateDERUsesNamedCurve(block.Bytes) {
		return pemBytes, nil
	}
	priv, err := privateKeyFromSEC1DER(block.Bytes)
	if err != nil {
		return nil, err
	}
	return marshalNamedCurvePrivatePEM(priv)
}

func privateKeyFromSEC1DER(der []byte) (*ecdsa.PrivateKey, error) {
	var raw ECPrivateKey
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}
	if raw.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("unknown EC private key version %d", raw.Version)
	}
	if len(raw.PrivateKey) == 0 {
		return nil, errors.New("empty EC private key scalar")
	}
	priv, err := toECDSA(raw.PrivateKey, true)
	if err == nil {
		return priv, nil
	}
	priv, looseErr := toECDSA(raw.PrivateKey, false)
	if looseErr != nil {
		return nil, err
	}
	return priv, nil
}

func marshalNamedCurvePrivatePEM(priv *ecdsa.PrivateKey) ([]byte, error) {
	if priv == nil || priv.D == nil {
		return nil, errors.New("invalid private key")
	}
	pub := MarshalPubkey(&priv.PublicKey)
	if pub == nil {
		return nil, errors.New("invalid public key")
	}
	der, err := asn1.Marshal(ECPrivateKey{
		Version:       ecPrivKeyVersion,
		PrivateKey:    Secp256k1ScalarBytes(priv),
		NamedCurveOID: Secp256k1NamedCurveOID,
		PublicKey:     asn1.BitString{Bytes: pub, BitLength: len(pub) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// Secp256k1ScalarBytes returns priv.D as exactly 32 big-endian bytes (leading zeros as needed).
// go-ethereum's secp256k1.Sign requires len(seckey)==32; big.Int.Bytes() strips leading zeros,
// which would return ErrInvalidKey ("invalid private key"). FillBytes is the idiomatic fixed-width encoding.
func Secp256k1ScalarBytes(priv *ecdsa.PrivateKey) []byte {
	if priv == nil || priv.D == nil {
		return nil
	}
	out := make([]byte, 32)
	priv.D.FillBytes(out)
	return out
}

// ToECDSA creates a private key with the given D value.
func ToECDSA(d []byte) (*ecdsa.PrivateKey, error) {
	return toECDSA(d, true)
}

// ToECDSAUnsafe blindly converts a binary blob to a private key. It should almost
// never be used unless you are sure the input is valid and want to avoid hitting
// errors due to bad origin encoding (0 prefixes cut off).
func ToECDSAUnsafe(d []byte) *ecdsa.PrivateKey {
	priv, _ := toECDSA(d, false)
	return priv
}

// DerToPublicKey returns uncompressed ecdsa public key bytes
func DerToPublicKey(derPubKey []byte) ([]byte, error) {
	pubKey := make([]byte, 1)
	var ecPubKey ECPublicKey
	if _, err := asn1.Unmarshal(derPubKey, &ecPubKey); err != nil {
		return pubKey, err
	}
	// uncompress
	return ecPubKey.PublicKey.Bytes, nil
}

// toECDSA creates a private key with the given D value. The strict parameter
// controls whether the key's length should be enforced at the curve size or
// it can also accept legacy encodings (0 prefixes).
func toECDSA(d []byte, strict bool) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = S256()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	//lint:ignore SA1019 secp256k1 not supported by crypto/ecdh; ScalarBaseMult required
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

// UnmarshalPubkey converts bytes to a secp256k1 public key.
func UnmarshalPubkey(pub []byte) (*ecdsa.PublicKey, error) {
	//lint:ignore SA1019 because S256() doesn't have it's own NewPublicKey method
	x, y := elliptic.Unmarshal(S256(), pub)
	if x == nil {
		return nil, errInvalidPubkey
	}
	return &ecdsa.PublicKey{Curve: S256(), X: x, Y: y}, nil
}

// MarshalPubkey converts secp256k1 public key to uncompressed bytes
func MarshalPubkey(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	//lint:ignore SA1019 because S256() doesn't have it's own Marshal method
	return elliptic.Marshal(S256(), pub.X, pub.Y)
}

// Sha256 the data
func Sha256(data []byte) []byte {
	sha256 := sha256.New()
	sha256.Write(data)
	return sha256.Sum(nil)
}

// Sha3Hash the data
func Sha3Hash(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// PubkeyFromCompressed returns public key generate from compressed public key
func PubkeyFromCompressed(pubkey []byte) (dpubkey []byte) {
	if len(pubkey) == 33 {
		dpubkey = secp256k1.DecompressPubkeyBytes(pubkey)
		return
	}
	// TODO: fix this
	if len(pubkey) != 65 {
		log.Panicf("This is not a pubkey %v", pubkey)
	}
	dpubkey = pubkey[1:]
	return
}

// HexToECDSA returns ecdsa private key for given hex string
func HexToECDSA(hexKey string) (key *ecdsa.PrivateKey, err error) {
	var binKey []byte
	binKey, err = hex.DecodeString(hexKey)
	if err != nil {
		return
	}
	key = ToECDSAUnsafe(binKey)
	if key == nil {
		err = fmt.Errorf("key was not correct")
		return
	}
	return
}
