// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

//go:build !gofuzz && cgo
// +build !gofuzz,cgo

// Package secp256k1 wraps the bitcoin secp256k1 C library.
package secp256k1

import (
	"math/big"

	gethsecp "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var (
	ErrInvalidMsgLen       = gethsecp.ErrInvalidMsgLen
	ErrInvalidSignatureLen = gethsecp.ErrInvalidSignatureLen
	ErrInvalidRecoveryID   = gethsecp.ErrInvalidRecoveryID
	ErrInvalidKey          = gethsecp.ErrInvalidKey
	ErrInvalidPubkey       = gethsecp.ErrInvalidPubkey
	ErrSignFailed          = gethsecp.ErrSignFailed
	ErrRecoverFailed       = gethsecp.ErrRecoverFailed
)

// Sign creates a recoverable ECDSA signature.
// The produced signature is in the 65-byte [V || R || S] format where V is 0 or 1.
//
// The caller is responsible for ensuring that msg cannot be chosen
// directly by an attacker. It is usually preferable to use a cryptographic
// hash function on any input before handing it to this function.
func Sign(msg []byte, seckey []byte) ([]byte, error) {
	sig, err := gethsecp.Sign(msg, seckey)
	if err != nil {
		return nil, err
	}
	if len(sig) != 65 {
		return nil, ErrInvalidSignatureLen
	}

	out := make([]byte, 65)
	out[0] = sig[64]
	copy(out[1:], sig[:64])
	return out, nil
}

// RecoverPubkey returns the public key of the signer.
// msg must be the 32-byte hash of the message to be signed.
// sig must be a 65-byte compact ECDSA signature containing the
// recovery id as the first element.
func RecoverPubkey(msg []byte, sig []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, ErrInvalidMsgLen
	}
	if err := checkSignature(sig); err != nil {
		return nil, err
	}

	shiftSig := make([]byte, 65)
	copy(shiftSig, sig[1:])
	shiftSig[64] = sig[0]
	return gethsecp.RecoverPubkey(msg, shiftSig)
}

// VerifySignature checks that the given pubkey created signature over message.
// The signature should be in [R || S] format.
func VerifySignature(pubkey, msg, signature []byte) bool {
	if len(msg) != 32 || len(signature) != 64 || len(pubkey) != 65 {
		return false
	}
	return gethsecp.VerifySignature(pubkey, msg, signature)
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
// It returns non-nil coordinates if the public key is valid.
func DecompressPubkey(pubkey []byte) (x, y *big.Int) {
	return gethsecp.DecompressPubkey(pubkey)
}

// CompressPubkey encodes a public key to 33-byte compressed format.
func CompressPubkey(x, y *big.Int) []byte {
	return gethsecp.CompressPubkey(x, y)
}

// DecompressPubkeyBytes parses public key bytes in the 33-byte compressed format.
func DecompressPubkeyBytes(pubkey []byte) []byte {
	x, y := gethsecp.DecompressPubkey(pubkey)
	if x == nil || y == nil {
		return nil
	}
	return gethsecp.S256().Marshal(x, y)
}

// CompressPubkeyBytes encodes a public key to 33-byte compressed format.
func CompressPubkeyBytes(pubkey []byte) []byte {
	if len(pubkey) != 65 {
		return nil
	}
	x, y := gethsecp.S256().Unmarshal(pubkey)
	if x == nil || y == nil {
		return nil
	}
	return gethsecp.CompressPubkey(x, y)
}

func checkSignature(sig []byte) error {
	if len(sig) != 65 {
		return ErrInvalidSignatureLen
	}
	if sig[0] >= 4 {
		return ErrInvalidRecoveryID
	}
	return nil
}
