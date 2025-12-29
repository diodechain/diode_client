// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package secp256k1

import (
	"math/big"

	gethsecp "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func (BitCurve *BitCurve) ScalarMult(Bx, By *big.Int, scalar []byte) (*big.Int, *big.Int) {
	return gethsecp.S256().ScalarMult(Bx, By, scalar)
}
