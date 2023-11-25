// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package blockquick

import (
	"fmt"
	"log"
	"math/big"

	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/crypto/secp256k1"
	"github.com/diodechain/diode_client/util"
	bert "github.com/diodechain/gobert"
)

// BlockHeader is the modified Ethereum Block header
// It additionally contains a miner signature (minerSig)
type BlockHeader struct {
	txHash      []byte
	stateHash   []byte
	prevBlock   []byte
	minerSig    []byte
	minerPubkey []byte
	timestamp   uint64
	number      uint64
	nonce       big.Int
}

// NewHeader creates a new block header from existing data
func NewHeader(txHash []byte, stateHash []byte, prevBlock []byte, minerSig []byte, minerPubkey []byte, timestamp uint64, number uint64, nonce big.Int) (bh BlockHeader, err error) {
	header := BlockHeader{
		txHash:      txHash,
		stateHash:   stateHash,
		prevBlock:   prevBlock,
		minerSig:    minerSig,
		minerPubkey: minerPubkey,
		timestamp:   timestamp,
		number:      number,
		nonce:       nonce,
	}
	if !header.ValidateSig() {
		err = fmt.Errorf("invalid block %v %v", header, header.Hash())
		return
	}
	bh = header
	return
}

// Serialize returns a serialized version
func (bh *BlockHeader) Serialize() ([]byte, error) {
	data, err := bert.Encode([7]bert.Term{
		bh.prevBlock,
		// bh.minerPubkey,
		bh.stateHash,
		bh.txHash,
		bh.timestamp,
		bh.number,
		bh.nonce,
		bh.minerSig})
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}

// Hash returns sha3 of bert encoded block header
func (bh *BlockHeader) Hash() (hash Sha3) {
	encHeader, err := bh.Serialize()
	if err != nil {
		log.Panicf("BlockHeader.Hash(): %v", err)
	}
	copy(hash[:], crypto.Sha256(encHeader))
	return
}

// Miner returns the block miners hash
func (bh *BlockHeader) Miner() Address {
	return util.PubkeyToAddress(bh.minerPubkey)
}

// Timestamp returns the block timestamp
func (bh *BlockHeader) Timestamp() uint64 {
	return bh.timestamp
}

// Parent returns the block parents hash (the previous block hash)
func (bh *BlockHeader) Parent() (hash Sha3) {
	copy(hash[:], bh.prevBlock)
	return
}

// Number returns the block number
func (bh *BlockHeader) Number() uint64 {
	return bh.number
}

// HashWithoutSig returns sha3 of bert encoded block header without miner signature
func (bh *BlockHeader) HashWithoutSig() ([]byte, error) {
	encHeader, err := bert.Encode([6]bert.Term{
		bh.prevBlock,
		bh.stateHash,
		bh.txHash,
		bh.timestamp,
		bh.number,
		bh.nonce})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(encHeader), nil
}

// ValidateSig check miner signature is valid
func (bh *BlockHeader) ValidateSig() bool {
	msgHash, err := bh.HashWithoutSig()
	if err != nil {
		return false
	}
	return secp256k1.VerifySignature(bh.minerPubkey, msgHash, bh.minerSig[1:65])
}
