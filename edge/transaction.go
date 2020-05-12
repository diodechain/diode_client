// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"crypto/ecdsa"

	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"github.com/diodechain/diode_go_client/rlp"
	"github.com/diodechain/diode_go_client/util"
)

const (
	chainID uint64 = 41043
)

// DeployTransaction struct
type DeployTransaction struct {
	from     Address
	Nonce    uint64
	GasPrice uint64
	GasLimit uint64
	To       []byte
	Value    uint64
	Data     []byte
	V        uint64
	R        [32]byte
	S        [32]byte
	chainID  uint64
	sig      [65]byte
}

// deployTransactionWithSig used to create EIP155 transaction
type deployTransactionWithSig struct {
	Nonce    uint64
	GasPrice uint64
	GasLimit uint64
	To       []byte
	Value    uint64
	Data     []byte
	V        uint64
	R        []byte
	S        []byte
}

type deployTransactionWithoutSig struct {
	Nonce    uint64
	GasPrice uint64
	GasLimit uint64
	To       []byte
	Value    uint64
	Data     []byte
}

// Transaction struct
type Transaction struct {
	from     Address
	Nonce    uint64
	GasPrice uint64
	GasLimit uint64
	To       Address
	Value    uint64
	Data     []byte
	V        uint64
	R        [32]byte
	S        [32]byte
	chainID  uint64
	sig      [65]byte
}

// transactionWithSig used to create EIP155 transaction
type transactionWithSig struct {
	Nonce    uint64
	GasPrice uint64
	GasLimit uint64
	To       Address
	Value    uint64
	Data     []byte
	V        uint64
	R        []byte
	S        []byte
}

type transactionWithoutSig struct {
	Nonce    uint64
	GasPrice uint64
	GasLimit uint64
	To       Address
	Value    uint64
	Data     []byte
}

// NewTransaction returns transaction
func NewDeployTransaction(nonce uint64, gasPrice uint64, gasLimit uint64, value uint64, data []byte, chainid uint64) *DeployTransaction {
	if chainid <= 0 {
		chainid = chainID
	}
	return &DeployTransaction{
		Nonce:    nonce,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		Value:    value,
		Data:     data,
		chainID:  chainid,
	}
}

// NewTransaction returns transaction
func NewTransaction(nonce uint64, gasPrice uint64, gasLimit uint64, to Address, value uint64, data []byte, chainid uint64) *Transaction {
	if chainid <= 0 {
		chainid = chainID
	}
	return &Transaction{
		Nonce:    nonce,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		To:       to,
		Value:    value,
		Data:     data,
		chainID:  chainid,
	}
}

// From returns from address if transaction had been signed
// Remember it takes some resources to recover address
func (tx *Transaction) From() (util.Address, error) {
	if tx.from != util.EmptyAddress {
		return tx.from, nil
	}
	msgHash, err := tx.HashWithSig()
	if err != nil {
		return [20]byte{}, err
	}
	pubKey, err := secp256k1.RecoverPubkey(msgHash, tx.sig[:])
	if err != nil {
		return [20]byte{}, err
	}
	tx.from = util.PubkeyToAddress(pubKey)
	return tx.from, nil
}

// HashWithSig returns keccak256 of rlp encoded transaction
func (tx *Transaction) HashWithSig() ([]byte, error) {
	txWithSig := transactionWithSig{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		GasLimit: tx.GasLimit,
		To:       tx.To,
		Value:    tx.Value,
		Data:     tx.Data,
		V:        tx.chainID,
		R:        []byte{},
		S:        []byte{},
	}
	encodedRlp, err := rlp.EncodeToBytes(txWithSig)
	if err != nil {
		return nil, err
	}
	hash := crypto.Sha3Hash(encodedRlp)
	return hash, nil
}

// HashWithoutSig returns keccak256 of rlp encoded transaction
func (tx *Transaction) HashWithoutSig() ([]byte, error) {
	txWithoutSig := transactionWithoutSig{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		GasLimit: tx.GasLimit,
		To:       tx.To,
		Value:    tx.Value,
		Data:     tx.Data,
	}
	encodedRlp, err := rlp.EncodeToBytes(txWithoutSig)
	if err != nil {
		return nil, err
	}
	hash := crypto.Sha3Hash(encodedRlp)
	return hash, nil
}

// Sign sign the transaction
func (tx *Transaction) Sign(privKey *ecdsa.PrivateKey) (err error) {
	var msgHash []byte
	if tx.chainID > 0 {
		msgHash, err = tx.HashWithSig()
	} else {
		msgHash, err = tx.HashWithoutSig()
	}
	if err != nil {
		return err
	}
	sig, err := secp256k1.Sign(msgHash, privKey.D.Bytes())
	if err != nil {
		return err
	}
	recid := uint64(sig[0])
	tx.V = recid + 35 + tx.chainID*2
	copy(tx.R[:], sig[1:33])
	copy(tx.S[:], sig[33:])
	copy(tx.sig[:], sig)
	return nil
}

// ToRLP returns rlp encoded of transaction
func (tx *Transaction) ToRLP() ([]byte, error) {
	txWithSig := transactionWithSig{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		GasLimit: tx.GasLimit,
		To:       tx.To,
		Value:    tx.Value,
		Data:     tx.Data,
		V:        tx.V,
		R:        tx.R[:],
		S:        tx.S[:],
	}
	return rlp.EncodeToBytes(txWithSig)
}

// TransactionHash returns keccak256 of rlp encoded transaction
// somehow transaction hash is different from the transaction in state
func (tx *Transaction) TransactionHash() ([]byte, error) {
	encodedRlp, err := tx.ToRLP()
	if err != nil {
		return nil, err
	}
	hash := crypto.Sha3Hash(encodedRlp)
	return hash, nil
}

// From returns from address if transaction had been signed
// Remember it takes some resources to recover address
func (tx *DeployTransaction) From() (util.Address, error) {
	if tx.from != util.EmptyAddress {
		return tx.from, nil
	}
	msgHash, err := tx.HashWithSig()
	if err != nil {
		return [20]byte{}, err
	}
	pubKey, err := secp256k1.RecoverPubkey(msgHash, tx.sig[:])
	if err != nil {
		return [20]byte{}, err
	}
	tx.from = util.PubkeyToAddress(pubKey)
	return tx.from, nil
}

// HashWithSig returns keccak256 of rlp encoded transaction
func (tx *DeployTransaction) HashWithSig() ([]byte, error) {
	txWithSig := deployTransactionWithSig{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		GasLimit: tx.GasLimit,
		To:       nil,
		Value:    tx.Value,
		Data:     tx.Data,
		V:        tx.chainID,
		R:        []byte{},
		S:        []byte{},
	}
	encodedRlp, err := rlp.EncodeToBytes(txWithSig)
	if err != nil {
		return nil, err
	}
	hash := crypto.Sha3Hash(encodedRlp)
	return hash, nil
}

// HashWithoutSig returns keccak256 of rlp encoded transaction
func (tx *DeployTransaction) HashWithoutSig() ([]byte, error) {
	txWithoutSig := deployTransactionWithoutSig{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		GasLimit: tx.GasLimit,
		To:       nil,
		Value:    tx.Value,
		Data:     tx.Data,
	}
	encodedRlp, err := rlp.EncodeToBytes(txWithoutSig)
	if err != nil {
		return nil, err
	}
	hash := crypto.Sha3Hash(encodedRlp)
	return hash, nil
}

// Sign sign the transaction
func (tx *DeployTransaction) Sign(privKey *ecdsa.PrivateKey) (err error) {
	var msgHash []byte
	if tx.chainID > 0 {
		msgHash, err = tx.HashWithSig()
	} else {
		msgHash, err = tx.HashWithoutSig()
	}
	if err != nil {
		return err
	}
	sig, err := secp256k1.Sign(msgHash, privKey.D.Bytes())
	if err != nil {
		return err
	}
	recid := uint64(sig[0])
	tx.V = recid + 35 + tx.chainID*2
	copy(tx.R[:], sig[1:33])
	copy(tx.S[:], sig[33:])
	copy(tx.sig[:], sig)
	return nil
}

// ToRLP returns rlp encoded of transaction
func (tx *DeployTransaction) ToRLP() ([]byte, error) {
	txWithSig := deployTransactionWithSig{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		GasLimit: tx.GasLimit,
		To:       nil,
		Value:    tx.Value,
		Data:     tx.Data,
		V:        tx.V,
		R:        tx.R[:],
		S:        tx.S[:],
	}
	return rlp.EncodeToBytes(txWithSig)
}

// TransactionHash returns keccak256 of rlp encoded transaction
// somehow transaction hash is different from the transaction in state
func (tx *DeployTransaction) TransactionHash() ([]byte, error) {
	encodedRlp, err := tx.ToRLP()
	if err != nil {
		return nil, err
	}
	hash := crypto.Sha3Hash(encodedRlp)
	return hash, nil
}