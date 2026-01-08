// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package edge

import (
	"bytes"
	"math/big"

	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/util"
	bert "github.com/diodechain/gobert"
)

// Address represents an Ethereum address
type Address = util.Address

type Response struct {
	Raw     []byte
	RawData [][]byte
	Method  string
}

type Request struct {
	Raw     []byte
	RawData [][]byte
	Method  string
}

type Error struct {
	Message string
}

type PortOpen struct {
	RequestID     uint64
	Ref           string
	Protocol      int
	PortNumber    int
	SrcPortNumber int
	DeviceID      Address
	Ok            bool
	Err           error
}

type PortOpen2 struct {
	RequestID      uint64
	PortName       string
	PhysicalPort   int
	SourceDeviceID Address
	Flags          string
	Ok             bool
	Err            error
}

type TicketRequest struct {
	RequestID uint64
	Usage     *big.Int
	Err       error
}

type PortSend struct {
	Ref  string
	Data []byte
	Ok   bool
	Err  error
}

type PortClose struct {
	Ref string
	Ok  bool
	Err error
}

type Goodbye struct {
	Reason  string
	Message string
	Err     error
}

type ServerObj struct {
	Node         util.Address
	Host         []byte
	EdgePort     uint64
	ServerPort   uint64
	Sig          []byte
	ServerPubKey []byte
	Extra        map[string]big.Int
	ExtraString  map[string]string
}

type StateRoots struct {
	StateRoots   [][]byte
	rawStateRoot []byte
	stateRoot    []byte
}

type AccountRoots struct {
	AccountRoots   [][]byte
	rawStorageRoot []byte
	storageRoot    []byte
}

type Account struct {
	Address     []byte
	StorageRoot []byte
	Nonce       int64
	Code        []byte
	Balance     *big.Int
	AccountHash []byte
	// TODO: Why is is this unused?
	// proof       []byte
	stateTree MerkleTree
}

func (err Error) Error() string {
	return err.Message
}

type AccountValue struct {
	accountTree MerkleTree
}

// StateRoot returns state root of given state roots
func (sr *StateRoots) StateRoot() []byte {
	if len(sr.stateRoot) > 0 {
		return sr.stateRoot
	}
	bertStateRoot := [16]bert.Term{}
	for i, stateRoot := range sr.StateRoots {
		bertStateRoot[i] = stateRoot
	}
	rawStateRoot, err := bert.Encode(bertStateRoot)
	if err != nil {
		return util.EmptyBytes(32)
	}
	stateRoot := crypto.Sha256(rawStateRoot)
	sr.rawStateRoot = rawStateRoot
	sr.stateRoot = stateRoot
	return stateRoot
}

// Find return index of state root
func (sr *StateRoots) Find(stateRoot []byte) int {
	index := -1
	for i, v := range sr.StateRoots {
		if bytes.Equal(v, stateRoot) {
			index = i
			break
		}
	}
	return index
}

// StorageRoot returns storage root of given account roots
func (ar *AccountRoots) StorageRoot() []byte {
	if len(ar.storageRoot) > 0 {
		return ar.storageRoot
	}
	bertStorageRoot := [16]bert.Term{}
	for i, accountRoot := range ar.AccountRoots {
		bertStorageRoot[i] = accountRoot
	}
	rawStorageRoot, err := bert.Encode(bertStorageRoot)
	if err != nil {
		return util.EmptyBytes(32)
	}
	storageRoot := crypto.Sha256(rawStorageRoot)
	ar.rawStorageRoot = rawStorageRoot
	ar.storageRoot = storageRoot
	return storageRoot
}

// Find return index of account root
func (ar *AccountRoots) Find(accountRoot []byte) int {
	index := -1
	for i, v := range ar.AccountRoots {
		if bytes.Equal(v, accountRoot) {
			index = i
			break
		}
	}
	return index
}

// IsValid check the account hash is valid
// should we check state root?
// func (ac *Account) IsValid() bool {
// 	return false
// }

// StateRoot returns state root of account, you can compare with stateroots[mod]
func (ac *Account) StateRoot() []byte {
	return ac.stateTree.RootHash
}

// StateTree returns merkle tree of account
func (ac *Account) StateTree() MerkleTree {
	return ac.stateTree
}

// AccountRoot returns account root of account value, you can compare with accountroots[mod]
func (acv *AccountValue) AccountRoot() []byte {
	return acv.accountTree.RootHash
}

// AccountTree returns merkle tree of account value
func (acv *AccountValue) AccountTree() MerkleTree {
	return acv.accountTree
}
