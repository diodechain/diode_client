// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"bytes"
	"log"

	// "io"

	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"

	// "github.com/diodechain/diode_go_client/crypto/sha3"
	// "github.com/diodechain/diode_go_client/util"

	bert "github.com/exosite/gobert"
	// "strings"
)

var (
	NullData = []byte("null")

	curlyBracketStart  = []byte("{")
	curlyBracketEnd    = []byte("}")
	squareBracketStart = []byte("[")
	squareBracketEnd   = []byte("]")
	doubleQuote        = []byte(`"`)
	comma              = []byte(",")
)

// ResponseFuture is a one time use channel
type ResponseFuture chan []byte
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
	Raw    []byte
	RawMsg []byte
	Method []byte
}

type BlockHeader struct {
	TxHash      []byte
	StateHash   []byte
	PrevBlock   []byte
	MinerSig    []byte
	Miner       []byte
	MinerPubkey []byte
	BlockHash   []byte
	Timestamp   int64
	Nonce       int64
}

type PortOpen struct {
	Ref      int64
	Port     int64
	DeviceID string
	Ok       bool
	Err      *Error
}

type PortSend struct {
	Ref  int64
	Data []byte
	Ok   bool
	Err  *Error
}

type PortClose struct {
	Ref int64
	Ok  bool
}

type ServerObj struct {
	Host         []byte
	EdgePort     int64
	ServerPort   int64
	Sig          []byte
	ServerPubKey []byte
}

type StateRoots struct {
	// BlockNumber int
	StateRoots   [][]byte
	rawStateRoot []byte
	stateRoot    []byte
}

type AccountRoots struct {
	// BlockNumber int
	AccountRoots   [][]byte
	rawStorageRoot []byte
	storageRoot    []byte
}

type Account struct {
	Address     []byte
	StorageRoot []byte
	Nonce       int64
	Code        []byte
	Balance     int64
	AccountHash []byte
	proof       []byte
	stateTree   *MerkleTree
}

type AccountValue struct {
	proof       []byte
	accountTree *MerkleTree
}

// RLPAccount struct for rlp encoding account
type RLPAccount struct {
	Nonce       uint
	Balance     uint
	StorageRoot []byte
	Code        []byte
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
		log.Fatal(err)
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
		log.Fatal(err)
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

// func BitstringToUint(src string) {}

func isJSONObj(json []byte) bool {
	if len(json) == 0 {
		return false
	}
	return (json[0] == curlyBracketStart[0]) && (json[len(json)-1] == curlyBracketEnd[0])
}

func isJSONArr(json []byte) bool {
	if len(json) == 0 {
		return false
	}
	return (json[0] == squareBracketStart[0]) && (json[len(json)-1] == squareBracketEnd[0])
}

func isJSONStr(json []byte) bool {
	if len(json) == 0 {
		return false
	}
	return (json[0] == doubleQuote[0]) && (json[len(json)-1] == doubleQuote[0])
}

// JSONArrLen returns array length of json
// TODO: JSONObjLen
func JSONArrLen(json []byte) int {
	var length int
	var sqbCount int
	if !isJSONArr(json) {
		return length
	}
	src := json[1 : len(json)-1]
	for _, byt := range src {
		if byt == squareBracketStart[0] {
			sqbCount++
		} else if byt == squareBracketEnd[0] {
			sqbCount--
		} else if (byt == comma[0]) && (sqbCount == 0) {
			length++
		}
	}
	length++
	return length
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
func (ac *Account) StateTree() *MerkleTree {
	return ac.stateTree
}

// AccountRoot returns account root of account value, you can compare with accountroots[mod]
func (acv *AccountValue) AccountRoot() []byte {
	return acv.accountTree.RootHash
}

// AccountTree returns merkle tree of account value
func (acv *AccountValue) AccountTree() *MerkleTree {
	return acv.accountTree
}

// Hash returns sha3 of bert encoded block header
func (blockHeader *BlockHeader) Hash() ([]byte, error) {
	encHeader, err := bert.Encode([7]bert.Term{blockHeader.PrevBlock, blockHeader.MinerPubkey, blockHeader.StateHash, blockHeader.TxHash, blockHeader.Timestamp, blockHeader.Nonce, blockHeader.MinerSig})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(encHeader), nil
}

// HashWithoutSig returns sha3 of bert encoded block header without miner signature
func (blockHeader *BlockHeader) HashWithoutSig() ([]byte, error) {
	encHeader, err := bert.Encode([6]bert.Term{blockHeader.PrevBlock, blockHeader.MinerPubkey, blockHeader.StateHash, blockHeader.TxHash, blockHeader.Timestamp, blockHeader.Nonce})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(encHeader), nil
}

// ValidateSig check miner signature is valid
func (blockHeader *BlockHeader) ValidateSig() bool {
	msgHash, err := blockHeader.HashWithoutSig()
	if err != nil {
		return false
	}
	sig := []byte{}
	sig = append(sig, blockHeader.MinerSig[1:65]...)
	pubkey := blockHeader.Miner
	return secp256k1.VerifySignature(pubkey, msgHash, sig)
}

// Hash returns hash of server object
func (serverObj *ServerObj) Hash() ([]byte, error) {
	msg, err := bert.Encode([3]bert.Term{serverObj.Host, serverObj.EdgePort, serverObj.ServerPort})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(msg), err
}

// RecoverServerPubKey returns server public key
func (serverObj *ServerObj) RecoverServerPubKey() ([]byte, error) {
	msgHash, err := serverObj.Hash()
	if err != nil {
		return nil, err
	}
	pubKey, err := secp256k1.RecoverPubkey(msgHash, serverObj.Sig)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (serverObj *ServerObj) ValidateSig(serverID [20]byte) bool {
	pubKey, err := serverObj.RecoverServerPubKey()
	if err != nil {
		log.Printf("ServerObj.ValidateSig(): %v\n", err)
		return false
	}
	return serverID == crypto.PubkeyToAddress(pubKey)
}
