// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"bytes"
	"fmt"
	"log"
	"math"

	//"math/big"
	//"strings"

	"github.com/buger/jsonparser"
	"github.com/diodechain/diode_go_client/util"
	bert "github.com/diodechain/gobert"
)

var (
	errorWrongTree   = fmt.Errorf("Wrong merkle tree data")
	errorKeyNotFound = fmt.Errorf("Key not found in merkle tree")
)

// MerkleTreeNode struct for node of merkle tree
type MerkleTreeNode struct {
	Hash []byte
}

// MerkleTreeLeave struct for leave of merkle tree
type MerkleTreeLeave struct {
	Key   []byte
	Value []byte
}

// MerkleTree struct for merkle tree
type MerkleTree struct {
	Nodes    []MerkleTreeNode
	Leaves   []MerkleTreeLeave
	RawTree  []byte
	RootHash []byte
	Module   int64
}

// NewMerkleTree returns merkle tree of given byte of json
// eg: ["0x", "0x1", ["0x2bbfda354b607b8cdd7d52c29344c76c17d76bb7d9187874a994144b55eaf931","0x0000000000000000000000000000000000000000000000000000000000000001"]]
func NewMerkleTree(rawTree []byte) (*MerkleTree, error) {
	if !isJSONArr(rawTree) {
		return nil, errorWrongTree
	}
	merkleTree := &MerkleTree{
		RawTree: rawTree,
	}
	rootHash, err := merkleTree.parse()
	if err != nil {
		return nil, err
	}
	merkleTree.RootHash = rootHash
	return merkleTree, nil
}

// Get returns the value of given key
func (mt *MerkleTree) Get(key []byte) ([]byte, error) {
	for _, leave := range mt.Leaves {
		if bytes.Equal(key, leave.Key) {
			return leave.Value, nil
		}
	}
	return nil, errorKeyNotFound
}

func (mt *MerkleTree) parse() ([]byte, error) {
	parsed, err := mt.rparse(mt.RawTree)
	if err != nil {
		return nil, err
	}
	return parsed.([]byte), nil
}

// parseProof returns bert hash of [proof]
// proof: [<prefix>, <modulo>, <values>] | {<proof>, <proof>} | <hash>
func (mt *MerkleTree) parseProof(proof []byte) ([]byte, error) {
	var proofLen, prefixByt, bitsLength int
	var prefix interface{}
	var bitsPrefix []byte
	var proofKey string
	proofLen = JSONArrLen(proof)
	bytPrefix, _, _, err := jsonparser.Get(proof, "[0]")
	if err != nil {
		return nil, err
	}
	// empty return 0x || empty string
	if len(bytPrefix) <= 0 || util.IsZeroPrefix(bytPrefix) {
		prefix = []byte("")
	} else {
		// decode bits string, change to binary encoding?
		splitPrefix := util.SplitBytesByN(bytPrefix, 8)
		for _, p := range splitPrefix {
			prefixByt = 0
			pLen := len(p)
			for j := 0; j < pLen; j++ {
				pow := 7 - j
				byt := p[j] - 48
				prefixByt += int(byt) * int(math.Pow(2, float64(pow)))
				bitsLength++
			}
			bitsPrefix = append(bitsPrefix, byte(prefixByt))
		}
		prefix = bert.Bitstring{
			Bytes: bitsPrefix,
			Bits:  uint8(bitsLength),
		}
	}
	hexModule, err := jsonparser.GetString(proof, "[1]")
	if err != nil {
		return nil, err
	}
	module, err := util.DecodeStringToInt(string(hexModule))
	if err != nil {
		return nil, err
	}
	mt.Module = module
	bertProof := bert.List{
		Items: []bert.Term{
			prefix,
			module,
		},
	}
	for i := 2; i < proofLen; i++ {
		proofKey = fmt.Sprintf("[%d]", i)
		values, _, _, _ := jsonparser.Get(proof, proofKey)
		hexKey, err := jsonparser.GetString(values, "[0]")
		if err != nil {
			return nil, err
		}
		hexValue, err := jsonparser.GetString(values, "[1]")
		if err != nil {
			return nil, err
		}
		key, err := util.DecodeString(hexKey)
		if err != nil {
			return nil, err
		}
		value, err := util.DecodeString(hexValue)
		if err != nil {
			return nil, err
		}
		proofs := make([][]byte, 2)
		proofs[0] = key
		proofs[1] = value
		bertProof.Items = append(bertProof.Items, proofs)
		// append leave
		leave := MerkleTreeLeave{
			Key:   key,
			Value: value,
		}
		mt.Leaves = append(mt.Leaves, leave)
	}
	return util.BertHash(bertProof)
}

// parse recursively
func (mt *MerkleTree) rparse(proof []byte) (interface{}, error) {
	var parsedProof []byte
	if isJSONArr(proof) {
		proofLen := JSONArrLen(proof)
		if proofLen == 1 {
			return util.DecodeString(string(proof[1 : len(proof)-1]))
		} else if proofLen == 2 {
			leftRaw, _, _, _ := jsonparser.Get(proof, "[0]")
			leftItem, err := mt.rparse(leftRaw)
			if err != nil {
				return nil, err
			}
			rightRaw, _, _, _ := jsonparser.Get(proof, "[1]")
			rightItem, err := mt.rparse(rightRaw)
			if err != nil {
				return nil, err
			}
			tree := [2]bert.Term{
				leftItem,
				rightItem,
			}
			return util.BertHash(tree)
		} else if proofLen >= 3 {
			// parseProof
			return mt.parseProof(proof)
		}
	} else if util.IsHexNumber(proof) {
		return util.DecodeStringToInt(string(proof))
	} else if util.IsHex(proof) {
		return util.DecodeString(string(proof))
	} else {
		log.Println("JSON of merkle proof must be hex or array")
		return nil, errorWrongTree
	}
	return parsedProof, nil
}
