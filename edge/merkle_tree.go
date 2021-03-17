// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"

	"github.com/diodechain/diode_go_client/util"
	bert "github.com/diodechain/gobert"
)

var (
	errWrongTree   = fmt.Errorf("wrong merkle tree data")
	errKeyNotFound = fmt.Errorf("key not found in merkle tree")
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
	mtp      MerkleTreeParser
	Nodes    []MerkleTreeNode
	Leaves   []MerkleTreeLeave
	RawTree  []interface{}
	RootHash []byte
	Modulo   uint64
}

// Get returns the value of given key
func (mt *MerkleTree) Get(key []byte) ([]byte, error) {
	for _, leave := range mt.Leaves {
		if bytes.Equal(key, leave.Key) {
			return leave.Value, nil
		}
	}
	return nil, errKeyNotFound
}

func (mt *MerkleTree) parse() (rootHash []byte, modulo uint64, leaves []MerkleTreeLeave, err error) {
	var parsed interface{}
	parsed, modulo, leaves, err = mt.mtp.rparse(mt.RawTree, 0)
	if err != nil {
		return
	}
	rootHash = parsed.([]byte)
	return
}

type MerkleTreeParser struct{}

// parseProof returns bert hash of [proof]
// proof: [<prefix>, <modulo>, <values>] | {<proof>, <proof>} | <hash>
func (mt MerkleTreeParser) parseProof(proof interface{}, depth int) (rootHash []byte, modulo uint64, leaves []MerkleTreeLeave, err error) {
	var prefix interface{}
	var bytPrefix []byte
	var bytModule []byte
	var key []byte
	var value []byte
	var subVal reflect.Value
	var ok bool
	val := reflect.ValueOf(proof)
	kind := val.Kind()
	if kind != reflect.Slice && kind != reflect.Array {
		err = errWrongTree
		return
	}
	proofLen := val.Len()
	if bytPrefix, ok = val.Index(0).Interface().([]byte); !ok {
		err = errWrongTree
		return
	}

	// The bytPrefix is actually fully client calculatable based on tree depth and position
	// The server provided prefix is encoded in base 2 encoding if the number of bits is not 8 dividable
	mod := depth % 8
	if mod == 0 {
		prefix = bytPrefix
	} else {
		left := (8 - mod)
		bits := make([]byte, len(bytPrefix))
		copy(bits, bytPrefix)
		if mod > 0 {
			bits = append(bits, make([]byte, left)...)
			for i := 0; i < left; i++ {
				bits[len(bits)-i-1] = 48
			}
		}
		var num big.Int
		if _, succ := num.SetString(string(bits), 2); !succ {
			err = errWrongTree
			return
		}
		prefix = bert.Bitstring{
			Bytes: num.Bytes(),
			Bits:  uint8(depth),
		}
	}
	if bytModule, ok = val.Index(1).Interface().([]byte); !ok {
		err = errWrongTree
		return
	}
	modulo = util.DecodeBytesToUint(bytModule)
	bertProof := bert.List{
		Items: []bert.Term{
			prefix,
			modulo,
		},
	}
	for i := 2; i < proofLen; i++ {
		subVal = val.Index(i).Elem()
		kind = subVal.Kind()
		if kind != reflect.Slice && kind != reflect.Array {
			err = errWrongTree
			return
		}
		if subVal.Len() < 1 {
			err = errWrongTree
			return
		}
		if key, ok = subVal.Index(0).Interface().([]byte); !ok {
			err = errWrongTree
			return
		}
		if value, ok = subVal.Index(1).Interface().([]byte); !ok {
			err = errWrongTree
			return
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
		leaves = append(leaves, leave)
	}
	rootHash, err = util.BertHash(bertProof)
	return
}

// parse recursively
func (mt MerkleTreeParser) rparse(proof interface{}, depth int) (interface{}, uint64, []MerkleTreeLeave, error) {
	val := reflect.ValueOf(proof)
	kind := val.Kind()
	if kind != reflect.Slice && kind != reflect.Array {
		return nil, 0, nil, errWrongTree
	}
	if bytVal, ok := val.Interface().([]byte); ok {
		return bytVal, 0, nil, nil
	}
	proofLen := val.Len()
	if proofLen == 0 {
		return nil, 0, nil, errWrongTree
	}
	// This can be a [prefix, pos | rest] list if and only if
	// prefix is a byte array of less than 32 bytes
	leftRaw := val.Index(0).Interface()
	if bytVal, ok := leftRaw.([]byte); ok {
		if len(bytVal) < 32 {
			return mt.parseProof(proof, depth)
		}
	}
	if proofLen != 2 {
		return nil, 0, nil, errWrongTree
	}

	leftItem, lmodule, lleaves, err := mt.rparse(leftRaw, depth+1)
	if err != nil {
		return nil, 0, nil, err
	}
	rightRaw := val.Index(1).Interface()
	rightItem, rmodule, rleaves, err := mt.rparse(rightRaw, depth+1)
	if err != nil {
		return nil, 0, nil, err
	}
	tree := [2]bert.Term{
		leftItem,
		rightItem,
	}
	rootHash, err := util.BertHash(tree)
	modulo := lmodule + rmodule
	leaves := append(lleaves, rleaves...)
	return rootHash, modulo, leaves, err
}
