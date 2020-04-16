// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"bytes"
	"fmt"
	"math"
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
	Module   uint64
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

func (mt *MerkleTree) parse() (rootHash []byte, module uint64, leaves []MerkleTreeLeave, err error) {
	var parsed interface{}
	parsed, module, leaves, err = mt.mtp.rparse(mt.RawTree)
	if err != nil {
		return
	}
	rootHash = parsed.([]byte)
	return
}

type RLPMerkleTreeParser struct{}

// parseProof returns bert hash of [proof]
// proof: [<prefix>, <modulo>, <values>] | {<proof>, <proof>} | <hash>
func (mt RLPMerkleTreeParser) parseProof(proof interface{}) (rootHash []byte, module uint64, leaves []MerkleTreeLeave, err error) {
	var proofLen, prefixByt, bitsLength int
	var prefix interface{}
	var bitsPrefix []byte
	var bytPrefix []byte
	var bytModule []byte
	var key []byte
	var value []byte
	var val reflect.Value
	var subVal reflect.Value
	var kind reflect.Kind
	var ok bool
	val = reflect.ValueOf(proof)
	kind = val.Kind()
	if kind != reflect.Slice && kind != reflect.Array {
		err = errWrongTree
		return
	}
	proofLen = val.Len()
	if bytPrefix, ok = val.Index(0).Interface().([]byte); !ok {
		err = errWrongTree
		return
	}
	if len(bytPrefix) <= 0 {
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
	if bytModule, ok = val.Index(1).Interface().([]byte); !ok {
		err = errWrongTree
		return
	}
	module = util.DecodeBytesToUint(bytModule)
	bertProof := bert.List{
		Items: []bert.Term{
			prefix,
			module,
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
func (mt RLPMerkleTreeParser) rparse(proof interface{}) (interface{}, uint64, []MerkleTreeLeave, error) {
	val := reflect.ValueOf(proof)
	kind := val.Kind()
	if kind == reflect.Slice || kind == reflect.Array {
		proofLen := val.Len()
		if bytVal, ok := val.Interface().([]byte); ok {
			return bytVal, 0, nil, nil
		}
		if proofLen == 2 {
			leftRaw := val.Index(0).Interface()
			leftItem, lmodule, lleaves, err := mt.rparse(leftRaw)
			if err != nil {
				return nil, 0, nil, err
			}
			rightRaw := val.Index(1).Interface()
			rightItem, rmodule, rleaves, err := mt.rparse(rightRaw)
			if err != nil {
				return nil, 0, nil, err
			}
			tree := [2]bert.Term{
				leftItem,
				rightItem,
			}
			rootHash, err := util.BertHash(tree)
			module := lmodule + rmodule
			leaves := append(lleaves, rleaves...)
			return rootHash, module, leaves, err
		} else if proofLen >= 3 {
			return mt.parseProof(proof)
		}
	}
	return nil, 0, nil, errWrongTree
}
