// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/diodechain/diode_client/util"
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

	parsed, modulo, leaves, err = mt.mtp.rparse(mt.RawTree, 0, 0)
	if err != nil {
		return
	}
	rootHash = parsed.([]byte)
	return
}

type MerkleTreeParser struct{}

// parseProof returns bert hash of [proof]
// proof: [<prefix>, <modulo>, <values>] | {<proof>, <proof>} | <hash>
func (mt MerkleTreeParser) parseProof(proof interface{}, depth int, bits uint64) (rootHash []byte, modulo uint64, leaves []MerkleTreeLeave, err error) {
	var prefix interface{}
	var bytModulo []byte
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

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, bits)
	for b[0] == 0 {
		b = b[1:]
	}

	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}

	prefix = bert.Bitstring{
		Bytes: b,
		Bits:  uint8(depth),
	}

	// out, _ := bert.Encode(prefix)
	// fmt.Printf("Bits: %b Depth: %d\n", bits, depth)
	// fmt.Printf("Bert: %s\n", util.EncodeToString(out))

	if bytModulo, ok = val.Index(1).Interface().([]byte); !ok {
		err = errWrongTree
		return
	}
	modulo = util.DecodeBytesToUint(bytModulo)
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

func setBit(n uint64, pos int, bit uint64) uint64 {
	// fmt.Printf("setBit(pos=%d, %d)\n", pos, bit)
	bytepos := ((pos - 1) % 8) + 1
	pos = pos - bytepos + (8 - bytepos)
	n |= (bit << pos)
	return n
}

// parse recursively
func (mt MerkleTreeParser) rparse(proof interface{}, depth int, bits uint64) (interface{}, uint64, []MerkleTreeLeave, error) {
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
			return mt.parseProof(proof, depth, bits)
		}
	}
	if proofLen != 2 {
		return nil, 0, nil, errWrongTree
	}

	depth = depth + 1
	leftItem, lmodulo, lleaves, err := mt.rparse(leftRaw, depth, setBit(bits, depth, 0))
	if err != nil {
		return nil, 0, nil, err
	}
	rightRaw := val.Index(1).Interface()
	rightItem, rmodulo, rleaves, err := mt.rparse(rightRaw, depth, setBit(bits, depth, 1))
	if err != nil {
		return nil, 0, nil, err
	}
	tree := [2]bert.Term{
		leftItem,
		rightItem,
	}

	rootHash, err := util.BertHash(tree)
	modulo := lmodulo + rmodulo
	leaves := append(lleaves, rleaves...)
	return rootHash, modulo, leaves, err
}
