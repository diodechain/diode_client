package rpc

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"math/big"

	"github.com/buger/jsonparser"
	bert "github.com/exosite/gobert"
)

var errorWrongTree = fmt.Errorf("Wrong merkle tree data")
var errorKeyNotFound = fmt.Errorf("Key not found in merkle tree")

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

// NewMerkleTree returns merkle tree of given byte
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
	return mt.rparse(mt.RawTree)
}

// parseProof returns bert hash of [proof]
func (mt *MerkleTree) parseProof(proof []byte) ([]byte, error) {
	var proofLen int
	var prefix interface{}
	var proofKey string
	// proof is array
	bytPrefix, _, _, err := jsonparser.Get(proof, "[0]")
	proofLen = JSONArrLen(proof)
	if err != nil {
		return nil, err
	}
	if len(bytPrefix) > 0 {
		bitsPrefix := []byte{}
		var intPrefix int
		for _, byt := range bytPrefix {
			bitsPrefix = append(bitsPrefix, (byt - 48))
		}
		for i := len(bytPrefix); i < 8; i++ {
			bitsPrefix = append(bitsPrefix, 0)
		}
		for i, byt := range bitsPrefix {
			intPrefix += int(byt) * int(math.Pow(2, float64(7-i)))
		}
		// decode prefix bitstring
		prefix = bert.Bitstring{
			Bytes: []byte{byte(intPrefix)},
			Bits:  uint8(len(bytPrefix)),
		}
	} else {
		prefix = []byte("")
		// prefix = bert.Bitstring{
		// 	Bytes: []byte(strPrefix),
		// 	Bits:  0,
		// }
	}
	hexModule, err := jsonparser.GetString(proof, "[1]")
	if err != nil {
		return nil, err
	}
	moduleByt, err := DecodeString(string(hexModule))
	if err != nil {
		return nil, err
	}
	module := big.Int{}
	module.SetBytes(moduleByt)
	mt.Module = module.Int64()
	bertProof := bert.List{
		Items: []bert.Term{
			prefix,
			mt.Module,
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
		key, err := DecodeString(hexKey)
		if err != nil {
			return nil, err
		}
		value, err := DecodeString(hexValue)
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
	return BertHash(bertProof)
}

// parse recursively
// how do we get the nodes?
func (mt *MerkleTree) rparse(proof []byte) ([]byte, error) {
	// check is array
	// if (proof[0] == squareBracketStart[0]) && (proof[len(proof)-1] == squareBracketEnd[0]) {
	var parsedProof []byte
	if isJSONArr(proof) {
		proofLen := JSONArrLen(proof)
		if proofLen == 1 {
			return DecodeString(string(proof[1 : len(proof)-1]))
		} else if proofLen == 2 {
			var leftItem interface{}
			var rightItem interface{}
			leftRaw, _, _, _ := jsonparser.Get(proof, "[0]")
			left, err := mt.rparse(leftRaw)
			if err != nil {
				return nil, err
			}
			// TODO: the better way to find hexed int/bitstring
			if bytes.Equal(leftRaw, left) && (len(left) > 0) {
				bitsPrefix := []byte{}
				var intPrefix int
				for _, byt := range left {
					bitsPrefix = append(bitsPrefix, (byt - 48))
				}
				for i := len(left); i < 8; i++ {
					bitsPrefix = append(bitsPrefix, 0)
				}
				for i, byt := range bitsPrefix {
					intPrefix += int(byt) * int(math.Pow(2, float64(7-i)))
				}
				// decode prefix bitstring
				leftItem = bert.Bitstring{
					Bytes: []byte{byte(intPrefix)},
					Bits:  uint8(len(left)),
				}
			} else if (len(left) < 32) && (len(left) > 0) && IsHexNumber(leftRaw) {
				leftBig := big.Int{}
				leftBig.SetBytes(left)
				leftItem = leftBig.Int64()
			} else {
				leftItem = left
			}
			rightRaw, _, _, _ := jsonparser.Get(proof, "[1]")
			right, err := mt.rparse(rightRaw)
			if err != nil {
				return nil, err
			}
			// TODO: the better way to find hexed int/bitstring
			if bytes.Equal(rightRaw, right) && (len(right) > 0) {
				bitsPrefix := []byte{}
				var intPrefix int
				for _, byt := range right {
					bitsPrefix = append(bitsPrefix, (byt - 48))
				}
				for i := len(right); i < 8; i++ {
					bitsPrefix = append(bitsPrefix, 0)
				}
				for i, byt := range bitsPrefix {
					intPrefix += int(byt) * int(math.Pow(2, float64(7-i)))
				}
				// decode prefix bitstring
				rightItem = bert.Bitstring{
					Bytes: []byte{byte(intPrefix)},
					Bits:  uint8(len(right)),
				}
			} else if (len(right) < 32) && (len(right) > 0) && IsHexNumber(rightRaw) {
				rightBig := big.Int{}
				rightBig.SetBytes(right)
				rightItem = rightBig.Int64()
			} else {
				rightItem = right
			}
			tree := [2]bert.Term{}
			tree[0] = leftItem
			tree[1] = rightItem
			return BertHash(tree)
		} else if proofLen >= 3 {
			// parseProof
			return mt.parseProof(proof)
		}
	} else if IsHex(proof) {
		return DecodeString(string(proof))
	} else if isJSONStr(proof) {
		// bitstring, string hex number, hash
		log.Println("JSON is string")
		return DecodeString(string(proof[1 : len(proof)-1]))
	} else if isJSONObj(proof) {
		log.Println("JSON is object")
		return parsedProof, nil
	} else {
		log.Println("JSON maybe bitstring, number, bool, nil?")
		if len(proof) == 0 {
			parsedProof = []byte("")
		} else if bitstringPattern.Match(proof) {
			parsedProof = proof
		}
		return parsedProof, nil
	}
	return parsedProof, nil
}
