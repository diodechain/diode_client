package rpc

import (
	"bytes"
	"fmt"
	"log"
	"math"
	//"math/big"
	//"strings"

	"github.com/buger/jsonparser"
	bert "github.com/exosite/gobert"
	"poc-client/util"
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
	return mt.rparse(mt.RawTree)
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
	if IsHex(bytPrefix) || IsHexNumber(bytPrefix) {
		bytPrefix, err = DecodeString(string(bytPrefix))
	} else {
		// bits string
		splitPrefix := util.SplitBytesByN(bytPrefix, 8)
		for _, p := range splitPrefix {
			prefixByt = 0
			pLen := len(p)
			for j := 0; j < pLen; j++ {
				pow := pLen - j - 1
				byt := p[j] - 48
				prefixByt += int(byt) * int(math.Pow(2, float64(pow)))
				bitsLength++
			}
			bitsPrefix = append(bitsPrefix, byte(prefixByt))
		}
	}
	if err != nil {
		return nil, err
	}
	if len(bytPrefix) > 0 {
		// decode prefix bitstring
		prefix = bert.Bitstring{
			Bytes: bitsPrefix,
			Bits:  uint8(bitsLength),
		}
	} else {
		prefix = []byte("")
	}
	hexModule, err := jsonparser.GetString(proof, "[1]")
	if err != nil {
		return nil, err
	}
	module, err := DecodeStringToInt(string(hexModule))
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
			// var leftItem interface{}
			// var rightItem interface{}
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
	} else {
		log.Println("JSON of merkle proof must be hex and array")
		return nil, errorWrongTree
	}
	return parsedProof, nil
}
