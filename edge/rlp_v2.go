// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"

	"github.com/buger/jsonparser"
	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"github.com/diodechain/diode_go_client/rlp"
	"github.com/diodechain/diode_go_client/util"
)

var (
	responsePivot         = []byte("response")
	errorPivot            = []byte("error")
	errWrongTypeForItems  = fmt.Errorf("Items should be array or slice")
	errKeyNotFoundInItems = fmt.Errorf("Key not found")
)

type RLP_V2 struct{}

// TODO: check error from jsonparser
func (rlpV2 RLP_V2) parseResponse(rawResponse []byte) (response Response, err error) {
	responseType := jsonString(rawResponse, "[0]")
	if responseType == "error" {
		errMsg, _ := jsonparser.GetString(rawResponse, "[2]")
		err = fmt.Errorf("error from server: %s", errMsg)
		return
	}
	if responseType != "response" {
		err = fmt.Errorf("unknown response type: %s", responseType)
		return
	}
	// correct response
	method, _, _, _ := jsonparser.Get(rawResponse, "[1]")
	rawData := [][]byte{}

	// see: https://github.com/buger/jsonparser/issues/145
	copyRawResponse := make([]byte, len(rawResponse))
	copy(copyRawResponse, rawResponse)
	tmpRawData := jsonparser.Delete(copyRawResponse, "[0]")
	tmpRawData = jsonparser.Delete(tmpRawData, "[0]")
	handler := func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		if err == nil {
			rawData = append(rawData, value)
		}
	}
	// should not catch error here
	jsonparser.ArrayEach(tmpRawData, handler)
	response = Response{
		Raw:     rawResponse,
		RawData: rawData,
		Method:  string(method),
	}
	return
}

func (rlpV2 RLP_V2) parseRequest(rawRequest []byte) (request Request, err error) {
	// correct response
	var method []byte
	var rawData [][]byte
	method, _, _, err = jsonparser.Get(rawRequest, "[0]")
	if err != nil {
		return
	}
	// see: https://github.com/buger/jsonparser/issues/145
	copyRawRequest := make([]byte, len(rawRequest))
	copy(copyRawRequest, rawRequest)
	tmpRawData := jsonparser.Delete(copyRawRequest, "[0]")
	handler := func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		if err == nil {
			rawData = append(rawData, value)
		}
	}
	// should not catch error here
	jsonparser.ArrayEach(tmpRawData, handler)
	request = Request{
		Raw:     rawRequest,
		Method:  string(method),
		RawData: rawData,
	}
	return
}

// TODO: check error from jsonparser
func (rlpV2 RLP_V2) parseError(rawError []byte) (Error, error) {
	var response errorResponse
	decodeStream := rlp.NewStream(bytes.NewReader(rawError), 0)
	_ = decodeStream.Decode(&response)
	err := Error{
		// Method:  response.Payload[0],
		// TODO: response.Payload[1] will be ? string
		Message: response.Payload[2],
	}
	return err, nil
}

func (rlpV2 RLP_V2) IsResponseType(rawData []byte) bool {
	return bytes.Contains(rawData, responsePivot)
}

func (rlpV2 RLP_V2) IsErrorType(rawData []byte) bool {
	return bytes.Contains(rawData, errorPivot)
}

func (rlpV2 RLP_V2) ResponseID(buffer []byte) uint64 {
	var response responseID
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	decodeStream.Decode(&response)
	return response.RequestID
}

// NewMerkleTree returns merkle tree of given byte of json
// eg: ["0x", "0x1", ["0x2bbfda354b607b8cdd7d52c29344c76c17d76bb7d9187874a994144b55eaf931","0x0000000000000000000000000000000000000000000000000000000000000001"]]
func (rlpV2 RLP_V2) NewMerkleTree(rawTree []byte) (mt MerkleTree, err error) {
	if !isJSONArr(rawTree) {
		err = errorWrongTree
		return
	}
	mt = MerkleTree{
		mtp:     JSONMerkleTreeParser{},
		RawTree: rawTree,
	}
	rootHash, module, leaves, err := mt.parse()
	if err != nil {
		return
	}
	mt.RootHash = rootHash
	mt.Module = module
	mt.Leaves = leaves
	return
}

func (rlpV2 RLP_V2) NewErrorResponse(method string, err error) Message {
	ret := []byte(fmt.Sprintf("[\"error\", \"%s\", \"%+v\"]", method, err.Error()))
	return Message{
		Len:    len(ret),
		Buffer: ret,
	}
}

// TODO: make sure it works
// Request struct
type blockPeakRequest struct {
	RequestID uint64
	Payload   struct {
		Method string
	}
}

type blockRequest struct {
	RequestID uint64
	Payload   struct {
		Method      string
		BlockNumber uint64
	}
}

type blockHeaderRequest struct {
	RequestID uint64
	Payload   struct {
		Method      string
		BlockNumber uint64
	}
}

type blockquickRequest struct {
	RequestID uint64
	Payload   struct {
		Method     string
		LastValid  uint64
		WindowSize uint64
	}
}

// Response struct
type Item struct {
	Key   string
	Value []byte
}

type responseID struct {
	RequestID uint64
}

type errorResponse struct {
	RequestID uint64
	Payload   []string
}

type blockPeakResponse struct {
	RequestID uint64
	Payload   struct {
		Type        string
		BlockNumber uint64
	}
}

// type blockResponse struct {}

type blockHeaderResponse struct {
	RequestID uint64
	Payload   struct {
		Type        string
		Items       [8]Item
		MinerPubkey []byte
	}
}

type blockquickResponse struct {
	RequestID uint64
	Payload   struct {
		Type  string
		Items []uint64
	}
}

func findItemInItems(items interface{}, key string) (item Item, err error) {
	val := reflect.ValueOf(items)
	switch val.Kind() {
	case reflect.Slice:
	case reflect.Array:
		ok := false
		i := 0
		len := val.Len()
		for ; i < len; i++ {
			v := val.Index(i)
			if item, ok = v.Interface().(Item); ok {
				if item.Key == key {
					return
				}
			}
		}
		break
	default:
		err = errWrongTypeForItems
		return
	}
	err = errKeyNotFoundInItems
	return
}

// TODO: change to encoding/binary
func (rlpV2 RLP_V2) NewMessage(requestID uint64, method string, args ...interface{}) ([]byte, func(buffer []byte) (interface{}, error), error) {
	switch method {
	case "getblock":
		request := blockRequest{}
		request.RequestID = requestID
		request.Payload.Method = method
		request.Payload.BlockNumber = args[0].(uint64)
		decodedRlp, err := rlp.EncodeToBytes(request)
		if err != nil {
			return nil, nil, err
		}
		return decodedRlp, rlpV2.parseBlock, err
	case "getblockpeak":
		request := blockPeakRequest{}
		request.RequestID = requestID
		request.Payload.Method = method
		decodedRlp, err := rlp.EncodeToBytes(request)
		if err != nil {
			return nil, nil, err
		}
		return decodedRlp, rlpV2.parseBlockPeak, err
	case "getblockheader2":
		request := blockHeaderRequest{}
		request.RequestID = requestID
		request.Payload.Method = method
		request.Payload.BlockNumber = args[0].(uint64)
		decodedRlp, err := rlp.EncodeToBytes(request)
		if err != nil {
			return nil, nil, err
		}
		return decodedRlp, rlpV2.parseBlockHeader, err
	case "getblockquick2":
		request := blockquickRequest{}
		request.RequestID = requestID
		request.Payload.Method = method
		request.Payload.LastValid = args[0].(uint64)
		request.Payload.WindowSize = args[1].(uint64)
		decodedRlp, err := rlp.EncodeToBytes(request)
		if err != nil {
			return nil, nil, err
		}
		return decodedRlp, rlpV2.parseBlockquick, err
	default:
		return nil, nil, fmt.Errorf("not found")
	}
}

func (rlpV2 RLP_V2) NewPortOpenRequest(request Request) (*PortOpen, error) {
	hexPort, err := jsonparser.GetString(request.Raw, "[1]")
	if err != nil {
		return nil, err
	}
	portByt, err := util.DecodeString(hexPort)
	if err != nil {
		return nil, err
	}
	portBig := &big.Int{}
	portBig.SetBytes(portByt)
	port := portBig.Int64()
	hexRef, err := jsonparser.GetString(request.Raw, "[2]")
	if err != nil {
		return nil, err
	}
	refByt, err := util.DecodeString(hexRef)
	if err != nil {
		return nil, err
	}
	refBig := &big.Int{}
	refBig.SetBytes(refByt)
	ref := refBig.Int64()
	deviceID, err := jsonparser.GetString(request.Raw, "[3]")
	if err != nil {
		return nil, err
	}
	portOpen := &PortOpen{
		Port:     port,
		Ref:      ref,
		DeviceID: deviceID,
		Ok:       true,
	}
	return portOpen, nil
}

func (rlpV2 RLP_V2) NewPortSendRequest(request Request) (*PortSend, error) {
	hexRef, err := jsonparser.GetString(request.Raw, "[1]")
	if err != nil {
		return nil, err
	}
	refByt, err := util.DecodeString(hexRef)
	if err != nil {
		return nil, err
	}
	refBig := &big.Int{}
	refBig.SetBytes(refByt)
	ref := refBig.Int64()
	data, _, _, err := jsonparser.Get(request.Raw, "[2]")
	if err != nil {
		return nil, err
	}
	portSend := &PortSend{
		Ref:  ref,
		Data: data,
		Ok:   true,
	}
	return portSend, nil
}

func (rlpV2 RLP_V2) NewPortCloseRequest(request Request) (*PortClose, error) {
	hexRef, err := jsonparser.GetString(request.Raw, "[1]")
	if err != nil {
		return nil, err
	}
	refByt, err := util.DecodeString(hexRef)
	if err != nil {
		return nil, err
	}
	refBig := &big.Int{}
	refBig.SetBytes(refByt)
	ref := refBig.Int64()
	portClose := &PortClose{
		Ref: ref,
		Ok:  true,
	}
	return portClose, nil
}

// parse response of rpc call

func (rlpV2 RLP_V2) parseBlockPeak(buffer []byte) (interface{}, error) {
	var response blockPeakResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	return response.Payload.BlockNumber, nil
}

// TODO: Test this
func (rlpV2 RLP_V2) parseBlock(buffer []byte) (interface{}, error) {
	var response blockPeakResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// TODO: check error from findItemInItems
// TODO: use big.Int instead of uint64?
func (rlpV2 RLP_V2) parseBlockHeader(buffer []byte) (interface{}, error) {
	var response blockHeaderResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	// get value
	txHash, _ := findItemInItems(response.Payload.Items, "transaction_hash")
	stateHash, _ := findItemInItems(response.Payload.Items, "state_hash")
	blockHash, _ := findItemInItems(response.Payload.Items, "block_hash")
	prevBlock, _ := findItemInItems(response.Payload.Items, "previous_block")
	nonce, _ := findItemInItems(response.Payload.Items, "nonce")
	minerSig, _ := findItemInItems(response.Payload.Items, "miner_signature")
	timestamp, _ := findItemInItems(response.Payload.Items, "timestamp")
	number, _ := findItemInItems(response.Payload.Items, "number")
	// decode to int
	dtimestamp := util.DecodeBytesToInt(timestamp.Value)
	dnumber := util.DecodeBytesToInt(number.Value)
	dnonce := util.DecodeBytesToInt(nonce.Value)
	// also can decompress pubkey and marshal to pubkey bytes
	dminerPubkey := secp256k1.DecompressPubkeyBytes(response.Payload.MinerPubkey)
	header, err := blockquick.NewHeader(
		txHash.Value,
		stateHash.Value,
		prevBlock.Value,
		minerSig.Value,
		dminerPubkey,
		uint64(dtimestamp),
		uint64(dnumber),
		uint64(dnonce),
	)
	if err != nil {
		return nil, err
	}
	hash := header.Hash()
	if !bytes.Equal(hash[:], blockHash.Value) {
		return nil, fmt.Errorf("Blockhash != real hash %v %v", blockHash.Value, header)
	}
	return header, nil
}

func (rlpV2 RLP_V2) parseBlockquick(buffer []byte) (interface{}, error) {
	var response blockquickResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	return response.Payload.Items, nil
}

func (rlpV2 RLP_V2) ParsePortOpen(rawResponse [][]byte) (*PortOpen, error) {
	ok := string(rawResponse[0])
	hexRef := string(rawResponse[1])
	refByt, err := util.DecodeString(hexRef)
	if err != nil {
		return nil, err
	}
	refBig := &big.Int{}
	refBig.SetBytes(refByt)
	ref := refBig.Int64()
	portOpen := &PortOpen{
		Ok:  (ok == "ok"),
		Ref: ref,
	}
	return portOpen, nil
}

func (rlpV2 RLP_V2) ParseServerObj(rawObject []byte) (*ServerObj, error) {
	if bytes.Equal(NullData, rawObject) {
		return nil, fmt.Errorf("cannot find the node of server")
	}
	host := []byte(jsonString(rawObject, "[1]"))
	edgePort := jsonInteger(rawObject, "[2]")
	serverPort := jsonInteger(rawObject, "[3]")
	serverSig := jsonString(rawObject, "[4]")
	dserverSig, err := util.DecodeString(serverSig[:])
	if err != nil {
		return nil, err
	}
	serverObj := &ServerObj{
		Host:       host,
		EdgePort:   edgePort,
		ServerPort: serverPort,
		Sig:        dserverSig,
	}
	return serverObj, nil
}

// TODO: check error from jsonparser
func (rlpV2 RLP_V2) ParseStateRoots(rawStateRoots []byte) (*StateRoots, error) {
	parsedStateRoots := make([][]byte, 16)
	ind := 0
	handler := func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		if err != nil {
			return
		}
		// Decode error: index out of range
		// decodedValue := make([]byte, 32)
		// _, err = Decode(decodedValue, value[:])
		decodedValue, err := util.DecodeString(string(value[:]))
		if err == nil {
			parsedStateRoots[ind] = decodedValue
			ind++
		}
	}
	// should not catch error here
	jsonparser.ArrayEach(rawStateRoots, handler)
	stateRoots := &StateRoots{
		StateRoots: parsedStateRoots,
	}
	return stateRoots, nil
}

// TODO: check error from jsonparser
func (rlpV2 RLP_V2) ParseAccountRoots(rawAccountRoots []byte) (*AccountRoots, error) {
	parsedAccountRoots := make([][]byte, 16)
	ind := 0
	handler := func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		if err != nil {
			return
		}
		// Decode error: index out of range
		// decodedValue := make([]byte, 32)
		// _, err = Decode(decodedValue, value[:])
		decodedValue, err := util.DecodeString(string(value[:]))
		if err == nil {
			parsedAccountRoots[ind] = decodedValue
			ind++
		}
	}
	// should not catch error here
	jsonparser.ArrayEach(rawAccountRoots, handler)
	accountRoots := &AccountRoots{
		AccountRoots: parsedAccountRoots,
	}
	return accountRoots, nil
}

// TODO: check error from jsonparser
// how about pass rawAccountData and rawAccountProof instead of multi dimension slice
func (rlpV2 RLP_V2) ParseAccount(rawAccount [][]byte) (*Account, error) {
	hexStorageRoot, err := jsonparser.GetString(rawAccount[0], "storageRoot")
	if err != nil {
		return nil, err
	}
	storageRoot, err := util.DecodeString(hexStorageRoot)
	if err != nil {
		return nil, err
	}
	hexNonce, err := jsonparser.GetString(rawAccount[0], "nonce")
	if err != nil {
		return nil, err
	}
	nonceByt, err := util.DecodeString(hexNonce)
	if err != nil {
		return nil, err
	}
	nonce := &big.Int{}
	nonce.SetBytes(nonceByt)
	hexCode, err := jsonparser.GetString(rawAccount[0], "code")
	if err != nil {
		return nil, err
	}
	code, err := util.DecodeString(hexCode)
	if err != nil {
		return nil, err
	}
	hexBalance, err := jsonparser.GetString(rawAccount[0], "balance")
	if err != nil {
		return nil, err
	}
	balanceByt, err := util.DecodeString(hexBalance)
	if err != nil {
		return nil, err
	}
	balance := &big.Int{}
	balance.SetBytes(balanceByt)
	stateTree, err := rlpV2.NewMerkleTree(rawAccount[1])
	if err != nil {
		return nil, err
	}
	account := &Account{
		StorageRoot: storageRoot,
		Nonce:       nonce.Int64(),
		Code:        code,
		Balance:     balance.Int64(),
		stateTree:   stateTree,
		proof:       rawAccount[1],
	}
	return account, nil
}

// TODO: check error from jsonparser
func (rlpV2 RLP_V2) ParseAccountValue(rawAccountValue []byte) (*AccountValue, error) {
	accountTree, err := rlpV2.NewMerkleTree(rawAccountValue)
	if err != nil {
		return nil, err
	}
	accountValue := &AccountValue{
		accountTree: accountTree,
		proof:       rawAccountValue,
	}
	return accountValue, nil
}

func (rlpV2 RLP_V2) ParseDeviceTicket(rawObject []byte) (*DeviceTicket, error) {
	if bytes.Equal(NullData, rawObject) {
		err := fmt.Errorf("cannot find the object of device")
		deviceObj := &DeviceTicket{
			Err: err,
		}
		return deviceObj, err
	}
	serverID, err := jsonparser.GetString(rawObject, "[1]")
	if err != nil {
		return nil, err
	}
	peakBlock, err := jsonparser.GetString(rawObject, "[2]")
	if err != nil {
		return nil, err
	}
	fleetAddr, err := jsonparser.GetString(rawObject, "[3]")
	if err != nil {
		return nil, err
	}
	totalConnections, err := jsonparser.GetString(rawObject, "[4]")
	if err != nil {
		return nil, err
	}
	totalBytes, err := jsonparser.GetString(rawObject, "[5]")
	if err != nil {
		return nil, err
	}
	localAddr, err := jsonparser.GetString(rawObject, "[6]")
	if err != nil {
		return nil, err
	}
	dlocalAddr, err := util.DecodeString(localAddr[:])
	if err != nil {
		return nil, err
	}
	deviceSig, err := jsonparser.GetString(rawObject, "[7]")
	if err != nil {
		return nil, err
	}
	serverSig, err := jsonparser.GetString(rawObject, "[8]")
	if err != nil {
		return nil, err
	}
	dserverID, err := util.DecodeString(serverID[:])
	if err != nil {
		return nil, err
	}
	var eserverID [20]byte
	copy(eserverID[:], dserverID)
	dpeakBlock, err := util.DecodeStringToInt(peakBlock[:])
	if err != nil {
		return nil, err
	}
	dfleetAddr, err := util.DecodeString(fleetAddr[:])
	if err != nil {
		return nil, err
	}
	var efleetAddr [20]byte
	copy(efleetAddr[:], dfleetAddr)
	dtotalConnections, err := util.DecodeStringToInt(totalConnections[:])
	if err != nil {
		return nil, err
	}
	dtotalBytes, err := util.DecodeStringToInt(totalBytes[:])
	if err != nil {
		return nil, err
	}
	ddeviceSig, err := util.DecodeString(deviceSig[:])
	if err != nil {
		return nil, err
	}
	dserverSig, err := util.DecodeString(serverSig[:])
	if err != nil {
		return nil, err
	}
	deviceObj := &DeviceTicket{
		ServerID:         eserverID,
		BlockNumber:      int(dpeakBlock),
		BlockHash:        nil,
		FleetAddr:        efleetAddr,
		TotalConnections: dtotalConnections,
		TotalBytes:       dtotalBytes,
		DeviceSig:        ddeviceSig,
		ServerSig:        dserverSig,
		LocalAddr:        dlocalAddr,
	}
	return deviceObj, nil
}
