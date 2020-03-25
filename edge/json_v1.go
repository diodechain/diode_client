// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"bytes"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"github.com/diodechain/diode_go_client/util"
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

type JSON_V1 struct{}

func jsonString(rawData []byte, location string) string {
	value, _, _, _ := jsonparser.Get(rawData, location)
	if value == nil {
		return ""
	}
	return string(value)
}

func jsonInteger(rawData []byte, location string) int64 {
	value, _, _, _ := jsonparser.Get(rawData, location)
	if value == nil {
		return -1
	}
	if util.IsHexNumber(value) {
		return int64(util.DecodeStringToIntForce(string(value)))
	}
	num, err := strconv.Atoi(string(value))
	if err != nil {
		return -2
	}
	return int64(num)
}

// TODO: check error from jsonparser
func (jsonV1 JSON_V1) parseResponse(rawResponse []byte) (response Response, err error) {
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

func (jsonV1 JSON_V1) parseRequest(rawRequest []byte) (request Request, err error) {
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
func (jsonV1 JSON_V1) parseError(rawError []byte) (Error, error) {
	// correct response
	method, _, _, _ := jsonparser.Get(rawError, "[1]")
	rawMsg, _, _, _ := jsonparser.Get(rawError, "[2]")
	err := Error{
		Raw:    rawError,
		RawMsg: rawMsg,
		Method: method,
	}
	return err, nil
}

func (jsonV1 JSON_V1) IsResponseType(rawData []byte) bool {
	return jsonString(rawData, "[0]") == "response"
}

func (jsonV1 JSON_V1) IsErrorType(rawData []byte) bool {
	return jsonString(rawData, "[0]") == "error"
}

func (jsonV1 JSON_V1) ResponseMethod(rawData []byte) string {
	return jsonString(rawData, "[1]")
}

// NewMerkleTree returns merkle tree of given byte of json
// eg: ["0x", "0x1", ["0x2bbfda354b607b8cdd7d52c29344c76c17d76bb7d9187874a994144b55eaf931","0x0000000000000000000000000000000000000000000000000000000000000001"]]
func (jsonV1 JSON_V1) NewMerkleTree(rawTree []byte) (mt MerkleTree, err error) {
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

func (jsonV1 JSON_V1) NewErrorResponse(method string, err error) Message {
	ret := []byte(fmt.Sprintf("[\"error\", \"%s\", \"%+v\"]", method, err.Error()))
	return Message{
		Len:    len(ret),
		Buffer: ret,
	}
}

// TODO: change to encoding/binary
func (jsonV1 JSON_V1) NewMessage(requestID uint64, method string, args ...interface{}) ([]byte, error) {
	key := 0
	strKey := ""
	bytVal := []byte{}
	strMsgs := make([]string, len(args)+1)
	strMsgs[0] = strconv.Quote(method)
	for i, _ := range args {
		strMsgs[i+1] = "0"
	}
	strMsg := strings.Join(strMsgs, ",")
	bytMsg := []byte("[")
	bytMsg = append(bytMsg[:], []byte(strMsg)...)
	bytMsg = append(bytMsg[:], []byte("]")...)
	for i, v := range args {
		key = i + 1
		strKey = "[" + strconv.Itoa(key) + "]"
		switch t := v.(type) {
		default:
			return nil, fmt.Errorf("newMessage(): Unexpected value type: %T", t)
		case int:
			bytVal = []byte(strconv.Itoa(v.(int)))
		case uint64:
			bytVal = []byte(strconv.FormatUint(v.(uint64), 10))
		case int64:
			bytVal = []byte(strconv.FormatInt(v.(int64), 10))
		case string:
			bytVal = []byte(strconv.Quote(v.(string)))
		case []uint8:
			bytVal = v.([]uint8)
		}
		nBytMsg, err := jsonparser.Set(bytMsg, bytVal, strKey)
		if err != nil {
			return nil, err
		}
		bytMsg = nBytMsg
	}
	return bytMsg, nil
}

func (jsonV1 JSON_V1) NewPortOpenRequest(request Request) (*PortOpen, error) {
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

func (jsonV1 JSON_V1) NewPortSendRequest(request Request) (*PortSend, error) {
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

func (jsonV1 JSON_V1) NewPortCloseRequest(request Request) (*PortClose, error) {
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

func (jsonV1 JSON_V1) ParsePortOpen(rawResponse [][]byte) (*PortOpen, error) {
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

func (jsonV1 JSON_V1) ParseServerObj(rawObject []byte) (*ServerObj, error) {
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
func (jsonV1 JSON_V1) ParseStateRoots(rawStateRoots []byte) (*StateRoots, error) {
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
func (jsonV1 JSON_V1) ParseAccountRoots(rawAccountRoots []byte) (*AccountRoots, error) {
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
func (jsonV1 JSON_V1) ParseAccount(rawAccount [][]byte) (*Account, error) {
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
	stateTree, err := jsonV1.NewMerkleTree(rawAccount[1])
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
func (jsonV1 JSON_V1) ParseAccountValue(rawAccountValue []byte) (*AccountValue, error) {
	accountTree, err := jsonV1.NewMerkleTree(rawAccountValue)
	if err != nil {
		return nil, err
	}
	accountValue := &AccountValue{
		accountTree: accountTree,
		proof:       rawAccountValue,
	}
	return accountValue, nil
}

func (jsonV1 JSON_V1) ParseBlockquick(raw []byte, size int) ([]int, error) {
	responses := make([]int, 0, size)
	var err error = nil
	jsonparser.ArrayEach(raw, func(value []byte, _type jsonparser.ValueType, offset int, err2 error) {
		if err != nil {
			return
		}
		if err != nil {
			err = err2
			return
		}
		num, err := util.DecodeStringToInt(string(value))
		if err != nil {
			return
		}
		responses = append(responses, int(num))
	})
	return responses, err
}

func (jsonV1 JSON_V1) ParseBlockHeaders(raw []byte, size int) ([]*blockquick.BlockHeader, error) {
	responses := make([]*blockquick.BlockHeader, 0, size)
	var err error = nil
	jsonparser.ArrayEach(raw, func(value []byte, _type jsonparser.ValueType, offset int, err2 error) {
		if err != nil {
			return
		}
		if err != nil {
			err = err2
			return
		}
		rawHeader, _, _, _ := jsonparser.Get(value, "[0]")
		miner, _, _, _ := jsonparser.Get(value, "[1]")
		header, err := jsonV1.ParseBlockHeader(rawHeader, miner)
		if err != nil {
			return
		}
		responses = append(responses, header)
	})
	return responses, err
}

// TODO: check error from jsonparser
func (jsonV1 JSON_V1) ParseBlockHeader(rawHeader []byte, minerPubkey []byte) (*blockquick.BlockHeader, error) {
	txHash, _, _, _ := jsonparser.Get(rawHeader, "transaction_hash")
	stateHash, _, _, _ := jsonparser.Get(rawHeader, "state_hash")
	blockHash, _, _, _ := jsonparser.Get(rawHeader, "block_hash")
	prevBlock, _, _, _ := jsonparser.Get(rawHeader, "previous_block")
	nonce, _, _, _ := jsonparser.Get(rawHeader, "nonce")
	minerSig, _, _, _ := jsonparser.Get(rawHeader, "miner_signature")
	timestamp, _, _, _ := jsonparser.Get(rawHeader, "timestamp")
	number, _, _, _ := jsonparser.Get(rawHeader, "number")

	dtxHash, err := util.DecodeString(string(txHash[:]))
	if err != nil {
		return nil, err
	}
	dstateHash, err := util.DecodeString(string(stateHash[:]))
	if err != nil {
		return nil, err
	}
	dminerSig, err := util.DecodeString(string(minerSig[:]))
	if err != nil {
		return nil, err
	}
	dminerPubkey, err := util.DecodeString(string(minerPubkey[:]))
	if err != nil {
		return nil, err
	}
	dprevBlock, err := util.DecodeString(string(prevBlock[:]))
	if err != nil {
		return nil, err
	}
	dblockHash, err := util.DecodeString(string(blockHash[:]))
	if err != nil {
		return nil, err
	}
	dtimestamp, err := util.DecodeStringToInt(string(timestamp[:]))
	if err != nil {
		return nil, err
	}
	dnumber, err := util.DecodeStringToInt(string(number[:]))
	if err != nil {
		return nil, err
	}
	dnonce, err := util.DecodeStringToInt(string(nonce[:]))
	if err != nil {
		return nil, err
	}
	// also can decompress pubkey and marshal to pubkey bytes
	dcminerPubkey := secp256k1.DecompressPubkeyBytes(dminerPubkey)
	header, err := blockquick.NewHeader(
		dtxHash,
		dstateHash,
		dprevBlock,
		dminerSig,
		dcminerPubkey,
		dtimestamp,
		dnumber,
		dnonce,
	)
	if err != nil {
		return nil, err
	}
	hash := header.Hash()
	var dbhash blockquick.Hash
	copy(dbhash[:], dblockHash)
	if hash != dbhash {
		return nil, fmt.Errorf("Blockhash != real hash %v %v", dblockHash, header)
	}
	return header, nil
}

func (jsonV1 JSON_V1) ParseDeviceTicket(rawObject []byte) (*DeviceTicket, error) {
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

// for merkle tree, TODO: refactor this
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
