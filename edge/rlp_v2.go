// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
	"reflect"

	"github.com/buger/jsonparser"
	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"github.com/diodechain/diode_go_client/rlp"
	"github.com/diodechain/diode_go_client/util"
)

var (
	responsePivot          = []byte("response")
	errorPivot             = []byte("error")
	ticketTooOldPivot      = []byte("too_old")
	ticketTooLowPivot      = []byte("too_low")
	ticketThanksPivot      = []byte("thanks!")
	okPivot                = []byte("ok")
	errWrongTypeForItems   = fmt.Errorf("items should be array or slice")
	errKeyNotFoundInItems  = fmt.Errorf("key not found")
	ErrFailedToParseTicket = fmt.Errorf("failed to parse ticket")
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
	log.Printf("%+v\n", response)
	err := Error{
		// Method:  response.Payload[0],
		// TODO: response.Payload[1] will be ? string
		// Message: response.Payload[2],
		Message: "",
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

type helloRequest struct {
	RequestID uint64
	Payload   struct {
		Method string
		Flag   uint64
	}
}

type ticketRequest struct {
	RequestID uint64
	Payload   struct {
		Method           string
		BlockNumber      uint64
		FleetAddr        []byte
		TotalConnections uint64
		TotalBytes       uint64
		LocalAddr        []byte
		DeviceSig        []byte
	}
}

type accountRequest struct {
	RequestID uint64
	Payload   struct {
		Method      string
		BlockNumber uint64
		Address     []byte
	}
}

type accountRootsRequest struct {
	RequestID uint64
	Payload   struct {
		Method      string
		BlockNumber uint64
		Address     []byte
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

// type helloResponse struct {}

type ticketThanksResponse struct {
	RequestID uint64
	Payload   struct {
		Type      string
		Result    string
		PaidBytes []byte
	}
}

type ticketTooOldResponse struct {
	RequestID uint64
	Payload   struct {
		Type   string
		Result string
		Min    []byte
	}
}

type ticketTooLowResponse struct {
	RequestID uint64
	Payload   struct {
		Type             string
		Result           string
		BlockHash        []byte
		TotalConnections []byte
		TotalBytes       []byte
		LocalAddr        []byte
		DeviceSig        []byte
	}
}

type accountResponse struct {
	RequestID uint64
	Payload   struct {
		Type  string
		Items [4]Item
		// StateTree struct {
		// 	Module []byte
		// 	Data1  []byte
		// }
	}
}

type accountRootsResponse struct {
	RequestID uint64
	Payload   struct {
		Type         string
		AccountRoots [][]byte
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
	case "getaccount":
		request := accountRequest{}
		request.RequestID = requestID
		request.Payload.Method = method
		request.Payload.BlockNumber = args[0].(uint64)
		request.Payload.Address = args[1].([]byte)
		decodedRlp, err := rlp.EncodeToBytes(request)
		if err != nil {
			return nil, nil, err
		}
		return decodedRlp, rlpV2.parseAccount, err
	case "getaccountroots":
		request := accountRootsRequest{}
		request.RequestID = requestID
		request.Payload.Method = method
		request.Payload.BlockNumber = args[0].(uint64)
		request.Payload.Address = args[1].([]byte)
		decodedRlp, err := rlp.EncodeToBytes(request)
		if err != nil {
			return nil, nil, err
		}
		return decodedRlp, rlpV2.parseAccountRoots, err
	case "hello":
		request := helloRequest{}
		request.RequestID = requestID
		request.Payload.Method = method
		request.Payload.Flag = args[0].(uint64)
		decodedRlp, err := rlp.EncodeToBytes(request)
		if err != nil {
			return nil, nil, err
		}
		return decodedRlp, nil, err
	case "ticket":
		request := ticketRequest{}
		request.RequestID = requestID
		request.Payload.Method = method
		request.Payload.BlockNumber = args[0].(uint64)
		request.Payload.FleetAddr = args[1].([]byte)
		request.Payload.TotalConnections = args[2].(uint64)
		request.Payload.TotalBytes = args[3].(uint64)
		request.Payload.LocalAddr = args[4].([]byte)
		request.Payload.DeviceSig = args[5].([]byte)
		decodedRlp, err := rlp.EncodeToBytes(request)
		if err != nil {
			return nil, nil, err
		}
		return decodedRlp, rlpV2.parseDeviceTicket, err
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
	// also can decompress pubkey and marshal to pubkey bytes
	dminerPubkey := secp256k1.DecompressPubkeyBytes(response.Payload.MinerPubkey)
	header, err := blockquick.NewHeader(
		txHash.Value,
		stateHash.Value,
		prevBlock.Value,
		minerSig.Value,
		dminerPubkey,
		util.DecodeBytesToUint(timestamp.Value),
		util.DecodeBytesToUint(number.Value),
		util.DecodeBytesToUint(nonce.Value),
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

// TODO: check error from findItemInItems
// TODO: use big.Int instead of uint64?
func (rlpV2 RLP_V2) parseDeviceTicket(buffer []byte) (interface{}, error) {
	if bytes.Contains(buffer, ticketThanksPivot) {
		var response ticketThanksResponse
		decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
		err := decodeStream.Decode(&response)
		if err != nil {
			return nil, err
		}
		// create empty ticket
		ticket := DeviceTicket{}
		return ticket, nil
	} else if bytes.Contains(buffer, ticketTooLowPivot) {
		var response ticketTooLowResponse
		decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
		err := decodeStream.Decode(&response)
		if err != nil {
			return nil, err
		}
		err = ErrTicketTooLow
		ticket := DeviceTicket{
			BlockHash:        response.Payload.BlockHash,
			TotalConnections: util.DecodeBytesToUint(response.Payload.TotalConnections),
			TotalBytes:       util.DecodeBytesToUint(response.Payload.TotalBytes),
			LocalAddr:        response.Payload.LocalAddr,
			DeviceSig:        response.Payload.DeviceSig,
			Err:              err,
		}
		return ticket, nil
	} else if bytes.Contains(buffer, ticketTooOldPivot) {
		var response ticketTooOldResponse
		decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
		err := decodeStream.Decode(&response)
		if err != nil {
			return nil, err
		}
		err = ErrTicketTooOld
		ticket := DeviceTicket{
			Err: err,
		}
		return ticket, nil
	}
	return nil, ErrFailedToParseTicket
}

// TODO: decode merkle tree from message
func (rlpV2 RLP_V2) parseAccount(buffer []byte) (interface{}, error) {
	var response accountResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	_ = decodeStream.Decode(&response)
	// if err != nil {
	// 	return nil, err
	// }
	storageRoot, _ := findItemInItems(response.Payload.Items, "storageRoot")
	nonce, _ := findItemInItems(response.Payload.Items, "nonce")
	code, _ := findItemInItems(response.Payload.Items, "code")
	balance, _ := findItemInItems(response.Payload.Items, "balance")
	dnonce := util.DecodeBytesToInt(nonce.Value)
	dbalance := util.DecodeBytesToInt(balance.Value)
	// stateTree, err := rlpV2.NewMerkleTree(rawAccount[1])
	// if err != nil {
	// 	return nil, err
	// }
	account := &Account{
		StorageRoot: storageRoot.Value,
		Nonce:       int64(dnonce),
		Code:        code.Value,
		Balance:     int64(dbalance),
		// stateTree:   stateTree,
		// proof:       rawAccount[1],
	}
	return account, nil
}

func (rlpV2 RLP_V2) parseAccountRoots(buffer []byte) (interface{}, error) {
	var response accountRootsResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	accountRoots := &AccountRoots{
		AccountRoots: response.Payload.AccountRoots,
	}
	return accountRoots, nil
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
