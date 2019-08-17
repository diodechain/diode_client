package rpc

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
	"poc-client/config"
	"poc-client/crypto/secp256k1"
	"strconv"
	"strings"

	"github.com/buger/jsonparser"
)

// Marshal the data
// func Marshal() {}

// Unmarshal the data
// func Unmarshal() {}

// TODO: change to encoding/binary
func newMessage(method string, args ...interface{}) ([]byte, error) {
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
			return nil, fmt.Errorf("Unexpected value type: %T", t)
		case int:
			bytVal = []byte(strconv.Itoa(v.(int)))
		case string:
			bytVal = []byte(strconv.Quote(v.(string)))
		case []uint8:
			bytVal = v.([]uint8)
		}
		if nBytMsg, err := jsonparser.Set(bytMsg, bytVal, strKey); err != nil {
			return nil, err
		} else {
			bytMsg = nBytMsg
		}
	}
	return bytMsg, nil
}

// TODO: check error from jsonparser
func parseResponse(rawResponse []byte) (*Response, error) {
	responseType, _, _, _ := jsonparser.Get(rawResponse, "[0]")
	if bytes.Equal(responseType, ErrorType) {
		errMsg, _ := jsonparser.GetString(rawResponse, "[2]")
		return nil, fmt.Errorf("Error from server: %s", errMsg)
	}
	if bytes.Equal(responseType, ResponseType) != true {
		return nil, fmt.Errorf("Unknown response type: %s", string(responseType[:]))
	}
	// correct response
	method, _, _, _ := jsonparser.Get(rawResponse, "[1]")
	// rawData, _, _, _ := jsonparser.Get(rawResponse, "[2]")
	rawData := [][]byte{}

	// see: https://github.com/buger/jsonparser/issues/145
	copyRawResponse := make([]byte, len(rawResponse))
	copy(copyRawResponse, rawResponse)
	tmpRawData := jsonparser.Delete(copyRawResponse, "[0]")
	tmpRawData = jsonparser.Delete(tmpRawData, "[0]")
	handler := func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		if err != nil {
			log.Fatal(err)
		}
		rawData = append(rawData, value)
	}
	jsonparser.ArrayEach(tmpRawData, handler)
	response := &Response{
		Raw:     rawResponse,
		RawData: rawData,
		Method:  method,
	}
	return response, nil
}

// TODO: check error from jsonparser
func parseError(rawError []byte) (*Error, error) {
	// correct response
	method, _, _, _ := jsonparser.Get(rawError, "[1]")
	rawMsg, _, _, _ := jsonparser.Get(rawError, "[2]")
	err := &Error{
		Raw:    rawError,
		RawMsg: rawMsg,
		Method: method,
	}
	return err, nil
}

// TODO: check error from jsonparser
func parseBlockHeader(rawHeader []byte) (*BlockHeader, error) {
	// log.Println(string(rawHeader[:]))
	txHash, _, _, _ := jsonparser.Get(rawHeader, "transaction_hash")
	stateHash, _, _, _ := jsonparser.Get(rawHeader, "state_hash")
	blockHash, _, _, _ := jsonparser.Get(rawHeader, "block_hash")
	prevBlock, _, _, _ := jsonparser.Get(rawHeader, "previous_block")
	minerSig, _, _, _ := jsonparser.Get(rawHeader, "miner_signature")
	timestamp, _, _, _ := jsonparser.Get(rawHeader, "timestamp")
	// miner was removed
	// miner, _, _, _ := jsonparser.Get(rawHeader, "miner")
	// decode header
	dtxHash, err := DecodeString(string(txHash[:]))
	if err != nil {
		return nil, err
	}
	dstateHash, err := DecodeString(string(stateHash[:]))
	if err != nil {
		return nil, err
	}
	dminerSig, err := DecodeString(string(minerSig[:]))
	if err != nil {
		return nil, err
	}
	dprevBlock, err := DecodeString(string(prevBlock[:]))
	if err != nil {
		return nil, err
	}
	dblockHash, err := DecodeString(string(blockHash[:]))
	if err != nil {
		return nil, err
	}
	dtimestamp, err := DecodeStringToInt(string(timestamp[:]))
	if err != nil {
		return nil, err
	}
	// dminer, err := DecodeString(string(miner[:]))
	// if err != nil {
	// 	return nil, err
	// }
	blockHeader := &BlockHeader{
		TxHash:    dtxHash,
		StateHash: dstateHash,
		PrevBlock: dprevBlock,
		MinerSig:  dminerSig,
		BlockHash: dblockHash,
		Timestamp: dtimestamp,
	}
	hashWithoutSig, err := blockHeader.HashWithoutSig()
	if err != nil {
		return nil, err
	}
	dminer, err := secp256k1.RecoverPubkey(hashWithoutSig, dminerSig)
	if err != nil {
		return nil, err
	}
	blockHeader.Miner = dminer
	return blockHeader, nil
}

// func requestMethod(rawResponse []byte) ([]byte, error) {
// 	method, _, _, err := jsonparser.Get(rawResponse, "[0]")
// 	if err != nil {
// 		return nil, err
// 	}
// 	return method, nil
// }

func parsePortOpen(rawResponse []byte) (*PortOpen, error) {
	ok, err := jsonparser.GetString(rawResponse, "[2]")
	if err != nil {
		return nil, err
	}
	hexRef, err := jsonparser.GetString(rawResponse, "[3]")
	if err != nil {
		return nil, err
	}
	refByt, err := DecodeString(hexRef)
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

func parseRPCRequest(rawRequest []byte) (*Request, error) {
	// correct response
	method, _, _, err := jsonparser.Get(rawRequest, "[0]")
	if err != nil {
		return nil, err
	}
	request := &Request{
		Raw:    rawRequest,
		Method: method,
	}
	return request, nil
}

func parseDeviceObj(rawObject []byte) (*DeviceObj, error) {
	if bytes.Equal(NullData, rawObject) {
		err := fmt.Errorf("cannot find the object of device")
		deviceObj := &DeviceObj{
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
	deviceSig, err := jsonparser.GetString(rawObject, "[3]")
	if err != nil {
		return nil, err
	}
	serverSig, err := jsonparser.GetString(rawObject, "[4]")
	if err != nil {
		return nil, err
	}
	dserverID, err := DecodeString(serverID[:])
	if err != nil {
		return nil, err
	}
	dpeakBlock, err := DecodeString(peakBlock[:])
	if err != nil {
		return nil, err
	}
	ddeviceSig, err := DecodeString(deviceSig[:])
	if err != nil {
		return nil, err
	}
	dserverSig, err := DecodeString(serverSig[:])
	if err != nil {
		return nil, err
	}
	deviceObj := &DeviceObj{
		ServerID:  dserverID,
		PeakBlock: dpeakBlock,
		DeviceSig: ddeviceSig,
		ServerSig: dserverSig,
	}
	return deviceObj, nil
}

func parseServerObj(rawObject []byte) (*ServerObj, error) {
	if bytes.Equal(NullData, rawObject) {
		return nil, fmt.Errorf("cannot find the node of server")
	}
	host, _, _, err := jsonparser.Get(rawObject, "[1]")
	if err != nil {
		return nil, err
	}
	edgePort, err := jsonparser.GetInt(rawObject, "[2]")
	if err != nil {
		return nil, err
	}
	serverPort, err := jsonparser.GetInt(rawObject, "[3]")
	if err != nil {
		return nil, err
	}
	serverSig, err := jsonparser.GetString(rawObject, "[4]")
	if err != nil {
		return nil, err
	}
	dserverSig, err := DecodeString(serverSig[:])
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
func parseStateRoots(rawStateRoots []byte) (*StateRoots, error) {
	parsedStateRoots := make([][]byte, 16)
	ind := 0
	handler := func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		if err != nil {
			log.Fatal(err)
		}
		// Decode error: index out of range
		// decodedValue := make([]byte, 32)
		// _, err = Decode(decodedValue, value[:])
		decodedValue, err := DecodeString(string(value[:]))
		if err != nil {
			log.Fatal(err)
		}
		parsedStateRoots[ind] = decodedValue
		ind++
	}
	jsonparser.ArrayEach(rawStateRoots, handler)
	stateRoots := &StateRoots{
		StateRoots: parsedStateRoots,
	}
	return stateRoots, nil
}

// TODO: check error from jsonparser
func parseAccountRoots(rawAccountRoots []byte) (*AccountRoots, error) {
	parsedAccountRoots := make([][]byte, 16)
	ind := 0
	handler := func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		if err != nil {
			log.Fatal(err)
		}
		// Decode error: index out of range
		// decodedValue := make([]byte, 32)
		// _, err = Decode(decodedValue, value[:])
		decodedValue, err := DecodeString(string(value[:]))
		if err != nil {
			log.Fatal(err)
		}
		parsedAccountRoots[ind] = decodedValue
		ind++
	}
	jsonparser.ArrayEach(rawAccountRoots, handler)
	accountRoots := &AccountRoots{
		AccountRoots: parsedAccountRoots,
	}
	return accountRoots, nil
}

// TODO: check error from jsonparser
// how about pass rawAccountData and rawAccountProof instead of multi dimension slice
func parseAccount(rawAccount [][]byte) (*Account, error) {
	hexStorageRoot, err := jsonparser.GetString(rawAccount[0], "storageRoot")
	if err != nil {
		return nil, err
	}
	storageRoot, err := DecodeString(hexStorageRoot)
	if err != nil {
		return nil, err
	}
	hexNonce, err := jsonparser.GetString(rawAccount[0], "nonce")
	if err != nil {
		return nil, err
	}
	nonceByt, err := DecodeString(hexNonce)
	if err != nil {
		return nil, err
	}
	nonce := &big.Int{}
	nonce.SetBytes(nonceByt)
	hexCode, err := jsonparser.GetString(rawAccount[0], "code")
	if err != nil {
		return nil, err
	}
	code, err := DecodeString(hexCode)
	if err != nil {
		return nil, err
	}
	hexBalance, err := jsonparser.GetString(rawAccount[0], "balance")
	if err != nil {
		return nil, err
	}
	balanceByt, err := DecodeString(hexBalance)
	if err != nil {
		return nil, err
	}
	balance := &big.Int{}
	balance.SetBytes(balanceByt)
	stateTree, err := NewMerkleTree(rawAccount[1])
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
func parseAccountValue(rawAccountValue []byte) (*AccountValue, error) {
	accountTree, err := NewMerkleTree(rawAccountValue)
	if err != nil {
		return nil, err
	}
	accountValue := &AccountValue{
		accountTree: accountTree,
		proof:       rawAccountValue,
	}
	return accountValue, nil
}

func isResponseType(rawData []byte) (bool, error) {
	firstColumn, _, _, err := jsonparser.Get(rawData, "[0]")
	if err != nil {
		return false, err
	}
	isResponseType := bytes.Equal(firstColumn, ResponseType)
	return isResponseType, nil
}

func isErrorType(rawData []byte) (bool, error) {
	firstColumn, _, _, err := jsonparser.Get(rawData, "[0]")
	if err != nil {
		return false, err
	}
	isErrorType := bytes.Equal(firstColumn, ErrorType)
	return isErrorType, nil
}

func (s *SSL) newPortOpenRequest(request *Request) (*PortOpen, error) {
	hexPort, err := jsonparser.GetString(request.Raw, "[1]")
	if err != nil {
		return nil, err
	}
	portByt, err := DecodeString(hexPort)
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
	refByt, err := DecodeString(hexRef)
	if err != nil {
		return nil, err
	}
	refBig := &big.Int{}
	refBig.SetBytes(refByt)
	ref := refBig.Int64()
	deviceId, err := jsonparser.GetString(request.Raw, "[3]")
	if err != nil {
		return nil, err
	}
	resMsg, err := newMessage("response", string(request.Method), int(ref), "ok")
	if err != nil {
		return nil, err
	}
	if config.AppConfig.Debug {
		log.Println(port, ref, deviceId, string(resMsg))
	}
	err = s.sendPayload(resMsg, false)
	if err != nil {
		return nil, err
	}
	portOpen := &PortOpen{
		Port:     port,
		Ref:      ref,
		DeviceId: deviceId,
		Ok:       true,
	}
	return portOpen, nil
}

func (s *SSL) newPortSendRequest(request *Request) (*PortSend, error) {
	hexRef, err := jsonparser.GetString(request.Raw, "[1]")
	if err != nil {
		return nil, err
	}
	refByt, err := DecodeString(hexRef)
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
	// resMsg, err := newMessage("response", string(request.Method), "ok")
	// if err != nil {
	// 	return nil, err
	// }
	// err = s.sendPayload(resMsg, false)
	// if err != nil {
	// 	return nil, err
	// }
	portSend := &PortSend{
		Ref:  ref,
		Data: data,
		Ok:   true,
	}
	return portSend, nil
}

func (s *SSL) newPortCloseRequest(request *Request) (*PortClose, error) {
	hexRef, err := jsonparser.GetString(request.Raw, "[1]")
	if err != nil {
		return nil, err
	}
	refByt, err := DecodeString(hexRef)
	if err != nil {
		return nil, err
	}
	refBig := &big.Int{}
	refBig.SetBytes(refByt)
	ref := refBig.Int64()
	// resMsg, err := newMessage("response", string(request.Method), "ok")
	// if err != nil {
	// 	return nil, err
	// }
	// err = s.sendPayload(resMsg, false)
	// if err != nil {
	// 	return nil, err
	// }
	portClose := &PortClose{
		Ref: ref,
		Ok:  true,
	}
	return portClose, nil
}
