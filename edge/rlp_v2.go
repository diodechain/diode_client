// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"github.com/diodechain/diode_go_client/rlp"
	"github.com/diodechain/diode_go_client/util"
	bert "github.com/diodechain/gobert"
)

var (
	responsePivot     = []byte("response")
	errorPivot        = []byte("error")
	ticketTooOldPivot = []byte("too_old")
	ticketTooLowPivot = []byte("too_low")
	ticketThanksPivot = []byte("thanks!")
	portOpenPivot     = []byte("portopen")
	portSendPivot     = []byte("portsend")
	portClosePivot    = []byte("portclose")
	goodbyePivot      = []byte("goodbye")
	// Maybe remove parse callback and use parse response?
	blockPivot                 = []byte("getblock")
	block2Pivot                = []byte("getblock2")
	blockHeaderPivot           = []byte("getblockheader")
	blockHeader2Pivot          = []byte("getblockheader2")
	blockquickPivot            = []byte("getblockquick")
	blockquick2Pivot           = []byte("getblockquick2")
	blockPeakPivot             = []byte("getblockpeak")
	accountRootsPivot          = []byte("getaccountroots")
	accountValuePivot          = []byte("getaccountvalue")
	accountPivot               = []byte("getaccount")
	stateRootsPivot            = []byte("getstateroots")
	objectPivot                = []byte("getobject")
	nodePivot                  = []byte("getnode")
	ticketPivot                = []byte("getticket")
	errWrongTypeForItems       = fmt.Errorf("items should be array or slice")
	errKeyNotFoundInItems      = fmt.Errorf("key not found")
	ErrFailedToParseTicket     = fmt.Errorf("failed to parse ticket")
	ErrResponseHandlerNotFound = fmt.Errorf("couldn't find handler for response")
	ErrRPCNotSupport           = fmt.Errorf("rpc method not support")
)

type RLP_V2 struct{}

// parse response
func (rlpV2 RLP_V2) parseResponse(buffer []byte) (interface{}, error) {
	if bytes.Contains(buffer, portOpenPivot) {
		return rlpV2.parsePortOpenResponse(buffer)
	} else if bytes.Contains(buffer, blockPivot) {
		return rlpV2.parseBlockResponse(buffer)
	} else if bytes.Contains(buffer, block2Pivot) {
		return rlpV2.parseBlockResponse(buffer)
	} else if bytes.Contains(buffer, blockHeaderPivot) {
		return rlpV2.parseBlockHeaderResponse(buffer)
	} else if bytes.Contains(buffer, blockHeader2Pivot) {
		return rlpV2.parseBlockHeaderResponse(buffer)
	} else if bytes.Contains(buffer, blockquickPivot) {
		return rlpV2.parseBlockquickResponse(buffer)
	} else if bytes.Contains(buffer, blockquick2Pivot) {
		return rlpV2.parseBlockquickResponse(buffer)
	} else if bytes.Contains(buffer, blockPeakPivot) {
		return rlpV2.parseBlockPeakResponse(buffer)
	} else if bytes.Contains(buffer, accountPivot) {
		return rlpV2.parseAccountResponse(buffer)
	} else if bytes.Contains(buffer, accountValuePivot) {
		return rlpV2.parseAccountValueResponse(buffer)
	} else if bytes.Contains(buffer, accountRootsPivot) {
		return rlpV2.parseAccountRootsResponse(buffer)
	} else if bytes.Contains(buffer, stateRootsPivot) {
		return rlpV2.parseStateRootsResponse(buffer)
	} else if bytes.Contains(buffer, objectPivot) {
		return rlpV2.parseDeviceObjectResponse(buffer)
	} else if bytes.Contains(buffer, nodePivot) {
		return rlpV2.parseServerObjResponse(buffer)
	} else if bytes.Contains(buffer, ticketPivot) {
		return rlpV2.parseDeviceTicketResponse(buffer)
	}
	return nil, ErrResponseHandlerNotFound
}

func (rlpV2 RLP_V2) parseError(buffer []byte) (Error, error) {
	var response errorResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	_ = decodeStream.Decode(&response)
	err := Error{
		Message: response.Payload[len(response.Payload)-1],
	}
	return err, nil
}

// parse response of rpc call
func (rlpV2 RLP_V2) parseBlockPeakResponse(buffer []byte) (interface{}, error) {
	var response blockPeakResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	return response.Payload.BlockNumber, nil
}

// TODO: parse block
func (rlpV2 RLP_V2) parseBlockResponse(buffer []byte) (interface{}, error) {
	var response blockResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	// response.Payload.Block.Coinbase
	// response.Payload.Block.Header
	// response.Payload.Block.Receipts
	// response.Payload.Block.Transactions
	return response, nil
}

// TODO: check error from findItemInItems
// TODO: use big.Int instead of uint64?
func (rlpV2 RLP_V2) parseBlockHeaderResponse(buffer []byte) (interface{}, error) {
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
		return nil, fmt.Errorf("blockhash != real hash %v %v", blockHash.Value, header)
	}
	return header, nil
}

func (rlpV2 RLP_V2) parseBlockquickResponse(buffer []byte) (interface{}, error) {
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
func (rlpV2 RLP_V2) parseDeviceTicketResponse(buffer []byte) (interface{}, error) {
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
			TotalConnections: response.Payload.TotalConnections,
			TotalBytes:       response.Payload.TotalBytes,
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

func (rlpV2 RLP_V2) parseDeviceObjectResponse(buffer []byte) (interface{}, error) {
	var response objectResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	serverID := [20]byte{}
	copy(serverID[:], response.Payload.Ticket.ServerID)
	fleetAddr := [20]byte{}
	copy(fleetAddr[:], response.Payload.Ticket.FleetAddr)
	deviceObj := &DeviceTicket{
		ServerID:         serverID,
		BlockNumber:      response.Payload.Ticket.PeakBlock,
		BlockHash:        nil,
		FleetAddr:        fleetAddr,
		TotalConnections: response.Payload.Ticket.TotalConnections,
		TotalBytes:       response.Payload.Ticket.TotalBytes,
		DeviceSig:        response.Payload.Ticket.DeviceSig,
		ServerSig:        response.Payload.Ticket.ServerSig,
		LocalAddr:        response.Payload.Ticket.LocalAddr,
	}
	return deviceObj, nil
}

// TODO: decode merkle tree from message
func (rlpV2 RLP_V2) parseAccountResponse(buffer []byte) (interface{}, error) {
	var response accountResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	storageRoot, _ := findItemInItems(response.Payload.Items, "storageRoot")
	nonce, _ := findItemInItems(response.Payload.Items, "nonce")
	code, _ := findItemInItems(response.Payload.Items, "code")
	balance, _ := findItemInItems(response.Payload.Items, "balance")
	dnonce := util.DecodeBytesToInt(nonce.Value)
	dbalance := util.DecodeBytesToInt(balance.Value)
	stateTree, err := rlpV2.NewMerkleTree(response.Payload.MerkleProof)
	if err != nil {
		return nil, err
	}
	account := &Account{
		StorageRoot: storageRoot.Value,
		Nonce:       int64(dnonce),
		Code:        code.Value,
		Balance:     int64(dbalance),
		stateTree:   stateTree,
	}
	return account, nil
}

func (rlpV2 RLP_V2) parseAccountRootsResponse(buffer []byte) (interface{}, error) {
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

func (rlpV2 RLP_V2) parseAccountValueResponse(buffer []byte) (interface{}, error) {
	var response accountValueResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	accountTree, err := rlpV2.NewMerkleTree(response.Payload.MerkleProof)
	if err != nil {
		return nil, err
	}
	accountValue := &AccountValue{
		accountTree: accountTree,
	}
	return accountValue, nil
}

func (rlpV2 RLP_V2) parsePortOpenResponse(buffer []byte) (interface{}, error) {
	var response portOpenResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	portOpen := &PortOpen{
		Ref: response.Payload.Ref,
		Ok:  (response.Payload.Result == "ok"),
		// RequestID: response.RequestID,
	}
	return portOpen, nil
}

func (rlpV2 RLP_V2) parseServerObjResponse(buffer []byte) (interface{}, error) {
	return doParseServerObjResponse(buffer)
}

func doParseServerObjResponse(buffer []byte) (obj *ServerObj, err error) {
	var response serverObjectResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	if err = decodeStream.Decode(&response); err != nil {
		return
	}
	data := response.Payload.ServerObject

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to decode serverObj: %v", r)
		}
	}()

	typename := string(data[0].([]byte))
	if typename != "server" {
		err = fmt.Errorf("wrong serverObj header %v expected 'server'", typename)
		return
	}

	obj = &ServerObj{
		Host:       data[1].([]byte),
		EdgePort:   parseUint(data[2].([]byte)),
		ServerPort: parseUint(data[3].([]byte)),
		Sig:        data[len(data)-1].([]byte),
	}

	var bertdata []byte

	if len(data) == 5 {
		bertdata, err = bert.Encode([3]bert.Term{
			obj.Host,
			obj.EdgePort,
			obj.ServerPort})
	} else if len(data) == 7 {
		version := data[4].([]byte)
		extra := data[5].([]interface{})
		tuples := make([]bert.Term, len(extra))
		for i, elem := range extra {
			slice := elem.([]interface{})
			tuples[i] = [2]bert.Term{slice[0].([]byte), parseUint(slice[1].([]byte))}
		}

		bertdata, err = bert.Encode([5]bert.Term{
			obj.Host,
			obj.EdgePort,
			obj.ServerPort,
			version,
			bert.List{Items: tuples}})
	} else {
		err = fmt.Errorf("wrong serverObj length: %d", len(data))
		return
	}

	hash := crypto.Sha256(bertdata)

	var pubkey []byte
	pubkey, err = secp256k1.RecoverPubkey(hash, obj.Sig)
	if err != nil {
		return
	}
	obj.ServerPubKey = pubkey
	return obj, nil
}

func parseUint(data []byte) (num uint64) {
	for _, b := range data {
		num = num*256 + uint64(b)
	}
	return
}

// TODO: check error from jsonparser
func (rlpV2 RLP_V2) parseStateRootsResponse(buffer []byte) (interface{}, error) {
	var response stateRootsResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	stateRoots := &StateRoots{
		StateRoots: response.Payload.StateRoots,
	}
	return stateRoots, nil
}

func (rlpV2 RLP_V2) parseTransactionResponse(buffer []byte) (interface{}, error) {
	var response transactionResponse
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&response)
	if err != nil {
		return nil, err
	}
	return response.Payload.Result, nil
}

// parse inbound request
func (rlpV2 RLP_V2) parseInboundPortOpenRequest(buffer []byte) (interface{}, error) {
	var inboundRequest portOpenInboundRequest
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&inboundRequest)
	if err != nil {
		return nil, err
	}

	portOpen := &PortOpen{
		RequestID: inboundRequest.RequestID,
		Ref:       inboundRequest.Payload.Ref,
		Ok:        true,
	}
	copy(portOpen.DeviceID[:], inboundRequest.Payload.DeviceID)
	port := inboundRequest.Payload.Port

	// Version 1 (before udp support)
	if len(port) <= 2 {
		portOpen.Protocol = config.TCPProtocol
		if len(port) == 2 {
			portOpen.PortNumber = int(binary.BigEndian.Uint16([]byte(port)))
		} else {
			portOpen.PortNumber = int(port[0])
		}
		return portOpen, nil
	}

	// Version 2 TCP
	n, err := fmt.Sscanf(port, "tcp:%d", &portOpen.PortNumber)
	if err == nil && n == 1 {
		portOpen.Protocol = config.TCPProtocol
		return portOpen, nil
	}

	// Version 2 TLS
	n, err = fmt.Sscanf(port, "tls:%d", &portOpen.PortNumber)
	if err == nil && n == 1 {
		portOpen.Protocol = config.TLSProtocol
		return portOpen, nil
	}

	// Version 2 UDP
	n, err = fmt.Sscanf(port, "udp:%d", &portOpen.PortNumber)
	if err == nil && n == 1 {
		portOpen.Protocol = config.UDPProtocol
		return portOpen, nil
	}

	return nil, fmt.Errorf("not supported port format: %v", inboundRequest.Payload.Port)
}

func (rlpV2 RLP_V2) parseInboundPortSendRequest(buffer []byte) (interface{}, error) {
	var inboundRequest portSendInboundRequest
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&inboundRequest)
	if err != nil {
		return nil, err
	}
	portSend := &PortSend{
		Ref:  inboundRequest.Payload.Ref,
		Data: inboundRequest.Payload.Data,
		Ok:   true,
	}
	return portSend, nil
}

func (rlpV2 RLP_V2) parseInboundPortCloseRequest(buffer []byte) (interface{}, error) {
	var inboundRequest portCloseInboundRequest
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&inboundRequest)
	if err != nil {
		return nil, err
	}
	portClose := &PortClose{
		Ref: inboundRequest.Payload.Ref,
		Ok:  true,
	}
	return portClose, nil
}

// TODO: should test it
func (rlpV2 RLP_V2) parseInboundGoodbyeRequest(buffer []byte) (interface{}, error) {
	var inboundRequest goodbyeInboundRequest
	decodeStream := rlp.NewStream(bytes.NewReader(buffer), 0)
	err := decodeStream.Decode(&inboundRequest)
	goodbye := Goodbye{
		Reason: []string{"unkown reason"},
	}
	if err != nil {
		goodbye.Reason[0] = err.Error()
		return goodbye, nil
	}
	goodbye.Reason = inboundRequest.Payload.Reason
	return goodbye, nil
}

func (rlpV2 RLP_V2) parseInboundRequest(buffer []byte) (req interface{}, err error) {
	if bytes.Contains(buffer, portOpenPivot) {
		return rlpV2.parseInboundPortOpenRequest(buffer)
	} else if bytes.Contains(buffer, portSendPivot) {
		return rlpV2.parseInboundPortSendRequest(buffer)
	} else if bytes.Contains(buffer, portClosePivot) {
		return rlpV2.parseInboundPortCloseRequest(buffer)
	} else if bytes.Contains(buffer, goodbyePivot) {
		return rlpV2.parseInboundGoodbyeRequest(buffer)
	}
	return
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
func (rlpV2 RLP_V2) NewMerkleTree(rawTree []interface{}) (mt MerkleTree, err error) {
	mt = MerkleTree{
		mtp:     RLPMerkleTreeParser{},
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

func (rlpV2 RLP_V2) NewErrorResponse(err error) (rpcErr Error) {
	rpcErr.Message = err.Error()
	return
}

func (rlpV2 RLP_V2) NewMessage(writer io.Writer, requestID uint64, method string, args ...interface{}) (func(buffer []byte) (interface{}, error), error) {
	request := generalRequest{}
	request.RequestID = requestID
	request.Payload = make([]interface{}, len(args)+1)
	request.Payload[0] = []byte(method)
	for i, arg := range args {
		request.Payload[i+1] = arg
	}
	err := rlp.Encode(writer, request)
	if err != nil {
		return nil, err
	}

	switch method {
	case "hello":
		return nil, nil
	case "portsend":
		return nil, nil
	case "portclose":
		return nil, nil
	case "getblock":
		return rlpV2.parseBlockResponse, nil
	case "getblockpeak":
		return rlpV2.parseBlockPeakResponse, nil
	case "getblockheader2":
		return rlpV2.parseBlockHeaderResponse, nil
	case "getblockquick2":
		return rlpV2.parseBlockquickResponse, nil
	case "getaccount":
		return rlpV2.parseAccountResponse, nil
	case "getaccountroots":
		return rlpV2.parseAccountRootsResponse, nil
	case "getaccountvalue":
		return rlpV2.parseAccountValueResponse, nil
	case "ticket":
		return rlpV2.parseDeviceTicketResponse, nil
	case "portopen":
		return rlpV2.parsePortOpenResponse, nil
	case "getobject":
		return rlpV2.parseDeviceObjectResponse, nil
	case "getnode":
		return rlpV2.parseServerObjResponse, nil
	case "getstateroots":
		return rlpV2.parseStateRootsResponse, nil
	case "sendtransaction":
		return rlpV2.parseTransactionResponse, nil
	default:
		return nil, ErrRPCNotSupport
	}
}

func (rlpV2 RLP_V2) NewResponseMessage(writer io.Writer, requestID uint64, responseType string, method string, args ...interface{}) (func(buffer []byte) (interface{}, error), error) {
	request := generalRequest{}
	request.RequestID = requestID
	request.Payload = make([]interface{}, len(args)+1)
	request.Payload[0] = []byte(method)
	for i, arg := range args {
		request.Payload[i+1] = arg
	}

	switch method {
	case "portopen":
		request.Payload[0] = responseType
	case "portsend":
	case "portclose":
	default:
		return nil, ErrRPCNotSupport
	}
	err := rlp.Encode(writer, request)
	if err != nil {
		return nil, err
	}
	return nil, nil
}
