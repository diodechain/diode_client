// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

// EdgeProtocol interface defines functions that are required to diode edge protocol
type EdgeProtocol interface {
	// parseResponse(bufefr []byte) (interface{}, err error)

	parseError(rawError []byte) (Error, error)
	// parse response of rpc call
	parseBlockPeak(buffer []byte) (interface{}, error)
	parseBlock(buffer []byte) (interface{}, error)
	parseBlockHeader(buffer []byte) (interface{}, error)
	parseBlockquick(buffer []byte) (interface{}, error)
	parseDeviceTicket(buffer []byte) (interface{}, error)
	parseDeviceObject(buffer []byte) (interface{}, error)
	parseAccount(buffer []byte) (interface{}, error)
	parseAccountRoots(buffer []byte) (interface{}, error)
	parseAccountValue(buffer []byte) (interface{}, error)
	parsePortOpen(buffer []byte) (interface{}, error)
	// parsePortSend(buffer []byte) (interface{}, error)
	// parsePortClose(buffer []byte) (interface{}, error)
	// parse inbound request
	parseInboundRequest(buffer []byte) (interface{}, error)
	parseInboundPortOpenRequest(buffer []byte) (interface{}, error)
	parseInboundPortSendRequest(buffer []byte) (interface{}, error)
	parseInboundPortCloseRequest(buffer []byte) (interface{}, error)
	parseInboundGoodbyeRequest(buffer []byte) (interface{}, error)
	IsResponseType(rawData []byte) bool
	IsErrorType(rawData []byte) bool
	ResponseID(buffer []byte) uint64
	NewMerkleTree(rawTree []interface{}) (MerkleTree, error)
	NewErrorResponse(method string, err error) Message
	NewMessage(requestID uint64, method string, args ...interface{}) ([]byte, func(buffer []byte) (interface{}, error), error)
	NewResponseMessage(requestID uint64, responseType string, method string, args ...interface{}) ([]byte, func(buffer []byte) (interface{}, error), error)
	// TODO: rpc calls
	ParseServerObj(rawObject []byte) (*ServerObj, error)
	ParseStateRoots(rawStateRoots []byte) (*StateRoots, error)
}

// MerkleTreeParser interface defines functions that are required to diode merkle tree
type MerkleTreeParser interface {
	parseProof(proof interface{}) (rootHash []byte, module uint64, leaves []MerkleTreeLeave, err error)
	rparse(proof interface{}) (interface{}, uint64, []MerkleTreeLeave, error)
}
