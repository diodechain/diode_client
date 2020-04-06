// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

// EdgeProtocol interface defines functions that are required to diode edge protocol
type EdgeProtocol interface {
	// parse response of rpc call
	parseResponse(bufefr []byte) (interface{}, error)
	parseError(rawError []byte) (Error, error)
	parseBlockPeakResponse(buffer []byte) (interface{}, error)
	parseBlockResponse(buffer []byte) (interface{}, error)
	parseBlockHeaderResponse(buffer []byte) (interface{}, error)
	parseBlockquickResponse(buffer []byte) (interface{}, error)
	parseDeviceTicketResponse(buffer []byte) (interface{}, error)
	parseDeviceObjectResponse(buffer []byte) (interface{}, error)
	parseAccountResponse(buffer []byte) (interface{}, error)
	parseAccountRootsResponse(buffer []byte) (interface{}, error)
	parseAccountValueResponse(buffer []byte) (interface{}, error)
	parsePortOpenResponse(buffer []byte) (interface{}, error)
	// parsePortSendResponse(buffer []byte) (interface{}, error)
	// parsePortCloseResponse(buffer []byte) (interface{}, error)
	parseServerObjResponse(buffer []byte) (interface{}, error)
	parseStateRootsResponse(buffer []byte) (interface{}, error)
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
	NewErrorResponse(err error) Error
	NewMessage(requestID uint64, method string, args ...interface{}) ([]byte, func(buffer []byte) (interface{}, error), error)
	NewResponseMessage(requestID uint64, responseType string, method string, args ...interface{}) ([]byte, func(buffer []byte) (interface{}, error), error)
}

// MerkleTreeParser interface defines functions that are required to diode merkle tree
type MerkleTreeParser interface {
	parseProof(proof interface{}) (rootHash []byte, module uint64, leaves []MerkleTreeLeave, err error)
	rparse(proof interface{}) (interface{}, uint64, []MerkleTreeLeave, error)
}
