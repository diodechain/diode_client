// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

// EdgeProtocol interface defines functions that are required to diode edge protocol
type EdgeProtocol interface {
	parseResponse(rawResponse []byte) (response Response, err error)
	parseRequest(rawRequest []byte) (request Request, err error)
	parseError(rawError []byte) (Error, error)
	// parse response of rpc call
	parseBlockPeak(buffer []byte) (interface{}, error)
	parseBlock(buffer []byte) (interface{}, error)
	parseBlockHeader(buffer []byte) (interface{}, error)
	parseBlockquick(buffer []byte) (interface{}, error)
	parseDeviceTicket(buffer []byte) (interface{}, error)
	parseAccount(buffer []byte) (interface{}, error)
	parseAccountRoots(buffer []byte) (interface{}, error)
	IsResponseType(rawData []byte) bool
	IsErrorType(rawData []byte) bool
	ResponseID(buffer []byte) uint64
	NewMerkleTree(rawTree []byte) (MerkleTree, error)
	NewErrorResponse(method string, err error) Message
	NewMessage(requestID uint64, method string, args ...interface{}) ([]byte, func(buffer []byte) (interface{}, error), error)
	NewPortOpenRequest(request Request) (*PortOpen, error)
	NewPortSendRequest(request Request) (*PortSend, error)
	NewPortCloseRequest(request Request) (*PortClose, error)
	// parse response of rpc call
	ParseAccountValue(rawAccountValue []byte) (*AccountValue, error)
	ParsePortOpen(rawResponse [][]byte) (*PortOpen, error)
	// ParsePortSend(rawResponse [][]byte) (*PortSend, error)
	// ParsePortClose(rawResponse [][]byte) (*PortClose, error)
	ParseServerObj(rawObject []byte) (*ServerObj, error)
	ParseStateRoots(rawStateRoots []byte) (*StateRoots, error)
	ParseDeviceTicket(rawObject []byte) (*DeviceTicket, error)
}

// MerkleTreeParser interface defines functions that are required to diode merkle tree
type MerkleTreeParser interface {
	parseProof(proof []byte) (rootHash []byte, module uint64, leaves []MerkleTreeLeave, err error)
	rparse(proof []byte) (interface{}, uint64, []MerkleTreeLeave, error)
}
