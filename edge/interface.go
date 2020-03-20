// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"github.com/diodechain/diode_go_client/blockquick"
)

// EdgeProtocol interface defines functions that are required to diode edge protocol
type EdgeProtocol interface {
	parseResponse(rawResponse []byte) (response Response, err error)
	parseRequest(rawRequest []byte) (request Request, err error)
	parseError(rawError []byte) (Error, error)
	IsResponseType(rawData []byte) bool
	IsErrorType(rawData []byte) bool
	ResponseMethod(rawData []byte) string
	NewErrorResponse(method string, err error) Message
	NewMessage(method string, args ...interface{}) ([]byte, error)
	NewPortOpenRequest(request Request) (*PortOpen, error)
	NewPortSendRequest(request Request) (*PortSend, error)
	NewPortCloseRequest(request Request) (*PortClose, error)
	// parse response of rpc call
	ParsePortOpen(rawResponse [][]byte) (*PortOpen, error)
	// ParsePortSend(rawResponse [][]byte) (*PortSend, error)
	// ParsePortClose(rawResponse [][]byte) (*PortClose, error)
	ParseServerObj(rawObject []byte) (*ServerObj, error)
	ParseStateRoots(rawStateRoots []byte) (*StateRoots, error)
	ParseAccountRoots(rawAccountRoots []byte) (*AccountRoots, error)
	ParseAccount(rawAccount [][]byte) (*Account, error)
	ParseAccountValue(rawAccountValue []byte) (*AccountValue, error)
	ParseBlockquick(raw []byte, size int) ([]int, error)
	ParseBlockHeaders(raw []byte, size int) ([]*blockquick.BlockHeader, error)
	ParseBlockHeader(rawHeader []byte, minerPubkey []byte) (*blockquick.BlockHeader, error)
	ParseDeviceTicket(rawObject []byte) (*DeviceTicket, error)
}
