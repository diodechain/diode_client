// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

// Message is the struct for each in/out rpc message
// TODO: implement io.Read/io.Write interface?
type Message struct {
	Len    int
	Buffer []byte
}

// ResponseID returns response identifier of the message
func (msg *Message) ResponseID(edgeProtocol EdgeProtocol) uint64 {
	if !msg.IsResponse(edgeProtocol) {
		return 0
	}
	return edgeProtocol.ResponseID(msg.Buffer)
}

func (msg *Message) pivotBuffer() []byte {
	var length int
	if len(msg.Buffer) > 20 {
		length = 19
	} else {
		length = len(msg.Buffer)
	}
	return msg.Buffer[0:length]
}

// IsResponse returns true if the message is response
func (msg *Message) IsResponse(edgeProtocol EdgeProtocol) bool {
	pivot := msg.pivotBuffer()
	return edgeProtocol.IsResponseType(pivot) || edgeProtocol.IsErrorType(pivot)
}

// IsRequest returns true if the message is request
func (msg *Message) IsRequest(edgeProtocol EdgeProtocol) bool {
	return !msg.IsResponse(edgeProtocol)
}

// IsError returns true if the message is error
func (msg *Message) IsError(edgeProtocol EdgeProtocol) bool {
	pivot := msg.pivotBuffer()
	return edgeProtocol.IsErrorType(pivot)
}

// ReadAsResponse returns Response of the message
func (msg *Message) ReadAsResponse(edgeProtocol EdgeProtocol) (interface{}, error) {
	return edgeProtocol.parseResponse(msg.Buffer)
}

// ReadAsInboundRequest returns Request of the message
func (msg *Message) ReadAsInboundRequest(edgeProtocol EdgeProtocol) (interface{}, error) {
	return edgeProtocol.parseInboundRequest(msg.Buffer)
}

// ReadAsError returns Error of the message
func (msg *Message) ReadAsError(edgeProtocol EdgeProtocol) (Error, error) {
	return edgeProtocol.parseError(msg.Buffer)
}
