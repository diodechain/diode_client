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
func (msg *Message) ResponseID() uint64 {
	if !msg.IsResponse() {
		return 0
	}
	return ResponseID(msg.Buffer)
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
func (msg *Message) IsResponse() bool {
	pivot := msg.pivotBuffer()
	return IsResponseType(pivot) || IsErrorType(pivot)
}

// IsRequest returns true if the message is request
func (msg *Message) IsRequest() bool {
	return !msg.IsResponse()
}

// IsError returns true if the message is error
func (msg *Message) IsError() bool {
	pivot := msg.pivotBuffer()
	return IsErrorType(pivot)
}

// ReadAsResponse returns Response of the message
func (msg *Message) ReadAsResponse() (interface{}, error) {
	return parseResponse(msg.Buffer)
}

// ReadAsInboundRequest returns Request of the message
func (msg *Message) ReadAsInboundRequest() (interface{}, error) {
	return parseInboundRequest(msg.Buffer)
}

// ReadAsError returns Error of the message
func (msg *Message) ReadAsError() (Error, error) {
	return parseError(msg.Buffer)
}
