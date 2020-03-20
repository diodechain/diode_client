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

// ResponseMethod returns response method of the message
func (msg *Message) ResponseMethod(edgeProtocol EdgeProtocol) string {
	if !msg.IsResponse(edgeProtocol) {
		return ""
	}
	return edgeProtocol.ResponseMethod(msg.Buffer)
}

// IsResponse returns true if the message is response
func (msg *Message) IsResponse(edgeProtocol EdgeProtocol) bool {
	return edgeProtocol.IsResponseType(msg.Buffer) || edgeProtocol.IsErrorType(msg.Buffer)
}

// IsRequest returns true if the message is request
func (msg *Message) IsRequest(edgeProtocol EdgeProtocol) bool {
	return !msg.IsResponse(edgeProtocol)
}

// ReadAsResponse returns Response of the message
func (msg *Message) ReadAsResponse(edgeProtocol EdgeProtocol) (Response, error) {
	return edgeProtocol.parseResponse(msg.Buffer)
}

// ReadAsRequest returns Request of the message
func (msg *Message) ReadAsRequest(edgeProtocol EdgeProtocol) (Request, error) {
	return edgeProtocol.parseRequest(msg.Buffer)
}

// ReadAsError returns Error of the message
func (msg *Message) ReadAsError(edgeProtocol EdgeProtocol) (Error, error) {
	return edgeProtocol.parseError(msg.Buffer)
}
