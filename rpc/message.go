// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

// Message is the struct for each in/out rpc message
// TODO: implement io.Read/io.Write interface?
type Message struct {
	Len    int
	buffer []byte
}

// ResponseMethod returns response method of the message
func (msg *Message) ResponseMethod() string {
	if !msg.IsResponse() {
		return ""
	}
	return responseMethod(msg.buffer)
}

// IsResponse returns true if the message is response
func (msg *Message) IsResponse() bool {
	return isResponseType(msg.buffer) || isErrorType(msg.buffer)
}

// IsRequest returns true if the message is request
func (msg *Message) IsRequest() bool {
	return !msg.IsResponse()
}

// ReadAsResponse returns *Response of the message
func (msg *Message) ReadAsResponse() (Response, error) {
	return parseResponse(msg.buffer)
}

// ReadAsRequest returns *Request of the message
func (msg *Message) ReadAsRequest() (Request, error) {
	return parseRequest(msg.buffer)
}
