// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

// reponse for inbound request
type portOpenOutboundResponse struct {
	RequestID uint64
	Payload   struct {
		ResponseType string
		Ref          uint64
		Result       string
	}
}

// type portSendOutboundResponse struct {}
// type portCloseOutboundResponse struct {}
