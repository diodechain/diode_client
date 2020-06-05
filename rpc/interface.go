// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

// ConnectedConn interface
type ConnectedConn interface {
	copyToSSL(client interface{}, ref string) error
	// setConn() net.Conn
}
