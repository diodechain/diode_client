// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

// remoteWriter Writes data to the remote end of a ConnectedPort
type remoteWriter struct {
	port *ConnectedPort
}

// Write binary data to the connectionn
func (c *remoteWriter) Write(data []byte) (n int, err error) {
	err = c.port.SendRemote(data)
	if err == nil {
		n = len(data)
	}
	return
}
