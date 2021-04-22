// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
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
