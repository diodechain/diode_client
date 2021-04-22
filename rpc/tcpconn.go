// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"net"
	"time"
)

func configureTcpConn(tcpConn *net.TCPConn) {
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(time.Minute)
	tcpConn.SetReadBuffer(1000000)
	tcpConn.SetWriteBuffer(1000000)
}
