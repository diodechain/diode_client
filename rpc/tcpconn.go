// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

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
