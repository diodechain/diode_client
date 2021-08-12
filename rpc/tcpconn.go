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
	// TODO: These buffer settings are actually not applied!
	//       They need to set before the TCP connection is connected
	//       atm using `sysctl net.ipv4.tcp_rmem="4096        531072  64291456"`
	//
	// TODO: Think dig into impl. it seems setting these will also
	//       disable linux auto-tune for sockets so now they are
	//       skipped
	// tcpConn.SetReadBuffer(1000000)
	// tcpConn.SetWriteBuffer(1000000)
}
