// logtarget_listener is a tiny TCP server that prints bytes received on a port.
// Run it on the machine (Diode device) given in diode's -logtarget=<hex_or_bns>:<port>
// so published clients can ship console-formatted logs through the tunnel.
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:9999", "TCP address to listen on (host:port); must match -logtarget port")
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("logtarget_listener: listening on %s (diode -logtarget=…:%s)", ln.Addr(), portOnly(*listen))

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	log.Printf("connection from %s", conn.RemoteAddr())
	if _, err := io.Copy(os.Stdout, conn); err != nil {
		log.Printf("read %s: %v", conn.RemoteAddr(), err)
	}
}

func portOnly(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return p
}
