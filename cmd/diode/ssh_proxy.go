// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
)

func runSSHProxyCommand(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	flagSet := flag.NewFlagSet("ssh-proxy", flag.ContinueOnError)
	flagSet.SetOutput(stderr)

	var proxyAddr string
	flagSet.StringVar(&proxyAddr, "proxy-addr", "", "local diode socks proxy address")
	if err := flagSet.Parse(args); err != nil {
		return err
	}
	if proxyAddr == "" {
		return fmt.Errorf("missing -proxy-addr")
	}

	rest := flagSet.Args()
	if len(rest) != 2 {
		return fmt.Errorf("usage: ssh-proxy -proxy-addr <host:port> <target-host> <target-port>")
	}

	port, err := strconv.Atoi(rest[1])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid target port: %s", rest[1])
	}

	return proxySSHStream(proxyAddr, rest[0], port, stdin, stdout)
}

func proxySSHStream(proxyAddr string, targetHost string, targetPort int, stdin io.Reader, stdout io.Writer) error {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := socks5Handshake(conn, targetHost, targetPort); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, stdin)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		done <- err
	}()

	_, err = io.Copy(stdout, conn)
	if err != nil {
		return err
	}
	select {
	case writeErr := <-done:
		if writeErr != nil {
			return writeErr
		}
	default:
	}
	return nil
}

func socks5Handshake(conn net.Conn, targetHost string, targetPort int) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("socks proxy does not support no-auth connect")
	}

	request, err := buildSocks5ConnectRequest(targetHost, targetPort)
	if err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unexpected socks version: %d", header[0])
	}
	if header[1] != 0x00 {
		return fmt.Errorf("socks connect failed with code %d", header[1])
	}

	addrLen, err := socks5ReplyAddressLength(header[3], conn)
	if err != nil {
		return err
	}
	discardLen := addrLen + 2
	if discardLen > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(discardLen)); err != nil {
			return err
		}
	}
	return nil
}

func buildSocks5ConnectRequest(targetHost string, targetPort int) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{0x05, 0x01, 0x00})
	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(0x01)
			buf.Write(ip4)
		} else {
			buf.WriteByte(0x04)
			buf.Write(ip.To16())
		}
	} else {
		if len(targetHost) > 255 {
			return nil, fmt.Errorf("target host is too long")
		}
		buf.WriteByte(0x03)
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(targetPort))
	buf.Write(portBytes[:])
	return buf.Bytes(), nil
}

func socks5ReplyAddressLength(addrType byte, conn net.Conn) (int, error) {
	switch addrType {
	case 0x01:
		return net.IPv4len, nil
	case 0x04:
		return net.IPv6len, nil
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return 0, err
		}
		return int(length[0]), nil
	default:
		return 0, fmt.Errorf("unsupported socks address type: %d", addrType)
	}
}
