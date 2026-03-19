package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

func TestRunSSHProxyCommandRequiresArgs(t *testing.T) {
	err := runSSHProxyCommand(nil, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "missing -proxy-addr") {
		t.Fatalf("expected missing proxy addr error, got %v", err)
	}
}

func TestRunSSHProxyCommandRejectsBadPort(t *testing.T) {
	err := runSSHProxyCommand([]string{"-proxy-addr", "127.0.0.1:1080", "host", "bogus"}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "invalid target port") {
		t.Fatalf("expected invalid target port error, got %v", err)
	}
}

func TestProxySSHStreamBridgesTraffic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		expectSocksGreeting(t, conn)
		host, port := expectSocksConnect(t, conn)
		if host != "target.diode" || port != 2222 {
			t.Errorf("unexpected connect target %s:%d", host, port)
			return
		}
		sendSocksConnectReply(t, conn, 0x00)

		payload := make([]byte, len("ping"))
		if _, err := io.ReadFull(conn, payload); err != nil {
			t.Errorf("ReadFull(): %v", err)
			return
		}
		if string(payload) != "ping" {
			t.Errorf("unexpected payload %q", string(payload))
			return
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			t.Errorf("Write(): %v", err)
		}
	}()

	var stdout bytes.Buffer
	if err := proxySSHStream(ln.Addr().String(), "target.diode", 2222, strings.NewReader("ping"), &stdout); err != nil {
		t.Fatalf("proxySSHStream(): %v", err)
	}
	if stdout.String() != "pong" {
		t.Fatalf("unexpected proxy output %q", stdout.String())
	}
	wg.Wait()
}

func TestProxySSHStreamRejectsSocksRefusal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		expectSocksGreeting(t, conn)
		_, _ = expectSocksConnect(t, conn)
		sendSocksConnectReply(t, conn, 0x05)
	}()

	err = proxySSHStream(ln.Addr().String(), "target.diode", 22, strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "socks connect failed") {
		t.Fatalf("expected socks failure, got %v", err)
	}
}

func expectSocksGreeting(t *testing.T, conn net.Conn) {
	t.Helper()
	var greeting [3]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		t.Fatalf("ReadFull(greeting): %v", err)
	}
	if greeting != [3]byte{0x05, 0x01, 0x00} {
		t.Fatalf("unexpected greeting %v", greeting)
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		t.Fatalf("Write(greeting reply): %v", err)
	}
}

func expectSocksConnect(t *testing.T, conn net.Conn) (string, int) {
	t.Helper()
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("ReadFull(header): %v", err)
	}
	if !bytes.Equal(header, []byte{0x05, 0x01, 0x00, 0x03}) {
		t.Fatalf("unexpected header %v", header)
	}

	var hostLen [1]byte
	if _, err := io.ReadFull(conn, hostLen[:]); err != nil {
		t.Fatalf("ReadFull(hostLen): %v", err)
	}
	hostBytes := make([]byte, hostLen[0])
	if _, err := io.ReadFull(conn, hostBytes); err != nil {
		t.Fatalf("ReadFull(host): %v", err)
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		t.Fatalf("ReadFull(port): %v", err)
	}
	return string(hostBytes), int(binary.BigEndian.Uint16(portBytes[:]))
}

func sendSocksConnectReply(t *testing.T, conn net.Conn, code byte) {
	t.Helper()
	reply := []byte{0x05, code, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34}
	if _, err := conn.Write(reply); err != nil {
		t.Fatalf("Write(reply): %v", err)
	}
}

func TestBuildSocks5ConnectRequestIPv4(t *testing.T) {
	req, err := buildSocks5ConnectRequest("127.0.0.1", 22)
	if err != nil {
		t.Fatalf("buildSocks5ConnectRequest(): %v", err)
	}
	want := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x16}
	if !bytes.Equal(req, want) {
		t.Fatalf("unexpected request %v", req)
	}
}

func TestBuildSocks5ConnectRequestRejectsLongHost(t *testing.T) {
	host := strings.Repeat("a", 256)
	_, err := buildSocks5ConnectRequest(host, 22)
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("expected long host error, got %v", err)
	}
}

func TestProxySSHStreamBadProxyAddress(t *testing.T) {
	err := proxySSHStream("127.0.0.1:1", "target.diode", 22, strings.NewReader(""), io.Discard)
	if err == nil {
		t.Fatalf("expected dial failure")
	}
}
