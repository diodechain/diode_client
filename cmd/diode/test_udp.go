// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

var (
	testUDPCmd = &command.Command{
		Name:             "test_udp",
		HelpText:         "  Test UDP relaying via portopen2.",
		ExampleText:      "  diode test_udp -publish 8080\n  diode test_udp -bind 0x...:8080",
		Run:              testUDPHandler,
		Type:             command.DaemonCommand,
		SingleConnection: true,
	}

	testUDPPublishPort int
	testUDPBindSpec    string
	testUDPFlags       string
	testUDPPayload     string
	testUDPInterval    time.Duration
)

func init() {
	testUDPCmd.Flag.IntVar(&testUDPPublishPort, "publish", 0, "port name to accept for test_udp (e.g. 8080)")
	testUDPCmd.Flag.StringVar(&testUDPBindSpec, "bind", "", "bind to a device test_udp port: <address|bns>:<port>")
	testUDPCmd.Flag.StringVar(&testUDPFlags, "flags", "rwu", "portopen2 flags (must include 'u' for udp)")
	testUDPCmd.Flag.StringVar(&testUDPPayload, "message", "diode test_udp", "message sent by bind side")
	testUDPCmd.Flag.DurationVar(&testUDPInterval, "interval", time.Second, "interval between messages")
}

func testUDPHandler() error {
	if testUDPPublishPort == 0 && testUDPBindSpec == "" {
		return errors.New("either -publish or -bind must be specified")
	}
	if testUDPPublishPort != 0 && testUDPBindSpec != "" {
		return errors.New("use only one of -publish or -bind")
	}
	if testUDPPublishPort != 0 && !util.IsPort(testUDPPublishPort) {
		return fmt.Errorf("invalid publish port: %d", testUDPPublishPort)
	}
	if testUDPInterval <= 0 {
		return fmt.Errorf("interval must be positive")
	}
	if !strings.Contains(testUDPFlags, "u") {
		return fmt.Errorf("flags must include 'u' for udp")
	}

	if err := app.Start(); err != nil {
		return err
	}
	cfg := config.AppConfig
	cfg.Logger.Debug("test_udp start publish=%d bind=%q flags=%q interval=%s message=%q", testUDPPublishPort, testUDPBindSpec, testUDPFlags, testUDPInterval, testUDPPayload)
	client := app.WaitForFirstClient(true)
	if client == nil {
		return fmt.Errorf("could not connect to network")
	}
	if host, err := client.Host(); err == nil {
		cfg.Logger.Debug("rpc host=%s", host)
	}
	if remote, err := client.RemoteAddr(); err == nil && remote != nil {
		cfg.Logger.Debug("rpc remote=%s", remote.String())
	}

	if testUDPPublishPort != 0 {
		return runTestUDPPublish(client, testUDPPublishPort)
	}
	return runTestUDPBind(client, testUDPBindSpec)
}

func runTestUDPPublish(client *rpc.Client, port int) error {
	cfg := config.AppConfig
	portName := strconv.Itoa(port)
	cfg.PrintInfo(fmt.Sprintf("Waiting for portopen2 requests on port name %s", portName))
	cfg.Logger.Debug("publish mode portName=%s", portName)

	client.SetPortOpen2Handler(func(portOpen *edge.PortOpen2) error {
		cfg.Logger.Debug("portopen2 inbound portName=%s physicalPort=%d flags=%s source=%s ok=%v err=%v", portOpen.PortName, portOpen.PhysicalPort, portOpen.Flags, portOpen.SourceDeviceID.HexString(), portOpen.Ok, portOpen.Err)
		if portOpen.PortName != portName {
			return fmt.Errorf("unexpected port name: %s", portOpen.PortName)
		}
		if !strings.Contains(portOpen.Flags, "u") {
			return fmt.Errorf("unsupported flags: %s", portOpen.Flags)
		}
		if portOpen.PhysicalPort <= 0 {
			return fmt.Errorf("invalid physical port: %d", portOpen.PhysicalPort)
		}

		conn, relayAddr, err := dialPortOpen2(client, portOpen.PhysicalPort, portOpen.Flags)
		if err != nil {
			cfg.Logger.Debug("dialPortOpen2 failed: %v", err)
			return err
		}
		cfg.Logger.Debug("dialPortOpen2 ok relay=%s local=%s remote=%s", relayAddr, conn.LocalAddr().String(), conn.RemoteAddr().String())
		cfg.PrintLabel("Relay address", relayAddr)
		if isUDPConn(conn) {
			poke := []byte("diode test_udp poke")
			if _, err := conn.Write(poke); err != nil {
				cfg.Logger.Debug("udp poke write failed: %s", describeNetErr(err))
			} else {
				cfg.Logger.Debug("udp poke sent bytes=%d", len(poke))
			}
		}
		go readRelayLoop(conn, cfg.Logger)
		return nil
	})

	app.Wait()
	return nil
}

func runTestUDPBind(client *rpc.Client, spec string) error {
	cfg := config.AppConfig
	deviceID, portName, err := parseTestUDPBindSpec(client, spec)
	if err != nil {
		return err
	}
	cfg.Logger.Debug("bind resolved device=%s portName=%s", deviceID.HexString(), portName)

	portOpen, err := client.PortOpen2(deviceID, portName, testUDPFlags)
	if err != nil {
		return err
	}
	cfg.Logger.Debug("portopen2 response ok=%v physicalPort=%d", portOpen != nil && portOpen.Ok, portOpen.PhysicalPort)
	if portOpen == nil || !portOpen.Ok {
		return fmt.Errorf("portopen2 failed")
	}
	if portOpen.PhysicalPort <= 0 {
		return fmt.Errorf("invalid physical port: %d", portOpen.PhysicalPort)
	}

	conn, relayAddr, err := dialPortOpen2(client, portOpen.PhysicalPort, testUDPFlags)
	if err != nil {
		return err
	}
	defer conn.Close()

	cfg.Logger.Debug("dialPortOpen2 ok relay=%s local=%s remote=%s", relayAddr, conn.LocalAddr().String(), conn.RemoteAddr().String())
	go readRelayLoop(conn, cfg.Logger)

	cfg.PrintLabel("Relay address", relayAddr)
	payload := []byte(testUDPPayload)
	sendCount := 0
	sendBytes := 0
	for !app.Closed() {
		sendCount++
		cfg.Logger.Debug("udp send attempt=%d bytes=%d", sendCount, len(payload))
		_, err := conn.Write(payload)
		if err != nil {
			if isUDPConn(conn) && isConnRefused(err) {
				cfg.Logger.Info("udp relay not ready yet, retrying: %s", describeNetErr(err))
			} else {
				return err
			}
		} else {
			sendBytes += len(payload)
			if sendCount%10 == 0 {
				cfg.Logger.Debug("udp send stats count=%d bytes=%d", sendCount, sendBytes)
			}
		}
		time.Sleep(testUDPInterval)
	}
	return nil
}

func parseTestUDPBindSpec(client *rpc.Client, spec string) (util.Address, string, error) {
	var addr util.Address
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		return addr, "", fmt.Errorf("bind format expected <address|bns>:<port> but got: %s", spec)
	}
	config.AppConfig.Logger.Debug("bind spec addr=%s port=%s", parts[0], parts[1])
	portNum, err := strconv.Atoi(parts[1])
	if err != nil || !util.IsPort(portNum) {
		return addr, "", fmt.Errorf("invalid bind port: %s", parts[1])
	}
	portName := parts[1]

	addr, err = util.DecodeAddress(parts[0])
	if err != nil {
		config.AppConfig.Logger.Debug("bind spec resolving bns=%s", parts[0])
		addrs, resolveErr := client.ResolveBNS(parts[0])
		if resolveErr != nil || len(addrs) == 0 {
			if resolveErr != nil {
				return addr, "", fmt.Errorf("failed to resolve address: %v", resolveErr)
			}
			return addr, "", fmt.Errorf("failed to resolve address: %s", parts[0])
		}
		addr = addrs[0]
	}
	return addr, portName, nil
}

func dialPortOpen2(client *rpc.Client, physicalPort int, flags string) (net.Conn, string, error) {
	relayAddr, err := relayAddress(client, physicalPort)
	if err != nil {
		return nil, "", err
	}
	network := "tcp"
	if strings.Contains(flags, "u") {
		network = "udp"
	}
	config.AppConfig.Logger.Debug("dialPortOpen2 network=%s relay=%s flags=%s", network, relayAddr, flags)
	conn, err := net.Dial(network, relayAddr)
	if err != nil {
		return nil, "", err
	}
	return conn, relayAddr, nil
}

func relayAddress(client *rpc.Client, physicalPort int) (string, error) {
	if remoteAddr, err := client.RemoteAddr(); err == nil && remoteAddr != nil {
		config.AppConfig.Logger.Debug("relayAddress remoteAddr=%s", remoteAddr.String())
		if host, _, err := net.SplitHostPort(remoteAddr.String()); err == nil {
			return net.JoinHostPort(host, strconv.Itoa(physicalPort)), nil
		}
	}
	hostPort, err := client.Host()
	if err != nil {
		return "", err
	}
	config.AppConfig.Logger.Debug("relayAddress hostPort=%s", hostPort)
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(physicalPort)), nil
}

func readRelayLoop(conn net.Conn, logger *config.Logger) {
	logger.Debug("relay read loop start local=%s remote=%s", conn.LocalAddr().String(), conn.RemoteAddr().String())
	buf := make([]byte, 2048)
	readCount := 0
	readBytes := 0
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if isConnRefused(err) && isUDPConn(conn) {
				logger.Info("udp relay read not ready yet, retrying: %s", describeNetErr(err))
				time.Sleep(200 * time.Millisecond)
				continue
			}
			logger.Info("relay read ended: %s", describeNetErr(err))
			return
		}
		readCount++
		readBytes += n
		logger.Debug("relay read bytes=%d", n)
		if readCount%10 == 0 {
			logger.Debug("udp read stats count=%d bytes=%d", readCount, readBytes)
		}
		msg := strings.TrimSpace(string(buf[:n]))
		if msg == "" {
			logger.Info("received %d bytes", n)
			continue
		}
		logger.Info("received: %s", msg)
	}
}

func isUDPConn(conn net.Conn) bool {
	_, ok := conn.(*net.UDPConn)
	return ok
}

func isConnRefused(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return strings.Contains(strings.ToLower(opErr.Err.Error()), "refused")
	}
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

func describeNetErr(err error) string {
	if err == nil {
		return ""
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			return fmt.Sprintf("op=%s net=%s addr=%v syscall=%s errno=%v err=%v", opErr.Op, opErr.Net, opErr.Addr, sysErr.Syscall, sysErr.Err, sysErr)
		}
		if errno, ok := opErr.Err.(syscall.Errno); ok {
			return fmt.Sprintf("op=%s net=%s addr=%v errno=%v err=%v", opErr.Op, opErr.Net, opErr.Addr, errno, opErr.Err)
		}
		return fmt.Sprintf("op=%s net=%s addr=%v err=%v", opErr.Op, opErr.Net, opErr.Addr, opErr.Err)
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		return fmt.Sprintf("syscall=%s errno=%v err=%v", sysErr.Syscall, sysErr.Err, sysErr)
	}
	if errno, ok := err.(syscall.Errno); ok {
		return fmt.Sprintf("errno=%v err=%v", errno, err)
	}
	return err.Error()
}
