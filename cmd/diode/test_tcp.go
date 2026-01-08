// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

var (
	testTCPCmd = &command.Command{
		Name:             "test_tcp",
		HelpText:         "  Test TCP relaying via portopen2.",
		ExampleText:      "  diode test_tcp -publish 8080\n  diode test_tcp -bind 0x...:8080",
		Run:              testTCPHandler,
		Type:             command.DaemonCommand,
		SingleConnection: true,
	}

	testTCPPublishPort int
	testTCPBindSpec    string
	testTCPFlags       string
	testTCPPayload     string
	testTCPInterval    time.Duration
)

func init() {
	testTCPCmd.Flag.IntVar(&testTCPPublishPort, "publish", 0, "port name to accept for test_tcp (e.g. 8080)")
	testTCPCmd.Flag.StringVar(&testTCPBindSpec, "bind", "", "bind to a device test_tcp port: <address|bns>:<port>")
	testTCPCmd.Flag.StringVar(&testTCPFlags, "flags", "rw", "portopen2 flags (must not include 'u' for tcp)")
	testTCPCmd.Flag.StringVar(&testTCPPayload, "message", "diode test_tcp", "message sent by bind side")
	testTCPCmd.Flag.DurationVar(&testTCPInterval, "interval", time.Second, "interval between messages")
}

func testTCPHandler() error {
	if testTCPPublishPort == 0 && testTCPBindSpec == "" {
		return errors.New("either -publish or -bind must be specified")
	}
	if testTCPPublishPort != 0 && testTCPBindSpec != "" {
		return errors.New("use only one of -publish or -bind")
	}
	if testTCPPublishPort != 0 && !util.IsPort(testTCPPublishPort) {
		return fmt.Errorf("invalid publish port: %d", testTCPPublishPort)
	}
	if testTCPInterval <= 0 {
		return fmt.Errorf("interval must be positive")
	}
	if strings.Contains(testTCPFlags, "u") {
		return fmt.Errorf("flags must not include 'u' for tcp")
	}

	if err := app.Start(); err != nil {
		return err
	}
	cfg := config.AppConfig
	cfg.Logger.Debug("test_tcp start publish=%d bind=%q flags=%q interval=%s message=%q", testTCPPublishPort, testTCPBindSpec, testTCPFlags, testTCPInterval, testTCPPayload)
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

	if testTCPPublishPort != 0 {
		return runTestTCPPublish(client, testTCPPublishPort)
	}
	return runTestTCPBind(client, testTCPBindSpec)
}

func runTestTCPPublish(client *rpc.Client, port int) error {
	cfg := config.AppConfig
	portName := fmt.Sprintf("%d", port)
	cfg.PrintInfo(fmt.Sprintf("Waiting for portopen2 requests on port name %s", portName))
	cfg.Logger.Debug("publish mode portName=%s", portName)

	client.SetPortOpen2Handler(func(portOpen *edge.PortOpen2) error {
		cfg.Logger.Debug("portopen2 inbound portName=%s physicalPort=%d flags=%s source=%s ok=%v err=%v", portOpen.PortName, portOpen.PhysicalPort, portOpen.Flags, portOpen.SourceDeviceID.HexString(), portOpen.Ok, portOpen.Err)
		if portOpen.PortName != portName {
			return fmt.Errorf("unexpected port name: %s", portOpen.PortName)
		}
		if strings.Contains(portOpen.Flags, "u") {
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
		go func() {
			defer conn.Close()
			payload := []byte(testTCPPayload)
			sendCount := 0
			sendBytes := 0
			for !app.Closed() {
				sendCount++
				cfg.Logger.Debug("tcp send attempt=%d bytes=%d", sendCount, len(payload))
				_, err := conn.Write(payload)
				if err != nil {
					cfg.Logger.Info("tcp send stopped: %v", err)
					return
				}
				sendBytes += len(payload)
				if sendCount%10 == 0 {
					cfg.Logger.Debug("tcp send stats count=%d bytes=%d", sendCount, sendBytes)
				}
				time.Sleep(testTCPInterval)
			}
		}()
		return nil
	})

	app.Wait()
	return nil
}

func runTestTCPBind(client *rpc.Client, spec string) error {
	cfg := config.AppConfig
	deviceID, portName, err := parseTestUDPBindSpec(client, spec)
	if err != nil {
		return err
	}
	cfg.Logger.Debug("bind resolved device=%s portName=%s", deviceID.HexString(), portName)

	portOpen, err := client.PortOpen2(deviceID, portName, testTCPFlags)
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

	conn, relayAddr, err := dialPortOpen2(client, portOpen.PhysicalPort, testTCPFlags)
	if err != nil {
		return err
	}
	defer conn.Close()

	cfg.Logger.Debug("dialPortOpen2 ok relay=%s local=%s remote=%s", relayAddr, conn.LocalAddr().String(), conn.RemoteAddr().String())

	cfg.PrintLabel("Relay address", relayAddr)
	readRelayLoop(conn, cfg.Logger)
	return nil
}
