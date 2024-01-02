// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
)

var (
	errPortNotPublished = fmt.Errorf("port was not published")
)

// handleInboundRequest handle inbound request
func (client *Client) handleInboundRequest(inboundRequest interface{}) {
	if portOpen, ok := inboundRequest.(*edge.PortOpen); ok {
		defer client.timer.profile(time.Now(), "handlePortOpen")

		go func() {
			if portOpen.Err != nil {
				client.ResponsePortOpen(portOpen, portOpen.Err)
				client.Log().Error("Failed to decode portopen request: %v", portOpen.Err.Error())
				return
			}
			// Checking blocklist and allowlist
			if len(client.config.Blocklists()) > 0 {
				if client.config.Blocklists()[portOpen.DeviceID] {
					err := fmt.Errorf(
						"device %x is on the block list",
						portOpen.DeviceID,
					)
					client.ResponsePortOpen(portOpen, err)
					return
				}
			} else {
				if len(client.config.Allowlists) > 0 {
					if !client.config.Allowlists[portOpen.DeviceID] {
						err := fmt.Errorf(
							"device %x is not in the allow list",
							portOpen.DeviceID,
						)
						client.ResponsePortOpen(portOpen, err)
						return
					}
				}
			}

			// find published port
			publishedPort := client.pool.GetPublishedPort(portOpen.PortNumber)
			if publishedPort == nil {
				client.ResponsePortOpen(portOpen, errPortNotPublished)
				client.Log().Info("Port was not published port = %v", portOpen.PortNumber)
				return
			}
			if publishedPort.Protocol != config.AnyProtocol && publishedPort.Protocol != portOpen.Protocol {
				client.ResponsePortOpen(portOpen, errPortNotPublished)
				client.Log().Info("Port was not published as this type (%v != %v) port = %v", publishedPort.Protocol, portOpen.Protocol, portOpen.PortNumber)
				return
			}

			if !client.isAllowlisted(publishedPort, portOpen.DeviceID) {
				err := fmt.Errorf("device %x is not in the Allowlist (2)", portOpen.DeviceID)
				client.ResponsePortOpen(portOpen, err)
				return
			}

			portOpen.SrcPortNumber = int(publishedPort.Src)
			port := NewConnectedPort(0, portOpen.Ref, portOpen.DeviceID, client, portOpen.PortNumber)
			defer port.Shutdown()

			// connect to stream service
			host := net.JoinHostPort(publishedPort.SrcHost, strconv.Itoa(portOpen.SrcPortNumber))

			network := "tcp"
			if portOpen.Protocol == config.UDPProtocol {
				network = "udp"
			}

			remoteConn, err := net.DialTimeout(network, host, client.localTimeout)
			if err != nil {
				_ = client.ResponsePortOpen(portOpen, err)
				client.Log().Error("Failed to connect local '%v': %v", host, err)
				return
			}
			if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
				configureTcpConn(tcpConn)
				port.Conn = remoteConn
			} else {
				// udp
				port.UDPAddr = remoteConn.RemoteAddr()
				port.Conn = NewPacketConn(remoteConn)
			}

			deviceKey := client.GetDeviceKey(portOpen.Ref)
			port.Protocol = portOpen.Protocol
			port.PortNumber = portOpen.PortNumber
			port.SrcPortNumber = portOpen.SrcPortNumber
			// port.Conn = NewLoggingConn("local", remoteConn)

			// For the E2E encryption we're wrapping remoteConn in TLS
			// if portOpen.Protocol == config.TLSProtocol || portOpen.Protocol == config.UDPProtocol {
			if portOpen.Protocol == config.TLSProtocol {
				err := port.UpgradeTLSServer()
				if err != nil {
					_ = client.ResponsePortOpen(portOpen, err)
					client.Log().Error("Failed to tunnel openssl server: %v", err)
					return
				}
			}
			client.pool.SetPort(deviceKey, port)
			_ = client.ResponsePortOpen(portOpen, nil)
			port.Copy()
		}()
	} else if portSend, ok := inboundRequest.(*edge.PortSend); ok {
		defer client.timer.profile(time.Now(), "handlePortSend")

		if portSend.Err != nil {
			client.Log().Error("Failed to decode portsend request: %v", portSend.Err.Error())
			return
		}
		decData := portSend.Data
		// start to write data
		deviceKey := client.GetDeviceKey(portSend.Ref)
		cachedConnDevice := client.pool.GetPort(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.SendLocal(decData)
		} else {
			// client.Log().Error("Couldn't find the portsend connected device %x", portSend.Ref)
			client.CastPortClose(portSend.Ref)
		}
	} else if portClose, ok := inboundRequest.(*edge.PortClose); ok {
		defer client.timer.profile(time.Now(), "handlePortClose")

		deviceKey := client.GetDeviceKey(portClose.Ref)
		cachedConnDevice := client.pool.GetPort(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.Close()
			client.pool.SetPort(deviceKey, nil)
		}
		//  else {
		// client.Log().Error("Couldn't find the portclose connected device %x", portClose.Ref)
		// }
	} else if goodbye, ok := inboundRequest.(edge.Goodbye); ok {
		defer client.timer.profile(time.Now(), "handleGoodbye")

		client.Log().Warn("server disconnected, reason: %v", goodbye.Reason)
		if !client.Closed() {
			client.Close()
		}
	} else {
		client.Log().Warn("doesn't support rpc request: %+v ", inboundRequest)
	}
}

// isAllowlisted returns true if device is allowlisted
func (client *Client) isAllowlisted(port *config.Port, addr Address) bool {
	switch port.Mode {
	case config.PublicPublishedMode:
		return true
	case config.ProtectedPublishedMode:
		allowFleets := []Address{client.config.FleetAddr}
		if len(port.Allowlist) > 0 {
			allowFleets = make([]Address, len(port.Allowlist))
			i := 0
			for fleet := range port.Allowlist {
				allowFleets[i] = fleet
				i++
			}
		}

		for _, fleetAddr := range allowFleets {
			isAccessWhilisted := client.IsDeviceAllowlisted(fleetAddr, addr)
			if isAccessWhilisted {
				return true
			}
		}

		return false
	case config.PrivatePublishedMode:
		if port.Allowlist[addr] {
			return true
		} else if len(port.BnsAllowlist) == 0 {
			return false
		} else {
			for bns, allowed := range port.BnsAllowlist {
				if !allowed {
					continue
				}
				addrs, err := client.GetCacheOrResolveBNS(bns)
				if err != nil {
					continue
				}
				for _, a := range addrs {
					if a == addr {
						return true
					}
				}
			}
			return false
		}
	default:
		return false
	}
}

// handleInboundMessage handle inbound message
func (client *Client) handleInboundMessage(msg edge.Message) {
	if msg.IsResponse() {
		defer client.timer.profile(time.Now(), "handleResponse")

		client.backoff.StepBack()
		call := client.cm.CallByID(msg.ResponseID())
		if call == nil {
			// receive empty call, client might drop call because timeout, should drop message
			return
		}
		// enqueueResponse will call call.Clean(CLOSED) in success cases
		defer call.Clean(CANCELLED)
		if call.id == 0 {
			client.Log().Warn("Call.id is 0 ")
			return
		}
		if call.response == nil {
			// should not wait response for the call
			client.Log().Warn("Call.response is nil id: %d, method: %s, this might lead to rpc timeout error if you wait rpc response", call.id, call.method)
			return
		}
		if msg.IsError() {
			rpcError, _ := msg.ReadAsError()
			call.enqueueResponse(rpcError)
			return
		}
		if call.Parse == nil {
			// no Parse callback for hello and portclose
			return
		}

		defer client.timer.profile(time.Now(), fmt.Sprintf("handle:%s", call.method))

		res, err := call.Parse(msg.Buffer)
		if err != nil {
			rpcError := edge.Error{
				Message: err.Error(),
			}
			call.enqueueResponse(rpcError)
			return
		}
		call.enqueueResponse(res)
		return
	}
	inboundRequest, err := msg.ReadAsInboundRequest()
	if err != nil {
		client.Log().Error("Not rpc request: %v", err)
		return
	}
	if inboundRequest == nil {
		client.Log().Debug("Unsupported rpc request: %v", msg)
		return
	}
	client.handleInboundRequest(inboundRequest)
}

// recvMessageLoop infinite loop to read message from server
func (client *Client) recvMessageLoop() {
	msgBuffer := make(chan edge.Message, 20)
	defer close(msgBuffer)

	go func() {
		for msg := range msgBuffer {
			client.handleInboundMessage(msg)
		}
	}()

	for {
		msg, err := client.s.readMessage()
		if err != nil {
			if !client.isClosed {
				// This was unexpected...
				client.Log().Info("Client connection closed: %v", err)
				client.Close()
			}
			return
		}
		if msg.Len > 0 {
			client.CheckTicket()
			select {
			case msgBuffer <- msg:
			default:
				// client.Log().Debug("Read queue full\n" + client.timer.Dump())
				msgBuffer <- msg
			}
		}
	}
}

// sendCall send the rpc call
func (client *Client) sendCall(c *Call) (err error) {
	ts := time.Now()
	err = client.s.sendMessage(c.data.Bytes())
	if err != nil {
		client.Log().Error("Failed to write to node: %v", err)
		return
	}
	tsDiff := time.Since(ts)
	if client.enableMetrics {
		client.metrics.UpdateWriteTimer(tsDiff)
	}
	return
}
