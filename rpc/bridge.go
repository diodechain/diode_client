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
	"github.com/diodechain/diode_client/rlp"
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

			// Rate limit: check if we're allowed to create another connection attempt for this device
			// This prevents connection storms when many inbound requests arrive rapidly
			if !client.pool.IncrementConnectionAttempt(portOpen.DeviceID) {
				err := fmt.Errorf("too many connection attempts to device %x", portOpen.DeviceID)
				client.ResponsePortOpen(portOpen, err)
				client.Log().Debug("Rejecting port open request due to rate limit for device %x", portOpen.DeviceID)
				return
			}
			defer client.pool.DecrementConnectionAttempt(portOpen.DeviceID)

			// Check if there's already an active port for this device/ref
			deviceKey := client.GetDeviceKey(portOpen.Ref)
			existingPort := client.pool.GetPort(deviceKey)
			if existingPort != nil && !existingPort.Closed() {
				// Port already exists and is active, reject the new request
				err := fmt.Errorf("port already open for device %x ref %s", portOpen.DeviceID, portOpen.Ref)
				client.ResponsePortOpen(portOpen, err)
				client.Log().Debug("Rejecting duplicate port open request for device %x ref %s", portOpen.DeviceID, portOpen.Ref)
				return
			}

			portOpen.SrcPortNumber = int(publishedPort.Src)

			// connect to stream service first, before creating the port
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

			// Only create the port after local connection succeeds
			port := NewConnectedPort(0, portOpen.Ref, portOpen.DeviceID, client, portOpen.PortNumber)
			defer port.Shutdown()
			if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
				configureTcpConn(tcpConn)
				port.Conn = remoteConn
			} else {
				// udp
				port.UDPAddr = remoteConn.RemoteAddr()
				port.Conn = NewPacketConn(remoteConn)
			}

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
	} else if portOpen2, ok := inboundRequest.(*edge.PortOpen2); ok {
		defer client.timer.profile(time.Now(), "handlePortOpen2")

		go func() {
			client.Log().Debug("portopen2 request portName=%s physicalPort=%d flags=%s source=%s ok=%v err=%v", portOpen2.PortName, portOpen2.PhysicalPort, portOpen2.Flags, portOpen2.SourceDeviceID.HexString(), portOpen2.Ok, portOpen2.Err)
			if portOpen2.Err != nil {
				_ = client.ResponsePortOpen2(portOpen2, portOpen2.Err)
				client.Log().Error("Failed to decode portopen2 request: %v", portOpen2.Err.Error())
				return
			}

			handlerVal := client.portOpen2Handler.Load()
			if handlerVal != nil {
				if handler, ok := handlerVal.(func(*edge.PortOpen2) error); ok && handler != nil {
					if err := handler(portOpen2); err != nil {
						client.Log().Debug("portopen2 handler error: %v", err)
						_ = client.ResponsePortOpen2(portOpen2, err)
						return
					}
					client.Log().Debug("portopen2 handler ok")
					_ = client.ResponsePortOpen2(portOpen2, nil)
					return
				}
			}

			client.Log().Debug("portopen2 handler missing")
			_ = client.ResponsePortOpen2(portOpen2, fmt.Errorf("no portopen2 handler configured"))
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
	} else if ticketReq, ok := inboundRequest.(*edge.TicketRequest); ok {
		defer client.timer.profile(time.Now(), "handleTicketRequest")
		go client.HandleTicketRequest(ticketReq)
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
		} else {
			if len(port.BnsAllowlist) != 0 {
				for bns, allowed := range port.BnsAllowlist {
					if !allowed {
						continue
					}
					addrs, err := client.GetCacheOrResolvePeers(bns)
					if err != nil {
						continue
					}
					for _, a := range addrs {
						if a == addr {
							return true
						}
					}
				}
			}
			if len(port.DriveMemberAllowList) != 0 {
				for driveMember, allowed := range port.DriveMemberAllowList {
					if !allowed {
						continue
					}
					addrs, err := client.GetCacheOrResolveAllPeersOfAddrs(driveMember)
					if err != nil {
						continue
					}
					for _, a := range addrs {
						if a == addr {
							return true
						}
					}
				}
			}
			if len(port.DriveAllowList) != 0 {
				for drive, allowed := range port.DriveAllowList {
					if !allowed {
						continue
					}
					addrs, err := client.GetCacheOrResolveAllPeersOfAddrs(drive)
					if err != nil {
						continue
					}
					for _, a := range addrs {
						if a == addr {
							return true
						}
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
	// If message framing is broken, the payload will not be valid RLP.
	// This is non-recoverable because we won't be able to find the beginning of
	// the next frame again, so close the connection to prevent a loop.
	if err := validateRLPMessage(msg.Buffer); err != nil {
		client.Log().Error("Invalid RLP frame received, closing connection: %v", err)
		client.Log().Debug("Invalid RLP data: %x", msg.Buffer)
		client.Close()
		return
	}

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
				Message: fmt.Sprintf("failed processing response %v %v", msg.Buffer, err.Error()),
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

func validateRLPMessage(b []byte) error {
	k, content, rest, err := rlp.Split(b)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return rlp.ErrMoreThanOneValue
	}
	return validateRLPValue(k, content)
}

func validateRLPValue(k rlp.Kind, content []byte) error {
	if k != rlp.List {
		return nil
	}
	for len(content) > 0 {
		innerKind, innerContent, rest, err := rlp.Split(content)
		if err != nil {
			return err
		}
		if err := validateRLPValue(innerKind, innerContent); err != nil {
			return err
		}
		content = rest
	}
	return nil
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
		if client.s == nil {
			if !client.isClosed {
				client.Log().Info("Client connection closed prematurely.")
				client.Close()
			}
			return
		}
		msg, err := client.s.readMessage()
		if err != nil {
			if !client.isClosed {
				client.Log().Info("Client connection closed unexpectedly: %v", err)
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
