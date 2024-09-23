// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
	"golang.org/x/net/publicsuffix"
)

var (
	defaultMode      = "rw"
	domainPattern    = regexp.MustCompile(`^(.+)\.(diode|diode\.link|diode\.ws)(:[\d]+)?$`)
	subdomainPattern = regexp.MustCompile(`^([rws]{1,3}-)?(0x[A-Fa-f0-9]{40}|[A-Za-z0-9][A-Za-z0-9-]{5,30}?)(-[^0][\d]+)?$`)

	errAddrType = errors.New("socks addr type not supported")
	errVer      = errors.New("socks version not supported")
	errCmd      = errors.New("socks only support connect command")
	localhost   = "localhost"
)

const (
	socksVer4                  = 0x04
	socksVer5                  = 0x05
	socksCmdConnect            = 0x01
	socksCmdUDP                = 0x03
	socksRepSuccess            = 0x00
	socksRepServerFailed       = 0x01
	socksRepNotAllowed         = 0x02
	socksRepNetworkUnreachable = 0x03
	socksRepHostUnreachable    = 0x04
	socksRepRefused            = 0x05
	socksRepTTLExpired         = 0x06
	stackBufferSize            = 2048
)

// Config is Socks Server configuration
type Config struct {
	Addr            string
	ProxyServerAddr string
	Fallback        string
	EnableProxy     bool
	FleetAddr       Address
	Blocklists      map[Address]bool
	Blockdomains    map[string]bool
	Allowlists      map[Address]bool
}

// Bind keeps track if existing binds
type Bind struct {
	def config.Bind
	tcp net.Listener
	udp net.PacketConn
}

// Server is the only instances of the Socks Server
type Server struct {
	datapool      *DataPool
	clientManager *ClientManager
	resolver      *Resolver
	Config        Config
	logger        *config.Logger
	listener      net.Listener
	udpconn       net.PacketConn
	closeCh       chan struct{}
	binds         []Bind
	cd            sync.Once
}

type DeviceError struct {
	err error
}

func (deviceError DeviceError) Error() string {
	return fmt.Sprintf("This device is offline - %v", deviceError.err)
}

func handshake(conn net.Conn) (version int, url string, err error) {
	const (
		idVer = 0
	)

	buf := make([]byte, 263)
	if _, err = io.ReadFull(conn, buf[0:2]); err != nil {
		return
	}

	switch buf[idVer] {
	case socksVer5:
		version = 5
		url, err = handShake5(conn, buf)
	case socksVer4:
		version = 4
		url, err = handShake4(conn, buf)
	default:
		err = errVer
	}
	return
}

// handShake4 only support SOCKS4A
func handShake4(conn net.Conn, buf []byte) (url string, err error) {
	const (
		idCmd = 1
	)

	if buf[idCmd] > 0x03 || buf[idCmd] == 0x00 {
		err = errCmd
		return
	}

	if buf[idCmd] != socksCmdConnect { //  only support CONNECT mode
		err = errCmd
		return
	}

	if _, err = io.ReadFull(conn, buf[0:6]); err != nil {
		return
	}

	portBytes := buf[0:2]
	port := binary.BigEndian.Uint16(portBytes)

	ip := buf[2:6]
	if ip[0] != 0 || ip[1] != 0 || ip[2] != 0 || ip[3] == 0 {
		err = errVer
		return
	}

	_, err = readString(conn, buf)
	if err != nil {
		return
	}
	host, err := readString(conn, buf)
	if err != nil {
		return
	}

	url = fmt.Sprintf("%s:%d", host, port)
	return
}

func readString(conn net.Conn, buf []byte) (string, error) {
	length := 0
	for {
		_, err := io.ReadFull(conn, buf[length:length+1])
		if err != nil {
			return "", err
		}
		length++
		if length >= len(buf) {
			return "", fmt.Errorf("string too long")
		}
		if buf[length-1] == 0 {
			// Finished reading
			return string(buf[:length-1]), nil
		}
	}
}

func handShake5(conn net.Conn, buf []byte) (url string, err error) {
	const (
		idNmethod = 1
	)

	nmethod := int(buf[idNmethod]) //  client support auth mode
	msgLen := nmethod + 2          //  auth msg length
	if msgLen == 2 {               // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[2:msgLen]); err != nil {
			return
		}
	}
	/*
		X'00' NO AUTHENTICATION REQUIRED
		X'01' GSSAPI
		X'02' USERNAME/PASSWORD
		X'03' to X'7F' IANA ASSIGNED
		X'80' to X'FE' RESERVED FOR PRIVATE METHODS
		X'FF' NO ACCEPTABLE METHODS
	*/
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{socksVer5, 0})
	if err != nil {
		return
	}

	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip address start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)

	// read till we get possible domain length field
	if _, err = io.ReadFull(conn, buf[0:idDmLen+1]); err != nil {
		return
	}

	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}

	/*
		CONNECT X'01'
		BIND X'02'
		UDP ASSOCIATE X'03'
	*/

	if buf[idCmd] > 0x03 || buf[idCmd] == 0x00 {
		err = errCmd
		return
	}

	// read target address
	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		err = fmt.Errorf("socks5 IPv4 not supported (only domain names)")
		return
	case typeIPv6:
		err = fmt.Errorf("socks5 IPv6 not supported (only domain names)")
		return
	case typeDm: // domain name
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if buf[idCmd] == socksCmdUDP { // UDP associate requests
		tcpAddr := conn.LocalAddr().(*net.TCPAddr)
		writeSocksReturn(conn, socksVer5, conn.LocalAddr(), tcpAddr.Port)
		return
	}

	if buf[idCmd] != socksCmdConnect { //  only support CONNECT mode
		err = errCmd
		return
	}

	if reqLen == 2 {
		// common case, do nothing
	} else { // rare case
		if _, err = io.ReadFull(conn, buf[5:reqLen]); err != nil {
			return
		}
	}

	host := string(buf[idDm0 : idDm0+buf[idDmLen]])
	port := binary.BigEndian.Uint16(buf[idDm0+buf[idDmLen] : idDm0+buf[idDmLen]+2])
	url = fmt.Sprintf("%s:%d", host, port)
	return
}

func isDiodeHost(host string) bool {
	subdomainPort := domainPattern.FindStringSubmatch(host)
	return len(subdomainPort) == 4
}

func (socksServer *Server) doConnectDevice(requestId int64, deviceName string, port int, protocol int, mode string, retry int) (*ConnectedPort, error) {
	// Define portname
	var portName string
	if protocol == config.UDPProtocol {
		portName = fmt.Sprintf("udp:%d", port)
	} else if protocol == config.TLSProtocol {
		portName = fmt.Sprintf("tls:%d", port)
	} else {
		portName = fmt.Sprintf("tcp:%d", port)
	}

	// TODO: This works when connections are already open, but fails
	// when another connection got "just" closed (e.g. within a second)
	// we might need to add some kind of memory here
	stickyPort := socksServer.datapool.FindOpenPort(deviceName)
	if stickyPort != nil && !stickyPort.client.Closed() {
		socksServer.logger.Debug("%d: Opening stickyPort %v for %v", requestId, string(stickyPort.DeviceID.Hex()), deviceName)
		portOpen, err := stickyPort.client.PortOpen(stickyPort.DeviceID, port, portName, mode)
		if err == nil && portOpen != nil && portOpen.Err == nil {
			portOpen.PortNumber = port
			return NewConnectedPort(requestId, portOpen.Ref, stickyPort.DeviceID, stickyPort.client, port), nil
		} else {
			socksServer.logger.Debug("%d: stickyPort %v for %v failed!", requestId, string(stickyPort.DeviceID.Hex()), deviceName)
		}
	}

	// This is double checked in some cases, but it does not hurt since
	// ResolveDevice internally caches
	devices, err := socksServer.resolver.ResolveDevice(deviceName)
	if err != nil {
		// Errors are fatal such as 'deviceName' is not an address
		// or 'deviceName' is not on the allow list. In latter case caching
		// might delay the time until an allowance recognized
		return nil, err
	}

	if len(devices) == 0 {
		err = fmt.Errorf("%d: empty device list", requestId)
	}

	type candidate struct {
		deviceID util.Address
		serverID util.Address
	}

	nearestClient, _ := socksServer.clientManager.PeekNearestClients()

	candidates := make([]candidate, 0)
	for _, device := range devices {
		var deviceID Address
		deviceID, err = device.DeviceAddress()
		if err != nil {
			socksServer.logger.Error("%d: DeviceAddress() failed: %v", requestId, err)
			continue
		}

		if nearestClient != nil {
			candidates = append(candidates, candidate{deviceID, nearestClient.serverID})
		}

		for _, serverID := range device.GetServerIDs() {
			socksServer.logger.Debug("Found device %s on server %s", deviceID.HexString(), serverID.HexString())
			if nearestClient != nil && serverID == nearestClient.serverID {
				continue
			}
			candidates = append(candidates, candidate{deviceID, serverID})
		}
	}

	ports := make(chan *ConnectedPort, 1)
	var wg sync.WaitGroup
	maxConcurrency := make(chan struct{}, 4)

	for _, candidate := range candidates {
		wg.Add(1)
		go func(deviceID Address, serverID Address) {
			defer func() {
				wg.Done()
				<-maxConcurrency
			}()
			maxConcurrency <- struct{}{}

			var client *Client
			client, err = socksServer.GetServer(serverID)
			if err != nil {
				socksServer.logger.Error("%d: GetServer() failed: %v", requestId, err)
				return
			}

			var portOpen *edge.PortOpen
			portOpen, err = client.PortOpen(deviceID, port, portName, mode)
			if err != nil {
				return
			}
			if portOpen != nil && portOpen.Err != nil {
				err = portOpen.Err
				return
			}
			portOpen.PortNumber = port
			connPort := NewConnectedPort(requestId, portOpen.Ref, deviceID, client, port)
			select {
			case ports <- connPort:
			default:
				connPort.Shutdown()
			}
		}(candidate.deviceID, candidate.serverID)
	}

	go func() {
		wg.Wait()
		close(ports)
	}()

	connPort, ok := <-ports
	if ok && connPort != nil {
		return connPort, nil
	}

	for _, device := range devices {
		deviceID, _ := device.DeviceAddress()
		// If connecting to this device has failed clear the cached
		// device ticket before trying again
		socksServer.datapool.SetCacheDevice(deviceID, nil)
	}

	if retry > 0 {
		return socksServer.doConnectDevice(requestId, deviceName, port, protocol, mode, retry-1)
	}

	msg := fmt.Sprintf("doConnectDevice() for '%v' failed: %v with %v candidates", deviceName, err, len(candidates))
	socksServer.logger.Error(msg)
	if _, ok := err.(RPCError); ok {
		return nil, HttpError{404, DeviceError{err}}
	}
	return nil, HttpError{500, errors.New(msg)}
}

func (socksServer *Server) connectDevice(deviceName string, port int, protocol int, mode string, fn func(*ConnectedPort) (net.Conn, error)) (*ConnectedPort, error) {
	if protocol == config.TLSProtocol && strings.Contains(mode, "s") {
		protocol = config.TCPProtocol
	}

	requestID := rand.Int63()
	socksServer.logger.Debug("%d: New request for %v", requestID, deviceName)
	connPort, err := socksServer.doConnectDevice(requestID, deviceName, port, protocol, mode, 1)

	if err != nil {
		connPort.Shutdown()
		return nil, err
	}
	connPort.TargetDeviceName = deviceName
	deviceKey := connPort.GetDeviceKey()

	conn, err := fn(connPort)
	if err != nil || conn == nil {
		connPort.Shutdown()
		return nil, err
	}

	connPort.Conn = conn

	// if protocol == config.TLSProtocol || protocol == config.UDPProtocol {
	if protocol == config.TLSProtocol {
		err := connPort.UpgradeTLSClient()
		if err != nil {
			socksServer.logger.Error("Failed to tunnel openssl client: %v", err.Error())
			connPort.Shutdown()
			return nil, err
		}
		// connPort.Conn = NewLoggingConnRef("e2e", connPort.Conn, conn)
	}

	socksServer.datapool.SetPort(deviceKey, connPort)
	return connPort, nil
}

func writeSocksError(conn net.Conn, ver int, err byte) {
	socksVer := byte(ver)
	conn.Write([]byte{socksVer, err})
}

func writeSocksReturn(conn net.Conn, ver int, addr net.Addr, port int) {
	tcpAddr := addr.(*net.TCPAddr)
	if ver == 4 {
		conn.Write([]byte{4, 0x5A, byte(port>>8) & 0xff, byte(port & 0xff), 0, 0, 0, 1})
		return
	}

	rep := make([]byte, 256)
	rep[0] = byte(ver)
	rep[1] = socksRepSuccess // success
	rep[2] = 0x00            //RSV

	// IP
	var ip net.IP
	if tcpAddr.IP.Equal(tcpAddr.IP.To4()) {
		ip = tcpAddr.IP.To4()
		rep[3] = 0x01
	} else {
		ip = tcpAddr.IP.To16()
		rep[3] = 0x04
	}

	pindex := 4
	for _, b := range ip {
		rep[pindex] = b
		pindex++
	}
	rep[pindex] = byte((port >> 8) & 0xff)
	rep[pindex+1] = byte(port & 0xff)
	conn.Write(rep[0 : pindex+2])
}

func (socksServer *Server) pipeFallback(conn net.Conn, ver int, host string) {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, stackBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			socksServer.logger.Error("panic pipeFallback %s: %v\n%s", conn.RemoteAddr().String(), err, buf)
		}
	}()
	remoteConn, err := net.Dial("tcp", host)
	if err != nil {
		socksServer.logger.Error("Failed to connect host: %v", host)
		writeSocksError(conn, ver, socksRepNetworkUnreachable)
		return
	}
	defer remoteConn.Close()

	port := remoteConn.RemoteAddr().(*net.TCPAddr).Port
	writeSocksReturn(conn, ver, remoteConn.LocalAddr(), port)
	tunnel := NewTunnel(conn, remoteConn)
	tunnel.Copy()
}

func (socksServer *Server) pipeSocksThenClose(conn net.Conn, ver int, deviceID string, port int, mode string) {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, stackBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			socksServer.logger.Error("panic pipeSocksThenClose %s: %v\n%s", conn.RemoteAddr().String(), err, buf)
		}
	}()
	connPort, err := socksServer.connectDevice(deviceID, port, config.TLSProtocol, mode, func(connPort *ConnectedPort) (net.Conn, error) {
		writeSocksReturn(conn, ver, connPort.ClientLocalAddr(), port)
		return conn, nil
	})

	if err == nil {
		connPort.Copy()
		return
	}

	socksServer.logger.Error("Failed to connectDevice(%v): %v", deviceID, err.Error())
	writeSocksError(conn, ver, socksRepNetworkUnreachable)
}

func lookupFallbackHost(h string) (string, error) {
	var host, port string
	sh := strings.Split(h, ":")
	if len(sh) > 1 {
		host = sh[0]
		port = sh[1]
	} else {
		host = h
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("host not found")
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return "", fmt.Errorf("proxy to loopback is not allowed")
		}
	}
	return net.JoinHostPort(ips[0].String(), port), err
}

func parseHost(host string) (isWS bool, mode string, deviceID string, port int, err error) {
	mode = defaultMode
	strPort := "80"
	sh := strings.Split(host, ":")
	if len(sh) > 1 {
		host = sh[0]
		strPort = sh[1]
	}

	suffix, icann := publicsuffix.PublicSuffix(host)
	// check whether domain is managed by ICANN (usually top level domain)
	if !icann && suffix != "diode" {
		err = fmt.Errorf("domain is not top a level domain %s (%s)", host, suffix)
		return
	}

	var domain string
	domain, err = publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return
	}

	var sub string
	if len(host) > len(domain) {
		sub = host[0 : len(host)-len(domain)-1]
	} else {
		// apex domain
		// TODO: support different suffix and subdomain in BNS
		deviceID = domain[0 : len(domain)-len(suffix)-1]
		port, err = strconv.Atoi(strPort[:])
		return
	}

	idx := strings.LastIndex(sub, ".")
	if idx >= 0 {
		sub = sub[idx+1:]
	}

	isWS = (domain == "diode.ws")
	modeHostPort := subdomainPattern.FindStringSubmatch(sub)
	if len(modeHostPort) != 4 {
		err = fmt.Errorf("subdomain pattern not supported %v", sub)
		return
	}
	if len(modeHostPort[1]) > 0 {
		mode = modeHostPort[1]
		mode = mode[:len(mode)-1]
	}
	if domain == "diode.link" || domain == "diode" || domain == "diode.ws" {
		deviceID = modeHostPort[2]
	} else {
		deviceID = domain[0 : len(domain)-len(suffix)-1]
	}
	if len(modeHostPort[3]) > 0 {
		strPort = modeHostPort[3][1:]
	}

	port, err = strconv.Atoi(strPort[:])
	return
}

func (socksServer *Server) handleSocksConnection(conn net.Conn) {
	defer conn.Close()

	ver, host, err := handshake(conn)
	if err != nil {
		socksServer.logger.Error("Handshake failed %v", err)
		return
	}
	if host == "" {
		// UDP associate request returns an empty host
		return
	}
	if !isDiodeHost(host) {
		if socksServer.Config.Fallback == "localhost" {
			fallbackHost, err := lookupFallbackHost(host)
			if err != nil {
				socksServer.logger.Error("Target not a valid fallback ip %v %v", host, err)
				writeSocksError(conn, ver, socksRepRefused)
				return
			}
			socksServer.pipeFallback(conn, ver, fallbackHost)
		} else {
			socksServer.logger.Error("Target not a diode host %v", host)
			writeSocksError(conn, ver, socksRepRefused)
		}
		return
	}

	isWS, mode, deviceID, port, err := parseHost(host)
	if err != nil {
		socksServer.logger.Error("Failed to parse host %v", err)
		return
	}
	if !isWS {
		socksServer.pipeSocksThenClose(conn, ver, deviceID, port, mode)
	} else {
		socksServer.logger.Error("Couldn't forward socks connection")
		writeSocksError(conn, ver, socksRepNotAllowed)
	}
}

// Start socks server
func (socksServer *Server) Start() error {
	if socksServer.Closed() {
		return nil
	}

	socksServer.logger.Info("Start socks server %s", socksServer.Config.Addr)
	tcp, err := net.Listen("tcp", socksServer.Config.Addr)
	if err != nil {
		return err
	}
	socksServer.listener = tcp

	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				if socksServer.Closed() {
					return
				}
				// Check whether error is temporary
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					delayTime := 5 * time.Millisecond
					socksServer.logger.Warn("socks: Accept error %v, retry in %v", err, delayTime)
					time.Sleep(delayTime)
					continue
				}

				socksServer.logger.Error(err.Error())
				socksServer.Close()
				return
			}
			go socksServer.handleSocksConnection(conn)
		}
	}()

	udp, err := net.ListenPacket("udp", socksServer.Config.Addr)
	if err != nil {
		return err
	}
	socksServer.udpconn = udp

	go func() {
		buf := make([]byte, 2048)
		for {
			socksServer.handleUDP(buf)
		}
	}()

	return nil
}

func (socksServer *Server) handleUDP(packet []byte) {
	n, addr, err := socksServer.udpconn.ReadFrom(packet)
	if err != nil {
		socksServer.logger.Error("handleUDP error: %v", err)
		return
	}

	packet = packet[:n]

	// Compare reference at: https://tools.ietf.org/html/rfc1928
	// Chapter: 7. Procedure for UDP-based clients
	const (
		idRsv   = 0
		idFrag  = 2
		idType  = 3 // address type index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address
	)

	if len(packet) <= idDmLen {
		socksServer.logger.Error("handleUDP error: too short")
		return
	}

	if packet[idFrag] != 0 {
		socksServer.logger.Error("handleUDP error: UDP frag %v not yet implemented", packet[idFrag])
		return
	}

	// Read target address
	dmLen := -1
	switch packet[idType] {
	case typeIPv4:
		socksServer.logger.Error("handleUDP error: IPv4 not supported (only domain names)")
		return
	case typeIPv6:
		socksServer.logger.Error("handleUDP error: IPv6 not supported (only domain names)")
		return
	case typeDm: // domain name
		dmLen = int(packet[idDmLen])
	default:
		socksServer.logger.Error("handleUDP error: Non supported protocol %v", packet[idType])
		return
	}

	if len(packet) <= idDm0+dmLen+3 {
		socksServer.logger.Error("handleUDP error: too short #2")
		return
	}

	host := string(packet[idDm0 : idDm0+dmLen])
	portBytes := packet[idDm0+dmLen : idDm0+dmLen+2]
	port := int(binary.BigEndian.Uint16(portBytes))
	data := packet[idDm0+dmLen+2:]

	// Finished parsing packet
	isWS, mode, deviceID, _, err := parseHost(host)
	if err != nil {
		socksServer.logger.Error("handleUDP error: Failed to parse %s %v", host, err)
		return
	}

	if isWS {
		socksServer.logger.Error("handleUDP error: WS is not supported")
		return
	}

	socksServer.forwardUDP(socksServer.udpconn, addr, deviceID, port, mode, data)
}

func (socksServer *Server) forwardUDP(pconn net.PacketConn, raddr net.Addr, deviceName string, port int, mode string, data []byte) {
	connPort := socksServer.datapool.FindUDPPort(raddr)
	if connPort != nil {
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, uint32(len(data)))
		err := connPort.SendRemote(append(bs, data...))
		if err != nil {
			socksServer.logger.Error("forwardUDP error: PortSend(): %v", err)
		}
		return
	}

	// Preparing a response channel
	conn := NewUDPReplyConn(pconn, raddr)
	var err error
	connPort, err = socksServer.connectDevice(deviceName, port, config.UDPProtocol, mode, func(connPort2 *ConnectedPort) (net.Conn, error) {
		connPort2.UDPAddr = raddr
		return conn, nil
	})

	if err == nil {
		go func() {
			connPort.AwaitTLS()
			bs := make([]byte, 4)
			binary.LittleEndian.PutUint32(bs, uint32(len(data)))
			err := connPort.SendRemote(append(bs, data...))
			if err != nil {
				socksServer.logger.Error("forwardUDP error: PortSend(): %v", err)
			}
		}()
		go func() {
			connPort.Copy()
			conn.Close()
		}()
		return
	}
	if httpErr, ok := err.(HttpError); ok {
		socksServer.logger.Error("forwardUDP error: connectDevice(): %v", httpErr.Error())
	}
	conn.Close()
}

func (socksServer *Server) SetBinds(bindDefs []config.Bind) {
	newBinds := make([]Bind, 0)
	for _, def := range bindDefs {
		newBind := &Bind{def: def}
		for _, b := range socksServer.binds {
			if b.def == def {
				newBind.tcp = b.tcp
				newBind.udp = b.udp
				break
			}
		}
		newBinds = append(newBinds, *newBind)
		err := socksServer.startBind(newBind)
		if err != nil {
			socksServer.logger.Error(err.Error())
		}
	}

	for _, bind := range socksServer.binds {
		stop := true
		for _, b := range newBinds {
			if b == bind {
				stop = false
				break
			}
		}
		if stop {
			socksServer.stopBind(bind)
		}
	}
	socksServer.binds = newBinds
}

func (socksServer *Server) stopBind(bind Bind) {
	if bind.udp != nil {
		bind.udp.Close()
		bind.udp = nil
	}
	if bind.tcp != nil {
		bind.tcp.Close()
		bind.tcp = nil
	}
}

func (socksServer *Server) startBind(bind *Bind) error {
	var err error
	address := net.JoinHostPort(localhost, strconv.Itoa(bind.def.LocalPort))
	switch bind.def.Protocol {
	case config.UDPProtocol:
		if bind.udp != nil {
			return nil
		}
		bind.udp, err = net.ListenPacket("udp", address)
		if err != nil {
			return fmt.Errorf("StartBind() failed for: %+v because %v", bind.def, err)
		}

		packet := make([]byte, 2048)
		go func() {
			for {
				n, addr, err := bind.udp.ReadFrom(packet)
				if err != nil {
					socksServer.logger.Error("StartBind(udp): %v", err)
					continue
				}
				socksServer.forwardUDP(bind.udp, addr, bind.def.To, bind.def.ToPort, "rw", packet[:n])
			}
		}()

	case config.TLSProtocol:
		fallthrough
	case config.TCPProtocol:
		if bind.tcp != nil {
			return nil
		}
		bind.tcp, err = net.Listen("tcp", address)
		if err != nil {
			return fmt.Errorf("StartBind() failed for: %+v because %v", bind.def, err)
		}

		go func() {
			for {
				conn, err := bind.tcp.Accept()
				if err != nil {
					if socksServer.Closed() {
						return
					}
					// Check whether error is temporary
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						delayTime := 5 * time.Millisecond
						socksServer.logger.Warn("StartBind(): Accept error %v, retry in %v", err, delayTime)
						time.Sleep(delayTime)
						continue
					} else {
						socksServer.logger.Error(err.Error())
						bind.tcp.Close()
					}
					break
				}
				go socksServer.handleBind(conn, bind.def)
			}
		}()
	default:
		return fmt.Errorf("StartBind() Unknown protocol: %+v", bind.def)
	}
	return nil
}

func (socksServer *Server) handleBind(conn net.Conn, bind config.Bind) {
	connPort, err := socksServer.connectDevice(bind.To, bind.ToPort, bind.Protocol, "rw", func(*ConnectedPort) (net.Conn, error) {
		return conn, nil
	})

	if err != nil {
		socksServer.logger.Error("Failed to connectDevice(%v): %v", bind.To, err.Error())
	} else {
		connPort.Copy()
	}
}

// NewSocksServer generate socksserver struct
func NewSocksServer(socksCfg Config, clientManager *ClientManager) (*Server, error) {
	socksServer := &Server{
		logger:        config.AppConfig.Logger,
		clientManager: clientManager,
		datapool:      clientManager.GetPool(),
		resolver:      NewResolver(socksCfg, clientManager),
		closeCh:       make(chan struct{}),
		binds:         make([]Bind, 0),
	}
	if err := socksServer.SetConfig(socksCfg); err != nil {
		return nil, err
	}
	return socksServer, nil
}

// SetConfig update the config of socks server
func (socksServer *Server) SetConfig(config Config) error {
	if len(config.Fallback) > 0 && config.Fallback != "localhost" && config.Fallback != "false" {
		return fmt.Errorf("wrong parameters for socks fallback, valid values are 'localhost' or 'false'")
	}

	socksServer.Config = config
	return nil
}

// GetServer gets or creates a new SSL connection to the given server
func (socksServer *Server) GetServer(nodeID Address) (client *Client, err error) {
	return socksServer.clientManager.GetClientOrConnect(nodeID)
}

// Closed returns whether socks server had closed
func (socksServer *Server) Closed() bool {
	return isClosed(socksServer.closeCh)
}

// Close the socks server
func (socksServer *Server) Close() {
	socksServer.cd.Do(func() {
		close(socksServer.closeCh)
		if socksServer.listener != nil {
			socksServer.listener.Close()
			socksServer.listener = nil
		}
		for _, bind := range socksServer.binds {
			if bind.tcp != nil {
				bind.tcp.Close()
			}
			if bind.udp != nil {
				bind.udp.Close()
			}
		}
	})
}
