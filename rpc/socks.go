// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

package rpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
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
	datapool *DataPool
	Config   Config
	logger   *config.Logger
	listener net.Listener
	udpconn  net.PacketConn
	wg       *sync.WaitGroup
	rm       sync.Mutex
	closeCh  chan struct{}
	binds    []Bind
	cd       sync.Once
}

type DeviceError struct {
	err error
}

func (deviceError DeviceError) Error() string {
	return fmt.Sprintf("This device is offline - %v", deviceError.err)
}

func handShake(conn net.Conn) (version int, url string, err error) {
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

func (socksServer *Server) parseHost(host string) (isWS bool, mode string, deviceID string, port int, err error) {
	mode = defaultMode
	strPort := ":80"

	subdomainPort := domainPattern.FindStringSubmatch(host)
	var sub, domain string
	if len(subdomainPort) != 4 {
		err = fmt.Errorf("domain pattern not supported %v", host)
		return
	}

	sub = subdomainPort[1]
	domain = subdomainPort[2]
	if len(subdomainPort[3]) > 0 {
		strPort = subdomainPort[3]
	}

	isWS = domain == "diode.ws"
	modeHostPort := subdomainPattern.FindStringSubmatch(sub)
	if len(modeHostPort) != 4 {
		err = fmt.Errorf("subdomain pattern not supported %v", sub)
		return
	}
	if len(modeHostPort[1]) > 0 {
		mode = modeHostPort[1]
		mode = mode[:len(mode)-1]
	}
	deviceID = modeHostPort[2]
	if len(modeHostPort[3]) > 0 {
		strPort = modeHostPort[3]
	}

	port, err = strconv.Atoi(strPort[1:])
	return
}

func (socksServer *Server) checkAccess(deviceName string) (ret []*edge.DeviceTicket, err error) {
	// Resolving BNS if needed
	var deviceIDs []Address
	client := socksServer.datapool.GetNearestClient()
	if client == nil {
		return nil, HttpError{404, err}
	}
	if !util.IsHex([]byte(deviceName)) {
		bnsKey := fmt.Sprintf("bns:%s", deviceName)
		var ok bool
		deviceIDs, ok = socksServer.datapool.GetCacheBNS(bnsKey)
		if !ok {
			deviceIDs, err = client.ResolveBNS(deviceName)
			if err != nil {
				return nil, HttpError{404, err}
			}
			socksServer.datapool.SetCacheBNS(bnsKey, deviceIDs)
		}
	} else {
		id, err := util.DecodeAddress(deviceName)
		if err != nil {
			err = fmt.Errorf("DeviceAddress '%s' is not an address: %v", deviceName, err)
			return nil, HttpError{400, err}
		}
		deviceIDs = make([]util.Address, 1)
		deviceIDs[0] = id
	}

	deviceIDs = util.Filter(deviceIDs, func(addr Address) bool {
		// Checking blocklist and allowlist
		if len(socksServer.Config.Blocklists) > 0 {
			if socksServer.Config.Blocklists[addr] {
				return false
			}
		} else {
			if len(socksServer.Config.Allowlists) > 0 {
				if !socksServer.Config.Allowlists[addr] {
					return false
				}
			}
		}
		return true
	})

	if len(deviceIDs) == 0 {
		err := fmt.Errorf("device %x is not allowed", deviceName)
		return nil, HttpError{403, err}
	}

	// Finding accessible deviceIDs
	for _, deviceID := range deviceIDs {

		// Calling GetObject to locate the device
		cachedDevice := socksServer.datapool.GetCacheDevice(deviceID)
		if cachedDevice != nil {
			ret = append(ret, cachedDevice)
			continue
		}

		device, err := client.GetObject(deviceID)
		if err != nil {
			continue
			// return nil, HttpError{404, err}
		}
		if device.BlockHash, err = client.ResolveBlockHash(device.BlockNumber); err != nil {
			client.Error("failed to resolve() %v", err)
			continue
		}
		if device.Err != nil {
			continue
		}
		if !device.ValidateDeviceSig(deviceID) {
			client.Error("wrong device signature in device object")
			continue
		}
		if !device.ValidateServerSig() {
			client.Error("wrong server signature in device object")
			continue
		}
		socksServer.datapool.SetCacheDevice(deviceID, device)
		ret = append(ret, device)
	}
	return ret, nil
}

func (socksServer *Server) doConnectDevice(deviceName string, port int, protocol int, mode string, retry int) (*ConnectedPort, error) {
	// This is double checked in some cases, but it does not hurt since
	// checkAccess internally caches
	devices, err := socksServer.checkAccess(deviceName)
	if err != nil {
		return nil, err
	}
	for _, device := range devices {
		// decode device id
		var deviceID Address
		deviceID, err = device.DeviceAddress()
		if err != nil {
			socksServer.logger.Error("DeviceAddress() failed: %v", err)
			continue
		}

		var client *RPCClient
		client, err = socksServer.GetServer(device.ServerID)
		if err != nil {
			socksServer.logger.Error("GetServer() failed: %v", err)
			continue

		}

		var portName string
		if protocol == config.UDPProtocol {
			portName = fmt.Sprintf("udp:%d", port)
		} else if protocol == config.TLSProtocol {
			portName = fmt.Sprintf("tls:%d", port)
		} else {
			portName = fmt.Sprintf("tcp:%d", port)
		}

		var portOpen *edge.PortOpen
		portOpen, err = client.PortOpen(deviceID, portName, mode)
		if err != nil {
			// This might fail when a device has reconnected. Clearing the cache and trying once more
			socksServer.logger.Debug("PortOpen() failed: %v", err)
			socksServer.datapool.SetCacheDevice(deviceID, nil)
			continue
		}
		if portOpen != nil && portOpen.Err != nil {
			socksServer.logger.Debug("PortOpen() failed(2): %v", portOpen.Err)
			continue
		}
		return NewConnectedPort(portOpen.Ref, deviceID, client), nil
	}

	if retry > 0 {
		return socksServer.doConnectDevice(deviceName, port, protocol, mode, retry-1)
	}

	socksServer.logger.Error("doConnectDevice() failed: %v", err)
	if _, ok := err.(RPCError); ok {
		return nil, HttpError{404, DeviceError{err}}
	}
	return nil, HttpError{500, fmt.Errorf("doConnectDevice() failed: %v", err)}
}

func (socksServer *Server) connectDeviceAndLoop(deviceName string, port int, protocol int, mode string, fn func(*ConnectedPort) (net.Conn, error)) error {
	if protocol == config.TLSProtocol && strings.Contains(mode, "s") {
		socksServer.logger.Debug("Using no encryption for shared connection %v", mode)
		protocol = config.TCPProtocol
	}

	connPort, err := socksServer.doConnectDevice(deviceName, port, protocol, mode, 1)
	if err != nil {
		return err
	}
	deviceKey := connPort.GetDeviceKey()

	conn, err := fn(connPort)
	if err != nil || conn == nil {
		return err
	}

	connPort.Conn = conn
	connPort.ClientID = conn.RemoteAddr().String()

	if protocol == config.TLSProtocol {
		err := connPort.UpgradeTLSClient()
		if err != nil {
			socksServer.logger.Error("Failed to tunnel openssl client: %v", err.Error())
			return err
		}
	}

	socksServer.datapool.SetPort(deviceKey, connPort)

	// rpc client might be different with socks server
	connPort.Copy()
	return nil
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

	socksServer.logger.Debug("host connect success @ %s", host)
	writeSocksReturn(conn, ver, remoteConn.LocalAddr(), port)

	tunnel := NewTunnel(conn, remoteConn)
	tunnel.Copy()
}

func (socksServer *Server) pipeSocksThenClose(conn net.Conn, ver int, devices []*edge.DeviceTicket, port int, mode string) {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, stackBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			socksServer.logger.Error("panic pipeSocksThenClose %s: %v\n%s", conn.RemoteAddr().String(), err, buf)
		}
	}()
	// bind request to remote tls server
	var deviceID string
	var err error

	for _, device := range devices {
		deviceID = device.GetDeviceID()
		socksServer.logger.Debug("Connect remote %s mode %s e2e...", deviceID, mode)

		clientIP := conn.RemoteAddr().String()
		protocol := config.TCPProtocol
		if config.AppConfig.EnableEdgeE2E {
			protocol = config.TLSProtocol
		}
		err = socksServer.connectDeviceAndLoop(deviceID, port, protocol, mode, func(connPort *ConnectedPort) (net.Conn, error) {
			// send data or receive data from ref
			socksServer.logger.Debug("Connect remote success @ %s %s %v", clientIP, deviceID, port)
			writeSocksReturn(conn, ver, connPort.ClientLocalAddr(), port)
			return conn, nil
		})

		if err == nil {
			return
		}
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

func (socksServer *Server) handleSocksConnection(conn net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, stackBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			socksServer.logger.Error("panic handleSocksConnection %s: %v\n%s", conn.RemoteAddr().String(), err, buf)
		}
		conn.Close()
		socksServer.wg.Done()
	}()
	ver, host, err := handShake(conn)
	if err != nil {
		socksServer.logger.Error("Dialed to handshake %v", err)
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

	isWS, mode, deviceID, port, err := socksServer.parseHost(host)
	if err != nil {
		socksServer.logger.Error("Failed to parse host %v", err)
		return
	}
	devices, httpErr := socksServer.checkAccess(deviceID)
	if len(devices) == 0 {
		socksServer.logger.Error("Failed to checkAccess %v", httpErr.Error())
		writeSocksError(conn, ver, socksRepNotAllowed)
		return
	}
	if !isWS {
		socksServer.pipeSocksThenClose(conn, ver, devices, port, mode)
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
				// See: https://golang.org/src/net/net.go?h=Temporary
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					delayTime := 5 * time.Millisecond
					socksServer.logger.Warn(fmt.Sprintf("socks: Accept error %v, retry in %v", err, delayTime))
					time.Sleep(delayTime)
					continue
				} else {
					socksServer.logger.Error(err.Error())
					socksServer.Close()
				}
				break
			}
			socksServer.logger.Debug("New socks client: %s", conn.RemoteAddr().String())
			socksServer.wg.Add(1)
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
	isWS, mode, deviceID, _, err := socksServer.parseHost(host)
	if err != nil {
		socksServer.logger.Error("handleUDP error: Failed to parse %s %v", host, err)
		return
	}

	if isWS {
		socksServer.logger.Error("handleUDP error: WS is not supported")
		return
	}

	socksServer.forwardUDP(addr, deviceID, port, mode, data)
}

func (socksServer *Server) forwardUDP(addr net.Addr, deviceName string, port int, mode string, data []byte) {
	connPort := socksServer.datapool.FindPort(addr.String())
	if connPort != nil {
		err := connPort.SendRemote(data)
		if err != nil {
			socksServer.logger.Error("forwardUDP error: PortSend(): %v", err)
		}
		return
	}

	// Preparing a response channel
	conn, err := net.DialUDP("udp", nil, addr.(*net.UDPAddr))
	if err != nil {
		socksServer.logger.Error("forwardUDP error: DialUDP %v", err)
		return
	}

	err = socksServer.connectDeviceAndLoop(deviceName, port, config.UDPProtocol, mode, func(connPort2 *ConnectedPort) (net.Conn, error) {
		err := connPort2.SendRemote(data)
		if err != nil {
			socksServer.logger.Error("forwardUDP error: PortSend(): %v", err)
		}
		return conn, err
	})

	if err != nil {
		if httpErr, ok := err.(HttpError); ok {
			socksServer.logger.Error("forwardUDP error: connectDevice(): %v", httpErr.Error())
		}
		conn.Close()
		return
	}
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
	socksServer.logger.Debug("Starting port bind %s", address)
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
				socksServer.forwardUDP(addr, bind.def.To, bind.def.ToPort, "rw", packet[:n])
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
					// See: https://golang.org/src/net/net.go?h=Temporary
					if ne, ok := err.(net.Error); ok && ne.Temporary() {
						delayTime := 5 * time.Millisecond
						socksServer.logger.Warn(fmt.Sprintf("StartBind(): Accept error %v, retry in %v", err, delayTime))
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
	err := socksServer.connectDeviceAndLoop(bind.To, bind.ToPort, bind.Protocol, "rw", func(*ConnectedPort) (net.Conn, error) {
		return conn, nil
	})

	if err != nil {
		socksServer.logger.Error("Failed to connectDevice(%v): %v", bind.To, err.Error())
	}
}

// NewSocksServer generate socksserver struct
func NewSocksServer(pool *DataPool) *Server {
	return &Server{
		Config:   Config{},
		logger:   config.AppConfig.Logger,
		wg:       &sync.WaitGroup{},
		datapool: pool,
		closeCh:  make(chan struct{}),
		binds:    make([]Bind, 0),
	}
}

func (socksServer *Server) SetConfig(config Config) {
	socksServer.rm.Lock()
	defer socksServer.rm.Unlock()
	socksServer.Config = config
}

// GetServer gets or creates a new SSL connection to the given server
func (socksServer *Server) GetServer(nodeID Address) (client *RPCClient, err error) {
	socksServer.rm.Lock()
	defer socksServer.rm.Unlock()
	client = socksServer.datapool.GetClient(nodeID)
	if client != nil {
		if client.Closed() {
			socksServer.logger.Warn("GetServer(): found closed server connection in pool %s", nodeID.HexString())
			socksServer.datapool.SetClient(nodeID, nil)
			client = nil
		}
		// should just return?
		if client != nil {
			return
		}
	}
	fclient := socksServer.datapool.GetNearestClient()
	if fclient == nil {
		socksServer.logger.Warn("GetServer(): couldn't found nearest server in pool %s", nodeID.HexString())
	}
	serverObj, err := fclient.GetNode(nodeID)
	if err != nil {
		fclient.Error("GetServer(): failed to getnode %v", err)
		return
	}
	if util.PubkeyToAddress(serverObj.ServerPubKey) != nodeID {
		err = fmt.Errorf("GetServer(): wrong signature in server object %+v", serverObj)
		return
	}
	// hardcode port to 41046
	host := net.JoinHostPort(string(serverObj.Host), "41046")
	client, err = DoConnect(host, config.AppConfig, socksServer.datapool)
	if err != nil {
		err = fmt.Errorf("couldn't connect to server '%+v' with error '%v'", serverObj, err)
		return
	}
	isValid, err := client.ValidateNetwork()
	if err != nil {
		err = fmt.Errorf("couldn't validate server with error '%v'", err)
		return
	}
	if !isValid {
		err = fmt.Errorf("network is not valid")
		return
	}
	err = client.Greet()
	if err != nil {
		err = fmt.Errorf("couldn't submitTicket to server with error '%v'", err)
		return
	}
	socksServer.datapool.SetClient(nodeID, client)
	client.SetCloseCB(func() {
		socksServer.datapool.SetClient(nodeID, nil)
	})
	return
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
