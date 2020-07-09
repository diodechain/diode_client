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
	"strings"
	"sync"
	"time"

	"regexp"
	"strconv"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
)

var (
	defaultMode      = "rw"
	domainPattern    = regexp.MustCompile(`^(.+)\.(diode|diode\.link|diode\.ws)(:[\d]+)?$`)
	subDomainpattern = regexp.MustCompile(`^([rws]{1,3}-)?(0x[A-Fa-f0-9]{40}|[A-Za-z0-9][A-Za-z0-9-]{5,30}?)(-[^0][\d]+)?$`)

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
	Client   *RPCClient
	pool     map[Address]*RPCClient
	datapool *DataPool
	Config   *Config
	listener net.Listener
	udpconn  net.PacketConn
	wg       *sync.WaitGroup
	rm       sync.Mutex
	started  bool
	binds    []Bind
}

type DeviceError struct {
	err error
}

func (deviceError DeviceError) Error() string {
	return fmt.Sprintf("This device is offline - Or you entered the wrong id? %v", deviceError.err)
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
		idIP0   = 4 // ip addres start index
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
	subDomainPort := domainPattern.FindStringSubmatch(host)
	return len(subDomainPort) == 4
}

func parseHost(host string) (isWS bool, mode string, deviceID string, port int, err error) {
	mode = defaultMode
	strPort := ":80"

	subDomainPort := domainPattern.FindStringSubmatch(host)
	var sub, domain string
	if len(subDomainPort) != 4 {
		err = fmt.Errorf("domain pattern not supported %v", host)
		return
	}

	sub = subDomainPort[1]
	domain = subDomainPort[2]
	if len(subDomainPort[3]) > 0 {
		strPort = subDomainPort[3]
	}

	isWS = domain == "diode.ws"
	modeHostPort := subDomainpattern.FindStringSubmatch(sub)
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

func (socksServer *Server) checkAccess(deviceName string) (*edge.DeviceTicket, error) {
	// Resolving DNS if needed
	var err error
	var deviceID Address
	if !util.IsHex([]byte(deviceName)) {
		dnsKey := fmt.Sprintf("dns:%s", deviceName)
		var ok bool
		deviceID, ok = socksServer.datapool.GetCacheDNS(dnsKey)
		if !ok {
			deviceID, err = socksServer.Client.ResolveBNS(deviceName)
			if err != nil {
				return nil, HttpError{404, err}
			}
			socksServer.datapool.SetCacheDNS(dnsKey, deviceID)
		}
	} else {
		deviceID, err = util.DecodeAddress(deviceName)
		if err != nil {
			err = fmt.Errorf("DeviceAddress '%s' is not an address: %v", deviceName, err)
			return nil, HttpError{400, err}
		}
	}

	// Checking blocklist and allowlist
	if len(socksServer.Config.Blocklists) > 0 {
		if socksServer.Config.Blocklists[deviceID] {
			err := fmt.Errorf("device %x is in the block list", deviceName)
			return nil, HttpError{403, err}
		}
	} else {
		if len(socksServer.Config.Allowlists) > 0 {
			if !socksServer.Config.Allowlists[deviceID] {
				err := fmt.Errorf("device %x is not in the allow list", deviceName)
				return nil, HttpError{403, err}
			}
		}
	}
	// Calling GetObject to locate the device
	cachedDevice := socksServer.datapool.GetCacheDevice(deviceID)
	if cachedDevice != nil {
		return cachedDevice, nil
	}
	device, err := socksServer.Client.GetObject(deviceID)
	if err != nil {
		return nil, HttpError{404, err}
	}
	if device.BlockHash, err = socksServer.Client.ResolveBlockHash(device.BlockNumber); err != nil {
		err = fmt.Errorf("failed to resolve() %v", err)
		return nil, HttpError{500, err}
	}
	if device.Err != nil {
		return nil, HttpError{404, DeviceError{err}}
	}
	if !device.ValidateDeviceSig(deviceID) {
		err = fmt.Errorf("wrong device signature in device object")
		return nil, HttpError{500, err}
	}
	if !device.ValidateServerSig() {
		err = fmt.Errorf("wrong server signature in device object")
		return nil, HttpError{500, err}
	}
	socksServer.datapool.SetCacheDevice(deviceID, device)
	return device, nil
}

func (socksServer *Server) doConnectDevice(deviceName string, port int, protocol int, mode string, retry int) (*ConnectedDevice, error) {
	// This is double checked in some cases, but it does not hurt since
	// checkAccess internally caches
	device, httpErr := socksServer.checkAccess(deviceName)
	if httpErr != nil {
		return nil, httpErr
	}

	// decode device id
	deviceID, err := device.DeviceAddress()
	if err != nil {
		return nil, HttpError{500, fmt.Errorf("DeviceAddress() failed: %v", err)}
	}

	client, err := socksServer.GetServer(device.ServerID)
	if err != nil {
		return nil, HttpError{500, fmt.Errorf("GetServer() failed: %v", err)}
	}

	var portName string
	if protocol == config.UDPProtocol {
		portName = fmt.Sprintf("udp:%d", port)
	} else if protocol == config.TLSProtocol {
		portName = fmt.Sprintf("tls:%d", port)
	} else {
		portName = fmt.Sprintf("tcp:%d", port)
	}

	portOpen, err := client.PortOpen(deviceID, portName, mode)
	if err != nil {
		// This might fail when a device has reconnected. Clearing the cache and trying once more
		socksServer.datapool.SetCacheDevice(deviceID, nil)

		if retry == 0 {
			if _, ok := err.(RPCError); ok {
				return nil, HttpError{404, DeviceError{err}}
			}
			return nil, HttpError{500, fmt.Errorf("PortOpen() failed: %v", err)}
		}
		return socksServer.doConnectDevice(deviceName, port, protocol, mode, retry-1)
	}
	if portOpen != nil && portOpen.Err != nil {
		return nil, HttpError{500, fmt.Errorf("PortOpen() failed(2): %v", portOpen.Err)}
	}
	return &ConnectedDevice{
		Ref:      portOpen.Ref,
		DeviceID: deviceID,
		Client:   client,
	}, nil
}

func (socksServer *Server) connectDeviceAndLoop(deviceName string, port int, protocol int, mode string, fn func(*ConnectedDevice) (*DeviceConn, error)) error {
	if protocol == config.TLSProtocol && strings.Contains(mode, "s") {
		fmt.Printf("Using no encryption for shared connection %v\n", mode)
		protocol = config.TCPProtocol
	}

	connDevice, err := socksServer.doConnectDevice(deviceName, port, protocol, mode, 1)
	if err != nil {
		return err
	}
	defer connDevice.Close()
	deviceKey := connDevice.Client.GetDeviceKey(connDevice.Ref)

	conn, err := fn(connDevice)
	if err != nil || conn == nil {
		return err
	}

	connDevice.Conn = *conn
	connDevice.ClientID = conn.Conn.RemoteAddr().String()

	if protocol == config.TLSProtocol {
		e2eServer := socksServer.Client.NewE2EServer(conn.Conn, connDevice.DeviceID)
		err := e2eServer.InternalConnect()
		if err != nil {
			socksServer.Client.Error("Failed to e2e.ListenAndServe(): %v", err.Error())
			return err
		}

		connDevice.Conn = DeviceConn{
			Conn:      e2eServer.localConn,
			e2eServer: &e2eServer,
		}
	}

	socksServer.datapool.SetDevice(deviceKey, connDevice)

	// write request data to device
	connDevice.copyLoop()
	return nil
}

//////////// EEEEEEEEND

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
	remote, err := net.Dial("tcp", host)
	if err != nil {
		socksServer.Client.Error("Failed to connect host: %v", host)
		writeSocksError(conn, ver, socksRepNetworkUnreachable)
		return
	}

	port := remote.RemoteAddr().(*net.TCPAddr).Port

	socksServer.Client.Debug("host connect success @ %s", host)
	writeSocksReturn(conn, ver, socksServer.Client.s.LocalAddr(), port)

	// Copy local to remote
	go netCopy(conn, remote)

	// Copy remote to local
	netCopy(remote, conn)
	remote.Close()
}

func netCopy(input, output net.Conn) (err error) {
	buf := make([]byte, readBufferSize)
	for {
		count, err := input.Read(buf)
		if err != nil {
			if err == io.EOF && count > 0 {
				output.Write(buf[:count])
			}
			break
		}
		if count > 0 {
			_, err := output.Write(buf[:count])
			if err != nil {
				break
			}
		}
	}
	return
}

func (socksServer *Server) pipeSocksThenClose(conn net.Conn, ver int, device *edge.DeviceTicket, port int, mode string) {
	// bind request to remote tls server
	deviceID := device.GetDeviceID()
	socksServer.Client.Debug("Connect remote %s mode %s e2e...", deviceID, mode)

	clientIP := conn.RemoteAddr().String()
	err := socksServer.connectDeviceAndLoop(deviceID, port, config.TLSProtocol, mode, func(*ConnectedDevice) (*DeviceConn, error) {
		// send data or receive data from ref
		socksServer.Client.Debug("Connect remote success @ %s %s %v", clientIP, deviceID, port)
		writeSocksReturn(conn, ver, socksServer.Client.s.LocalAddr(), port)
		return &DeviceConn{Conn: conn}, nil
	})

	if err != nil {
		socksServer.Client.Error("Failed to connectDevice(%v): %v", deviceID, err.Error())
		writeSocksError(conn, ver, socksRepNetworkUnreachable)
	}
}

func (socksServer *Server) pipeSocksWSThenClose(conn net.Conn, ver int, device *edge.DeviceTicket, port int, mode string) {
	remoteConn, err := net.DialTimeout("tcp", socksServer.Config.ProxyServerAddr, time.Duration(time.Second*15))
	if err != nil {
		socksServer.Client.Error("Failed to connect remote: %s", err.Error())
		writeSocksError(conn, ver, socksRepNetworkUnreachable)
		return
	}

	writeSocksReturn(conn, ver, remoteConn.LocalAddr(), port)

	go netCopy(conn, remoteConn)
	netCopy(remoteConn, conn)
}

func (socksServer *Server) handleSocksConnection(conn net.Conn) {
	defer conn.Close()
	defer socksServer.wg.Done()
	ver, host, err := handShake(conn)
	if err != nil {
		socksServer.Client.Error("Dailed to handshake %v", err)
		return
	}
	if host == "" {
		// UDP associate request returns an empty host
		return
	}
	if !isDiodeHost(host) {
		if socksServer.Config.Fallback == "localhost" {
			socksServer.pipeFallback(conn, ver, host)
		} else {
			socksServer.Client.Error("Target not a diode host %v", host)
			writeSocksError(conn, ver, socksRepRefused)
		}
		return
	}

	isWS, mode, deviceID, port, err := parseHost(host)
	if err != nil {
		socksServer.Client.Error("Failed to parse host %v", err)
		return
	}
	device, httpErr := socksServer.checkAccess(deviceID)
	if device == nil {
		socksServer.Client.Error("Failed to checkAccess %v", httpErr.Error())
		writeSocksError(conn, ver, socksRepNotAllowed)
		return
	}
	if !isWS {
		socksServer.pipeSocksThenClose(conn, ver, device, port, mode)
	} else if socksServer.Config.EnableProxy {
		socksServer.pipeSocksWSThenClose(conn, ver, device, port, mode)
	} else {
		socksServer.Client.Error("Proxy not enabled, can't forward websocket connection")
		writeSocksError(conn, ver, socksRepNotAllowed)
	}
}

// Start socks server
func (socksServer *Server) Start() error {
	if socksServer.started {
		return nil
	}

	socksServer.Client.Info("Start socks server %s", socksServer.Config.Addr)
	tcp, err := net.Listen("tcp", socksServer.Config.Addr)
	if err != nil {
		return err
	}
	socksServer.started = true
	socksServer.listener = tcp

	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				// Accept will return op close error/syscall.EINVAL
				if !isOpError(err) {
					socksServer.Client.Error(err.Error())
				}
				break
			}
			socksServer.Client.Debug("New socks client: %s", conn.RemoteAddr().String())
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
		socksServer.Client.Error("handleUDP error: %v", err)
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
		socksServer.Client.Error("handleUDP error: too short")
		return
	}

	if packet[idFrag] != 0 {
		socksServer.Client.Error("handleUDP error: UDP frag %v not yet implemented", packet[idFrag])
		return
	}

	// Read target address
	dmLen := -1
	switch packet[idType] {
	case typeIPv4:
		socksServer.Client.Error("handleUDP error: IPv4 not supported (only domain names)")
		return
	case typeIPv6:
		socksServer.Client.Error("handleUDP error: IPv6 not supported (only domain names)")
		return
	case typeDm: // domain name
		dmLen = int(packet[idDmLen])
	default:
		socksServer.Client.Error("handleUDP error: Non supported protocol %v", packet[idType])
		return
	}

	if len(packet) <= idDm0+dmLen+3 {
		socksServer.Client.Error("handleUDP error: too short #2")
		return
	}

	host := string(packet[idDm0 : idDm0+dmLen])
	portBytes := packet[idDm0+dmLen : idDm0+dmLen+2]
	port := int(binary.BigEndian.Uint16(portBytes))
	data := packet[idDm0+dmLen+2:]

	// Finished parsing packet
	isWS, mode, deviceID, _, err := parseHost(host)
	if err != nil {
		socksServer.Client.Error("handleUDP error: Failed to parse %s %v", host, err)
		return
	}

	if isWS {
		socksServer.Client.Error("handleUDP error: WS is not supported")
		return
	}

	socksServer.forwardUDP(addr, deviceID, port, mode, data)
}

func (socksServer *Server) forwardUDP(addr net.Addr, deviceName string, port int, mode string, data []byte) {
	connDevice := socksServer.datapool.FindDevice(addr.String())
	if connDevice != nil {
		err := connDevice.Client.PortSend(connDevice.Ref, data)
		if err != nil {
			socksServer.Client.Error("forwardUDP error: PortSend(): %v", err)
		}
		return
	}

	// Preparing a response channel
	conn, err := net.DialUDP("udp", nil, addr.(*net.UDPAddr))
	if err != nil {
		socksServer.Client.Error("forwardUDP error: DialUDP %v", err)
		return
	}

	err = socksServer.connectDeviceAndLoop(deviceName, port, config.UDPProtocol, mode, func(connDevice2 *ConnectedDevice) (*DeviceConn, error) {
		err := connDevice2.Client.PortSend(connDevice2.Ref, data)
		if err != nil {
			socksServer.Client.Error("forwardUDP error: PortSend(): %v", err)
		}
		return &DeviceConn{Conn: conn}, err
	})

	if err != nil {
		if httpErr, ok := err.(HttpError); ok {
			socksServer.Client.Error("forwardUDP error: connectDevice(): %v", httpErr.Error())
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
				newBind = &b
				break
			}
		}
		newBinds = append(newBinds, *newBind)
		err := socksServer.startBind(newBind)
		if err != nil {
			socksServer.Client.Error(err.Error())
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
			socksServer.stopBind(&bind)
		}
	}
	socksServer.binds = newBinds
}

func (socksServer *Server) stopBind(bind *Bind) {
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
	socksServer.Client.Info("Starting port bind %s", address)
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
					socksServer.Client.Error("StartBind(udp): %v", err)
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
					// Accept will return op close error/syscall.EINVAL
					if !isOpError(err) {
						socksServer.Client.Error(err.Error())
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
	err := socksServer.connectDeviceAndLoop(bind.To, bind.ToPort, bind.Protocol, "rw", func(*ConnectedDevice) (*DeviceConn, error) {
		return &DeviceConn{Conn: conn}, nil
	})

	if err != nil {
		socksServer.Client.Error("Failed to connectDevice(%v): %v", bind.To, err.Error())
	}
}

// NewSocksServer generate socksserver struct
func (client *RPCClient) NewSocksServer(pool *DataPool) *Server {
	return &Server{
		Config:   &Config{},
		wg:       &sync.WaitGroup{},
		pool:     make(map[Address]*RPCClient),
		datapool: pool,
		started:  false,
		Client:   client,
		binds:    make([]Bind, 0),
	}
}

func (socksServer *Server) SetConfig(config *Config) {
	socksServer.rm.Lock()
	defer socksServer.rm.Unlock()
	socksServer.Config = config
}

// GetServer gets or creates a new SSL connection to the given server
func (socksServer *Server) GetServer(nodeID Address) (client *RPCClient, err error) {
	socksServer.rm.Lock()
	defer socksServer.rm.Unlock()
	serverID, err := socksServer.Client.s.GetServerID()
	if err != nil {
		socksServer.Client.Warn("Failed to get server id: %v", err)
		return
	}

	if nodeID == serverID {
		client = socksServer.Client
		if client.s.Closed() {
			socksServer.Client.Error("GetServer(): own connection is closed %v", client.s)
		} else {
			return
		}
	}
	client, ok := socksServer.pool[nodeID]
	if ok {
		if client != nil && !client.Started() {
			socksServer.Client.Error("GetServer(): found closed server connection in pool %v", client.s)
			delete(socksServer.pool, nodeID)
			client = nil
		}
		if client != nil {
			return
		}
	}
	serverObj, err := socksServer.Client.GetNode(nodeID)
	if err != nil {
		socksServer.Client.Error("Failed to getnode: %v", err)
		return
	}
	if util.PubkeyToAddress(serverObj.ServerPubKey) != nodeID {
		err = fmt.Errorf("wrong signature in server object %+v", serverObj)
		return
	}
	// host := fmt.Sprintf("%s:%d", string(serverObj.Host), serverObj.EdgePort)
	// TODO: remove this
	host := fmt.Sprintf("%s:%d", string(serverObj.Host), 41046)
	client, err = DoConnect(host, config.AppConfig, socksServer.datapool)
	if err != nil {
		err = fmt.Errorf("couldn't connect to server '%+v' with error '%v'", serverObj, err)
		return
	}
	err = client.Greet()
	if err != nil {
		err = fmt.Errorf("couldn't submitTicket to server with error '%v'", err)
		return
	}
	socksServer.pool[nodeID] = client
	// listen to signal
	go func(nodeID Address) {
		for {
			// TODO check this logic
			signal, ok := <-client.signal
			if !ok {
				return
			}
			switch signal {
			case CLOSED:
				socksServer.setRPCClient(nodeID, nil)
				return
			case RECONNECTED:
				continue
			}
		}
	}(nodeID)
	return
}

func (socksServer *Server) setRPCClient(nodeID util.Address, rpcClient *RPCClient) {
	socksServer.rm.Lock()
	defer socksServer.rm.Unlock()
	if rpcClient == nil {
		delete(socksServer.pool, nodeID)
		return
	}
	socksServer.pool[nodeID] = rpcClient
}

// Started returns whether socks server had started
func (socksServer *Server) Started() bool {
	socksServer.rm.Lock()
	defer socksServer.rm.Unlock()
	return socksServer.started
}

// Close the socks server
func (socksServer *Server) Close() {
	socksServer.rm.Lock()
	if !socksServer.started {
		socksServer.rm.Unlock()
		return
	}
	socksServer.started = false
	socksServer.rm.Unlock()
	if socksServer.listener != nil {
		socksServer.listener.Close()
		socksServer.listener = nil
	}
	// if socksServer.udpconn != nil {
	// 	socksServer.udpconn.Close()
	// 	socksServer.udpconn = nil
	// }
	// close all connections in the pool
	for serverID, rpcClient := range socksServer.pool {
		rpcClient.Close()
		socksServer.setRPCClient(serverID, nil)
	}
	for _, bind := range socksServer.binds {
		if bind.tcp != nil {
			bind.tcp.Close()
		}
		if bind.udp != nil {
			bind.udp.Close()
		}
	}
}
