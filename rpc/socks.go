// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

package rpc

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"regexp"
	"strconv"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/go-cache"
)

var (
	Commands    = []string{"CONNECT", "BIND", "UDP ASSOCIATE"}
	AddrType    = []string{"", "IPv4", "", "Domain", "IPv6"}
	defaultPort = 80
	defaultMode = "rw"
	pattern     = regexp.MustCompile(`^([rws]{1,3}[-_])?([\w]+)([-_][\d]+)?\.(diode|diode\.link|diode\.ws)(\:[\d]+)?$`)
	devices     = &Devices{
		connectedDevice: make(map[string]*ConnectedDevice),
	}
	bitstringPattern = regexp.MustCompile(`^[01]+$`)

	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support noauth method")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks only support connect command")
	errReqURL        = errors.New("request url not supported")

	prefix            = "0x"
	prefixBytes       = []byte(prefix)
	prefixLength      = len(prefix)
	upperPrefix       = "0X"
	upperPrefixBytes  = []byte(upperPrefix)
	upperPrefixLength = len(upperPrefix)
)

const (
	socksVer5                  = 0x05
	socksCmdConnect            = 0x01
	socksRepSuccess            = 0x00
	socksRepServerFailed       = 0x01
	socksRepNotAllowed         = 0x02
	socksRepNetworkUnreachable = 0x03
	socksRepHostUnreachable    = 0x04
	socksRepRefused            = 0x05
	socksRepTTLExpired         = 0x06
	// 00[“portsend”,”data”]
	// fixed: 17 bytes
	// see: https://www.igvita.com/2013/10/24/optimizing-tls-record-size-and-buffering-latency/
	readBufferSize  = 8000
	writeBufferSize = 8000
)

// Config is Socks Server configuration
type Config struct {
	Addr            string
	ProxyServerAddr string
	Verbose         bool
	EnableProxy     bool
	FleetAddr       [20]byte
}

// Server is the only instances of the Socks Server
type Server struct {
	s        *SSL
	pool     map[[20]byte]*SSL
	Config   *Config
	listener net.Listener
	wg       *sync.WaitGroup
}

func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)

	buf := make([]byte, 258)

	var n int

	// make sure we get the method field
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}

	if buf[idVer] != socksVer5 {
		return errVer
	}

	nmethod := int(buf[idNmethod]) //  client support auth mode
	msgLen := nmethod + 2          //  auth msg length
	if n == msgLen {               // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errAuthExtraData
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
	return
}

// TODO: mapping human redable string to port.
func parseHost(host string) (isWS bool, deviceID string, mode string, port int, err error) {
	mode = defaultMode
	port = defaultPort

	parsedHost := pattern.FindStringSubmatch(host)
	switch len(parsedHost) {
	case 6:
		deviceID = parsedHost[2]
		if len(parsedHost[1]) > 0 {
			mode = string(parsedHost[1][:len(parsedHost[1])-1])
		}
		if parsedHost[4] == "diode.ws" {
			isWS = true
		}
		if len(parsedHost[3]) > 1 {
			port, err = strconv.Atoi(string(parsedHost[3][1:len(parsedHost[3])]))
			if err != nil {
				log.Print("Cannot parse port from string to int")
			}
		}
		break
	default:
		err = errReqURL
	}
	return
}

func parseTarget(conn net.Conn) (host string, port int, mode string, deviceID string, isWS bool, err error) {
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
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int

	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
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
		log.Println("Unknown Command: ", buf[idCmd])
	}

	if buf[idCmd] != socksCmdConnect { //  only support CONNECT mode
		err = errCmd
		return
	}

	// read target address
	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm: // domain name
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// port = binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	isWS, deviceID, mode, port, err = parseHost(host)
	return
}

func (socksServer *Server) connectDevice(deviceID string, port int, mode string) (*ConnectedDevice, *HttpError) {
	// This is double checked in some cases, but it does not hurt since
	// checkAccess internally caches
	device, httpErr := socksServer.checkAccess(deviceID)
	if httpErr != nil {
		return nil, httpErr
	}

	// decode device id
	dDeviceID, err := device.DeviceAddress()
	if err != nil {
		return nil, &HttpError{500, fmt.Errorf("DeviceAdrress() failed: %v", err)}
	}

	server, err := socksServer.GetServer(device.ServerID)
	if err != nil {
		return nil, &HttpError{500, fmt.Errorf("GetServer() failed: %v", err)}
	}

	portOpen, err := server.PortOpen(deviceID, int(port), mode)
	if err != nil {
		return nil, &HttpError{500, fmt.Errorf("PortOpen() failed: %v", err)}
	}
	// failed to open port
	if portOpen != nil && portOpen.Err != nil {
		return nil, &HttpError{500, fmt.Errorf("PortOpen() failed(2): %v", portOpen.Err)}
	}
	return &ConnectedDevice{
		Ref:       portOpen.Ref,
		DeviceID:  deviceID,
		DDeviceID: dDeviceID[:],
		Server:    server,
	}, nil
}

func (socksServer *Server) pipeSocksThenClose(conn net.Conn, device *DeviceTicket, port int, mode string) {
	deviceID := device.GetDeviceID()
	if socksServer.Config.Verbose {
		log.Println("Connect remote ", deviceID, " mode: ", mode, "...")
	}
	rep := make([]byte, 256)
	rep[0] = socksVer5
	clientIP := conn.RemoteAddr().String()
	connDevice := devices.GetDevice(clientIP)
	var httpErr *HttpError

	// check device id
	if connDevice == nil {
		connDevice, httpErr = socksServer.connectDevice(deviceID, port, mode)

		if httpErr != nil {
			log.Printf("connectDevice() failed: %v", httpErr.err)
			rep[1] = socksRepNetworkUnreachable
			conn.Write(rep[:])
			return
		}

		connDevice.ClientID = clientIP
		connDevice.Conn = ConnectedConn{
			Conn: conn,
		}
		devices.SetDevice(clientIP, connDevice)
	}

	// send data or receive data from ref
	if socksServer.Config.Verbose {
		log.Println("Connect remote success @ ", clientIP, deviceID, port)
	}
	tcpAddr := socksServer.s.LocalAddr().(*net.TCPAddr)
	if tcpAddr.Zone == "" {
		if tcpAddr.IP.Equal(tcpAddr.IP.To4()) {
			tcpAddr.Zone = "ip4"
		} else {
			tcpAddr.Zone = "ip6"
		}
	}

	rep[1] = socksRepSuccess // success
	rep[2] = 0x00            //RSV

	// IP
	if tcpAddr.Zone == "ip6" {
		rep[3] = 0x04
	} else {
		rep[3] = 0x01
	}

	var ip net.IP
	if "ip6" == tcpAddr.Zone {
		ip = tcpAddr.IP.To16()
	} else {
		ip = tcpAddr.IP.To4()
	}
	pindex := 4
	for _, b := range ip {
		rep[pindex] = b
		pindex++
	}
	rep[pindex] = byte((port >> 8) & 0xff)
	rep[pindex+1] = byte(port & 0xff)
	conn.Write(rep[0 : pindex+2])

	// write request data to device
	connDevice.copyToSSL()

	log.Println("Close socks connection")
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
			output.Write(buf[:count])
		}
	}
	return
}

func (socksServer *Server) pipeSocksWSThenClose(conn net.Conn, device *DeviceTicket, port int, mode string) {
	if socksServer.Config.Verbose {
		log.Println("Connect remote ", socksServer.Config.ProxyServerAddr, " mode: ", mode, "...")
	}

	rep := make([]byte, 256)
	rep[0] = socksVer5
	remoteConn, err := net.DialTimeout("tcp", socksServer.Config.ProxyServerAddr, time.Duration(time.Second*15))
	if err != nil {
		log.Println("Connect remote :", err)
		rep[1] = socksRepNetworkUnreachable
		conn.Write(rep[:])
		return
	}

	tcpAddr := remoteConn.LocalAddr().(*net.TCPAddr)
	if tcpAddr.Zone == "" {
		if tcpAddr.IP.Equal(tcpAddr.IP.To4()) {
			tcpAddr.Zone = "ip4"
		} else {
			tcpAddr.Zone = "ip6"
		}
	}

	if socksServer.Config.Verbose {
		log.Println("Connect remote success @", tcpAddr.String())
	}

	rep[1] = socksRepSuccess // success
	rep[2] = 0x00            //RSV

	// IP
	if tcpAddr.Zone == "ip6" {
		rep[3] = 0x04
	} else {
		rep[3] = 0x01
	}

	var ip net.IP
	if "ip6" == tcpAddr.Zone {
		ip = tcpAddr.IP.To16()
	} else {
		ip = tcpAddr.IP.To4()
	}
	pindex := 4
	for _, b := range ip {
		rep[pindex] = b
		pindex++
	}
	rep[pindex] = byte((port >> 8) & 0xff)
	rep[pindex+1] = byte(port & 0xff)
	conn.Write(rep[0 : pindex+2])

	// Copy local to remote
	go netCopy(conn, remoteConn)

	// Copy remote to local
	netCopy(remoteConn, conn)
}

func (socksServer *Server) checkAccess(deviceID string) (*DeviceTicket, *HttpError) {
	mc := socksServer.s.MemoryCache()
	// decode device id
	bDeviceID, err := util.DecodeString(deviceID)
	var dDeviceID [20]byte
	copy(dDeviceID[:], bDeviceID)
	if err != nil {
		return nil, &HttpError{500, err}
	}
	// Calling GetObject to locate the device
	var device *DeviceTicket
	cacheObj, hit := mc.Get(deviceID)
	if !hit {
		device, err = socksServer.s.GetObject(dDeviceID)
		if err != nil {
			log.Println(err)
			return nil, &HttpError{500, err}
		}
		if err = device.ResolveBlockHash(socksServer.s); err != nil {
			err = fmt.Errorf("Failed to resolve() %v", err)
			return nil, &HttpError{500, err}
		}
		if device.Err != nil {
			err = fmt.Errorf("This device is offline - Or you entered the wrong id? %v", device.Err)
			return nil, &HttpError{404, err}
		}
		if !device.ValidateSigs(dDeviceID) {
			err = fmt.Errorf("Wrong signature in device object")
			return nil, &HttpError{500, err}
		}
		mc.Set(deviceID, device, cache.DefaultExpiration)
	} else {
		device = cacheObj.(*DeviceTicket)
	}

	// Checking access
	addr, err := socksServer.s.GetClientAddress()
	if err != nil {
		return nil, &HttpError{500, err}
	}
	isAccessWhitelisted, hit := mc.Get(deviceID + "accesswhitelist")
	if !hit {
		isAccessWhitelisted, err = socksServer.s.IsAccessWhitelisted(device.FleetAddr, dDeviceID, addr)
		if err != nil {
			return nil, &HttpError{500, err}
		}
		mc.Set(deviceID+"accesswhitelist", isAccessWhitelisted, cache.DefaultExpiration)
	}
	if !isAccessWhitelisted.(bool) {
		err = fmt.Errorf(
			"Gateway %v is not on the access list for this device %v of fleet %v",
			util.EncodeToString(addr[:]), deviceID, util.EncodeToString(device.FleetAddr[:]),
		)
		return nil, &HttpError{403, err}
	}
	return device, nil
}

func (socksServer *Server) handleSocksConnection(conn net.Conn) {
	defer conn.Close()
	defer socksServer.wg.Done()
	if err := handShake(conn); err != nil {
		log.Println("handShake() failed:", err)
		return
	}
	_, port, mode, deviceID, isWS, err := parseTarget(conn)
	if err != nil {
		log.Println("parseTarget() failed: ", err)
		return
	}
	device, httpErr := socksServer.checkAccess(deviceID)
	if device == nil {
		log.Println("checkAccess() failed: ", httpErr.err)
		return
	}
	if !isWS {
		socksServer.pipeSocksThenClose(conn, device, port, mode)
	} else if socksServer.Config.EnableProxy {
		socksServer.pipeSocksWSThenClose(conn, device, port, mode)
	}
	return
}

// Start socks server
func (socksServer *Server) Start() error {
	log.Printf("Start socks server %s\n", socksServer.Config.Addr)
	ln, err := net.Listen("tcp", socksServer.Config.Addr)
	if err != nil {
		return err
	}
	socksServer.listener = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if socksServer.Config.Verbose {
				log.Println("New socks client:", conn.RemoteAddr())
			}
			socksServer.wg.Add(1)
			go socksServer.handleSocksConnection(conn)
		}
	}()
	return nil
}

// NewSocksServer generate socksserver struct
func (s *SSL) NewSocksServer(config *Config) *Server {
	return &Server{
		s:      s,
		Config: config,
		wg:     &sync.WaitGroup{},
		pool:   make(map[[20]byte]*SSL),
	}
}

// GetServer gets or creates a new SSL connectio to the given server
func (socksServer *Server) GetServer(nodeID [20]byte) (server *SSL, err error) {
	serverID, err := socksServer.s.GetServerID()
	if err != nil {
		panic("can't get my own server id")
	}

	if nodeID == serverID {
		server = socksServer.s
		return
	}
	server = socksServer.pool[nodeID]
	if server != nil {
		return
	}
	serverObj, err := socksServer.s.GetNode(nodeID)
	if err != nil {
		log.Println(err)
		return
	}
	if !serverObj.ValidateSig(nodeID) {
		err = fmt.Errorf("Wrong signature in server object %+v", serverObj)
		return
	}
	host := fmt.Sprintf("%s:%d", string(serverObj.Host), serverObj.EdgePort)
	server, err = DoConnect(host, config.AppConfig)
	if err != nil {
		err = fmt.Errorf("Couldn't connect to server '%+v' with error '%v'", serverObj, err)
		return
	}
	socksServer.pool[nodeID] = server
	return
}

// Close the socks server
func (socksServer *Server) Close() {
	log.Println("Socks server exit")
	socksServer.listener.Close()
	socksServer.wg.Wait()
}
