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
	"sync"
	"time"

	"regexp"
	"strconv"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/util"
)

var (
	Commands         = []string{"CONNECT", "BIND", "UDP ASSOCIATE"}
	AddrType         = []string{"", "IPv4", "", "Domain", "IPv6"}
	defaultPort      = "80"
	defaultMode      = "rw"
	domainPattern    = regexp.MustCompile(`^(.+)\.(diode|diode\.link|diode\.ws)(:[\d]+)?$`)
	subDomainpattern = regexp.MustCompile(`^([rws]{1,3}-)?(0x[A-Fa-f0-9]{40}|[A-Za-z0-9][A-Za-z0-9-]{5,30}[A-Za-z])(-[\d]+)?$`)
	bitstringPattern = regexp.MustCompile(`^[01]+$`)

	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support noauth method")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks only support connect command")

	prefix            = "0x"
	prefixBytes       = []byte(prefix)
	prefixLength      = len(prefix)
	upperPrefix       = "0X"
	upperPrefixBytes  = []byte(upperPrefix)
	upperPrefixLength = len(upperPrefix)
)

const (
	socksVer4                  = 0x04
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
	EnableProxy     bool
	FleetAddr       [20]byte
	Blacklists      map[string]bool
	Whitelists      map[string]bool
}

// Server is the only instances of the Socks Server
type Server struct {
	Client   *RPCClient
	pool     map[[20]byte]*RPCClient
	datapool *DataPool
	Config   *Config
	listener net.Listener
	wg       *sync.WaitGroup
	rm       sync.Mutex
	started  bool
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

	user, err := readString(conn, buf)
	if err != nil {
		return
	}
	if user != "" {
		// TODO: user authentication?
	}

	host, err := readString(conn, buf)
	if err != nil {
		return
	}

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
			return "", fmt.Errorf("String too long")
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
	if 2 == msgLen {               // handshake done, common case
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

	if buf[idCmd] != socksCmdConnect { //  only support CONNECT mode
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

	if 2 == reqLen {
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

func parseHost(host string) (isWS bool, deviceID string, mode string, port int, err error) {
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

func (socksServer *Server) connectDevice(deviceName string, port int, mode string) (*ConnectedDevice, *HttpError) {
	return socksServer.doConnectDevice(deviceName, port, mode, 1)
}

func (socksServer *Server) doConnectDevice(deviceName string, port int, mode string, retry int) (*ConnectedDevice, *HttpError) {
	// This is double checked in some cases, but it does not hurt since
	// checkAccess internally caches
	device, httpErr := socksServer.checkAccess(deviceName)
	if httpErr != nil {
		return nil, httpErr
	}

	// decode device id
	dDeviceID, err := device.DeviceAddress()
	deviceID := util.EncodeToString(dDeviceID[:])
	if err != nil {
		return nil, &HttpError{500, fmt.Errorf("DeviceAddress() failed: %v", err)}
	}

	client, err := socksServer.GetServer(device.ServerID)
	if err != nil {
		return nil, &HttpError{500, fmt.Errorf("GetServer() failed: %v", err)}
	}

	portOpen, err := client.PortOpen(deviceID, int(port), mode)
	if err != nil {
		// This might fail when a device has reconnected. Clearing the cache and trying once more
		socksServer.datapool.SetCache(deviceID, nil)

		if retry == 0 {
			return nil, &HttpError{500, fmt.Errorf("PortOpen() failed: %v", err)}
		}
		return socksServer.doConnectDevice(deviceName, port, mode, 0)
	}
	if portOpen != nil && portOpen.Err != nil {
		return nil, &HttpError{500, fmt.Errorf("PortOpen() failed(2): %v", portOpen.Err)}
	}

	return &ConnectedDevice{
		Ref:       portOpen.Ref,
		DeviceID:  deviceID,
		DDeviceID: dDeviceID[:],
		Client:    client,
	}, nil
}

func writeSocksError(conn net.Conn, ver int, err byte) {
	socksVer := byte(ver)
	conn.Write([]byte{socksVer, err})
}

func writeSocksReturn(conn net.Conn, ver int, tcpAddr *net.TCPAddr, port int) {
	if ver == 4 {
		conn.Write([]byte{4, 0x5A, byte(port>>8) & 0xff, byte(port & 0xff), 0, 0, 0, 1})
		return
	}

	rep := make([]byte, 256)
	rep[0] = byte(ver)
	rep[1] = socksRepSuccess // success
	rep[2] = 0x00            //RSV

	if tcpAddr.Zone == "" {
		if tcpAddr.IP.Equal(tcpAddr.IP.To4()) {
			tcpAddr.Zone = "ip4"
		} else {
			tcpAddr.Zone = "ip6"
		}
	}

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

}

func (socksServer *Server) pipeSocksThenClose(conn net.Conn, ver int, device *DeviceTicket, port int, mode string) {
	deviceID := device.GetDeviceID()
	socksServer.Client.Debug("connect remote %s mode %s...", deviceID, mode)
	clientIP := conn.RemoteAddr().String()
	connDevice, httpErr := socksServer.connectDevice(deviceID, port, mode)

	if httpErr != nil {
		socksServer.Client.Error("failed to connectDevice(): %v", httpErr.err)
		writeSocksError(conn, ver, socksRepNetworkUnreachable)
		return
	}
	deviceKey := connDevice.Client.GetDeviceKey(connDevice.Ref)

	connDevice.ClientID = clientIP
	connDevice.Conn = ConnectedConn{
		Conn: conn,
	}
	socksServer.datapool.SetDevice(deviceKey, connDevice)

	// send data or receive data from ref
	socksServer.Client.Debug("connect remote success @ %s %s %v %v", clientIP, deviceID, port, connDevice.Ref)
	tcpAddr := socksServer.Client.s.LocalAddr().(*net.TCPAddr)
	writeSocksReturn(conn, ver, tcpAddr, port)

	// write request data to device
	connDevice.copyToSSL()
	connDevice.Close()
	socksServer.Client.Debug("close socks connection @ %s %s %v %v", clientIP, deviceID, port, connDevice.Ref)
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

func (socksServer *Server) pipeSocksWSThenClose(conn net.Conn, ver int, device *DeviceTicket, port int, mode string) {
	socksServer.Client.Debug("connect remote %s mode %s...", socksServer.Config.ProxyServerAddr, mode)

	remoteConn, err := net.DialTimeout("tcp", socksServer.Config.ProxyServerAddr, time.Duration(time.Second*15))
	if err != nil {
		socksServer.Client.Error("failed to connect remote: %s", err.Error())
		writeSocksError(conn, ver, socksRepNetworkUnreachable)
		return
	}

	tcpAddr := remoteConn.LocalAddr().(*net.TCPAddr)
	writeSocksReturn(conn, ver, tcpAddr, port)

	// Copy local to remote
	go netCopy(conn, remoteConn)

	// Copy remote to local
	netCopy(remoteConn, conn)
}

func (socksServer *Server) checkAccess(deviceID string) (*DeviceTicket, *HttpError) {
	// Resolving DNS if needed
	if !util.IsHex([]byte(deviceID)) {
		dnsKey := fmt.Sprintf("dns:%s", deviceID)
		cachedDNS := socksServer.datapool.GetCacheDNS(dnsKey)
		if cachedDNS != nil {
			deviceID = util.EncodeToString(cachedDNS[:])
		} else {
			id, err := socksServer.Client.ResolveDNS(deviceID)
			if err != nil {
				return nil, &HttpError{500, err}
			}
			socksServer.datapool.SetCacheDNS(dnsKey, id[:])
			deviceID = util.EncodeToString(id[:])
		}
	}

	// Checking blacklist and whitelist
	if len(socksServer.Config.Blacklists) > 0 {
		if socksServer.Config.Blacklists[deviceID] {
			err := fmt.Errorf(
				"Device %v is in the black list",
				deviceID,
			)
			return nil, &HttpError{403, err}
		}
	} else {
		if len(socksServer.Config.Whitelists) > 0 {
			if !socksServer.Config.Whitelists[deviceID] {
				err := fmt.Errorf(
					"Device %v is not in the white list",
					deviceID,
				)
				return nil, &HttpError{403, err}
			}
		}
	}
	// decode device id
	bDeviceID, err := util.DecodeString(deviceID)
	var dDeviceID [20]byte
	copy(dDeviceID[:], bDeviceID)
	if err != nil {
		return nil, &HttpError{500, err}
	}
	// Calling GetObject to locate the device
	cachedDevice := socksServer.datapool.GetCache(deviceID)
	if cachedDevice != nil {
		return cachedDevice, nil
	}
	device, err := socksServer.Client.GetObject(dDeviceID)
	if err != nil {
		return nil, &HttpError{500, err}
	}
	if err = device.ResolveBlockHash(socksServer.Client); err != nil {
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
	socksServer.Client.s.pool.SetCache(deviceID, device)
	return device, nil
}

func (socksServer *Server) handleSocksConnection(conn net.Conn) {
	defer conn.Close()
	defer socksServer.wg.Done()
	ver, host, err := handShake(conn)
	if err != nil {
		socksServer.Client.Error("failed to handshake %v", err)
		return
	}
	isWS, deviceID, mode, port, err := parseHost(host)
	if err != nil {
		socksServer.Client.Error("failed to parseTarget %v", err)
		return
	}
	device, httpErr := socksServer.checkAccess(deviceID)
	if device == nil {
		socksServer.Client.Error("failed to checkAccess %v", httpErr.err)
		return
	}
	if !isWS {
		socksServer.pipeSocksThenClose(conn, ver, device, port, mode)
	} else if socksServer.Config.EnableProxy {
		socksServer.pipeSocksWSThenClose(conn, ver, device, port, mode)
	}
	return
}

// Start socks server
func (socksServer *Server) Start() error {
	socksServer.Client.Info("start socks server %s", socksServer.Config.Addr)
	ln, err := net.Listen("tcp", socksServer.Config.Addr)
	if err != nil {
		return err
	}
	socksServer.listener = ln
	socksServer.started = true

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			socksServer.Client.Debug("new socks client: %s", conn.RemoteAddr().String())
			socksServer.wg.Add(1)
			go socksServer.handleSocksConnection(conn)
		}
	}()
	return nil
}

// NewSocksServer generate socksserver struct
func (client *RPCClient) NewSocksServer(config *Config, pool *DataPool) *Server {
	return &Server{
		Config:   config,
		wg:       &sync.WaitGroup{},
		pool:     make(map[[20]byte]*RPCClient),
		datapool: pool,
		started:  false,
		Client:   client,
	}
}

// GetServer gets or creates a new SSL connectio to the given server
func (socksServer *Server) GetServer(nodeID [20]byte) (client *RPCClient, err error) {
	socksServer.rm.Lock()
	defer socksServer.rm.Unlock()
	serverID, err := socksServer.Client.s.GetServerID()
	if err != nil {
		socksServer.Client.Warn("failed to get server id: %v", err)
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
		socksServer.Client.Error("failed to getnode: %v", err)
		return
	}
	if !serverObj.ValidateSig(nodeID) {
		err = fmt.Errorf("Wrong signature in server object %+v", serverObj)
		return
	}
	host := fmt.Sprintf("%s:%d", string(serverObj.Host), serverObj.EdgePort)
	client, err = DoConnect(host, config.AppConfig, socksServer.datapool)
	if err != nil {
		err = fmt.Errorf("Couldn't connect to server '%+v' with error '%v'", serverObj, err)
		return
	}
	err = client.Greet()
	if err != nil {
		err = fmt.Errorf("Couldn't submitTicket to server with error '%v'", err)
		return
	}
	socksServer.pool[nodeID] = client
	// listen to signal
	go func(nodeID [20]byte) {
		for {
			select {
			case signal, ok := <-client.channel.signal:
				if !ok {
					return
				}
				switch signal {
				case CLOSED:
					delete(socksServer.pool, nodeID)
					break
				case RECONNECTED:
					break
				}
				break
			}
		}
	}(nodeID)
	return
}

// Started returns whether socks server had started
func (socksServer *Server) Started() bool {
	return socksServer.started
}

// Close the socks server
func (socksServer *Server) Close() {
	socksServer.listener.Close()
	socksServer.started = false
	// close all connections in the pool
	for serverID, rpcClient := range socksServer.pool {
		if rpcClient.Started() {
			rpcClient.Close()
		}
		delete(socksServer.pool, serverID)
	}
	// close all device connections in the pool
	// for deviceKey, device := range socksServer.datapool.devices {
	// 	device.Close()
	//  delete(socksServer.datapool.devices, deviceKey)
	// }
	// Should we close gracefully?
	socksServer.wg.Wait()
}
