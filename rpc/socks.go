/*
 * Socks5 proxy server by golang
 * http://github.com/ring04h/s5.go
 *
 * reference: shadowsocks go local.go
 * https://github.com/shadowsocks/shadowsocks-go
 *
 * socks5 rfc: https://tools.ietf.org/html/rfc1928
 */

package rpc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"

	"regexp"
	"strconv"

	"github.com/diodechain/go-cache"
)

var (
	Commands     = []string{"CONNECT", "BIND", "UDP ASSOCIATE"}
	AddrType     = []string{"", "IPv4", "", "Domain", "IPv6"}
	defaultMode  = "rw"
	diodePattern = regexp.MustCompile(`([rws]{1,3}.)?([\w]+).diode(.ws)?(:[\d]+)?`)
	// map[clientip]ref from socks
	// map[portOpen.DeviceId + portOpen.Ref]ref from device
	// connectedDevice = make(map[string]ConnectedDevice)
	// connectedConns  = make(map[int64]net.Conn)
	devices = &Devices{
		connectedDevice: make(map[string]ConnectedDevice),
	}
	bitstringPattern = regexp.MustCompile(`^[01]+$`)

	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support noauth method")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks only support connect command")
	errReqUrl        = errors.New("request url not supported")
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
	readBufferSize  = 6000
	writeBufferSize = 6000
)

type SocksConfig struct {
	Addr         string
	WSServerAddr string
	Verbose      bool
	EnableWS     bool
	FleetAddr    []byte
}

// type SocksWSConfig struct {
// 	Addr         string
// 	WSServerAddr string
// 	Verbose      bool
// }

type SocksServer struct {
	s        *SSL
	Config   *SocksConfig
	listener net.Listener
}

func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)

	buf := make([]byte, 258)

	var n int

	// make sure we get the nmethod field
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

func parseTarget(conn net.Conn) (host string, port uint16, mode string, deviceID string, isWS bool, err error) {
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
		log.Println("Unknown Command", buf[idCmd])
	}
	log.Println("Command:", Commands[buf[idCmd]-1])

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
	port = binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	parsedHost := diodePattern.FindStringSubmatch(host)

	switch len(parsedHost) {
	case 5:
		deviceID = parsedHost[2]
		if len(parsedHost[1]) > 0 {
			mode = string(parsedHost[1][:len(parsedHost[1])-1])
		} else {
			mode = defaultMode
		}
		if len(parsedHost[3]) > 0 {
			isWS = true
		}
		break
	default:
		err = errReqUrl
		return
	}
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return
}

func (socksServer *SocksServer) pipeSocksWhenClose(conn net.Conn, deviceID string, port uint16, mode string) {
	// deviceID = strings.ToLower(deviceID)
	if socksServer.Config.Verbose {
		log.Println("Connect remote ", deviceID, " mode: ", mode, "...")
	}
	rep := make([]byte, 256)
	rep[0] = socksVer5
	clientIP := conn.RemoteAddr().String()
	connDevice := devices.GetDevice(clientIP)
	mc := socksServer.s.MemoryCache()
	// check device id
	if connDevice.Ref == 0 {
		// decode device id
		log.Println(deviceID)
		dDeviceID, err := DecodeString(deviceID)
		if err != nil {
			log.Println(err)
			rep[1] = socksRepServerFailed
			conn.Write(rep[:])
			return
		}
		// call getobject rpc
		// mc.Set("foo", "bar", cache.DefaultExpiration)
		_, hit := mc.Get(deviceID)
		if !hit {
			_, err = socksServer.s.GetObject(false, dDeviceID)
			if err != nil {
				log.Println(err)
				rep[1] = socksRepServerFailed
				conn.Write(rep[:])
				return
			}
			deviceObj := <-DeviceObjChan
			if deviceObj.Err != nil {
				log.Println("couldn't find device object")
				rep[1] = socksRepHostUnreachable
				conn.Write(rep[:])
				return
			}
			if !deviceObj.ValidateSig() {
				log.Println("wrong signature in device object")
				rep[1] = socksRepServerFailed
				conn.Write(rep[:])
				return
			}
			mc.Set(deviceID, true, cache.DefaultExpiration)
		}
		// check access
		fleetAddr := socksServer.Config.FleetAddr
		isDeviceWhitelisted, hit := mc.Get(deviceID + "devicewhitelist")
		if !hit {
			isDeviceWhitelisted, _ = socksServer.s.IsDeviceWhitelisted(false, fleetAddr, dDeviceID)
			mc.Set(deviceID+"devicewhitelist", isDeviceWhitelisted, cache.DefaultExpiration)
		}
		if !isDeviceWhitelisted.(bool) {
			log.Println("Device wasn't not white listed")
			conn.Write(rep[:])
			return
		}
		clientAddr, err := socksServer.s.GetClientAddress()
		if err != nil {
			log.Println(err)
			rep[1] = socksRepServerFailed
			conn.Write(rep[:])
			return
		}
		isAccessWhitelisted, hit := mc.Get(deviceID + "accesswhitelist")
		if !hit {
			isAccessWhitelisted, _ = socksServer.s.IsAccessWhitelisted(false, fleetAddr, dDeviceID, clientAddr)
			mc.Set(deviceID+"accesswhitelist", isDeviceWhitelisted, cache.DefaultExpiration)
		}
		if !isAccessWhitelisted.(bool) {
			log.Println("Access was not whitelisted")
			conn.Write(rep[:])
			return
		}
		if !bytes.Equal(prefixBytes, []byte(deviceID[0:prefixLength])) {
			deviceID = prefix + deviceID
		}
		_, err = socksServer.s.PortOpen(false, deviceID, int(port), mode)
		if err != nil {
			log.Println(err)
			rep[1] = socksRepNetworkUnreachable
			conn.Write(rep[:])
			return
		}
		log.Println("Port open sent")
		// wait for response
		portOpen := <-PortOpenChan
		// failed to open port
		if portOpen.Err != nil {
			log.Printf("Failed to open port: %s", string(portOpen.Err.Raw))
			rep[1] = socksRepNetworkUnreachable
			conn.Write(rep[:])
			return
		}
		connDevice.Ref = portOpen.Ref
		connDevice.ClientID = clientIP
		connDevice.DeviceID = deviceID
		connDevice.DDeviceID = dDeviceID
		connDevice.Conn.Conn = conn
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
		pindex += 1
	}
	rep[pindex] = byte((port >> 8) & 0xff)
	rep[pindex+1] = byte(port & 0xff)
	conn.Write(rep[0 : pindex+2])

	// write request data to device
	connDevice.copyToSSL(socksServer.s)

	log.Println("Close socks connection")
}

func (socksServer *SocksServer) handleSocksConnection(conn net.Conn) {
	defer conn.Close()
	if err := handShake(conn); err != nil {
		log.Println("socks handshake:", err)
		return
	}
	_, port, mode, deviceID, isWS, err := parseTarget(conn)
	if err != nil {
		log.Println("socks consult transfer mode or parse target: ", err)
		return
	}
	if !isWS {
		socksServer.pipeSocksWhenClose(conn, deviceID, port, mode)
	} else {
		if socksServer.Config.EnableWS {
			socksServer.pipeSocksWSWhenClose(conn, deviceID, port, mode)
		}
	}
}

// Start socks server
func (socksServer *SocksServer) Start() error {
	log.Printf("Start socks server %s \n", socksServer.Config.Addr)
	ln, err := net.Listen("tcp", socksServer.Config.Addr)
	if err != nil {
		return err
	}
	socksServer.listener = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// log.Println(err)
				return
			}
			if socksServer.Config.Verbose {
				log.Println("new client:", conn.RemoteAddr())
			}
			go socksServer.handleSocksConnection(conn)
		}
	}()
	return nil
}

// NewSocksServer generate socksserver struct
func (s *SSL) NewSocksServer(config *SocksConfig) *SocksServer {
	return &SocksServer{
		s:      s,
		Config: config,
	}
}

// Close the socks server
func (socksServer *SocksServer) Close() {
	log.Println("Socks server exit")
	socksServer.listener.Close()
}
