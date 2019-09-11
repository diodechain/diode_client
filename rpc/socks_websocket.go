/*
 * Socks5 proxy server by golang
 * http://github.com/ring04h/s5.go
 *
 * reference: shadowsocks go local.go
 * https://github.com/shadowsocks/shadowsocks-go
 *
 * socks5 rfc: https://tools.ietf.org/html/rfc1928
 *
 * TODO: another way for websocket server
 */

package rpc

import (
	"bytes"

	// "fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

var (
	diodeWSPattern = regexp.MustCompile(`([rws]{1,3}.)?([\w]+).diode.ws(:[\d]+)?`)
)

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

func (socksServer *SocksServer) pipeSocksWSWhenClose(conn net.Conn, deviceID string, port uint16, mode string) {
	// deviceID = strings.ToLower(deviceID)
	if socksServer.Config.Verbose {
		log.Println("Connect remote ", socksServer.Config.WSServerAddr, " mode: ", mode, "...")
	}

	rep := make([]byte, 256)
	rep[0] = socksVer5
	remoteConn, err := net.DialTimeout("tcp", socksServer.Config.WSServerAddr, time.Duration(time.Second*15))
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
		pindex += 1
	}
	rep[pindex] = byte((port >> 8) & 0xff)
	rep[pindex+1] = byte(port & 0xff)
	conn.Write(rep[0 : pindex+2])

	// Copy local to remote
	go netCopy(conn, remoteConn)

	// Copy remote to local
	netCopy(remoteConn, conn)
}

// TODO: check origin
func checkOrigin(r *http.Request) bool {
	// origin := r.Header["Origin"]
	// if len(origin) == 0 {
	// 	return true
	// }
	// u, err := url.Parse(origin[0])
	// if err != nil {
	// 	return false
	// }
	return true
}

// should we use net/url to parse request? schema://..........
// u, err := url.Parse(host)
// if err != nil {
// 	log.Print(err)
// 	http.Error(w, http.StatusText(500), 500)
// 	return
// }
func (socksServer *SocksServer) pipeWebsocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:    readBufferSize,
		WriteBufferSize:   writeBufferSize,
		CheckOrigin:       checkOrigin,
		EnableCompression: true,
	}
	host := r.Host
	if len(host) == 0 {
		log.Print("Host was wrong")
		http.Error(w, http.StatusText(500), 500)
		return
	}
	var err error
	deviceID := ""
	mode := ""
	port := 0
	parsedHost := diodeWSPattern.FindStringSubmatch(host)
	switch len(parsedHost) {
	case 4:
		deviceID = parsedHost[2]
		if len(parsedHost[1]) > 0 {
			mode = string(parsedHost[1][:len(parsedHost[1])-1])
		} else {
			mode = defaultMode
		}
		if len(parsedHost[3]) <= 0 {
			break
		}
		port, err = strconv.Atoi(string(parsedHost[3][1:len(parsedHost[3])]))
		if err != nil {
			log.Print("Cannot parse port from string to int")
			http.Error(w, http.StatusText(500), 500)
			return
		}
		break
	case 3:
		if len(parsedHost[2]) > 6 {
			break
		}
		deviceID = parsedHost[1]
		mode = defaultMode
		if len(parsedHost[3]) <= 0 {
			break
		}
		port, err = strconv.Atoi(string(parsedHost[2][1:len(parsedHost[2])]))
		if err != nil {
			log.Print("Cannot parse port from string to int")
			http.Error(w, http.StatusText(500), 500)
			return
		}
		break
	default:
		break
	}
	if port == 0 {
		log.Print("Cannot find port from string to int")
		http.Error(w, http.StatusText(500), 500)
		return
	}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		http.Error(w, http.StatusText(500), 500)
		return
	}
	// set connectedConn.Conn to conn?!
	// conn := c.UnderlyingConn()
	defer c.Close()

	// deviceID = strings.ToLower(deviceID)
	clientIP := c.RemoteAddr().String()
	connDevice := devices.GetDevice(clientIP)
	// check device id
	if connDevice.Ref == 0 {
		// decode device id
		dDeviceID, err := DecodeString(deviceID)
		if err != nil {
			log.Println(err)
			return
		}
		// call getobject rpc
		_, err = socksServer.s.GetObject(false, dDeviceID)
		if err != nil {
			log.Println(err)
			return
		}
		deviceObj := <-DeviceObjChan
		if deviceObj.Err != nil {
			log.Println("couldn't find device object")
			return
		}
		// if !deviceObj.ValidateSig() {
		// 	log.Println("wrong signature in device object")
		// 	return
		// }
		// get server id
		// serverID, err := socksServer.s.GetServerID()
		// if err != nil {
		// 	log.Println(err)
		// 	return
		// }
		// if !bytes.Equal(deviceObj.ServerID, serverID) {
		// 	// device not exist in the node, change ssl connection?!
		// 	log.Println("device wasn't existed, please change node")
		// 	return
		// }
		// check access
		fleetAddr := socksServer.Config.FleetAddr
		isDeviceWhitelisted, err := socksServer.s.IsDeviceWhitelisted(false, fleetAddr, dDeviceID)
		if err != nil {
			log.Println(err)
		}
		if !isDeviceWhitelisted {
			log.Println("Device wan not white listed")
			return
		}
		if !bytes.Equal(prefixBytes, []byte(deviceID[0:prefixLength])) {
			deviceID = prefix + deviceID
		}
		_, err = socksServer.s.PortOpen(false, deviceID, int(port), mode)
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("Port open sent")
		// wait for response
		portOpen := <-PortOpenChan
		// failed to open port
		if portOpen.Err != nil {
			log.Printf("Failed to open port: %s", string(portOpen.Err.Raw))
			return
		}
		connDevice.Ref = portOpen.Ref
		connDevice.ClientID = clientIP
		connDevice.DeviceID = deviceID
		connDevice.DDeviceID = dDeviceID
		connDevice.Conn.IsWS = true
		connDevice.Conn.WSConn = c
		devices.SetDevice(clientIP, connDevice)
		connDevice.copyToSSL(socksServer.s)
	}
}

// StartWS start websocket server
func (socksServer *SocksServer) StartWS() error {
	// start websocket server
	log.Printf("Start websocket server %s\n", socksServer.Config.WSServerAddr)
	http.HandleFunc("/", socksServer.pipeWebsocket)
	go func() {
		log.Println(http.ListenAndServe(socksServer.Config.WSServerAddr, nil))
	}()
	return nil
}
