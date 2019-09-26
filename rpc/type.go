package rpc

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"log"

	"github.com/gorilla/websocket"

	// "io"
	"net"
	"poc-client/crypto"
	"poc-client/crypto/secp256k1"

	// "poc-client/crypto/sha3"
	// "poc-client/util"
	"sync"

	bert "github.com/exosite/gobert"
	// "strings"
)

var ResponseType = []byte("response")
var ErrorType = []byte("error")

var PortOpenType = []byte("portopen")
var PortSendType = []byte("portsend")
var PortCloseType = []byte("portclose")
var GetObjectType = []byte("getobject")
var GetNodeType = []byte("getnode")
var GetAccountValueType = []byte("getaccountvalue")
var GetAccountRootsType = []byte("getaccountroots")
var GetStateRootsType = []byte("getstateroots")
var GoodbyeType = []byte("goodbye")

var NullData = []byte("null")

var ResponseChan = make(chan *Response, 1024)
var RequestChan = make(chan *Request, 1024)
var PortOpenChan = make(chan *PortOpen)
var PortCloseChan = make(chan *PortClose)
var DeviceObjChan = make(chan *DeviceObj)
var ServerObjChan = make(chan *ServerObj)
var ErrorChan = make(chan *Error)
var AccountValueChan = make(chan *AccountValue)
var AccountRootsChan = make(chan *AccountRoots)
var StateRootsChan = make(chan *StateRoots)

var curlyBracketStart = []byte("{")
var curlyBracketEnd = []byte("}")
var squareBracketStart = []byte("[")
var squareBracketEnd = []byte("]")
var doubleQuote = []byte(`"`)
var comma = []byte(",")

// var SendDataChan = make(chan []byte)

type Response struct {
	Raw     []byte
	RawData [][]byte
	Method  []byte
}

type Request struct {
	Raw     []byte
	RawData [][]byte
	Method  []byte
}

type Error struct {
	Raw    []byte
	RawMsg []byte
	Method []byte
}

type BlockHeader struct {
	TxHash      []byte
	StateHash   []byte
	PrevBlock   []byte
	MinerSig    []byte
	Miner       []byte
	MinerPubkey []byte
	BlockHash   []byte
	Timestamp   int64
	Nonce       int64
}

type PortOpen struct {
	Ref      int64
	Port     int64
	DeviceId string
	Ok       bool
	Err      *Error
}

type PortSend struct {
	Ref  int64
	Data []byte
	Ok   bool
}

type PortClose struct {
	Ref int64
	Ok  bool
}

type DeviceObj struct {
	ServerID         []byte
	PeakBlock        []byte
	FleetAddr        []byte
	TotalConnections int64
	TotalBytes       int64
	LocalAddr        []byte
	DeviceSig        []byte
	ServerSig        []byte
	Err              error
}

type ServerObj struct {
	ServerID   []byte
	Host       []byte
	EdgePort   int64
	ServerPort int64
	Sig        []byte
}

type StateRoots struct {
	// BlockNumber int
	StateRoots   [][]byte
	rawStateRoot []byte
	stateRoot    []byte
}

type AccountRoots struct {
	// BlockNumber int
	AccountRoots   [][]byte
	rawStorageRoot []byte
	storageRoot    []byte
}

type Account struct {
	Address     []byte
	StorageRoot []byte
	Nonce       int64
	Code        []byte
	Balance     int64
	AccountHash []byte
	proof       []byte
	stateTree   *MerkleTree
}

type AccountValue struct {
	proof       []byte
	accountTree *MerkleTree
}

// RLPAccount struct for rlp encoding account
type RLPAccount struct {
	Nonce       uint
	Balance     uint
	StorageRoot []byte
	Code        []byte
}

// Ticket struct for connection and transmission
type Ticket struct {
	ServerID         []byte
	BlockNumber      int
	BlockHash        []byte
	FleetAddr        []byte
	TotalConnections int
	TotalBytes       int
	LocalAddr        []byte
	sig              []byte
}

// Hash returns hash of ticket
func (ct *Ticket) Hash() ([]byte, error) {
	msg, err := bert.Encode([6]bert.Term{ct.ServerID, ct.BlockHash, ct.FleetAddr, ct.TotalConnections, ct.TotalBytes, ct.LocalAddr})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(msg), nil
}

// Sign ticket with given ecdsa private key
func (ct *Ticket) Sign(privKey *ecdsa.PrivateKey) error {
	msgHash, err := ct.Hash()
	if err != nil {
		return err
	}
	sig, err := secp256k1.Sign(msgHash, privKey.D.Bytes())
	if err != nil {
		return err
	}
	ct.sig = sig
	return nil
}

// Sig returns signature of ticket
func (ct *Ticket) Sig() []byte {
	return ct.sig
}

// StateRoot returns state root of given state roots
func (sr *StateRoots) StateRoot() []byte {
	if len(sr.stateRoot) > 0 {
		return sr.stateRoot
	}
	bertStateRoot := [16]bert.Term{}
	for i, stateRoot := range sr.StateRoots {
		bertStateRoot[i] = stateRoot
	}
	rawStateRoot, err := bert.Encode(bertStateRoot)
	if err != nil {
		log.Fatal(err)
	}
	stateRoot := crypto.Sha256(rawStateRoot)
	sr.rawStateRoot = rawStateRoot
	sr.stateRoot = stateRoot
	return stateRoot
}

// Find return index of state root
func (sr *StateRoots) Find(stateRoot []byte) int {
	index := -1
	for i, v := range sr.StateRoots {
		if bytes.Equal(v, stateRoot) {
			index = i
			break
		}
	}
	return index
}

// StorageRoot returns storage root of given account roots
func (ar *AccountRoots) StorageRoot() []byte {
	if len(ar.storageRoot) > 0 {
		return ar.storageRoot
	}
	bertStorageRoot := [16]bert.Term{}
	for i, accountRoot := range ar.AccountRoots {
		bertStorageRoot[i] = accountRoot
	}
	rawStorageRoot, err := bert.Encode(bertStorageRoot)
	if err != nil {
		log.Fatal(err)
	}
	storageRoot := crypto.Sha256(rawStorageRoot)
	ar.rawStorageRoot = rawStorageRoot
	ar.storageRoot = storageRoot
	return storageRoot
}

// Find return index of account root
func (ar *AccountRoots) Find(accountRoot []byte) int {
	index := -1
	for i, v := range ar.AccountRoots {
		if bytes.Equal(v, accountRoot) {
			index = i
			break
		}
	}
	return index
}

// func BitstringToUint(src string) {}

func isJSONObj(json []byte) bool {
	if len(json) == 0 {
		return false
	}
	return (json[0] == curlyBracketStart[0]) && (json[len(json)-1] == curlyBracketEnd[0])
}

func isJSONArr(json []byte) bool {
	if len(json) == 0 {
		return false
	}
	return (json[0] == squareBracketStart[0]) && (json[len(json)-1] == squareBracketEnd[0])
}

func isJSONStr(json []byte) bool {
	if len(json) == 0 {
		return false
	}
	return (json[0] == doubleQuote[0]) && (json[len(json)-1] == doubleQuote[0])
}

// JSONArrLen returns array length of json
// TODO: JSONObjLen
func JSONArrLen(json []byte) int {
	var length int
	var sqbCount int
	if !isJSONArr(json) {
		return length
	}
	src := json[1 : len(json)-1]
	for _, byt := range src {
		if byt == squareBracketStart[0] {
			sqbCount++
		} else if byt == squareBracketEnd[0] {
			sqbCount--
		} else if (byt == comma[0]) && (sqbCount == 0) {
			length++
		}
	}
	length++
	return length
}

// IsValid check the account hash is valid
// should we check state root?
// func (ac *Account) IsValid() bool {
// 	return false
// }

// StateRoot returns state root of account, you can compare with stateroots[mod]
func (ac *Account) StateRoot() []byte {
	return ac.stateTree.RootHash
}

// StateTree returns merkle tree of account
func (ac *Account) StateTree() *MerkleTree {
	return ac.stateTree
}

// AccountRoot returns account root of account value, you can compare with accountroots[mod]
func (acv *AccountValue) AccountRoot() []byte {
	return acv.accountTree.RootHash
}

// AccountTree returns merkle tree of account value
func (acv *AccountValue) AccountTree() *MerkleTree {
	return acv.accountTree
}

// Devices keep the connected devices
type Devices struct {
	connectedDevice map[string]ConnectedDevice
	rw              sync.RWMutex
}

func (d *Devices) GetDevice(k string) ConnectedDevice {
	d.rw.RLock()
	defer d.rw.RUnlock()
	return d.connectedDevice[k]
}

func (d *Devices) SetDevice(k string, ud ConnectedDevice) {
	d.rw.Lock()
	defer d.rw.Unlock()
	d.connectedDevice[k] = ud
	return
}

func (d *Devices) DelDevice(k string) {
	d.rw.Lock()
	defer d.rw.Unlock()
	delete(d.connectedDevice, k)
	return
}

func (d *Devices) FindDeviceByRef(ref int64) ConnectedDevice {
	d.rw.RLock()
	defer d.rw.RUnlock()
	clientID := ""
	for d, r := range d.connectedDevice {
		if r.Ref == ref {
			clientID = d
			break
		}
	}
	return d.connectedDevice[clientID]
}

// ConnectedDevice connected device
// TODO: Add mutex
type ConnectedDevice struct {
	Ref       int64
	ClientID  string
	DeviceID  string
	DDeviceID []byte
	Conn      ConnectedConn
}

func (device *ConnectedDevice) copyToSSL(s *SSL) {
	ref := int(device.Ref)
	err := device.Conn.copyToSSL(s, ref)
	if err != nil {
		// check if disconnect
		if devices.GetDevice(device.ClientID).Ref != 0 {
			// send portclose request and channel
			s.PortClose(false, ref)
			portClose := &PortClose{
				Ref: int64(ref),
				Ok:  true,
			}
			PortCloseChan <- portClose
		}
	}
	return
}

func (device *ConnectedDevice) writeToTCP(data []byte) {
	device.Conn.writeToTCP(data)
	return
}

// ConnectedConn connected net/websocket connection
// TODO: Add mutex
type ConnectedConn struct {
	IsWS bool
	// IsConnected bool
	Conn   net.Conn
	WSConn *websocket.Conn
}

func (conn *ConnectedConn) copyToSSL(s *SSL, ref int) error {
	if conn.IsWS {
		for {
			_, buf, err := conn.WSConn.ReadMessage()
			count := len(buf)
			encStr := EncodeToString(buf[:count])
			encBuf := []byte(fmt.Sprintf(`"%s"`, encStr[2:]))
			if err != nil {
				log.Println("Got error when read from websocket: " + err.Error())
				// if err == io.EOF ||
				// 	strings.Contains(err.Error(), "websocket: close") {
				// disconnect from connection
				if count > 0 {
					s.PortSend(false, ref, encBuf)
				}
				return err
				// }
			}
			if count > 0 {
				s.PortSend(false, ref, encBuf)
			}
			// log.Println("Sleep 100 milliseconds")
			// time.Sleep(100 * time.Millisecond)
		}
	}
	for {
		buf := make([]byte, readBufferSize)
		count, err := conn.Conn.Read(buf)
		// if Verbose {
		log.Printf("Read %d bytes data from connection... Start to send...", count)
		// 	log.Println(string(buf[:count]))
		// }
		encStr := EncodeToString(buf[:count])
		encBuf := []byte(fmt.Sprintf(`"%s"`, encStr[2:]))
		if err != nil {
			log.Println("Got error when read from tcp: " + err.Error())
			// if err == io.EOF ||
			// 	strings.Contains(err.Error(), "connection reset by peer") {
			// disconnect from connection
			if count > 0 {
				s.PortSend(false, ref, encBuf)
			}
			return err
			// }
		}
		if count > 0 {
			s.PortSend(false, ref, encBuf)
		}
		// log.Println("Sleep 100 milliseconds")
		// time.Sleep(100 * time.Millisecond)
	}
}

func (conn *ConnectedConn) writeToTCP(data []byte) {
	if conn.IsWS {
		err := conn.WSConn.WriteMessage(websocket.BinaryMessage, data)
		if err != nil {
			log.Println("Websocket write error")
			log.Println(err)
			return
		}
	} else {
		_, err := conn.Conn.Write(data)
		if err != nil {
			log.Println(err)
			return
		}
		// if Verbose {
		// log.Printf("Write %d bytes of data to client\n", n)
		// 	log.Println(data)
		// 	log.Println(string(data))
		// }
		// time.Sleep(100 * time.Millisecond)
		return
	}
}

// func (c *ConnectedConn) Read() {}

// Hash returns sha3 of bert encoded block header
func (blockHeader *BlockHeader) Hash() ([]byte, error) {
	encHeader, err := bert.Encode([7]bert.Term{blockHeader.PrevBlock, blockHeader.MinerPubkey, blockHeader.StateHash, blockHeader.TxHash, blockHeader.Timestamp, blockHeader.Nonce, blockHeader.MinerSig})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(encHeader), nil
}

// HashWithoutSig returns sha3 of bert encoded block header without miner signature
func (blockHeader *BlockHeader) HashWithoutSig() ([]byte, error) {
	encHeader, err := bert.Encode([6]bert.Term{blockHeader.PrevBlock, blockHeader.MinerPubkey, blockHeader.StateHash, blockHeader.TxHash, blockHeader.Timestamp, blockHeader.Nonce})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(encHeader), nil
}

// ValidateSig check miner signature is valid
func (blockHeader *BlockHeader) ValidateSig() (bool, error) {
	msgHash, err := blockHeader.HashWithoutSig()
	if err != nil {
		return false, err
	}
	sig := []byte{}
	sig = append(sig, blockHeader.MinerSig[1:65]...)
	pubkey := blockHeader.Miner
	return secp256k1.VerifySignature(pubkey, msgHash, sig), nil
}

// HashWithoutSig returns hash of device object without device signature
func (deviceObj *DeviceObj) HashWithoutSig() ([]byte, error) {
	msg, err := bert.Encode([6]bert.Term{deviceObj.ServerID, deviceObj.PeakBlock, deviceObj.FleetAddr, deviceObj.TotalConnections, deviceObj.TotalBytes, deviceObj.LocalAddr})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(msg), nil
}

// Hash returns hash of device object
func (deviceObj *DeviceObj) Hash() ([]byte, error) {
	msg, err := bert.Encode([7]bert.Term{deviceObj.ServerID, deviceObj.PeakBlock, deviceObj.FleetAddr, deviceObj.TotalConnections, deviceObj.TotalBytes, deviceObj.LocalAddr, deviceObj.DeviceSig})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(msg), nil
}

// RecoverDevicePubKey returns uncompressed device public key
func (deviceObj *DeviceObj) RecoverDevicePubKey() ([]byte, error) {
	hashMsg, err := deviceObj.HashWithoutSig()
	if err != nil {
		return nil, err
	}
	pubKey, err := secp256k1.RecoverPubkey(hashMsg, deviceObj.DeviceSig)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// DeviceAddress returns device address
func (deviceObj *DeviceObj) DeviceAddress() ([]byte, error) {
	devicePubkey, err := deviceObj.RecoverDevicePubKey()
	if err != nil {
		return nil, err
	}
	return crypto.PubkeyToAddress(devicePubkey)
}

// RecoverServerPubKey returns server public key
func (deviceObj *DeviceObj) RecoverServerPubKey() ([]byte, error) {
	hashMsg, err := deviceObj.Hash()
	if err != nil {
		return nil, err
	}
	pubKey, err := secp256k1.RecoverPubkey(hashMsg, deviceObj.ServerSig)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// ValidateSig returns device object sig is valid
func (deviceObj *DeviceObj) ValidateSig() bool {
	pubKey, err := deviceObj.RecoverServerPubKey()
	if err != nil {
		return false
	}
	serverID, err := crypto.PubkeyToAddress(pubKey)
	if err != nil {
		return false
	}
	log.Println(serverID, deviceObj.ServerID)
	return bytes.Equal(deviceObj.ServerID, serverID)
}

// RecoverServerPubKey returns server public key
func (serverObj *ServerObj) RecoverServerPubKey() ([]byte, error) {
	msg, err := bert.Encode([3]bert.Term{serverObj.Host, serverObj.EdgePort, serverObj.ServerPort})
	if err != nil {
		return nil, err
	}
	hashMsg := crypto.Sha256(msg)
	pubKey, err := secp256k1.RecoverPubkey(hashMsg, serverObj.Sig)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (serverObj *ServerObj) ValidateSig() bool {
	pubKey, err := serverObj.RecoverServerPubKey()
	if err != nil {
		return false
	}
	serverID, err := crypto.PubkeyToAddress(pubKey)
	if err != nil {
		return false
	}
	return bytes.Equal(serverObj.ServerID, serverID)
}
