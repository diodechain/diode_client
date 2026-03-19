// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
	"golang.org/x/crypto/ssh"
)

const sshHostKeyDBKey = "ssh_host_ed25519"

type EmbeddedSSHService struct {
	signer ssh.Signer
}

type sshConnMeta struct {
	Port         *config.Port
	SourceDevice Address
}

type sshPTYRequest struct {
	Term string
	Cols uint32
	Rows uint32
}

type sshProcessHandle struct {
	stdin  io.WriteCloser
	stdout io.Reader
	stderr io.Reader
	wait   func() error
	resize func(cols, rows uint32) error
	close  func() error
}

type sshDirectTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type sshTCPIPForwardPayload struct {
	BindAddr string
	BindPort uint32
}

type sshForwardedTCPIPPayload struct {
	BindAddr   string
	BindPort   uint32
	OriginAddr string
	OriginPort uint32
}

type sshRemoteForwardKey struct {
	bindAddr string
	bindPort uint32
}

type sshRemoteForward struct {
	key         sshRemoteForwardKey
	listenAddr  string
	payloadAddr string
	listener    net.Listener
}

type embeddedSSHConn struct {
	meta           sshConnMeta
	conn           ssh.Conn
	remoteForwards map[sshRemoteForwardKey]*sshRemoteForward
	remoteMu       sync.Mutex
}

func NewEmbeddedSSHService() (*EmbeddedSSHService, error) {
	signer, err := loadOrCreateSSHHostSigner()
	if err != nil {
		return nil, err
	}
	return &EmbeddedSSHService{signer: signer}, nil
}

func loadOrCreateSSHHostSigner() (ssh.Signer, error) {
	if db.DB == nil {
		return nil, fmt.Errorf("database is not initialized")
	}

	if raw, err := db.DB.Get(sshHostKeyDBKey); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("ssh host key is invalid")
		}
		privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return ssh.NewSignerFromKey(privAny)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	if err := db.DB.Put(sshHostKeyDBKey, pemKey); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

func authorizeSSHUser(port *config.Port, requestedUser string) error {
	if port == nil || !port.SSHEnabled {
		return fmt.Errorf("ssh service is not enabled")
	}
	if port.SSHLocalUser == "" {
		return fmt.Errorf("ssh service local user is not configured")
	}
	if requestedUser != port.SSHLocalUser {
		return fmt.Errorf("ssh user %q is not allowed on port %d", requestedUser, port.To)
	}
	return nil
}

func validateEmbeddedSSHPort(port *config.Port) error {
	if port == nil {
		return fmt.Errorf("ssh service port is not configured")
	}
	if err := validateNativeSSHAccess(port.SSHLocalUser); err != nil {
		return fmt.Errorf("embedded Diode SSH is unavailable for user %q: %w", port.SSHLocalUser, err)
	}
	return nil
}

func sshPermissions(meta sshConnMeta, connMeta ssh.ConnMetadata) (*ssh.Permissions, error) {
	if err := authorizeSSHUser(meta.Port, connMeta.User()); err != nil {
		return nil, err
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			"diode.source_device": meta.SourceDevice.HexString(),
			"diode.local_user":    connMeta.User(),
		},
	}, nil
}

func (svc *EmbeddedSSHService) ServeConn(conn net.Conn, meta sshConnMeta) error {
	if svc == nil {
		return fmt.Errorf("ssh service not initialized")
	}
	if meta.Port == nil {
		return fmt.Errorf("missing ssh port configuration")
	}

	serverConfig := &ssh.ServerConfig{
		NoClientAuth:         true,
		NoClientAuthCallback: func(connMeta ssh.ConnMetadata) (*ssh.Permissions, error) { return sshPermissions(meta, connMeta) },
		PublicKeyCallback: func(connMeta ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			return sshPermissions(meta, connMeta)
		},
	}
	serverConfig.AddHostKey(svc.signer)

	serverConn, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		return err
	}
	defer serverConn.Close()

	connState := &embeddedSSHConn{
		meta:           meta,
		conn:           serverConn,
		remoteForwards: make(map[sshRemoteForwardKey]*sshRemoteForward),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		connState.handleGlobalRequests(requests)
	}()
	for newChannel := range channels {
		wg.Add(1)
		go func(ch ssh.NewChannel) {
			defer wg.Done()
			if err := connState.handleChannel(ch); err != nil {
				if config.AppConfig != nil && config.AppConfig.Logger != nil {
					config.AppConfig.Logger.Warn("ssh session failed port=%d source=%s err=%v", meta.Port.To, meta.SourceDevice.HexString(), err)
				}
			}
		}(newChannel)
	}
	connState.closeAllRemoteForwards()
	wg.Wait()
	return nil
}

func (connState *embeddedSSHConn) handleChannel(newChannel ssh.NewChannel) error {
	switch newChannel.ChannelType() {
	case "session":
		return connState.handleSessionChannel(newChannel)
	case "direct-tcpip":
		return connState.handleDirectTCPIPChannel(newChannel)
	default:
		return newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
	}
}

func (connState *embeddedSSHConn) handleSessionChannel(newChannel ssh.NewChannel) error {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	defer channel.Close()

	var (
		proc   *sshProcessHandle
		ptyReq *sshPTYRequest
		once   sync.Once
	)

	waitForProcess := func() {
		once.Do(func() {
			if proc == nil {
				return
			}
			status := uint32(0)
			if err := proc.wait(); err != nil {
				status = exitStatusCode(err)
			}
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: status}))
			if proc.close != nil {
				_ = proc.close()
			}
			_ = channel.CloseWrite()
			_ = channel.Close()
		})
	}

	for req := range requests {
		switch req.Type {
		case "pty-req":
			nextPTY, err := parseSSHPTYRequest(req.Payload)
			if req.WantReply {
				req.Reply(err == nil, nil)
			}
			if err == nil {
				ptyReq = nextPTY
			}
		case "window-change":
			cols, rows, err := parseSSHWindowChange(req.Payload)
			if err == nil && proc != nil && proc.resize != nil {
				err = proc.resize(cols, rows)
			}
			if req.WantReply {
				req.Reply(err == nil, nil)
			}
		case "shell":
			next, handled, err := startSSHRequestProcess(req, proc, connState.meta.Port.SSHLocalUser, "", ptyReq)
			if err != nil {
				return err
			}
			if handled {
				proc = next
				go proxySSHProcessIO(channel, proc)
				go waitForProcess()
			}
		case "exec":
			command, err := parseSSHExecRequest(req.Payload)
			if err != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				return err
			}
			next, handled, err := startSSHRequestProcess(req, proc, connState.meta.Port.SSHLocalUser, command, ptyReq)
			if err != nil {
				return err
			}
			if handled {
				proc = next
				go proxySSHProcessIO(channel, proc)
				go waitForProcess()
			}
		case "env":
			if req.WantReply {
				req.Reply(false, nil)
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}

	waitForProcess()
	return nil
}

func (connState *embeddedSSHConn) handleDirectTCPIPChannel(newChannel ssh.NewChannel) error {
	var payload sshDirectTCPIPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		return newChannel.Reject(ssh.Prohibited, "invalid direct-tcpip payload")
	}

	targetConn, err := net.Dial("tcp", net.JoinHostPort(payload.DestAddr, strconv.Itoa(int(payload.DestPort))))
	if err != nil {
		return newChannel.Reject(ssh.ConnectionFailed, err.Error())
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = targetConn.Close()
		return err
	}
	defer channel.Close()
	defer targetConn.Close()

	go ssh.DiscardRequests(requests)
	proxySSHForward(channel, targetConn)
	return nil
}

func (connState *embeddedSSHConn) handleGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "tcpip-forward":
			connState.handleTCPIPForward(req)
		case "cancel-tcpip-forward":
			connState.handleCancelTCPIPForward(req)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (connState *embeddedSSHConn) handleTCPIPForward(req *ssh.Request) {
	var payload sshTCPIPForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	listenAddr, payloadAddr, err := normalizeSSHForwardBindAddr(payload.BindAddr)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(listenAddr, strconv.Itoa(int(payload.BindPort))))
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	forward := &sshRemoteForward{
		key: sshRemoteForwardKey{
			bindAddr: payloadAddr,
			bindPort: uint32(tcpAddr.Port),
		},
		listenAddr:  listenAddr,
		payloadAddr: payloadAddr,
		listener:    listener,
	}

	if err := connState.storeRemoteForward(forward); err != nil {
		_ = listener.Close()
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	if req.WantReply {
		replyPayload := []byte(nil)
		if payload.BindPort == 0 {
			replyPayload = ssh.Marshal(struct {
				BindPort uint32
			}{BindPort: forward.key.bindPort})
		}
		if err := req.Reply(true, replyPayload); err != nil {
			connState.deleteRemoteForward(forward.key)
			_ = listener.Close()
			return
		}
	}

	go connState.serveRemoteForward(forward)
}

func (connState *embeddedSSHConn) handleCancelTCPIPForward(req *ssh.Request) {
	var payload sshTCPIPForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	_, bindAddr, err := normalizeSSHForwardBindAddr(payload.BindAddr)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	key := sshRemoteForwardKey{bindAddr: bindAddr, bindPort: payload.BindPort}
	forward := connState.deleteRemoteForward(key)
	if forward != nil {
		_ = forward.listener.Close()
	}
	if req.WantReply {
		_ = req.Reply(forward != nil, nil)
	}
}

func (connState *embeddedSSHConn) storeRemoteForward(forward *sshRemoteForward) error {
	connState.remoteMu.Lock()
	defer connState.remoteMu.Unlock()
	if _, ok := connState.remoteForwards[forward.key]; ok {
		return fmt.Errorf("remote forward already exists")
	}
	connState.remoteForwards[forward.key] = forward
	return nil
}

func (connState *embeddedSSHConn) deleteRemoteForward(key sshRemoteForwardKey) *sshRemoteForward {
	connState.remoteMu.Lock()
	defer connState.remoteMu.Unlock()
	forward := connState.remoteForwards[key]
	delete(connState.remoteForwards, key)
	return forward
}

func (connState *embeddedSSHConn) closeAllRemoteForwards() {
	connState.remoteMu.Lock()
	forwards := make([]*sshRemoteForward, 0, len(connState.remoteForwards))
	for key, forward := range connState.remoteForwards {
		delete(connState.remoteForwards, key)
		forwards = append(forwards, forward)
	}
	connState.remoteMu.Unlock()

	for _, forward := range forwards {
		_ = forward.listener.Close()
	}
}

func (connState *embeddedSSHConn) serveRemoteForward(forward *sshRemoteForward) {
	for {
		targetConn, err := forward.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		go connState.handleForwardedTCPIPConn(forward, targetConn)
	}
}

func (connState *embeddedSSHConn) handleForwardedTCPIPConn(forward *sshRemoteForward, targetConn net.Conn) {
	originAddr, originPort := sshConnAddress(targetConn.RemoteAddr())
	channel, requests, err := connState.conn.OpenChannel("forwarded-tcpip", ssh.Marshal(sshForwardedTCPIPPayload{
		BindAddr:   forward.payloadAddr,
		BindPort:   forward.key.bindPort,
		OriginAddr: originAddr,
		OriginPort: originPort,
	}))
	if err != nil {
		_ = targetConn.Close()
		return
	}
	defer channel.Close()
	defer targetConn.Close()

	go ssh.DiscardRequests(requests)
	proxySSHForward(channel, targetConn)
}

func startSSHRequestProcess(req *ssh.Request, proc *sshProcessHandle, localUser string, command string, ptyReq *sshPTYRequest) (*sshProcessHandle, bool, error) {
	if proc != nil {
		if req.WantReply {
			req.Reply(false, nil)
		}
		return proc, false, nil
	}

	next, err := startSSHProcess(localUser, command, ptyReq)
	if req.WantReply {
		req.Reply(err == nil, nil)
	}
	if err != nil {
		return nil, false, err
	}
	return next, true, nil
}

func proxySSHProcessIO(channel ssh.Channel, proc *sshProcessHandle) {
	if proc == nil {
		return
	}

	if proc.stdin != nil {
		go func() {
			_, _ = io.Copy(proc.stdin, channel)
			_ = proc.stdin.Close()
		}()
	}
	if proc.stdout != nil {
		go func() {
			_, _ = io.Copy(channel, proc.stdout)
		}()
	}
	if proc.stderr != nil {
		go func() {
			_, _ = io.Copy(channel.Stderr(), proc.stderr)
		}()
	}
}

func proxySSHForward(channel ssh.Channel, targetConn net.Conn) {
	done := make(chan struct{}, 2)

	go copySSHForward(targetConn, channel, done)
	go copySSHForward(channel, targetConn, done)

	<-done
	<-done
}

func copySSHForward(dst io.Writer, src io.Reader, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	closeSSHWrite(dst)
	done <- struct{}{}
}

func closeSSHWrite(dst io.Writer) {
	type closeWriter interface {
		CloseWrite() error
	}
	if writer, ok := dst.(closeWriter); ok {
		_ = writer.CloseWrite()
	}
}

func parseSSHExecRequest(payload []byte) (string, error) {
	value, rest, ok := parseSSHString(payload)
	if !ok || len(rest) != 0 {
		return "", fmt.Errorf("invalid ssh exec payload")
	}
	return value, nil
}

func parseSSHPTYRequest(payload []byte) (*sshPTYRequest, error) {
	term, rest, ok := parseSSHString(payload)
	if !ok || len(rest) < 16 {
		return nil, fmt.Errorf("invalid ssh pty payload")
	}
	return &sshPTYRequest{
		Term: term,
		Cols: binary.BigEndian.Uint32(rest[0:4]),
		Rows: binary.BigEndian.Uint32(rest[4:8]),
	}, nil
}

func parseSSHWindowChange(payload []byte) (uint32, uint32, error) {
	if len(payload) < 8 {
		return 0, 0, fmt.Errorf("invalid ssh window-change payload")
	}
	return binary.BigEndian.Uint32(payload[0:4]), binary.BigEndian.Uint32(payload[4:8]), nil
}

func parseSSHString(payload []byte) (string, []byte, bool) {
	if len(payload) < 4 {
		return "", nil, false
	}
	size := int(binary.BigEndian.Uint32(payload[:4]))
	payload = payload[4:]
	if size < 0 || len(payload) < size {
		return "", nil, false
	}
	return string(payload[:size]), payload[size:], true
}

func normalizeSSHForwardBindAddr(bindAddr string) (listenAddr string, payloadAddr string, err error) {
	switch bindAddr {
	case "":
		return "127.0.0.1", "localhost", nil
	case "localhost":
		return "127.0.0.1", "localhost", nil
	case "127.0.0.1":
		return "127.0.0.1", "127.0.0.1", nil
	case "::1":
		return "::1", "::1", nil
	default:
		return "", "", fmt.Errorf("remote forwarding only supports loopback bind addresses")
	}
}

func sshConnAddress(addr net.Addr) (string, uint32) {
	if addr == nil {
		return "", 0
	}

	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 {
		return host, 0
	}
	return host, uint32(port)
}

func exitStatusCode(err error) uint32 {
	if err == nil {
		return 0
	}
	type exitCoder interface {
		ExitCode() int
	}
	var coder exitCoder
	if errors.As(err, &coder) {
		code := coder.ExitCode()
		if code >= 0 {
			return uint32(code)
		}
	}
	return 1
}
