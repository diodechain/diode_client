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
	go ssh.DiscardRequests(requests)

	var wg sync.WaitGroup
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		wg.Add(1)
		go func(ch ssh.NewChannel) {
			defer wg.Done()
			if err := svc.handleSessionChannel(ch, meta); err != nil {
				if config.AppConfig != nil && config.AppConfig.Logger != nil {
					config.AppConfig.Logger.Warn("ssh session failed port=%d source=%s err=%v", meta.Port.To, meta.SourceDevice.HexString(), err)
				}
			}
		}(newChannel)
	}
	wg.Wait()
	return nil
}

func (svc *EmbeddedSSHService) handleSessionChannel(newChannel ssh.NewChannel, meta sshConnMeta) error {
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
			next, handled, err := startSSHRequestProcess(req, proc, meta.Port.SSHLocalUser, "", ptyReq, channel, waitForProcess)
			if err != nil {
				return err
			}
			if handled {
				proc = next
			}
		case "exec":
			command, err := parseSSHExecRequest(req.Payload)
			if err != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				return err
			}
			next, handled, err := startSSHRequestProcess(req, proc, meta.Port.SSHLocalUser, command, ptyReq, channel, waitForProcess)
			if err != nil {
				return err
			}
			if handled {
				proc = next
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

func startSSHRequestProcess(req *ssh.Request, proc *sshProcessHandle, localUser string, command string, ptyReq *sshPTYRequest, channel ssh.Channel, waitForProcess func()) (*sshProcessHandle, bool, error) {
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
	go proxySSHProcessIO(channel, next)
	go waitForProcess()
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
