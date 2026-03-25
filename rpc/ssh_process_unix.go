//go:build !windows

// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/creack/pty"
)

type sshLocalUser struct {
	user   *user.User
	shell  string
	uid    uint32
	gid    uint32
	groups []uint32
}

func validateNativeSSHAccess(localUser string) error {
	account, err := lookupSSHLocalUser(localUser)
	if err != nil {
		return err
	}
	currentUID := uint64(os.Geteuid())
	if currentUID != 0 && currentUID != uint64(account.uid) {
		return fmt.Errorf("embedded Diode SSH requires root to switch from uid %d to user %s", currentUID, localUser)
	}
	return nil
}

func startSSHProcess(localUser string, command string, ptyReq *sshPTYRequest) (*sshProcessHandle, error) {
	account, err := lookupSSHLocalUser(localUser)
	if err != nil {
		return nil, err
	}

	argv := []string{account.shell}
	if command != "" {
		argv = append(argv, "-lc", command)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(),
		"HOME="+account.user.HomeDir,
		"USER="+account.user.Username,
		"LOGNAME="+account.user.Username,
		"SHELL="+account.shell,
	)
	cmd.Dir = account.user.HomeDir

	currentUID := uint64(os.Geteuid())
	if currentUID != 0 && currentUID != uint64(account.uid) {
		return nil, fmt.Errorf("running as uid %d cannot switch to user %s", currentUID, localUser)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if currentUID == 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid:    account.uid,
			Gid:    account.gid,
			Groups: account.groups,
		}
	}

	if ptyReq != nil {
		win := &pty.Winsize{Cols: uint16(ptyReq.Cols), Rows: uint16(ptyReq.Rows)}
		if win.Cols == 0 {
			win.Cols = 80
		}
		if win.Rows == 0 {
			win.Rows = 24
		}
		ptmx, err := pty.StartWithAttrs(cmd, win, cmd.SysProcAttr)
		if err != nil {
			return nil, err
		}
		return &sshProcessHandle{
			stdin:  ptmx,
			stdout: ptmx,
			wait:   cmd.Wait,
			resize: func(cols, rows uint32) error {
				return pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
			},
			close: ptmx.Close,
		}, nil
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &sshProcessHandle{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		wait:   cmd.Wait,
		close: func() error {
			_ = stdin.Close()
			return nil
		},
	}, nil
}

func lookupSSHLocalUser(name string) (*sshLocalUser, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	shell := "/bin/sh"
	passwd, err := os.Open("/etc/passwd")
	if err != nil {
		return newSSHLocalUser(name, u, shell)
	}
	defer passwd.Close()

	reader := bufio.NewReader(passwd)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return newSSHLocalUser(name, u, shell)
		}
		line = strings.TrimSpace(line)
		if line != "" {
			parts := strings.Split(line, ":")
			if len(parts) >= 7 && parts[0] == name && strings.TrimSpace(parts[6]) != "" {
				shell = strings.TrimSpace(parts[6])
				break
			}
		}
		if err == io.EOF {
			break
		}
	}
	return newSSHLocalUser(name, u, shell)
}

func newSSHLocalUser(name string, u *user.User, shell string) (*sshLocalUser, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid uid for user %s: %w", name, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid gid for user %s: %w", name, err)
	}
	groupIDs, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("could not resolve supplementary groups for user %s: %w", name, err)
	}
	groups, err := normalizeSupplementaryGroups(groupIDs, uint32(gid))
	if err != nil {
		return nil, fmt.Errorf("invalid supplementary groups for user %s: %w", name, err)
	}
	return &sshLocalUser{
		user:   u,
		shell:  shell,
		uid:    uint32(uid),
		gid:    uint32(gid),
		groups: groups,
	}, nil
}

func normalizeSupplementaryGroups(groupIDs []string, primaryGID uint32) ([]uint32, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}
	groups := make([]uint32, 0, len(groupIDs))
	seen := make(map[uint32]struct{}, len(groupIDs))
	for _, groupID := range groupIDs {
		value, err := strconv.ParseUint(groupID, 10, 32)
		if err != nil {
			return nil, err
		}
		gid := uint32(value)
		if gid == primaryGID {
			continue
		}
		if _, ok := seen[gid]; ok {
			continue
		}
		seen[gid] = struct{}{}
		groups = append(groups, gid)
	}
	return groups, nil
}
