// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
// +build !windows

package config

import (
	"syscall"
)

// see: http://man7.org/linux/man-pages/man2/setrlimit.2.html
func SetRlimitNofile(newRlimit int) error {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		return err
	}
	rLimit.Cur = uint64(newRlimit)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		return err
	}
	return nil
}
