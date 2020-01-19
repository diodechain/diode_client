// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package config

import (
	"log"
	"syscall"
)

// see: http://man7.org/linux/man-pages/man2/setrlimit.2.html
func setRlimitNofile(newRlimit int) {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		log.Printf("cannot get rlimit: %s", err.Error())
		return
	}
	rLimit.Cur = uint64(newRlimit)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		log.Printf("cannot ser rlimit: %s", err.Error())
		return
	}
}
