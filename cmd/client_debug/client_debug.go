// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"github.com/diodechain/diode_go_client/pkg/client_debug/cmd"
	"os"
)

func exit(err error) {
	if err != nil {
		fmt.Printf("Exit with error: %s\n", err.Error())
		os.Exit(2)
	}
	os.Exit(0)
}

func main() {
	err := cmd.Execute()
	if err != nil {
		exit(err)
	}
	exit(nil)
}
