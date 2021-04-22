// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"os"

	"github.com/diodechain/diode_client/pkg/gauge/cmd"
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
