// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
//go:build windows
// +build windows

package config

func SetRlimitNofile(newRlimit int) error {
	return nil
}
