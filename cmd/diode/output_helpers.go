package main

import (
	"fmt"
	"io"
	"os"

	"github.com/diodechain/diode_client/config"
)

func stdoutWriter() io.Writer {
	cfg := config.AppConfig
	if cfg != nil && cfg.StdoutWriter != nil {
		return cfg.StdoutWriter
	}
	return os.Stdout
}

func stderrWriter() io.Writer {
	cfg := config.AppConfig
	if cfg != nil && cfg.StderrWriter != nil {
		return cfg.StderrWriter
	}
	return os.Stderr
}

func stdoutf(format string, args ...interface{}) {
	fmt.Fprintf(stdoutWriter(), format, args...)
}

func stdoutln(args ...interface{}) {
	fmt.Fprintln(stdoutWriter(), args...)
}

func stderrln(args ...interface{}) {
	fmt.Fprintln(stderrWriter(), args...)
}
