// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package config

import (
	"fmt"
	"os"
	"sync"

	"github.com/diodechain/log15"
)

// Logger represent log service for client
type Logger struct {
	mode    int
	verbose bool
	logger  log15.Logger
	closeCh chan struct{}
	cd      sync.Once
}

// NewLogger initialize logger with given config
func NewLogger(cfg *Config) (l Logger, err error) {
	var logHandler log15.Handler
	logger := log15.New()
	if (cfg.LogMode & LogToConsole) > 0 {
		logHandler = log15.StreamHandler(os.Stderr, log15.TerminalFormat(cfg.LogDateTime))
	} else if (cfg.LogMode & LogToFile) > 0 {
		logHandler, err = log15.FileHandler(cfg.LogFilePath, log15.TerminalFormat(cfg.LogDateTime))
		if err != nil {
			return
		}
	}
	logger.SetHandler(logHandler)
	l.logger = logger
	l.verbose = cfg.Debug
	l.closeCh = make(chan struct{})
	l.mode = cfg.LogMode
	return
}

// InfoWithHost logs to logger in Info level
func (l *Logger) InfoWithHost(msg string, host string) {
	l.logger.Info(msg, "server", host)
}

// DebugWithHost logs to logger in Debug level
func (l *Logger) DebugWithHost(msg string, host string) {
	if l.verbose {
		l.logger.Debug(msg, "server", host)
	}
}

// ErrorWithHost logs to logger in Error level
func (l *Logger) ErrorWithHost(msg string, host string) {
	l.logger.Error(msg, "server", host)
}

// WarnWithHost logs to logger in Warn level
func (l *Logger) WarnWithHost(msg string, host string) {
	l.logger.Warn(msg, "server", host)
}

// CritWithHost logs to logger in Crit level
func (l *Logger) CritWithHost(msg string, host string) {
	l.logger.Crit(msg, "server", host)
}

// Info logs to logger in Info level
func (l *Logger) Info(msg string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(msg, args...))
}

// Debug logs to logger in Debug level
func (l *Logger) Debug(msg string, args ...interface{}) {
	if l.verbose {
		l.logger.Debug(fmt.Sprintf(msg, args...))
	}
}

// Error logs to logger in Error level
func (l *Logger) Error(msg string, args ...interface{}) {
	l.logger.Error(fmt.Sprintf(msg, args...))
}

// Warn logs to logger in Warn level
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.logger.Warn(fmt.Sprintf(msg, args...))
}

// Crit logs to logger in Crit level
func (l *Logger) Crit(msg string, args ...interface{}) {
	l.logger.Crit(fmt.Sprintf(msg, args...))
}

// Close logger handler
func (l *Logger) Close() {
	l.cd.Do(func() {
		close(l.closeCh)
		handler := l.logger.GetHandler()
		if closingHandler, ok := handler.(log15.ClosingHandler); ok {
			closingHandler.WriteCloser.Close()
		}
	})
}
