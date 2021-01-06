// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package config

import (
	"fmt"
	// "os"
	"sync"

	"github.com/diodechain/zap"
	"github.com/diodechain/zap/zapcore"
)

const (
	termDatetimeTempl = "01/02/2006 15:04:05"
)

// Logger represent log service for client
type Logger struct {
	mode    int
	verbose bool
	logger  *zap.Logger
	closeCh chan struct{}
	cd      sync.Once
}

func newZapLogger(cfg *Config) (logger *zap.Logger) {
	var zapCfg zap.Config
	if cfg.Debug {
		zapCfg = zap.NewDevelopmentConfig()
		zapCfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	} else {
		zapCfg = zap.NewProductionConfig()
		zapCfg.EncoderConfig.CallerKey = ""
		zapCfg.DisableStacktrace = true
	}
	if (cfg.LogMode & LogToFile) > 0 {
		// TODO: check whether file is existed?
		zapCfg.OutputPaths = []string{cfg.LogFilePath}
		zapCfg.ErrorOutputPaths = []string{cfg.LogFilePath}
		zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	} else {
		zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	if !cfg.LogDateTime {
		zapCfg.EncoderConfig.TimeKey = ""
	} else {
		zapCfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(termDatetimeTempl)
	}
	zapCfg.Sampling = nil
	zapCfg.Encoding = "consoleraw"
	zapCfg.EncoderConfig.ConsoleSeparator = " "
	zapCfg.EncoderConfig.LevelKey = "[L]"
	logger, _ = zapCfg.Build()
	defer logger.Sync()
	return
}

// NewLogger initialize logger with given config
func NewLogger(cfg *Config) (l Logger, err error) {
	logger := newZapLogger(cfg)
	l.logger = logger
	l.verbose = cfg.Debug
	l.closeCh = make(chan struct{})
	l.mode = cfg.LogMode
	return
}

// ZapLogger returns *zap.Logger
func (l *Logger) ZapLogger() *zap.Logger {
	return l.logger
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
	l.logger.Fatal(fmt.Sprintf(msg, args...))
}

// Close logger handler
func (l *Logger) Close() {
	l.cd.Do(func() {
		close(l.closeCh)
	})
}
