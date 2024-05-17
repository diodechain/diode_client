// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/diodechain/zap"
	"github.com/diodechain/zap/zapcore"
)

const (
	termDatetimeTempl = "01/02/2006 15:04:05"
)

// Logger represent log service for client
type Logger struct {
	logger *zap.Logger
}

func newZapLogger(cfg *Config) (logger *zap.Logger, err error) {
	zapCfg := zap.NewProductionConfig()
	if cfg.LogDateTime || cfg.Debug {
		zapCfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	zapCfg.EncoderConfig.CallerKey = ""
	zapCfg.DisableStacktrace = true
	if (cfg.LogMode & LogToFile) > 0 {
		_, err = os.Stat(cfg.LogFilePath)
		if err == nil || (err != nil && os.IsExist(err)) {
			zapCfg.OutputPaths = []string{cfg.LogFilePath}
			zapCfg.ErrorOutputPaths = []string{cfg.LogFilePath}
			zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
		} else {
			zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}
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
	l.logger, err = newZapLogger(cfg)
	return
}

// Info logs to logger in Info level
func (l *Logger) With(fields ...zap.Field) *Logger {
	return &Logger{
		logger: l.logger.With(fields...),
	}
}

// Info logs to logger in Info level
func (l *Logger) Info(msg string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(msg, args...))
}

// Debug logs to logger in Debug level
func (l *Logger) Debug(msg string, args ...interface{}) {
	l.logger.Debug(fmt.Sprintf(msg, args...))
}

// Error logs to logger in Error level
func (l *Logger) Error(msg string, args ...interface{}) {
	msg = fmt.Sprintf(msg, args...)
	if !strings.Contains(msg, "rpc call has been cancelled") {
		l.logger.Error(msg)
	}
}

// Warn logs to logger in Warn level
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.logger.Warn(fmt.Sprintf(msg, args...))
}

// Fatal logs to logger in Fatal level
// Note: this will exit the program after flush the log
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.logger.Fatal(fmt.Sprintf(msg, args...))
}
