// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package config

import (
	"fmt"
	"os"
	"path/filepath"
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

func logToFileReady(cfg *Config) bool {
	return (cfg.LogMode&LogToFile) > 0 && cfg.LogFilePath != ""
}

func openLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	// Open the path with os.OpenFile rather than zap OutputPaths: zap parses
	// OutputPaths as URLs, so Windows drive letters (C:\...) break as schemes.
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
}

func loggerLevel(cfg *Config) zap.AtomicLevel {
	if cfg.LogDateTime || cfg.Debug {
		return zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	return zap.NewAtomicLevelAt(zap.InfoLevel)
}

func loggerEncoderConfig(cfg *Config) zapcore.EncoderConfig {
	zapCfg := zap.NewProductionConfig()
	zapCfg.EncoderConfig.CallerKey = ""
	zapCfg.DisableStacktrace = true
	if logToFileReady(cfg) {
		zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	} else {
		zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	if !cfg.LogDateTime {
		zapCfg.EncoderConfig.TimeKey = ""
	} else {
		zapCfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(termDatetimeTempl)
	}
	zapCfg.EncoderConfig.ConsoleSeparator = " "
	zapCfg.EncoderConfig.LevelKey = "[L]"
	return zapCfg.EncoderConfig
}

func newZapLoggerLegacy(cfg *Config) (logger *zap.Logger, err error) {
	level := loggerLevel(cfg)
	encCfg := loggerEncoderConfig(cfg)

	if logToFileReady(cfg) {
		f, err := openLogFile(cfg.LogFilePath)
		if err != nil {
			return nil, err
		}
		core := zapcore.NewCore(zapcore.NewConsoleEncoder(encCfg), zapcore.AddSync(f), level)
		return zap.New(core), nil
	}

	zapCfg := zap.NewProductionConfig()
	zapCfg.Level = level
	zapCfg.EncoderConfig = encCfg
	zapCfg.DisableStacktrace = true
	zapCfg.Sampling = nil
	zapCfg.Encoding = "consoleraw"
	return zapCfg.Build()
}

func newZapLogger(cfg *Config) (logger *zap.Logger, err error) {
	var remote zapcore.WriteSyncer
	if cfg.LogTargetRemote != nil {
		if ws, ok := cfg.LogTargetRemote.(zapcore.WriteSyncer); ok {
			remote = ws
		}
	}
	if remote == nil {
		return newZapLoggerLegacy(cfg)
	}

	// Tee: build primary the same way as legacy, then add a second core for remote.
	primary, err := newZapLoggerLegacy(cfg)
	if err != nil {
		return nil, err
	}
	// Extract the single core from the legacy logger (zap always has at least one).
	cores := primary.Core()
	encCfg := loggerEncoderConfig(cfg)
	level := loggerLevel(cfg)
	encR := zapcore.NewConsoleEncoder(encCfg)
	remoteCore := zapcore.NewCore(encR, remote, level)
	return zap.New(zapcore.NewTee(cores, remoteCore)), nil
}

// NewLogger initialize logger with given config
func NewLogger(cfg *Config) (l Logger, err error) {
	l.logger, err = newZapLogger(cfg)
	return
}

// ReloadLogger replaces cfg.Logger using current cfg (e.g. after LogTargetRemote is set).
func ReloadLogger(cfg *Config) error {
	logger, err := newZapLogger(cfg)
	if err != nil {
		return err
	}
	cfg.Logger = &Logger{logger: logger}
	return nil
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
