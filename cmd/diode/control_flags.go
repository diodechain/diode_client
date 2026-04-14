package main

import (
	"flag"

	"github.com/diodechain/diode_client/cmd/diode/internal/control"
)

type stagedControlFlag struct {
	batch    *control.Batch
	key      string
	boolFlag bool
}

func (f *stagedControlFlag) String() string {
	return ""
}

func (f *stagedControlFlag) Set(value string) error {
	f.batch.Add(f.key, value)
	return nil
}

func (f *stagedControlFlag) IsBoolFlag() bool {
	return f.boolFlag
}

func registerControlStringFlag(fs *flag.FlagSet, batch *control.Batch, name string, usage string, key string) {
	fs.Var(&stagedControlFlag{batch: batch, key: key}, name, usage)
}

func registerControlBoolFlag(fs *flag.FlagSet, batch *control.Batch, name string, usage string, key string) {
	fs.Var(&stagedControlFlag{batch: batch, key: key, boolFlag: true}, name, usage)
}
