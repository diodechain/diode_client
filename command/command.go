// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package command

import (
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/sc0vu/didyoumean"
)

var (
	ErrWrongFlag    = fmt.Errorf("wrong command line flag")
	ErrEmptyCommand = fmt.Errorf("empty command to execute")
	finalText       = `
Run 'diode COMMAND --help' for more information on a command.
`
)

// Type defines the type of command
type Type int

const (
	// OneOffCommand is a command that executes a task and quits
	OneOffCommand Type = iota
	// DaemonCommand is a command that keeps running forever
	DaemonCommand
	// EmptyConnectionCommand is a command that not require any blockchain network and executes a task and quits
	EmptyConnectionCommand
)

// Command represent command
type Command struct {
	subCommands      map[string]*Command
	Name             string
	PreRun           func() error
	Run              func() error
	PostRun          func() error
	HelpText         string
	ExampleText      string
	UsageText        string
	Flag             flag.FlagSet
	Type             Type
	SingleConnection bool
}

// AddSubCommand add subcommand to the given command, the subcommand will execute if
// not set Run in parent command
func (cmd *Command) AddSubCommand(subCmd *Command) {
	if len(subCmd.Name) > 0 && cmd.subCommands[subCmd.Name] == nil {
		if cmd.subCommands == nil {
			cmd.subCommands = make(map[string]*Command)
		}
		cmd.subCommands[subCmd.Name] = subCmd
	}
}

func (cmd *Command) subCommandsKey() []string {
	subCommandsKey := make([]string, len(cmd.subCommands))
	count := 0

	for i := range cmd.subCommands {
		subCommandsKey[count] = i
		count++
	}
	return subCommandsKey
}

// SubCommand returns the selected subcommand
func (cmd *Command) SubCommand() *Command {
	// find subcommand and run it
	commandName := cmd.Flag.Arg(0)
	// should go to help command?
	if commandName == "" {
		commandName = "publish"
	}
	subCmd := cmd.subCommands[commandName]
	if subCmd == nil || len(subCmd.Name) == 0 {
		subCommandsKey := cmd.subCommandsKey()
		didyoumean.ThresholdRate = 0.4
		mightCommandName := didyoumean.FirstMatch(commandName, subCommandsKey)
		fmt.Printf("diode: '%s' is not a diode command. See 'diode --help'.\n", commandName)
		if len(mightCommandName) > 0 {
			fmt.Printf("\nThe most similar command is\n    %s\n", mightCommandName)
		}
		return nil
	}
	return subCmd
}

// Execute will run the command
func (cmd *Command) Execute() (err error) {
	args := os.Args[1:]
	cmd.Flag.Usage = func() {
		cmd.printUsage()
	}
	err = cmd.Flag.Parse(args)
	if err != nil {
		err = nil
		return
	}
	if len(cmd.subCommands) == 0 {
		return run(cmd.PreRun, cmd.Run, cmd.PostRun)
	}

	subCmd := cmd.SubCommand()
	if subCmd == nil {
		// cmd.Flag.Usage()
		return
	}
	subCmd.Flag.Usage = func() {
		subCmd.printUsage()
	}
	args = cmd.Flag.Args()
	if len(args) > 0 {
		err = subCmd.Flag.Parse(args[1:])
	} else {
		subCmd.Flag.Parse([]string{})
	}
	if err != nil {
		err = nil
		return
	}

	return run(cmd.PreRun, subCmd.PreRun, subCmd.Run, subCmd.PostRun, cmd.PostRun)
}

// Executes the given functions in order until one of them
// returns an error
func run(funs ...func() error) error {
	for _, fun := range funs {
		if fun == nil {
			continue
		}
		if err := fun(); err != nil {
			return err
		}
	}
	return nil
}

func (cmd *Command) printUsage() {
	if len(cmd.subCommands) > 0 {
		fmt.Printf("Name\n  %s -%s\n\n", cmd.Name, cmd.HelpText)
		fmt.Printf("SYNOPSYS\n  %s", cmd.Name)
		count := 0
		cmd.Flag.VisitAll(func(flag *flag.Flag) {
			count++
			if count > 3 {
				count = 0
				fmt.Print("\n       ")
			}
			if len(flag.DefValue) < 10 {
				fmt.Printf(" [-%s=%s]", flag.Name, flag.DefValue)
			} else {
				fmt.Printf(" [-%s=%s...]", flag.Name, flag.DefValue[:7])
			}
		})
		cmd.printSubCommandDefaults(0)
	} else {
		fmt.Printf("Name\n  diode %s -%s\n\n", cmd.Name, cmd.HelpText)
		fmt.Printf("SYNOPSYS\n  diode %s <args>\n\n", cmd.Name)
		cmd.printCommandDefaults(0)
	}
}

func (cmd *Command) printSubCommandDefaults(indent int) {
	s := " COMMAND <args>\n\nCOMMANDS\n"

	subCommandsKey := cmd.subCommandsKey()
	sort.Strings(subCommandsKey)
	for _, i := range subCommandsKey {
		subCmd := cmd.subCommands[i]
		s += fmt.Sprintf("  %-10s %s\n", subCmd.Name, subCmd.HelpText)
	}
	s += finalText
	fmt.Fprint(cmd.Flag.Output(), s)
}

func (cmd *Command) printCommandDefaults(indent int) {
	s := fmt.Sprintf("%*sARGS\n", indent, "")
	count := 0
	cmd.Flag.VisitAll(func(f *flag.Flag) {
		count++
		s += fmt.Sprintf("%*s-%s", indent+2, "", f.Name) // Two spaces before -; see next two comments.
		name, usage := flag.UnquoteUsage(f)
		if len(name) > 0 {
			s += " " + name
		}
		// Boolean flags of one ASCII letter are so common we
		// treat them specially, putting their usage on the same line.
		if len(s) <= 4 { // space, space, '-', 'x'.
			s += "\t"
		} else {
			// Four spaces before the tab triggers good alignment
			// for both 4- and 8-space tab stops.
			s += "\n    \t"
		}
		s += strings.ReplaceAll(usage, "\n", "\n    \t")

		if !isZeroValue(f, f.DefValue) {
			if ok := isStringValue(f); ok {
				// put quotes on the value
				s += fmt.Sprintf(" (default %q)", f.DefValue)
			} else {
				s += fmt.Sprintf(" (default %v)", f.DefValue)
			}
		}
		s += "\n"
	})
	if count == 0 {
		s += "  Empty\n"
	}
	s += fmt.Sprintf("%*sEXAMPLE\n%*s%s\n", indent, "", indent, "", cmd.ExampleText)
	fmt.Fprint(cmd.Flag.Output(), s)
}

// isZeroValue determines whether the string represents the zero
// value for a flag.
func isZeroValue(f *flag.Flag, value string) bool {
	// Build a zero value of the flag's Value type, and see if the
	// result of calling its String method equals the value passed in.
	// This works unless the Value type is itself an interface type.
	typ := reflect.TypeOf(f.Value)
	var z reflect.Value
	if typ.Kind() == reflect.Ptr {
		z = reflect.New(typ.Elem())
	} else {
		z = reflect.Zero(typ)
	}
	return value == z.Interface().(flag.Value).String()
}

func isStringValue(f *flag.Flag) bool {
	typ := reflect.TypeOf(f.Value)
	if typ.Kind() != reflect.Ptr {
		return false

	}
	return typ.Elem().String() == "flag.stringValue"
}
