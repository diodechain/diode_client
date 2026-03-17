package command

import (
	"os"
	"testing"
)

func TestExecutePassThroughSubcommandAllowsUnknownFlags(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	root := &Command{Name: "diode"}
	var ran bool
	sub := &Command{
		Name:            "ssh",
		PassThroughArgs: true,
		Run: func() error {
			ran = true
			return nil
		},
	}
	root.AddSubCommand(sub)

	os.Args = []string{"diode", "ssh", "-p", "2222", "host.diode"}
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !ran {
		t.Fatalf("expected pass-through subcommand to run")
	}
}

func TestExecutePassThroughSubcommandHelp(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	root := &Command{Name: "diode"}
	var ran bool
	sub := &Command{
		Name:            "ssh",
		PassThroughArgs: true,
		Run: func() error {
			ran = true
			return nil
		},
	}
	root.AddSubCommand(sub)

	os.Args = []string{"diode", "ssh", "--help"}
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if ran {
		t.Fatalf("did not expect help-only invocation to run the command")
	}
}
