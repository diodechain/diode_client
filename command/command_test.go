package command

import (
	"bytes"
	"os"
	"strings"
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

func TestExecuteSkipParentHooksForHiddenSubcommand(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	root := &Command{Name: "diode"}
	var rootRan bool
	root.PreRun = func() error {
		rootRan = true
		return nil
	}

	var subRan bool
	sub := &Command{
		Name:            "ssh-proxy",
		Hidden:          true,
		SkipParentHooks: true,
		Run: func() error {
			subRan = true
			return nil
		},
	}
	root.AddSubCommand(sub)

	os.Args = []string{"diode", "ssh-proxy"}
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if rootRan {
		t.Fatalf("did not expect root hooks to run for hidden internal command")
	}
	if !subRan {
		t.Fatalf("expected hidden internal command to run")
	}
}

func TestHiddenSubcommandsAreOmittedFromUsage(t *testing.T) {
	root := &Command{Name: "diode"}
	var out bytes.Buffer
	root.Flag.SetOutput(&out)

	root.AddSubCommand(&Command{Name: "visible", HelpText: "shown"})
	root.AddSubCommand(&Command{Name: "ssh-proxy", HelpText: "hidden", Hidden: true})

	root.printSubCommandDefaults(0)
	usage := out.String()
	if !strings.Contains(usage, "visible") {
		t.Fatalf("expected visible subcommand in usage: %q", usage)
	}
	if strings.Contains(usage, "ssh-proxy") {
		t.Fatalf("did not expect hidden subcommand in usage: %q", usage)
	}
}
