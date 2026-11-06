package main

import (
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A flag missing from --help is a flag a reader never finds. Round 55 found
// --signer-key missing from the help text the docs pointed to.
func TestHelpListsEveryFlag(t *testing.T) {
	if os.Getenv("VERDIFAX_PRINT_USAGE") == "1" {
		printUsage()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHelpListsEveryFlag")
	cmd.Env = append(os.Environ(), "VERDIFAX_PRINT_USAGE=1")
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		t.Fatal(runErr)
	}
	fs := flag.NewFlagSet("usage", flag.ContinueOnError)
	defineFlags(fs)
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(string(out), "-"+f.Name) {
			t.Errorf("--help does not list -%s", f.Name)
		}
	})
}
