package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Round 59 (owner decision, November 12, 2026): an intact, completely
// anchored record whose rule requires a person's sign-off reads ANCHORED,
// SIGN-OFF NOT SHOWN and exits 4 when no sign-offs are given, never VERIFIED
// and never 0; --strict-signoff makes it FAILED, exit 1. A sign-off given
// without the history, a rejection in force and a left-out sign-off fail
// with exit 1 whatever the flags, and the whole evidence verifies with 0.
// Run 3235 is a production readiness record of November 12, 2026.
func TestARequiredSignOffNotShownHasItsOwnVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "verdifax-verify")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build: %v\n%s", buildErr, out)
	}
	dir := filepath.Join("testdata", "round59")
	record := filepath.Join(dir, "run-3235-signoff-required.json")
	signoffs := filepath.Join(dir, "run-3235-signoffs.json")
	atReject := filepath.Join(dir, "run-3235-signoffs-at-reject.json")
	history := filepath.Join(dir, "account-500-signoff-history.json")
	cases := []struct {
		name   string
		args   []string
		want   int
		stdout string
	}{
		{"no sign-offs given", []string{record}, 4, "VERDICT: ⚠ ANCHORED, SIGN-OFF NOT SHOWN"},
		{"no sign-offs given, JSON", []string{"--json", record}, 4, `"verdict_tier":"ANCHORED_SIGNOFF_NOT_SHOWN"`},
		{"no sign-offs given, strict", []string{"--strict-signoff", record}, 1, "VERDICT: ✗ FAILED"},
		{"sign-offs without the history", []string{"--signoff", signoffs, record}, 1, "VERDICT: ✗ FAILED"},
		{"the job's approval left out", []string{"--signoff", atReject, "--signoff-history", history, record}, 1, "VERDICT: ✗ FAILED"},
		{"the whole evidence", []string{"--signoff", signoffs, "--signoff-history", history, record}, 0, "VERDICT: ✓ VERIFIED AND ANCHORED"},
		{"the whole evidence, strict", []string{"--strict-signoff", "--signoff", signoffs, "--signoff-history", history, record}, 0, "VERDICT: ✓ VERIFIED AND ANCHORED"},
		// Round 61, N24: the history's head is past a limit it is checked
		// against, so it fails and says to fetch the history again.
		{"the whole evidence, head past its limit", []string{"--signoff-head-max-age", "1s", "--signoff", signoffs, "--signoff-history", history, record}, 1,
			"the head statement is older than the limit; fetch the history again"},
	}
	// The stored history's head is of November 12, 2026: the cases that
	// pass check it with a limit wide enough for any later day.
	for i := range cases {
		if cases[i].want == 0 || strings.Contains(cases[i].name, "left out") {
			cases[i].args = append([]string{"--signoff-head-max-age", "876000h"}, cases[i].args...)
		}
	}
	for _, c := range cases {
		out, runErr := exec.Command(bin, c.args...).Output()
		code := 0
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			code = exitErr.ExitCode()
		} else if runErr != nil {
			t.Fatalf("%s: %v", c.name, runErr)
		}
		if code != c.want || !strings.Contains(string(out), c.stdout) {
			t.Errorf("%s: exit %d, want %d and %q in:\n%s", c.name, code, c.want, c.stdout, out)
		}
	}
}
