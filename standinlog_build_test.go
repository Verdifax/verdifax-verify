//go:build standinlog

package main

import (
	"strings"
	"testing"
)

// The stand-in build accepts a genuine stand-in entry, pins the stand-in
// signer under a name that says test build, and names itself in its version.
func TestStandInBuildTrustsTheStandInLog(t *testing.T) {
	if toolVersion() != Version+"+standinlog" {
		t.Fatalf("version %s", toolVersion())
	}
	if testStandinLogSeed != standinLogSeed || testStandinSignerSeed != standinSignerSeed {
		t.Fatal("the test seeds differ from the build's seeds")
	}
	l := standinTestLog(t)
	k, pinned := pinnedEntrySigners[signerFingerprint(t, l.signer)]
	if !pinned || !k.TestOnly || !strings.Contains(k.Name, "test build only") {
		t.Fatalf("stand-in signer pinned=%v name=%q", pinned, k.Name)
	}
	a := l.entry(t, hexOf("record"), hexOf("leaf"))
	if err := rekorAnchorVerifier(anchorInputOf(a)); err != nil {
		t.Fatalf("the stand-in build refuses a stand-in entry: %v", err)
	}
	a.IntegratedTime++
	if rekorAnchorVerifier(anchorInputOf(a)) == nil {
		t.Fatal("the stand-in build accepts a changed entry")
	}
}
