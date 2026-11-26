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
	if testStandinLogSeed != standinLogSeed || testStandinSignerSeed != standinSignerSeed || testStandinCopyStatementSeed != standinCopyStatementSeed {
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

// Round 65, N40: the stand-in build pins the rehearsal's copy-statement key
// beside the machine's, under a label that says test build, so a rehearsal
// checks --copy-statement on the copy its server keeps.
func TestStandInBuildPinsTheStandInCopyStatementKey(t *testing.T) {
	_, fp := standinPEM(&standinKey(testStandinCopyStatementSeed).PublicKey)
	k, pinned := copyStatementKeys[fp]
	if !pinned || !strings.Contains(k.Label, "test build only") {
		t.Fatalf("stand-in copy-statement key pinned=%v label=%q", pinned, k.Label)
	}
	if _, machine := copyStatementKeys["93a6eb8db2b50f62c462cc92e588e9f3bd98668c81e8cffad4f7dd4f4c2afe7e"]; !machine {
		t.Fatal("the stand-in build dropped the machine's copy-statement key")
	}
}
