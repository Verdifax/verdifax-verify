//go:build !standinlog

package main

import "testing"

// R284: a release build trusts neither stand-in key, names no build flavor,
// and fails a genuine stand-in entry, so the public seeds can never vouch
// for a record checked with a released verifier.
func TestReleaseBuildTrustsNoStandInLog(t *testing.T) {
	if buildFlavor != "" || toolVersion() != Version {
		t.Fatalf("a release build reports flavor %q and version %s", buildFlavor, toolVersion())
	}
	l := standinTestLog(t)
	if _, pinned := pinnedEntrySigners[signerFingerprint(t, l.signer)]; pinned {
		t.Fatal("a release build pins the stand-in entry signer")
	}
	for _, k := range pinnedEntrySigners {
		if k.TestOnly {
			t.Fatalf("a release build pins a test-only key: %s", k.Name)
		}
	}
	a := l.entry(t, hexOf("record"), hexOf("leaf"))
	if err := rekorAnchorVerifier(anchorInputOf(a)); err == nil {
		t.Fatal("a release build accepts an entry on the stand-in log")
	}
}
