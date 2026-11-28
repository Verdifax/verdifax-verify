package main

import (
	"bytes"
	"strings"
	"testing"
)

// --log-keys lists every pinned log-signing key with its fingerprint, its
// name and its acceptance window, so a client can check a server's key is
// trusted before relying on its records (round 62).
func TestLogKeysListsEveryPinnedKey(t *testing.T) {
	var out bytes.Buffer
	printLogKeys(&out)
	text := out.String()
	for fp, k := range pinnedEntrySigners {
		line := ""
		for _, l := range strings.Split(text, "\n") {
			if strings.HasPrefix(l, fp+"  ") {
				line = l
			}
		}
		if line == "" || !strings.Contains(line, k.Name) || !strings.Contains(line, "accepted from ") {
			t.Errorf("key %s is not listed with its name and window: %q", k.Name, line)
		}
	}
	if !strings.Contains(text, verdifaxLogSigningKey3Fingerprint+"  Verdifax log-signing key 3 (AWS KMS)  accepted from 2026-10-24T15:59:19Z until always") {
		t.Errorf("key 3's line is wrong:\n%s", text)
	}
	if strings.Count(strings.TrimSpace(text), "\n")+1 != len(pinnedEntrySigners)+len(copyStatementKeys) {
		t.Errorf("%d lines for %d keys:\n%s", strings.Count(strings.TrimSpace(text), "\n")+1, len(pinnedEntrySigners)+len(copyStatementKeys), text)
	}
	// Round 66, N49: one inventory. Every key is listed with its custody,
	// purpose and first use, the copy-statement key among them.
	for fp, k := range pinnedEntrySigners {
		if k.TestOnly {
			continue
		}
		if k.Custody == "" || k.Purpose == "" || k.FirstUse == "" {
			t.Errorf("%s has no custody, purpose or first use for --keys", k.Name)
		}
		if !strings.Contains(text, fp+"  "+k.Name+"  accepted from ") {
			t.Errorf("%s is not listed", k.Name)
		}
	}
	for fp, k := range copyStatementKeys {
		if !strings.Contains(text, fp+"  "+k.Name+"  accepted from ") || !strings.Contains(text, "custody: "+k.Custody) {
			t.Errorf("copy-statement key %s is not listed with its period and custody:\n%s", fp, text)
		}
	}
}

// Key 4, the hardware-attested machine's KMS key, is accepted from the
// moment KMS created it and never before (round 62).
func TestKey4IsAcceptedFromItsCreation(t *testing.T) {
	k, pinned := pinnedEntrySigners[verdifaxLogSigningKey4Fingerprint]
	if !pinned {
		t.Fatal("key 4 is not pinned")
	}
	if signerAcceptsAt(k, key4CreatedUnix-1) {
		t.Error("key 4 vouches for an entry logged before it existed")
	}
	if !signerAcceptsAt(k, key4CreatedUnix) || !signerAcceptsAt(k, key4CreatedUnix+10*365*24*3600) {
		t.Error("key 4 must be accepted from its creation with no end date")
	}
	if k.NotAfter != 0 {
		t.Errorf("key 4 has an end date %d; it was decided to have none", k.NotAfter)
	}
}
