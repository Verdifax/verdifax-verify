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
	if strings.Count(strings.TrimSpace(text), "\n")+1 != len(pinnedEntrySigners) {
		t.Errorf("%d lines for %d keys:\n%s", strings.Count(strings.TrimSpace(text), "\n")+1, len(pinnedEntrySigners), text)
	}
}
