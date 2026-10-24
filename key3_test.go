package main

// Log-signing key rotation (2026-10-24): key 1, a file on the server
// volume, is accepted only for entries logged up to the switch; key 3,
// held in AWS KMS, only for entries logged from the switch on.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestKey3IsPinnedWithItsPublishedFingerprint(t *testing.T) {
	k, ok := pinnedEntrySigners[verdifaxLogSigningKey3Fingerprint]
	if !ok {
		t.Fatal("key 3 must be a published Verdifax log-signing key")
	}
	block, _ := pem.Decode([]byte(k.PEM))
	sum := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(sum[:]) != "df009371c140e355d6c9dd46b29ed7fb37ff835bf94192a1f13bded66c92a54f" {
		t.Fatal("key 3's PEM must match its published fingerprint")
	}
	if k.NotBefore != keySwitchUnix || k.NotAfter != 0 {
		t.Fatalf("key 3 must be accepted from the switch on, open-ended: %+v", k)
	}
}

func TestKey1IsRefusedForEntriesLoggedAfterTheSwitch(t *testing.T) {
	k := pinnedEntrySigners[verdifaxLogSigningKey1Fingerprint]
	if k.NotAfter != keySwitchUnix {
		t.Fatalf("key 1 must stop at the switch: %+v", k)
	}
	if signerAcceptsAt(k, keySwitchUnix+1) {
		t.Fatal("an entry signed by key 1 after the switch must be refused")
	}
	// Run 253's entries, logged 2026-10-19, stay valid.
	if !signerAcceptsAt(k, 1792373100) {
		t.Fatal("key 1 entries logged before the switch must stay valid")
	}
}

func TestKey3IsRefusedForEntriesLoggedBeforeTheSwitch(t *testing.T) {
	k := pinnedEntrySigners[verdifaxLogSigningKey3Fingerprint]
	if signerAcceptsAt(k, keySwitchUnix-1) {
		t.Fatal("an entry signed by key 3 before the switch must be refused")
	}
	if !signerAcceptsAt(k, keySwitchUnix) || !signerAcceptsAt(k, keySwitchUnix+86400*365) {
		t.Fatal("key 3 must be accepted from the switch on")
	}
}

func TestKeySwitchIsTheDocumentedMoment(t *testing.T) {
	// 2026-10-24T15:59:19Z, when production restarted signing with key 3.
	if keySwitchUnix != 1792857559 {
		t.Fatalf("keySwitchUnix = %d", keySwitchUnix)
	}
}
