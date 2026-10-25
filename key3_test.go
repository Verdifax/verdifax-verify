package main

// Log-signing key rotation (2026-10-24): key 1, a file on the server
// volume, is accepted only for entries logged before the switch; key 3,
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

// At the switch second itself exactly one key is accepted: key 3. No
// moment exists at which both keys, or neither, may vouch for an entry
// (round 34 noted that v0.17.0 accepted both at that one second).
func TestExactlyOneKeyIsAcceptedAroundTheSwitch(t *testing.T) {
	k1 := pinnedEntrySigners[verdifaxLogSigningKey1Fingerprint]
	k3 := pinnedEntrySigners[verdifaxLogSigningKey3Fingerprint]
	if signerAcceptsAt(k1, keySwitchUnix) {
		t.Fatal("key 1 must not be accepted at the switch second")
	}
	for _, at := range []int64{keySwitchUnix - 1, keySwitchUnix, keySwitchUnix + 1} {
		if signerAcceptsAt(k1, at) == signerAcceptsAt(k3, at) {
			t.Fatalf("at %d exactly one of key 1 and key 3 must be accepted", at)
		}
	}
}

// Key 2's window still contains the hardware run's single entry.
func TestKey2StillAcceptsTheHardwareRunEntry(t *testing.T) {
	k2 := pinnedEntrySigners[verdifaxLogSigningKey2Fingerprint]
	if !signerAcceptsAt(k2, 1791039647) || signerAcceptsAt(k2, 1791039647+3600) {
		t.Fatal("key 2 must accept the hardware run's entry and nothing from an hour after it")
	}
}

// The only seconds accepted by two keys are key 2's documented window
// around the hardware run's entry, which lies inside key 1's period; no
// handover overlaps and no second up to well past the switch is accepted
// by no key. A new key or a changed period that adds any other overlap
// or gap fails here.
func TestKeyPeriodsOverlapOnlyInKey2sDocumentedWindow(t *testing.T) {
	k2 := pinnedEntrySigners[verdifaxLogSigningKey2Fingerprint]
	key1Era := pinnedEntrySigners[verdifaxLogSigningKey1Fingerprint]
	checkpoints := map[int64]bool{}
	for _, k := range pinnedEntrySigners {
		for _, edge := range []int64{k.NotBefore, k.NotAfter} {
			if edge != 0 {
				checkpoints[edge-1], checkpoints[edge], checkpoints[edge+1] = true, true, true
			}
		}
	}
	checkpoints[keySwitchUnix+86400*365] = true
	for at := range checkpoints {
		accepted := 0
		for _, k := range pinnedEntrySigners {
			if signerAcceptsAt(k, at) {
				accepted++
			}
		}
		inKey2Window := signerAcceptsAt(k2, at)
		switch {
		case accepted == 0:
			t.Fatalf("no key is accepted at %d", at)
		case accepted == 2 && !(inKey2Window && signerAcceptsAt(key1Era, at)):
			t.Fatalf("two keys are accepted at %d outside key 2's documented window", at)
		case accepted > 2:
			t.Fatalf("%d keys are accepted at %d", accepted, at)
		case accepted == 1 && inKey2Window:
			t.Fatalf("key 2's window at %d is no longer inside key 1's period", at)
		}
	}
	if k2.NotAfter-k2.NotBefore != 7200 {
		t.Fatalf("key 2's window is %d seconds, documented as one hour either side", k2.NotAfter-k2.NotBefore)
	}
}
