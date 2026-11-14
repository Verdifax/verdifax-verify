package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/rekorverify"
)

// The stand-in log's seeds, as the orchestrator's internal/standinlog holds
// them; R284 keeps the three copies equal.
const (
	testStandinLogSeed    = "verdifax stand-in public log key, test use only"
	testStandinSignerSeed = "verdifax stand-in log entry signer, test use only"
)

// standinTestLog is a test log with the stand-in's seed-derived keys.
func standinTestLog(t *testing.T) *testLog {
	t.Helper()
	derive := func(seed string) *ecdsa.PrivateKey {
		sum := sha256.Sum256([]byte(seed))
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	l := &testLog{key: derive(testStandinLogSeed), signer: derive(testStandinSignerSeed)}
	l.logID = signerFingerprint(t, l.key)
	return l
}

func hexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func anchorInputOf(a *artifacts.BundleAnchor) rekorverify.AnchorInput {
	return rekorverify.AnchorInput{
		LeafHashHex: a.LeafHashHex, EntryBody: a.EntryBody, LogIndex: a.LogIndex, TreeSize: a.TreeSize,
		RootHashHex: a.RootHashHex, InclusionPath: a.InclusionPath, Checkpoint: a.Checkpoint, LogID: a.LogID,
		LogEntryID: a.LogEntryID, IntegratedTime: a.IntegratedTime, SignedEntryTimestamp: a.SignedEntryTimestamp,
	}
}
