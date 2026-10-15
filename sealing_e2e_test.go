package main

// End-to-end tests of the version-3 anchored sealing: these encode
// the external reviewer's two forgeries (actor replacement, scaffold
// flag clearing) and prove both now break the anchored leaf.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// v3Bundle builds a minimal bundle whose anchored leaf uses the v3
// form over its own section contents, the way the orchestrator now
// anchors every pipeline run.
func v3Bundle(t *testing.T) *artifacts.AuditBundle {
	t.Helper()
	b, _ := signedBundle(t) // genuine nrep section over envelope+aer
	b.AER.Seal.SealedHash = b.FinalVFA.AerHash
	b.ZkspBinding.Seal.SealedHash = "b1" + b.FinalVFA.AerHash[2:]
	b.Transcript.Scaffold.IsScaffold = true
	b.HardwareAttestation.Scaffold.IsScaffold = true
	b.ZkspBinding.Scaffold.IsScaffold = true
	b.LeakageBundle.Scaffold.IsScaffold = true

	b.NrepSectionHash = artifacts.ComputeNrepSectionHash(
		b.Nrep.ActorID, b.Nrep.PublicKey, b.Nrep.Signature, b.Nrep.SignedAt)
	b.ScaffoldFlagsHash = artifacts.ComputeScaffoldFlagsHash(true, true, true, true)

	b.RuntimeTiming = []artifacts.StageTiming{
		{Stage: "dtl", DurationNanos: 120000},
		{Stage: "aer", DurationNanos: 340000},
	}
	b.RuntimeTimingHash = artifacts.ComputeRuntimeTimingHash(b.RuntimeTiming)

	b.RekorAnchor.Backend = "rekor"
	b.RekorAnchor.InputNonce = 424242
	preimage := joinLeafParts(leafDomainV3,
		b.Envelope.EnvelopeID, b.AER.Seal.SealedHash, b.ZkspBinding.Seal.SealedHash,
		strconv.FormatInt(b.RekorAnchor.InputNonce, 10),
		b.NrepSectionHash, b.ScaffoldFlagsHash)
	sum := sha256.Sum256([]byte(preimage))
	b.RekorAnchor.LeafHashHex = hex.EncodeToString(sum[:])
	return b
}

func TestV3IntactBundleSealsActorAndFlags(t *testing.T) {
	b := v3Bundle(t)
	leaf := verifyLeafBinding(b)
	if !leaf.Performed || !leaf.Match || leaf.Form != leafDomainV3 {
		t.Fatalf("intact v3 bundle must match its anchored leaf: %+v", leaf)
	}
	nrep := verifyNrepSignature(b, leaf)
	if !nrep.Match || !nrep.Sealed {
		t.Fatalf("genuine signature under a matched v3 leaf must report sealed: %+v", nrep)
	}
	if nrep.KeyPinned {
		t.Fatalf("nothing may claim key pinning yet: %+v", nrep)
	}
	timing := verifyRuntimeTiming(b)
	if !timing.Performed || !timing.Match || timing.Stages != 2 {
		t.Fatalf("intact timing must verify: %+v", timing)
	}
}

func TestV3ActorReplacementBreaksTheAnchor(t *testing.T) {
	// The reviewer's forgery, replayed against the sealed format: a
	// wholesale self-consistent replacement of the actor section.
	b := v3Bundle(t)
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	const forgedActor = "chief-risk-officer@victim-bank.example"
	const forgedClock = "2026-10-15T14:00:00.000000000Z"
	sig := ed25519.Sign(attackerPriv,
		nrepPreimage(b.Envelope.EnvelopeID, b.FinalVFA.AerHash, forgedActor, forgedClock))
	b.Nrep = artifacts.NrepSection{
		ActorID:   forgedActor,
		PublicKey: base64.StdEncoding.EncodeToString(attackerPub),
		Signature: base64.StdEncoding.EncodeToString(sig),
		SignedAt:  forgedClock,
	}
	// The attacker can rewrite every unanchored field, including the
	// stored digest; the recomputed digest still diverges from the
	// one inside the anchored leaf.
	b.NrepSectionHash = artifacts.ComputeNrepSectionHash(
		b.Nrep.ActorID, b.Nrep.PublicKey, b.Nrep.Signature, b.Nrep.SignedAt)

	leaf := verifyLeafBinding(b)
	if leaf.Match {
		t.Fatal("a replaced actor section must break the anchored leaf")
	}
	nrep := verifyNrepSignature(b, leaf)
	if nrep.Sealed {
		t.Fatalf("a forged section must never report sealed: %+v", nrep)
	}
}

func TestV3ClearedScaffoldFlagBreaksTheAnchor(t *testing.T) {
	// The reviewer's second forgery: clearing placeholder flags.
	b := v3Bundle(t)
	b.HardwareAttestation.Scaffold.IsScaffold = false
	b.ScaffoldFlagsHash = artifacts.ComputeScaffoldFlagsHash(true, false, true, true)
	leaf := verifyLeafBinding(b)
	if leaf.Match {
		t.Fatal("a cleared scaffold flag must break the anchored leaf")
	}
}

func TestTimingTamperFailsTheBundleSeal(t *testing.T) {
	b := v3Bundle(t)
	b.RuntimeTiming[0].DurationNanos = 1
	timing := verifyRuntimeTiming(b)
	if timing.Match {
		t.Fatal("an edited duration must fail the timing digest")
	}
}
