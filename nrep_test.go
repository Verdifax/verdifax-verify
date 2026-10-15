package main

// Tests for the offline NREP actor-signature check.
//
// The signing side here mirrors the orchestrator's internal/nrep
// kernel: sign the canonical preimage with a fresh Ed25519 key, seal
// the four fields into a bundle, and confirm the verifier accepts it.
// Every mutation test then proves the check actually gates on the
// thing it claims to gate on, per the house rule that a test for a
// fix must fail when the fix is mutated.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// signedBundle builds a minimal bundle whose nrep section carries a
// genuine signature over the bundle's own envelope_id and aer_hash.
func signedBundle(t *testing.T) (*artifacts.AuditBundle, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	b := &artifacts.AuditBundle{}
	b.Envelope.EnvelopeID = "env-test-0123456789abcdef"
	b.FinalVFA.AerHash = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	const actorID = "api-key-test"
	const signedAt = "2026-10-15T18:00:00.000000000Z"
	sig := ed25519.Sign(priv, nrepPreimage(b.Envelope.EnvelopeID, b.FinalVFA.AerHash, actorID, signedAt))
	b.Nrep = artifacts.NrepSection{
		ActorID:   actorID,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Signature: base64.StdEncoding.EncodeToString(sig),
		SignedAt:  signedAt,
	}
	return b, priv
}

func TestNrepSignatureVerifies(t *testing.T) {
	b, _ := signedBundle(t)
	c := verifyNrepSignature(b)
	if !c.Performed || !c.Match {
		t.Fatalf("genuine signature should verify: %+v", c)
	}
	if c.ActorID != "api-key-test" {
		t.Fatalf("actor id not surfaced: %+v", c)
	}
}

func TestNrepFlippedSignatureFails(t *testing.T) {
	b, _ := signedBundle(t)
	raw, _ := base64.StdEncoding.DecodeString(b.Nrep.Signature)
	raw[0] ^= 0x01
	b.Nrep.Signature = base64.StdEncoding.EncodeToString(raw)
	c := verifyNrepSignature(b)
	if !c.Performed || c.Match {
		t.Fatalf("flipped signature must fail: %+v", c)
	}
}

func TestNrepTamperedSignedAtFails(t *testing.T) {
	// The clock is outside every hash; the signature alone must catch
	// a backdated or altered signed_at.
	b, _ := signedBundle(t)
	b.Nrep.SignedAt = "2026-10-15T17:59:59.000000000Z"
	c := verifyNrepSignature(b)
	if !c.Performed || c.Match {
		t.Fatalf("tampered signed_at must fail: %+v", c)
	}
}

func TestNrepTamperedAerHashFails(t *testing.T) {
	// A signature lifted onto a different run's record must not verify.
	b, _ := signedBundle(t)
	b.FinalVFA.AerHash = "0000000000000000000000000000000000000000000000000000000000000000"
	c := verifyNrepSignature(b)
	if !c.Performed || c.Match {
		t.Fatalf("signature over a different aer_hash must fail: %+v", c)
	}
}

func TestNrepWrongKeyFails(t *testing.T) {
	b, _ := signedBundle(t)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	b.Nrep.PublicKey = base64.StdEncoding.EncodeToString(otherPub)
	c := verifyNrepSignature(b)
	if !c.Performed || c.Match {
		t.Fatalf("signature against the wrong key must fail: %+v", c)
	}
}

func TestNrepEmptySectionIsNotAFailure(t *testing.T) {
	b := &artifacts.AuditBundle{}
	b.Envelope.EnvelopeID = "env-x"
	b.FinalVFA.AerHash = "aa"
	c := verifyNrepSignature(b)
	if c.Performed {
		t.Fatalf("empty section must report no claim, not a verdict: %+v", c)
	}
}

func TestNrepPartialSectionFails(t *testing.T) {
	b, _ := signedBundle(t)
	b.Nrep.PublicKey = ""
	c := verifyNrepSignature(b)
	if !c.Performed || c.Match {
		t.Fatalf("partial section must fail: %+v", c)
	}
}

func TestNrepGoldenBundlePredatesSignedAt(t *testing.T) {
	// The golden production bundle carries a real signature sealed
	// before signed_at shipped, so the honest verdict is "present,
	// not offline-verifiable", distinct from pass and from fail, and
	// it must not flip the overall verdict.
	b := goldenBundle(t)
	if b.Nrep.ActorID == "" || b.Nrep.Signature == "" {
		t.Skip("golden bundle carries no actor signature; nothing to assert")
	}
	if b.Nrep.SignedAt != "" {
		t.Skip("golden bundle gained signed_at; this legacy-state test no longer applies")
	}
	c := verifyNrepSignature(b)
	if c.Performed {
		t.Fatalf("pre-signed_at bundle must report not-verifiable, got a verdict: %+v", c)
	}
	if c.ActorID != b.Nrep.ActorID {
		t.Fatalf("actor id should surface in the not-verifiable state: %+v", c)
	}
}

func TestNrepForgedSectionIsConsistentNotIdentity(t *testing.T) {
	// Encodes the 2026-10-15 external forgery demonstration as a
	// permanent boundary test: an attacker who replaces the WHOLE
	// nrep section, their own actor name, their own key, their own
	// signature over this run's real envelope_id and aer_hash,
	// produces a section this check finds consistent, because the
	// key comes from the bundle and nothing sealed covers the
	// section yet. The check MUST therefore never present Match as
	// identity: KeyPinned and Sealed must both be false until
	// registry pinning and section sealing actually land, at which
	// point this test gets rewritten, not deleted.
	b, _ := signedBundle(t)
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	const forgedActor = "chief-risk-officer@victim-bank.example"
	const forgedClock = "2026-10-15T13:00:00.000000000Z"
	sig := ed25519.Sign(attackerPriv,
		nrepPreimage(b.Envelope.EnvelopeID, b.FinalVFA.AerHash, forgedActor, forgedClock))
	b.Nrep = artifacts.NrepSection{
		ActorID:   forgedActor,
		PublicKey: base64.StdEncoding.EncodeToString(attackerPub),
		Signature: base64.StdEncoding.EncodeToString(sig),
		SignedAt:  forgedClock,
	}
	c := verifyNrepSignature(b)
	if !c.Performed || !c.Match {
		t.Fatalf("forged-but-self-consistent section is expected to pass consistency: %+v", c)
	}
	if c.KeyPinned || c.Sealed {
		t.Fatalf("nothing may claim pinning or sealing yet: %+v", c)
	}
}
