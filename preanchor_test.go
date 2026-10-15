package main

// v5 tamper suite: every rewrite class the round-five review
// demonstrated must break a v5 record, where the pre-anchor table's
// digest is bound inside the anchored leaf.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// v5Bundle upgrades the v3 fixture with a pre-anchor table whose
// digest is sealed into a v5 leaf.
func v5Bundle(t *testing.T) *artifacts.AuditBundle {
	t.Helper()
	b := v3Bundle(t)
	b.Envelope.ProgramID = "aaaa"
	b.Envelope.RouteID = "buyer-demo-test"
	b.Envelope.RegistryRecordHash = "bbbb"
	b.Payload.ContentHash = "cafe" + b.FinalVFA.AerHash[4:]
	b.AivpT4.Outcome = "release"
	b.AivpT4.AdapterID = "live-claude-api"
	b.AivpT4.PiaHash = "11" + b.FinalVFA.AerHash[2:]
	b.AivpT4.AiOutputHash = "22" + b.FinalVFA.AerHash[2:]
	b.EPA.AttestedContext = artifacts.AttestedContext{
		Attested: true, ActorID: "loan-officer-7", DecisionKind: "approve",
		DecisionResult: "approved", ModelName: "claude",
	}

	names := artifacts.PreAnchorNames
	val := map[string]string{
		"program_id":                b.Envelope.ProgramID,
		"route_id":                  b.Envelope.RouteID,
		"registry_record_hash":      b.Envelope.RegistryRecordHash,
		"clock_epoch":               b.Nrep.SignedAt,
		"attested_digest":           artifacts.ComputeAttestedContextDigest(b.EPA.AttestedContext),
		"input_hash":                b.Payload.ContentHash,
		"envelope_id":               b.Envelope.EnvelopeID,
		"envelope_hash":             b.Envelope.Seal.SealedHash,
		"transport_hash":            b.Transport.Seal.SealedHash,
		"epa_hash":                  b.EPA.Seal.SealedHash,
		"efa_hash":                  b.EFA.Seal.SealedHash,
		"aer_hash":                  b.AER.Seal.SealedHash,
		"execution_ids":             "",
		"pepg_outcome":              "allow",
		"allow_token_hash":          "",
		"deny_receipt_hash":         "",
		"aivp_outcome":              b.AivpT4.Outcome,
		"aivp_adapter_id":           b.AivpT4.AdapterID,
		"aivp_pia_hash":             b.AivpT4.PiaHash,
		"aivp_ai_output_hash":       b.AivpT4.AiOutputHash,
		"aivp_halt_receipt_hash":    b.AivpT4.HaltReceiptHash,
		"transcript_hash":           b.Transcript.Seal.SealedHash,
		"hardware_attestation_hash": b.HardwareAttestation.Seal.SealedHash,
		"leakage_bundle_hash":       b.LeakageBundle.Seal.SealedHash,
		"zksp_binding_hash":         b.ZkspBinding.Seal.SealedHash,
		"formal_verifier_status":    b.ZkspBinding.VerificationStatus,
		"migration_token_hash":      b.MigrationToken.Seal.SealedHash,
		"replay_fingerprint":        b.ReplayFingerprint.Seal.SealedHash,
		"nrep_actor_id":             b.Nrep.ActorID,
		"nrep_public_key":           b.Nrep.PublicKey,
		"nrep_signature":            b.Nrep.Signature,
		"nrep_signed_at":            b.Nrep.SignedAt,
		"scaffold_flags_hash":       artifacts.ComputeScaffoldFlagsHash(true, true, true, true),
	}
	b.PreAnchor = nil
	for _, n := range names {
		b.PreAnchor = append(b.PreAnchor, artifacts.PreAnchorEntry{Name: n, Value: val[n]})
	}
	b.PreAnchorDigest = artifacts.ComputePreAnchorDigestFromTable(b.PreAnchor)
	b.AttestedDigest = val["attested_digest"]

	preimage := joinLeafParts(leafDomainV5,
		b.Envelope.EnvelopeID, b.AER.Seal.SealedHash, b.ZkspBinding.Seal.SealedHash,
		strconv.FormatInt(int64(b.RekorAnchor.InputNonce), 10), b.PreAnchorDigest)
	sum := sha256.Sum256([]byte(preimage))
	b.RekorAnchor.LeafHashHex = hex.EncodeToString(sum[:])
	return b
}

func TestV5IntactRecordIsFullyConsistent(t *testing.T) {
	b := v5Bundle(t)
	leaf := verifyLeafBinding(b)
	if !leaf.Match || leaf.Form != leafDomainV5 {
		t.Fatalf("intact v5 record must match its anchored leaf: %+v", leaf)
	}
	pa := verifyPreAnchor(b)
	if !pa.Performed || !pa.Match {
		t.Fatalf("intact v5 table must be consistent: %+v", pa.Failures)
	}
}

func TestV5AivpOutputSwapFails(t *testing.T) {
	// The reviewer's A7 forgery, replayed against v5.
	b := v5Bundle(t)
	b.AivpT4.AiOutputHash = "33" + b.AivpT4.AiOutputHash[2:]
	if pa := verifyPreAnchor(b); pa.Match {
		t.Fatal("a swapped AI-output hash must disagree with the anchored table")
	}
}

func TestV5StoryRewriteFails(t *testing.T) {
	// The reviewer's R7 forgery: rewrite the attested decision story.
	b := v5Bundle(t)
	b.EPA.AttestedContext.DecisionKind = "deny"
	b.EPA.AttestedContext.ActorRole = "chief-risk-officer"
	if pa := verifyPreAnchor(b); pa.Match {
		t.Fatal("a rewritten attested story must disagree with the anchored table")
	}
}

func TestV5PayloadSwapFails(t *testing.T) {
	b := v5Bundle(t)
	b.Payload.ContentHash = "dead" + b.Payload.ContentHash[4:]
	if pa := verifyPreAnchor(b); pa.Match {
		t.Fatal("a swapped payload hash must disagree with the anchored table")
	}
}

func TestV5TableRewriteBreaksTheLeaf(t *testing.T) {
	// Editing the table itself (with the record aligned to it) must
	// break the anchored leaf: that is the whole point of v5.
	b := v5Bundle(t)
	for i := range b.PreAnchor {
		if b.PreAnchor[i].Name == "aivp_ai_output_hash" {
			b.PreAnchor[i].Value = "4444"
			b.AivpT4.AiOutputHash = "4444"
		}
	}
	b.PreAnchorDigest = artifacts.ComputePreAnchorDigestFromTable(b.PreAnchor)
	if leaf := verifyLeafBinding(b); leaf.Match {
		t.Fatal("a rewritten table must break the anchored leaf")
	}
}

func TestV5TableShapeIsFrozen(t *testing.T) {
	b := v5Bundle(t)
	b.PreAnchor = b.PreAnchor[:len(b.PreAnchor)-1]
	if pa := verifyPreAnchor(b); pa.Match {
		t.Fatal("a truncated table must fail the shape check")
	}
}

func TestReviewerFixturesRegression(t *testing.T) {
	// The round-five fixtures, kept verbatim as third-party
	// regression tests. R5 fails on every generation; A7 and R7 are
	// v3-era records whose verdict may not claim full coverage.
	for name, wantCross := range map[string]bool{
		"A7_aivp_output_hash_swapped": false,
		"R5_payload_hash_replaced":    true,
		"R7_story_rewrite":            false,
	} {
		b := loadBundleFixture(t, name+".json")
		cross := verifyCrossGeneration(b)
		if (len(cross) > 0) != wantCross {
			t.Fatalf("%s: cross-check failures = %v, want failing=%v", name, cross, wantCross)
		}
		if pa := verifyPreAnchor(b); pa.Performed {
			t.Fatalf("%s: a pre-v5 record must report partial coverage, not a table verdict", name)
		}
	}
}

func loadBundleFixture(t *testing.T, name string) *artifacts.AuditBundle {
	t.Helper()
	raw, err := os.ReadFile("internal/artifacts/testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var b artifacts.AuditBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return &b
}
