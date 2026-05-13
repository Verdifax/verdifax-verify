package artifacts

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildAuditBundleDeterministic verifies that the same input produces
// byte-identical canonical bytes across two builds. This is the load-bearing
// property — without it the audit projection cannot be re-verified.
func TestBuildAuditBundleDeterministic(t *testing.T) {
	in := sampleInput()
	b1 := BuildAuditBundle(in)
	b2 := BuildAuditBundle(in)

	// We cannot compare GeneratedAt across two builds because the builder
	// stamps time.Now(). All other fields must be identical.
	b1.GeneratedAt = ""
	b2.GeneratedAt = ""
	b1.Envelope.Timestamp = ""
	b2.Envelope.Timestamp = ""
	b1.EPA.EnvironmentSnapshot.Time = ""
	b2.EPA.EnvironmentSnapshot.Time = ""
	// Recompute hashes after stripping time so we can compare cleanly.
	b1.BundleHash = ""
	b2.BundleHash = ""

	j1, _ := json.Marshal(b1)
	j2, _ := json.Marshal(b2)
	if string(j1) != string(j2) {
		t.Fatalf("audit bundle is not deterministic across two builds:\nrun1: %s\nrun2: %s", j1, j2)
	}
}

func TestBuildAuditBundleHasAllFourteenArtifacts(t *testing.T) {
	b := BuildAuditBundle(sampleInput())
	checks := map[string]string{
		"payload":              b.Payload.Hash,
		"envelope":             b.Envelope.Hash,
		"transport":            b.Transport.Hash,
		"epa":                  b.EPA.Hash,
		"efa":                  b.EFA.Hash,
		"aer":                  b.AER.Hash,
		"transcript":           b.Transcript.Hash,
		"hardware_attestation": b.HardwareAttestation.Hash,
		"leakage_bundle":       b.LeakageBundle.Hash,
		"zksp_binding":         b.ZkspBinding.Hash,
		"migration_token":      b.MigrationToken.Hash,
		"replay_fingerprint":   b.ReplayFingerprint.Hash,
		"pote_proof":           b.PoteProof.Hash,
		"final_vfa":            b.FinalVFA.Hash,
	}
	for name, h := range checks {
		if len(h) != 64 {
			t.Errorf("artifact %s has hash of len %d (want 64): %q", name, len(h), h)
		}
	}
	if len(b.BundleHash) != 64 {
		t.Errorf("bundle hash len %d, want 64", len(b.BundleHash))
	}
}

func TestSealReferenceMatchesManifest(t *testing.T) {
	in := sampleInput()
	b := BuildAuditBundle(in)
	// Each artifact's seal must point to the same manifest_hash.
	seals := []SealReference{
		b.Envelope.Seal, b.Transport.Seal, b.EPA.Seal, b.EFA.Seal, b.AER.Seal,
		b.Transcript.Seal, b.HardwareAttestation.Seal, b.LeakageBundle.Seal,
		b.ZkspBinding.Seal, b.MigrationToken.Seal, b.ReplayFingerprint.Seal,
		b.PoteProof.Seal, b.FinalVFA.Seal,
	}
	for i, s := range seals {
		if s.ManifestHash != in.ManifestHash {
			t.Errorf("seal[%d] manifest_hash = %q, want %q", i, s.ManifestHash, in.ManifestHash)
		}
	}
}

func TestUnattestedDecisionRecordsSelfAttested(t *testing.T) {
	in := sampleInput()
	in.Attested = AttestedContext{} // empty
	b := BuildAuditBundle(in)
	if got, want := b.AER.Decision.Source, "self_attested_deterministic"; got != want {
		t.Errorf("decision.source = %q, want %q", got, want)
	}
	if b.EPA.AttestedContext.Attested {
		t.Error("EPA.AttestedContext.Attested = true, want false")
	}
}

func TestAttestedContextRecordedVerbatim(t *testing.T) {
	in := sampleInput()
	temp := 0.2
	in.Attested = AttestedContext{
		Attested:           true,
		ActorID:            "user_42",
		ActorRole:          "compliance_officer",
		ModelProvider:      "anthropic",
		ModelName:          "claude-sonnet-4-6",
		ModelTemperature:   &temp,
		PromptHash:         strings.Repeat("p", 64),
		DecisionKind:       "approve",
		DecisionResult:     "approved",
	}
	b := BuildAuditBundle(in)
	if b.EPA.AttestedContext.ActorID != "user_42" {
		t.Errorf("actor_id = %q", b.EPA.AttestedContext.ActorID)
	}
	if b.EPA.AttestedContext.ModelName != "claude-sonnet-4-6" {
		t.Errorf("model_name = %q", b.EPA.AttestedContext.ModelName)
	}
	if b.AER.Decision.Source != "caller_attested" {
		t.Errorf("decision.source = %q, want caller_attested", b.AER.Decision.Source)
	}
}

func TestScaffoldFlagsHonest(t *testing.T) {
	b := BuildAuditBundle(sampleInput())
	scaffolds := map[string]ScaffoldNote{
		"transcript":           b.Transcript.Scaffold,
		"hardware_attestation": b.HardwareAttestation.Scaffold,
		"zksp_binding":         b.ZkspBinding.Scaffold,
		"pote_proof":           b.PoteProof.Scaffold,
	}
	for name, s := range scaffolds {
		if !s.IsScaffold {
			t.Errorf("artifact %s should be flagged as scaffold (currently is_scaffold=false)", name)
		}
		if s.ActivatedBy == "" {
			t.Errorf("artifact %s scaffold note has empty ActivatedBy", name)
		}
	}
}

// sampleInput returns a deterministic BuildInput for test cases.
func sampleInput() BuildInput {
	return BuildInput{
		Payload:                 []byte("hello verdifax audit projection"),
		ProgramID:               strings.Repeat("a", 64),
		RouteID:                 "route-test",
		RegistryRecordHash:      strings.Repeat("b", 64),
		RunID:                   1,
		Status:                  "ok",
		EnvelopeID:              "env-deadbeef",
		EnvelopeHash:            strings.Repeat("e", 64),
		SequenceID:              "seq-feedface",
		TransportHash:           strings.Repeat("t", 64),
		EpaHash:                 strings.Repeat("p", 64),
		EfaHash:                 strings.Repeat("f", 64),
		ExecutionIDs:            [6]string{"e1", "e2", "e3", "e4", "e5", "e6"},
		AerHash:                 strings.Repeat("r", 64),
		TranscriptHash:          strings.Repeat("c", 64),
		HardwareAttestationHash: strings.Repeat("h", 64),
		LeakageBundleHash:       strings.Repeat("l", 64),
		FormalVerifierStatus:    "VERIFIED_SOUND_COMPLETE_ZK",
		ZkspBindingHash:         strings.Repeat("z", 64),
		MigrationTokenHash:      strings.Repeat("m", 64),
		ReplayFingerprint:       strings.Repeat("y", 64),
		PoteProofHash:           strings.Repeat("o", 64),
		LogEntryID:              "rekor-test",
		FinalVfaHash:            strings.Repeat("v", 64),
		IndependentVerified:     true,
		ManifestHash:            strings.Repeat("M", 64),
		Region:                  "test-region",
	}
}
