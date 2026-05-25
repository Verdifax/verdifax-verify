package artifacts

// Hash recomputation, the canonical source of truth for "given an
// artifact, what is its hash?"
//
// Both the builder (which fills in Hash fields when a bundle is first
// constructed) and the standalone verifier (which independently
// re-derives every hash to detect tampering) call into these functions.
// Keeping the hash preimage in exactly one place is the load-bearing
// guarantee of the audit projection: if these functions match the
// original builder logic byte-for-byte, every existing bundle remains
// verifiable; if they ever drift, every bundle in the database becomes
// unverifiable. So treat changes here with extreme care.
//
// Conventions:
//
//   - For pipeline artifacts whose canonical preimage is a flat list of
//     string fields, we use canonicalHashOf(kind, kvList), the same
//     hand-crafted JSON-object writer the builder used originally.
//   - For pipeline artifacts whose preimage includes structured
//     sub-records (EFA's Steps, AER's Decision, EPA's AttestedContext),
//     we use MustCanonicalHash on a one-shot anonymous struct that
//     omits the artifact's own Hash and Seal fields.
//   - For the five extension categories, we zero the Hash and Seal
//     fields and MustCanonicalHash the whole struct. An external
//     verifier reproduces this by setting Hash="" and Seal=
//     SealReference{} on the received artifact and recomputing.

import (
	"strings"
)

// ── Pipeline artifact recomputation (14) ─────────────────────────────────────

func RecomputePayloadHash(p Payload) string {
	return MustCanonicalHash(struct {
		Kind          string `json:"kind"`
		PayloadID     string `json:"payload_id"`
		ContentHash   string `json:"content_hash"`
		ContentLength int    `json:"content_length"`
		OriginType    string `json:"origin_type"`
		SchemaVersion string `json:"schema_version"`
	}{p.Kind, p.PayloadID, p.ContentHash, p.ContentLength, p.OriginType, p.SchemaVersion})
}

func RecomputeEnvelopeHash(e Envelope) string {
	return canonicalHashOf("verdifax.artifact.envelope.v1", []kv{
		{"envelope_id", e.EnvelopeID},
		{"payload_hash", e.PayloadHash},
		{"program_id", e.ProgramID},
		{"route_id", e.RouteID},
		{"registry_record_hash", e.RegistryRecordHash},
		{"timestamp", e.Timestamp},
	})
}

func RecomputeTransportHash(t Transport) string {
	return canonicalHashOf("verdifax.artifact.transport.v1", []kv{
		{"envelope_id", t.EnvelopeID},
		{"envelope_hash", t.EnvelopeHash},
		{"sequence_id", t.SequenceID},
		{"route", strings.Join(t.Route, "|")},
	})
}

func RecomputeEPAHash(e EPA) string {
	return MustCanonicalHash(struct {
		Kind                string          `json:"kind"`
		KernelID            string          `json:"kernel_id"`
		KernelVersion       string          `json:"kernel_version"`
		PolicyHash          string          `json:"policy_hash"`
		EnvironmentSnapshot EnvSnapshot     `json:"environment_snapshot"`
		AttestedContext     AttestedContext `json:"attested_context"`
	}{e.Kind, e.KernelID, e.KernelVersion, e.PolicyHash, e.EnvironmentSnapshot, e.AttestedContext})
}

func RecomputeEFAHash(e EFA) string {
	return MustCanonicalHash(struct {
		Kind          string     `json:"kind"`
		Steps         []ExecStep `json:"steps"`
		Deterministic bool       `json:"deterministic"`
		FailClosed    bool       `json:"fail_closed"`
	}{e.Kind, e.Steps, e.Deterministic, e.FailClosed})
}

func RecomputeAERHash(a AER) string {
	return MustCanonicalHash(struct {
		Kind         string         `json:"kind"`
		EnvelopeID   string         `json:"envelope_id"`
		SequenceID   string         `json:"sequence_id"`
		ExecutionIDs []string       `json:"execution_ids"`
		FinalState   string         `json:"final_state"`
		Decision     DecisionRecord `json:"decision"`
	}{a.Kind, a.EnvelopeID, a.SequenceID, a.ExecutionIDs, a.FinalState, a.Decision})
}

func RecomputeTranscriptHash(t Transcript) string {
	return canonicalHashOf("verdifax.artifact.transcript.v1", []kv{
		{"proof_hash_input", t.ProofHashInput},
		{"transcript_hash", t.TranscriptHash},
		{"scaffold_is_scaffold", boolStr(t.Scaffold.IsScaffold)},
	})
}

func RecomputeHardwareAttestationHash(h HardwareAttestation) string {
	return MustCanonicalHash(struct {
		Kind                 string   `json:"kind"`
		AttestationMode      string   `json:"attestation_mode"`
		EnclaveMeasurement   string   `json:"enclave_measurement"`
		FirmwareClass        string   `json:"firmware_class"`
		SecureBootState      string   `json:"secure_boot_state"`
		ExecutionEnvironment string   `json:"execution_environment"`
		PCRSelection         string   `json:"pcr_selection"`
		Tier4Blockers        []string `json:"tier4_blockers"`
	}{h.Kind, h.AttestationMode, h.EnclaveMeasurement, h.FirmwareClass, h.SecureBootState, h.ExecutionEnvironment, h.PCRSelection, h.Tier4Blockers})
}

func RecomputeLeakageBundleHash(l LeakageBundle) string {
	return MustCanonicalHash(struct {
		Kind                   string   `json:"kind"`
		ConstantTimeCompliant  bool     `json:"constant_time_compliant"`
		TimingVarianceObserved bool     `json:"timing_variance_observed"`
		Mitigations            []string `json:"mitigations"`
	}{l.Kind, l.ConstantTimeCompliant, l.TimingVarianceObserved, l.Mitigations})
}

func RecomputeZkspBindingHash(z ZkspBinding) string {
	return MustCanonicalHash(struct {
		Kind               string   `json:"kind"`
		ProvingSystem      string   `json:"proving_system"`
		VerificationStatus string   `json:"verification_status"`
		BindsTo            []string `json:"binds_to"`
	}{z.Kind, z.ProvingSystem, z.VerificationStatus, z.BindsTo})
}

func RecomputeMigrationTokenHash(m MigrationToken) string {
	return canonicalHashOf("verdifax.artifact.migration_token.v1", []kv{
		{"from_version", m.FromVersion},
		{"to_version", m.ToVersion},
		{"state_hash", m.StateHash},
	})
}

func RecomputeReplayFingerprintHash(r ReplayFingerprint) string {
	return MustCanonicalHash(struct {
		Kind                string   `json:"kind"`
		DeterministicInputs []string `json:"deterministic_inputs"`
		ExpectedOutputHash  string   `json:"expected_output_hash"`
	}{r.Kind, r.DeterministicInputs, r.ExpectedOutputHash})
}

func RecomputePoteProofHash(p PoteProof) string {
	return canonicalHashOf("verdifax.artifact.pote.v1", []kv{
		{"proof_type", p.ProofType},
		{"execution_trace_hash", p.ExecutionTraceHash},
		{"log_entry_id", p.LogEntryID},
	})
}

func RecomputeFinalVFAHash(v FinalVFA) string {
	return MustCanonicalHash(struct {
		Kind                string `json:"kind"`
		EnvelopeHash        string `json:"envelope_hash"`
		TransportHash       string `json:"transport_hash"`
		EpaHash             string `json:"epa_hash"`
		EfaHash             string `json:"efa_hash"`
		AerHash             string `json:"aer_hash"`
		TranscriptHash      string `json:"transcript_hash"`
		HardwareAttestHash  string `json:"hardware_attestation_hash"`
		LeakageBundleHash   string `json:"leakage_bundle_hash"`
		ZkspBindingHash     string `json:"zksp_binding_hash"`
		MigrationTokenHash  string `json:"migration_token_hash"`
		ReplayFingerprint   string `json:"replay_fingerprint"`
		PoteProofHash       string `json:"pote_proof_hash"`
		IndependentVerified bool   `json:"independent_verified"`
	}{
		v.Kind, v.EnvelopeHash, v.TransportHash, v.EpaHash, v.EfaHash,
		v.AerHash, v.TranscriptHash, v.HardwareAttestHash, v.LeakageBundleHash,
		v.ZkspBindingHash, v.MigrationTokenHash, v.ReplayFingerprint,
		v.PoteProofHash, v.IndependentVerified,
	})
}

// ── Category recomputation (5) ───────────────────────────────────────────────
//
// Convention: zero the Hash and Seal fields, then canonical-hash the whole
// struct. An external verifier that receives the bundle reproduces this
// by setting those two fields to their zero values before recomputing.

func RecomputeRequestSubstanceHash(rs RequestSubstance) string {
	rs.Hash = ""
	rs.Seal = SealReference{}
	return MustCanonicalHash(rs)
}

func RecomputeAuthorizationChainHash(ac AuthorizationChain) string {
	ac.Hash = ""
	ac.Seal = SealReference{}
	return MustCanonicalHash(ac)
}

func RecomputeRegulatoryScaffoldingHash(reg RegulatoryScaffolding) string {
	reg.Hash = ""
	reg.Seal = SealReference{}
	return MustCanonicalHash(reg)
}

func RecomputeCausalGraphHash(cg CausalGraph) string {
	cg.Hash = ""
	cg.Seal = SealReference{}
	return MustCanonicalHash(cg)
}

func RecomputeSystemProvenanceHash(sp SystemProvenance) string {
	sp.Hash = ""
	sp.Seal = SealReference{}
	return MustCanonicalHash(sp)
}

// ── Bundle recomputation ─────────────────────────────────────────────────────

// RecomputeBundleHash reproduces the canonical bundle hash. The preimage
// is the bundle's identity fields plus the 14 pipeline-artifact hashes
// plus the 6 category hashes, explicitly NOT the bundle's own Hash field
// or its run_id (which is metadata) or generated_at (which varies between
// bundle constructions on the same content).
//
// Category 6 (ReproducibilityContext) was added 2026-05-10. Bundles
// produced before that date will have a zero ReproducibilityContext
// with Hash = the canonical hash of the empty struct, verifiers
// running against pre-Phase-6 bundles still recompute deterministic
// hashes because the empty-struct hash is itself stable.
func RecomputeBundleHash(b *AuditBundle) string {
	return MustCanonicalHash(struct {
		Kind                        string `json:"kind"`
		SchemaVersion               string `json:"schema_version"`
		ManifestHash                string `json:"manifest_hash"`
		PayloadHash                 string `json:"payload_hash"`
		EnvelopeHash                string `json:"envelope_hash"`
		TransportHash               string `json:"transport_hash"`
		EpaHash                     string `json:"epa_hash"`
		EfaHash                     string `json:"efa_hash"`
		AerHash                     string `json:"aer_hash"`
		TranscriptHash              string `json:"transcript_hash"`
		HwaHash                     string `json:"hwa_hash"`
		LeakageHash                 string `json:"leakage_hash"`
		ZkspHash                    string `json:"zksp_hash"`
		MigrationHash               string `json:"migration_hash"`
		ReplayHash                  string `json:"replay_hash"`
		PoteHash                    string `json:"pote_hash"`
		VfaHash                     string `json:"vfa_hash"`
		RequestSubstanceHash        string `json:"request_substance_hash"`
		AuthorizationChainHash      string `json:"authorization_chain_hash"`
		RegulatoryScaffoldingHash   string `json:"regulatory_scaffolding_hash"`
		CausalGraphHash             string `json:"causal_graph_hash"`
		SystemProvenanceHash        string `json:"system_provenance_hash"`
		ReproducibilityContextHash  string `json:"reproducibility_context_hash"`
	}{
		b.Kind, b.SchemaVersion, b.ManifestHash,
		b.Payload.Hash, b.Envelope.Hash, b.Transport.Hash,
		b.EPA.Hash, b.EFA.Hash, b.AER.Hash,
		b.Transcript.Hash, b.HardwareAttestation.Hash, b.LeakageBundle.Hash,
		b.ZkspBinding.Hash, b.MigrationToken.Hash, b.ReplayFingerprint.Hash,
		b.PoteProof.Hash, b.FinalVFA.Hash,
		b.RequestSubstance.Hash, b.AuthorizationChain.Hash,
		b.RegulatoryScaffolding.Hash, b.CausalGraph.Hash,
		b.SystemProvenance.Hash, b.ReproducibilityContext.Hash,
	})
}
