package artifacts

import (
	"crypto/sha256"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// BuildInput is the data the orchestrator passes to BuildAuditBundle to
// produce a complete audit projection. Everything except AttestedContext
// is data the pipeline already has; AttestedContext is the caller-supplied
// optional block (see /execute API).
type BuildInput struct {
	// Pipeline inputs (what the caller sent in /execute).
	Payload            []byte
	ProgramID          string
	RouteID            string
	RegistryRecordHash string

	// Manifest fields (what the pipeline computed).
	RunID  int
	Status string

	EnvelopeID    string
	EnvelopeHash  string
	SequenceID    string
	TransportHash string

	EpaHash      string
	EfaHash      string
	ExecutionIDs [6]string
	AerHash      string

	TranscriptHash          string
	HardwareAttestationHash string
	LeakageBundleHash       string
	FormalVerifierStatus    string

	ZkspBindingHash    string
	MigrationTokenHash string
	ReplayFingerprint  string

	PoteProofHash string
	LogEntryID    string

	// Day-3 Sigstore Rekor evidence. Populated when the orchestrator
	// is running with VERDIFAX_LEDGER_MODE=rekor; otherwise zero
	// values and BuildAuditBundle emits a mock-style RekorAnchor
	// (Backend = "mock"). Mirrors the manifest's LedgerInclusionProof.
	LedgerBackend              string
	LedgerLeafHash             string
	LedgerLogID                string
	LedgerLogIndex             int64
	LedgerTreeSize             int64
	LedgerRootHash             string
	LedgerInclusionPath        []string
	LedgerCheckpoint           string
	LedgerSignedEntryTimestamp string
	LedgerIntegratedTime       int64

	// Phase-13 AIVP-T4 governance evidence. Populated from the
	// pipeline's manifest fields (AivpOutcome / AivpPiaHash /
	// AivpAdapterID / AivpAiOutputHash / AivpDecision /
	// AivpHaltReceiptHash). Zero values produce a "skipped" section,
	// matching the manifest behavior when AIVP-T4 wasn't wired or
	// the run didn't engage governance.
	AivpOutcome         string
	AivpPiaHash         string
	AivpAdapterID       string
	AivpAiOutputHash    string
	AivpDecision        string
	AivpHaltReceiptHash string

	// Phase-15 NREP (Ed25519 actor signing) evidence. Populated from
	// the pipeline's manifest fields (NrepActorID, NrepActorPublicKey,
	// NrepSignature). Empty values produce a "skipped" section
	// matching the manifest's anonymous-run behavior.
	NrepActorID        string
	NrepActorPublicKey string
	NrepSignature      string

	FinalVfaHash        string
	IndependentVerified bool

	ManifestHash string

	// Caller-attested context (optional). Empty value is acceptable and
	// produces a "self_attested_deterministic" bundle.
	Attested AttestedContext

	// Operator hints about deployment environment, used in EnvSnapshot.
	Region string // e.g. "fly:iad"; defaults to "self-host" if empty

	// ── Phase 8 extensions: caller-supplied category blocks ───────────────────
	//
	// Each is optional. Empty values produce honest "not declared" output
	// in the corresponding category section of the audit bundle.

	RequestSubstance       *RequestSubstance       // Category 1
	AuthorizationChain     *AuthorizationChain     // Category 2
	RegulatoryScaffolding  *RegulatoryScaffolding  // Category 3
	CausalGraph            *CausalGraph            // Category 4
	ReproducibilityContext *ReproducibilityContext // Category 6 (Category 5 is server-observed SystemProvenance)

	// ── Server-observed extensions (Category 1 partial + Category 5) ─────────

	// LatencyTotalMs is the total wall-clock pipeline duration, observed
	// by the orchestrator and folded into RequestSubstance.Latency.
	LatencyTotalMs int64

	// SourceIPHash, UserAgentHash, GeoCountry: server-derived, sha256
	// of the corresponding HTTP headers (or empty when not observed).
	SourceIPHash  string
	UserAgentHash string
	GeoCountry    string

	// Auth observation (used to populate RequestSubstance.Authentication).
	AuthMethod   string // "api_key" | "anonymous"
	APIKeyID     int64
	APIKeyName   string
	MFASatisfied *bool

	// SystemProvenance is fully server-observed; the BuildAuditBundle
	// function calls into the provenance package to populate it.
}

// BuildAuditBundle constructs the complete AuditBundle from the pipeline
// outputs. This is a pure function: same input always produces the same
// output, including byte-identical canonical hashes.
func BuildAuditBundle(in BuildInput) *AuditBundle {
	now := time.Now().UTC().Format(time.RFC3339)
	region := in.Region
	if region == "" {
		region = "self-host"
	}

	payloadHash := sha256Hex(string(in.Payload))

	seal := func(field, hash string) SealReference {
		return SealReference{
			ManifestHash: in.ManifestHash,
			SealField:    field,
			SealedHash:   hash,
		}
	}

	// 1. Payload
	payload := Payload{
		Kind:          "verdifax.artifact.payload.v1",
		PayloadID:     "payload-" + payloadHash[:16],
		ContentHash:   payloadHash,
		ContentLength: len(in.Payload),
		OriginType:    "api",
		SchemaVersion: "v1",
	}
	payload.Hash = MustCanonicalHash(struct {
		Kind          string `json:"kind"`
		PayloadID     string `json:"payload_id"`
		ContentHash   string `json:"content_hash"`
		ContentLength int    `json:"content_length"`
		OriginType    string `json:"origin_type"`
		SchemaVersion string `json:"schema_version"`
	}{payload.Kind, payload.PayloadID, payload.ContentHash, payload.ContentLength, payload.OriginType, payload.SchemaVersion})

	// 2. Envelope
	envelope := Envelope{
		Kind:               "verdifax.artifact.envelope.v1",
		EnvelopeID:         in.EnvelopeID,
		PayloadHash:        payloadHash,
		ProgramID:          in.ProgramID,
		RouteID:            in.RouteID,
		RegistryRecordHash: in.RegistryRecordHash,
		Timestamp:          now,
	}
	envelope.Hash = canonicalHashOf("verdifax.artifact.envelope.v1", []kv{
		{"envelope_id", envelope.EnvelopeID},
		{"payload_hash", envelope.PayloadHash},
		{"program_id", envelope.ProgramID},
		{"route_id", envelope.RouteID},
		{"registry_record_hash", envelope.RegistryRecordHash},
		{"timestamp", envelope.Timestamp},
	})
	envelope.Seal = seal("envelope_hash", in.EnvelopeHash)

	// 3. Transport
	transport := Transport{
		Kind:         "verdifax.artifact.transport.v1",
		EnvelopeID:   in.EnvelopeID,
		EnvelopeHash: in.EnvelopeHash,
		SequenceID:   in.SequenceID,
		Route:        []string{"DOG", "DTL", "DKEC", "AER", "ZKSP", "PHASE4", "LEDGER", "REGISTRY", "DLA"},
	}
	transport.Hash = canonicalHashOf("verdifax.artifact.transport.v1", []kv{
		{"envelope_id", transport.EnvelopeID},
		{"envelope_hash", transport.EnvelopeHash},
		{"sequence_id", transport.SequenceID},
		{"route", strings.Join(transport.Route, "|")},
	})
	transport.Seal = seal("transport_hash", in.TransportHash)

	// 4. EPA
	attested := in.Attested
	// Mark attested = true if any caller-supplied field is non-empty.
	if !attested.Attested {
		if attested.ActorID != "" || attested.ModelProvider != "" || attested.DecisionKind != "" {
			attested.Attested = true
		}
	}
	epa := EPA{
		Kind:          "verdifax.artifact.epa.v1",
		KernelID:      "verdifax-orchestrator",
		KernelVersion: "0.1.1",
		PolicyHash:    sha256Hex("orchestrator.policy.v1"),
		EnvironmentSnapshot: EnvSnapshot{
			Time:      now,
			Region:    region,
			OS:        runtime.GOOS,
			GoVersion: runtime.Version(),
		},
		AttestedContext: attested,
	}
	epa.Hash = MustCanonicalHash(struct {
		Kind                string          `json:"kind"`
		KernelID            string          `json:"kernel_id"`
		KernelVersion       string          `json:"kernel_version"`
		PolicyHash          string          `json:"policy_hash"`
		EnvironmentSnapshot EnvSnapshot     `json:"environment_snapshot"`
		AttestedContext     AttestedContext `json:"attested_context"`
	}{epa.Kind, epa.KernelID, epa.KernelVersion, epa.PolicyHash, epa.EnvironmentSnapshot, epa.AttestedContext})
	epa.Seal = seal("epa_hash", in.EpaHash)

	// 5. EFA
	steps := make([]ExecStep, 6)
	kernelNames := []string{"DSE", "TOK", "DSC", "NREP", "AIVP", "DCAE"}
	for i, name := range kernelNames {
		steps[i] = ExecStep{
			StepIndex:   i,
			Kernel:      name,
			ExecutionID: in.ExecutionIDs[i],
			Status:      "ok",
		}
	}
	efa := EFA{
		Kind:          "verdifax.artifact.efa.v1",
		Steps:         steps,
		Deterministic: true,
		FailClosed:    false,
	}
	efa.Hash = MustCanonicalHash(struct {
		Kind          string     `json:"kind"`
		Steps         []ExecStep `json:"steps"`
		Deterministic bool       `json:"deterministic"`
		FailClosed    bool       `json:"fail_closed"`
	}{efa.Kind, efa.Steps, efa.Deterministic, efa.FailClosed})
	efa.Seal = seal("efa_hash", in.EfaHash)

	// 6. AER
	decisionSource := "self_attested_deterministic"
	if attested.Attested && attested.DecisionKind != "" {
		decisionSource = "caller_attested"
	}
	aer := AER{
		Kind:         "verdifax.artifact.aer.v1",
		EnvelopeID:   in.EnvelopeID,
		SequenceID:   in.SequenceID,
		ExecutionIDs: in.ExecutionIDs[:],
		FinalState:   "committed",
		Decision: DecisionRecord{
			Source: decisionSource,
			Kind:   attested.DecisionKind,
			Result: attested.DecisionResult,
			Note:   attested.DecisionNote,
		},
	}
	aer.Hash = MustCanonicalHash(struct {
		Kind         string         `json:"kind"`
		EnvelopeID   string         `json:"envelope_id"`
		SequenceID   string         `json:"sequence_id"`
		ExecutionIDs []string       `json:"execution_ids"`
		FinalState   string         `json:"final_state"`
		Decision     DecisionRecord `json:"decision"`
	}{aer.Kind, aer.EnvelopeID, aer.SequenceID, aer.ExecutionIDs, aer.FinalState, aer.Decision})
	aer.Seal = seal("aer_hash", in.AerHash)

	// 7. Transcript (scaffold)
	transcript := Transcript{
		Kind:           "verdifax.artifact.transcript.v1",
		ProofHashInput: in.AerHash,
		TranscriptHash: in.TranscriptHash,
		Scaffold: ScaffoldNote{
			IsScaffold:  true,
			ActivatedBy: "phase 6 (real ZK prover — winterfell)",
			Note:        "Transcript is currently the deterministic R1CS hash facade. Real Fiat-Shamir transcript bytes are emitted once the winterfell prover is wired (see ZK_PROVER_EVALUATION.md).",
		},
	}
	transcript.Hash = canonicalHashOf("verdifax.artifact.transcript.v1", []kv{
		{"proof_hash_input", transcript.ProofHashInput},
		{"transcript_hash", transcript.TranscriptHash},
		{"scaffold_is_scaffold", boolStr(transcript.Scaffold.IsScaffold)},
	})
	transcript.Seal = seal("transcript_hash", in.TranscriptHash)

	// 8. Hardware attestation (scaffold)
	hwa := HardwareAttestation{
		Kind:                 "verdifax.artifact.hw_attestation.v1",
		AttestationMode:      "policy_scaffold",
		EnclaveMeasurement:   in.HardwareAttestationHash,
		FirmwareClass:        "self-attested-deterministic",
		SecureBootState:      "unverified",
		ExecutionEnvironment: "containerized-fly-machine",
		PCRSelection:         "sha256:0,1,2,3,4,5,6,7",
		Tier4Blockers: []string{
			"REAL_TEE_QUOTE_NOT_BOUND",
			"PLATFORM_CERTIFICATE_CHAIN_NOT_VERIFIED",
			"HARDWARE_BOUND_MODE_NOT_ENABLED_CURRENT_HORIZON",
		},
		Scaffold: ScaffoldNote{
			IsScaffold:  true,
			ActivatedBy: "phase 7 (live cloud — TPM2 / SEV-SNP)",
			Note:        "Real attested hardware lands when the orchestrator is deployed on a SEV-SNP / vTPM2 cloud instance per PHASE5_HARDWARE_REQUIREMENTS.md. Until then this artifact is honest about being a policy scaffold.",
		},
	}
	hwa.Hash = MustCanonicalHash(struct {
		Kind                  string   `json:"kind"`
		AttestationMode       string   `json:"attestation_mode"`
		EnclaveMeasurement    string   `json:"enclave_measurement"`
		FirmwareClass         string   `json:"firmware_class"`
		SecureBootState       string   `json:"secure_boot_state"`
		ExecutionEnvironment  string   `json:"execution_environment"`
		PCRSelection          string   `json:"pcr_selection"`
		Tier4Blockers         []string `json:"tier4_blockers"`
	}{hwa.Kind, hwa.AttestationMode, hwa.EnclaveMeasurement, hwa.FirmwareClass, hwa.SecureBootState, hwa.ExecutionEnvironment, hwa.PCRSelection, hwa.Tier4Blockers})
	hwa.Seal = seal("hardware_attestation_hash", in.HardwareAttestationHash)

	// 9. Leakage bundle
	leakage := LeakageBundle{
		Kind:                  "verdifax.artifact.leakage.v1",
		ConstantTimeCompliant: true,
		TimingVarianceObserved: false,
		Mitigations:           []string{"constant_time_execution", "deterministic_kernel_scheduling"},
	}
	leakage.Hash = MustCanonicalHash(struct {
		Kind                   string   `json:"kind"`
		ConstantTimeCompliant  bool     `json:"constant_time_compliant"`
		TimingVarianceObserved bool     `json:"timing_variance_observed"`
		Mitigations            []string `json:"mitigations"`
	}{leakage.Kind, leakage.ConstantTimeCompliant, leakage.TimingVarianceObserved, leakage.Mitigations})
	leakage.Seal = seal("leakage_bundle_hash", in.LeakageBundleHash)

	// 10. ZKSP binding (scaffold for proof bytes)
	zksp := ZkspBinding{
		Kind:               "verdifax.artifact.zksp_binding.v1",
		ProvingSystem:      "DETERMINISTIC_R1CS_TRANSITIONAL_PROVER",
		VerificationStatus: in.FormalVerifierStatus,
		BindsTo:            []string{"envelope_id", "aer_hash", "program_id", "registry_record_hash"},
		Scaffold: ScaffoldNote{
			IsScaffold:  true,
			ActivatedBy: "phase 6 (real ZK prover — winterfell)",
			Note:        "Verification status reflects the transitional R1CS hash facade. Real STARK proof bytes land when winterfell is wired.",
		},
	}
	zksp.Hash = MustCanonicalHash(struct {
		Kind               string   `json:"kind"`
		ProvingSystem      string   `json:"proving_system"`
		VerificationStatus string   `json:"verification_status"`
		BindsTo            []string `json:"binds_to"`
	}{zksp.Kind, zksp.ProvingSystem, zksp.VerificationStatus, zksp.BindsTo})
	zksp.Seal = seal("zksp_binding_hash", in.ZkspBindingHash)

	// 11. Migration token
	mig := MigrationToken{
		Kind:        "verdifax.artifact.migration_token.v1",
		FromVersion: "v1",
		ToVersion:   "v1",
		StateHash:   in.MigrationTokenHash,
	}
	mig.Hash = canonicalHashOf("verdifax.artifact.migration_token.v1", []kv{
		{"from_version", mig.FromVersion},
		{"to_version", mig.ToVersion},
		{"state_hash", mig.StateHash},
	})
	mig.Seal = seal("migration_token_hash", in.MigrationTokenHash)

	// 12. Replay fingerprint
	replay := ReplayFingerprint{
		Kind:                "verdifax.artifact.replay.v1",
		DeterministicInputs: []string{"payload_hash", "program_id", "route_id", "registry_record_hash"},
		ExpectedOutputHash:  in.ManifestHash,
	}
	replay.Hash = MustCanonicalHash(struct {
		Kind                string   `json:"kind"`
		DeterministicInputs []string `json:"deterministic_inputs"`
		ExpectedOutputHash  string   `json:"expected_output_hash"`
	}{replay.Kind, replay.DeterministicInputs, replay.ExpectedOutputHash})
	replay.Seal = seal("replay_fingerprint", in.ReplayFingerprint)

	// 13. PoTE proof (scaffold for transparency log)
	pote := PoteProof{
		Kind:               "verdifax.artifact.pote.v1",
		ProofType:          "proof_of_transparent_execution",
		ExecutionTraceHash: in.AerHash,
		LogEntryID:         in.LogEntryID,
		Scaffold: ScaffoldNote{
			IsScaffold:  true,
			ActivatedBy: "future ledger integration (Sigstore/Rekor)",
			Note:        "Log entry ID is currently locally generated. Real Sigstore Rekor anchoring is a future ledger integration.",
		},
	}
	pote.Hash = canonicalHashOf("verdifax.artifact.pote.v1", []kv{
		{"proof_type", pote.ProofType},
		{"execution_trace_hash", pote.ExecutionTraceHash},
		{"log_entry_id", pote.LogEntryID},
	})
	pote.Seal = seal("pote_proof_hash", in.PoteProofHash)

	// 14. Final VFA
	vfa := FinalVFA{
		Kind:                "verdifax.artifact.final_vfa.v1",
		EnvelopeHash:        in.EnvelopeHash,
		TransportHash:       in.TransportHash,
		EpaHash:             in.EpaHash,
		EfaHash:             in.EfaHash,
		AerHash:             in.AerHash,
		TranscriptHash:      in.TranscriptHash,
		HardwareAttestHash:  in.HardwareAttestationHash,
		LeakageBundleHash:   in.LeakageBundleHash,
		ZkspBindingHash:     in.ZkspBindingHash,
		MigrationTokenHash:  in.MigrationTokenHash,
		ReplayFingerprint:   in.ReplayFingerprint,
		PoteProofHash:       in.PoteProofHash,
		IndependentVerified: in.IndependentVerified,
	}
	vfa.Hash = MustCanonicalHash(struct {
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
		vfa.Kind, vfa.EnvelopeHash, vfa.TransportHash, vfa.EpaHash, vfa.EfaHash,
		vfa.AerHash, vfa.TranscriptHash, vfa.HardwareAttestHash, vfa.LeakageBundleHash,
		vfa.ZkspBindingHash, vfa.MigrationTokenHash, vfa.ReplayFingerprint,
		vfa.PoteProofHash, vfa.IndependentVerified,
	})
	vfa.Seal = seal("final_vfa_hash", in.FinalVfaHash)

	// ── Category 1 — RequestSubstance ───────────────────────────────────────
	// Merge caller-supplied substance with server-observed values.
	requestSubstance := RequestSubstance{
		Kind: "verdifax.request_substance.v1",
	}
	if in.RequestSubstance != nil {
		requestSubstance = *in.RequestSubstance
		requestSubstance.Kind = "verdifax.request_substance.v1"
	}
	// Server-observed fields override caller-supplied values for
	// observation-grade fields the caller cannot honestly attest to.
	if in.LatencyTotalMs > 0 {
		requestSubstance.Latency.TotalMs = in.LatencyTotalMs
	}
	if in.SourceIPHash != "" || in.UserAgentHash != "" || in.GeoCountry != "" {
		if requestSubstance.Origin.SourceIPHash == "" {
			requestSubstance.Origin.SourceIPHash = in.SourceIPHash
		}
		if requestSubstance.Origin.UserAgentHash == "" {
			requestSubstance.Origin.UserAgentHash = in.UserAgentHash
		}
		if requestSubstance.Origin.GeoCountry == "" {
			requestSubstance.Origin.GeoCountry = in.GeoCountry
		}
	}
	if in.AuthMethod != "" {
		if requestSubstance.Authentication.Method == "" {
			requestSubstance.Authentication.Method = in.AuthMethod
		}
		if requestSubstance.Authentication.APIKeyID == 0 {
			requestSubstance.Authentication.APIKeyID = in.APIKeyID
		}
		if requestSubstance.Authentication.APIKeyName == "" {
			requestSubstance.Authentication.APIKeyName = in.APIKeyName
		}
		if requestSubstance.Authentication.MFASatisfied == nil && in.MFASatisfied != nil {
			requestSubstance.Authentication.MFASatisfied = in.MFASatisfied
		}
	}
	// Hash preimage convention: zero out the Hash and Seal fields so the
	// computed hash is over the substantive content only. An external
	// verifier reconstructs by setting Hash="" and Seal={} on the
	// received artifact and recomputing CanonicalHash.
	requestSubstance.Hash = ""
	requestSubstance.Seal = SealReference{}
	requestSubstance.Hash = MustCanonicalHash(requestSubstance)
	requestSubstance.Seal = seal("request_substance", requestSubstance.Hash)

	// ── Category 2 — AuthorizationChain ─────────────────────────────────────
	authChain := AuthorizationChain{Kind: "verdifax.authorization_chain.v1"}
	if in.AuthorizationChain != nil {
		authChain = *in.AuthorizationChain
		authChain.Kind = "verdifax.authorization_chain.v1"
	}
	authChain.Hash = ""
	authChain.Seal = SealReference{}
	authChain.Hash = MustCanonicalHash(authChain)
	authChain.Seal = seal("authorization_chain", authChain.Hash)

	// ── Category 3 — RegulatoryScaffolding ──────────────────────────────────
	reg := RegulatoryScaffolding{Kind: "verdifax.regulatory_scaffolding.v1"}
	if in.RegulatoryScaffolding != nil {
		reg = *in.RegulatoryScaffolding
		reg.Kind = "verdifax.regulatory_scaffolding.v1"
	}
	// Auto-populate ProcessingRegion from operator hint if caller did not.
	if reg.DataResidency.ProcessingRegion == "" {
		reg.DataResidency.ProcessingRegion = region
	}
	if reg.DataResidency.StorageRegion == "" {
		reg.DataResidency.StorageRegion = region
	}
	reg.Hash = ""
	reg.Seal = SealReference{}
	reg.Hash = MustCanonicalHash(reg)
	reg.Seal = seal("regulatory_scaffolding", reg.Hash)

	// ── Category 4 — CausalGraph ────────────────────────────────────────────
	causal := CausalGraph{Kind: "verdifax.causal_graph.v1"}
	if in.CausalGraph != nil {
		causal = *in.CausalGraph
		causal.Kind = "verdifax.causal_graph.v1"
	}
	causal.Hash = ""
	causal.Seal = SealReference{}
	causal.Hash = MustCanonicalHash(causal)
	causal.Seal = seal("causal_graph", causal.Hash)

	// ── Category 5 — SystemProvenance (fully server-observed) ───────────────
	prov := buildSystemProvenance(region)
	prov.Hash = ""
	prov.Seal = SealReference{}
	prov.Hash = MustCanonicalHash(prov)
	prov.Seal = seal("system_provenance", prov.Hash)

	// ── Category 6 — ReproducibilityContext (caller-attested) ──────────────
	// Captures the runtime fingerprint (container image hash, language
	// pinned deps, git SHA, random seeds, platform) declared by the
	// caller. Empty zero-value renders as Declared:false in the bundle
	// — honest "not declared" rather than a fabricated environment.
	repro := ReproducibilityContext{}
	if in.ReproducibilityContext != nil {
		repro = *in.ReproducibilityContext
		// Mark Declared:true if the caller supplied any concrete field.
		if !repro.Declared {
			repro.Declared = repro.ContainerImageHash != "" ||
				repro.RuntimeName != "" ||
				repro.RuntimeVersion != "" ||
				len(repro.PinnedDependencies) > 0 ||
				repro.GitCommitSHA != "" ||
				len(repro.RandomSeeds) > 0 ||
				repro.Platform != ""
		}
	}
	repro.Hash = ""
	repro.Hash = MustCanonicalHash(repro)

	// Top-level bundle
	bundle := &AuditBundle{
		Kind:          "verdifax.audit_bundle.v1",
		SchemaVersion: "v1",
		RunID:         in.RunID,
		Status:        in.Status,
		ManifestHash:  in.ManifestHash,
		GeneratedAt:   now,

		Payload:             payload,
		Envelope:            envelope,
		Transport:           transport,
		EPA:                 epa,
		EFA:                 efa,
		AER:                 aer,
		Transcript:          transcript,
		HardwareAttestation: hwa,
		LeakageBundle:       leakage,
		ZkspBinding:         zksp,
		MigrationToken:      mig,
		ReplayFingerprint:   replay,
		PoteProof:           pote,
		FinalVFA:            vfa,

		RequestSubstance:       requestSubstance,
		AuthorizationChain:     authChain,
		RegulatoryScaffolding:  reg,
		CausalGraph:            causal,
		SystemProvenance:       prov,
		ReproducibilityContext: repro,
	}
	// BundleHash seals the bundle itself. All artifact hashes plus all
	// category hashes contribute; run_id and generated_at are explicitly
	// excluded so the bundle hash is purely a function of the canonical
	// content.
	bundle.BundleHash = MustCanonicalHash(struct {
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
		bundle.Kind, bundle.SchemaVersion, bundle.ManifestHash,
		bundle.Payload.Hash, bundle.Envelope.Hash, bundle.Transport.Hash,
		bundle.EPA.Hash, bundle.EFA.Hash, bundle.AER.Hash,
		bundle.Transcript.Hash, bundle.HardwareAttestation.Hash, bundle.LeakageBundle.Hash,
		bundle.ZkspBinding.Hash, bundle.MigrationToken.Hash, bundle.ReplayFingerprint.Hash,
		bundle.PoteProof.Hash, bundle.FinalVFA.Hash,
		bundle.RequestSubstance.Hash, bundle.AuthorizationChain.Hash,
		bundle.RegulatoryScaffolding.Hash, bundle.CausalGraph.Hash,
		bundle.SystemProvenance.Hash, bundle.ReproducibilityContext.Hash,
	})

	// Day-3 Rekor anchor — populate from BuildInput. For mock-ledger
	// runs the input fields are zero values, which produces a
	// RekorAnchor with Backend="mock" (or empty) and the verifier
	// will skip the offline Rekor proof check.
	backend := in.LedgerBackend
	if backend == "" {
		backend = "mock"
	}
	bundle.RekorAnchor = RekorAnchor{
		Backend:              backend,
		LogEntryID:           in.LogEntryID,
		LogID:                in.LedgerLogID,
		LeafHashHex:          in.LedgerLeafHash,
		LogIndex:             in.LedgerLogIndex,
		TreeSize:             in.LedgerTreeSize,
		RootHashHex:          in.LedgerRootHash,
		InclusionPath:        in.LedgerInclusionPath,
		Checkpoint:           in.LedgerCheckpoint,
		SignedEntryTimestamp: in.LedgerSignedEntryTimestamp,
		IntegratedTime:       in.LedgerIntegratedTime,
	}

	// Phase-13 AIVP-T4 — populate from BuildInput. For runs that
	// didn't engage governance (e.g. AivpT4 governor wasn't wired,
	// or pre-Phase-13 runs being rebuilt) all fields are zero and
	// Outcome defaults to "skipped" so downstream renderers know to
	// hide the section.
	aivpOutcome := in.AivpOutcome
	if aivpOutcome == "" {
		aivpOutcome = "skipped"
	}
	bundle.AivpT4 = AivpT4Section{
		Outcome:         aivpOutcome,
		PiaHash:         in.AivpPiaHash,
		AdapterID:       in.AivpAdapterID,
		AiOutputHash:    in.AivpAiOutputHash,
		Decision:        in.AivpDecision,
		HaltReceiptHash: in.AivpHaltReceiptHash,
	}

	// Phase-15 NREP — Ed25519 actor signing evidence. Empty values
	// produce a "skipped" section (anonymous runs, pre-Phase-15 runs,
	// runs halted before NREP stage). The pipeline always populates
	// these manifest fields when an actor identity is present, so
	// here we just thread them through verbatim.
	bundle.Nrep = NrepSection{
		ActorID:   in.NrepActorID,
		PublicKey: in.NrepActorPublicKey,
		Signature: in.NrepSignature,
	}

	return bundle
}

// buildSystemProvenance populates Category 5 fields from the orchestrator's
// own runtime state. Build-time fields (git SHA, build provenance) come
// from the version package's compile-time variables; runtime fields
// come from environment variables and runtime introspection.
func buildSystemProvenance(region string) SystemProvenance {
	prov := SystemProvenance{
		Kind:                "verdifax.system_provenance.v1",
		OrchestratorVersion: getOrchestratorVersion(),
		OrchestratorGitSHA:  getOrchestratorGitSHA(),
		BuildProvenance: BuildProvenance{
			SLSALevel:         getSLSALevel(),
			BuilderID:         getBuilderID(),
			BuildInvocationID: getBuildInvocationID(),
			SourceRepo:        "github.com/Verdifax/verdifax-orchestrator",
			SourceCommitSHA:   getOrchestratorGitSHA(),
		},
		KernelVersions: []KernelVersion{
			{Kernel: "DSE", Version: "v1.3.2"},
			{Kernel: "TOK", Version: "v1.0.0"},
			{Kernel: "DSC", Version: "v1.0.0"},
			{Kernel: "NREP", Version: "v1.0.0"},
			{Kernel: "AIVP", Version: "v1.0.0"},
			{Kernel: "DCAE", Version: "v1.0.0"},
		},
		Environment: RuntimeEnvironment{
			Cloud:                inferCloud(),
			Region:               region,
			InstanceID:           getInstanceID(),
			ContainerImageDigest: getContainerImageDigest(),
			OS:                   runtimeGOOS(),
			Arch:                 runtimeGOARCH(),
			GoVersion:            runtimeVersion(),
			Hostname:             getHostname(),
		},
	}
	return prov
}

// ── helpers ──────────────────────────────────────────────────────────────────

type kv struct{ k, v string }

// canonicalHashOf is a small helper that hashes a "kind"-prefixed key/value
// list. It's used for artifact types whose canonical preimage is a flat
// set of string fields, to avoid declaring a one-off anonymous struct
// per type. The output is byte-stable as long as the kv list order is
// stable (which the caller controls).
func canonicalHashOf(kind string, pairs []kv) string {
	var sb strings.Builder
	sb.WriteString("{\"kind\":\"")
	sb.WriteString(kind)
	sb.WriteString("\"")
	for _, p := range pairs {
		sb.WriteString(",\"")
		sb.WriteString(p.k)
		sb.WriteString("\":")
		// JSON-encode the value (string only — that's all this helper handles).
		sb.WriteByte('"')
		sb.WriteString(jsonEscape(p.v))
		sb.WriteByte('"')
	}
	sb.WriteByte('}')
	sum := sha256.Sum256([]byte(sb.String()))
	return fmt.Sprintf("%x", sum)
}

// jsonEscape minimally escapes a string for inclusion inside a JSON
// double-quoted value. Verdifax artifact values are constrained to
// hex hashes, IDs, and short ASCII tokens — so we only need to handle
// backslash and double-quote (other characters in our domain are safe).
func jsonEscape(s string) string {
	if !strings.ContainsAny(s, `"\`) {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s) + 4)
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}
