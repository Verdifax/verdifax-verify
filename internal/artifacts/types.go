package artifacts

// AttestedContext is the caller-supplied "what was happening when this
// run was triggered" block. Verdifax does not call an AI or evaluate a
// business policy — it produces a sealed manifest of what the caller
// did. The caller passes this block in the /execute request; Verdifax
// records it verbatim into the EPA artifact.
//
// Every field is optional. When the caller supplies nothing, the bundle
// records `attested: false` and the EPA's actor / model fields read as
// "self_attested_deterministic" — meaning "the caller did not declare a
// human actor or AI model; the run is the deterministic pipeline alone."
type AttestedContext struct {
	// Attested is true when the caller supplied at least one field.
	Attested bool `json:"attested"`

	// Actor — who initiated the action.
	ActorID            string `json:"actor_id,omitempty"`
	ActorRole          string `json:"actor_role,omitempty"`
	AuthorizationPolicy string `json:"authorization_policy,omitempty"`
	ActorSignature     string `json:"actor_signature,omitempty"` // base64

	// Model — which AI (if any) the caller invoked before /execute.
	ModelProvider   string  `json:"model_provider,omitempty"`
	ModelName       string  `json:"model_name,omitempty"`
	ModelVersion    string  `json:"model_version,omitempty"`
	ModelTemperature *float64 `json:"model_temperature,omitempty"`
	PromptHash      string  `json:"prompt_hash,omitempty"` // sha256 of the prompt

	// Decision — the caller's interpretation of the result.
	DecisionKind   string `json:"decision_kind,omitempty"`   // e.g. "approve", "deny", "advise"
	DecisionResult string `json:"decision_result,omitempty"` // e.g. "approved"
	DecisionNote   string `json:"decision_note,omitempty"`   // free-form
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. PAYLOAD
// ─────────────────────────────────────────────────────────────────────────────

// Payload is the canonical record of the input bytes that entered the
// pipeline. Verdifax stores the SHA-256 of the payload and metadata
// about its origin; for confidentiality, the raw bytes are NOT stored
// in the audit bundle by default (the caller can opt in).
type Payload struct {
	Kind            string `json:"kind"`             // "verdifax.artifact.payload.v1"
	PayloadID       string `json:"payload_id"`       // matches envelope payload field
	ContentHash     string `json:"content_hash"`     // sha256 of raw payload bytes
	ContentLength   int    `json:"content_length"`   // bytes
	ContentInline   string `json:"content_inline,omitempty"` // base64; only when caller opts in
	OriginType      string `json:"origin_type"`      // "api" | "user" | "system"
	SchemaVersion   string `json:"schema_version"`   // "v1"
	Hash            string `json:"hash"`             // canonical hash of this object (filled by Build)
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. ENVELOPE
// ─────────────────────────────────────────────────────────────────────────────

// Envelope describes the sealed envelope produced by the DOG kernel.
// It binds the payload to the program and route, and is the first
// link in the deterministic execution chain.
type Envelope struct {
	Kind               string `json:"kind"` // "verdifax.artifact.envelope.v1"
	EnvelopeID         string `json:"envelope_id"`
	PayloadHash        string `json:"payload_hash"`
	ProgramID          string `json:"program_id"`
	RouteID            string `json:"route_id"`
	RegistryRecordHash string `json:"registry_record_hash"`
	Timestamp          string `json:"timestamp"`     // RFC3339
	Hash               string `json:"hash"`
	Seal               SealReference `json:"seal"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. TRANSPORT
// ─────────────────────────────────────────────────────────────────────────────

// Transport describes the deterministic transport-layer record. It
// binds the envelope to a specific slot-scoped sequence position so
// the execution order is reproducible.
type Transport struct {
	Kind         string `json:"kind"` // "verdifax.artifact.transport.v1"
	EnvelopeID   string `json:"envelope_id"`
	EnvelopeHash string `json:"envelope_hash"`
	SequenceID   string `json:"sequence_id"`
	Route        []string `json:"route"` // canonical hop list
	Hash         string `json:"hash"`
	Seal         SealReference `json:"seal"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. EPA — Execution Pre-Attestation
// ─────────────────────────────────────────────────────────────────────────────

// EPA describes the state of the system at the moment of execution. This
// is the artifact that incorporates the caller's AttestedContext.
type EPA struct {
	Kind                string          `json:"kind"` // "verdifax.artifact.epa.v1"
	KernelID            string          `json:"kernel_id"`
	KernelVersion       string          `json:"kernel_version"`
	PolicyHash          string          `json:"policy_hash"`
	EnvironmentSnapshot EnvSnapshot     `json:"environment_snapshot"`
	AttestedContext     AttestedContext `json:"attested_context"`
	Hash                string          `json:"hash"`
	Seal                SealReference   `json:"seal"`
}

type EnvSnapshot struct {
	Time   string `json:"time"`   // RFC3339
	Region string `json:"region"` // e.g. "fly:iad", "self-host"
	OS     string `json:"os"`     // "linux", "darwin"
	GoVersion string `json:"go_version"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. EFA — Execution Flow Artifact
// ─────────────────────────────────────────────────────────────────────────────

// EFA describes the per-kernel execution chain (DSE, TOK, DSC, NREP,
// AIVP, DCAE — six steps in canonical order).
type EFA struct {
	Kind            string         `json:"kind"` // "verdifax.artifact.efa.v1"
	Steps           []ExecStep     `json:"steps"`
	Deterministic   bool           `json:"deterministic"`
	FailClosed      bool           `json:"fail_closed"`
	Hash            string         `json:"hash"`
	Seal            SealReference  `json:"seal"`
}

type ExecStep struct {
	StepIndex   int    `json:"step_index"`
	Kernel      string `json:"kernel"`       // "DSE", "TOK", ...
	ExecutionID string `json:"execution_id"` // matches manifest.ExecutionIDs[i]
	Status      string `json:"status"`       // "ok" | "halt"
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. AER — Attestation Execution Record
// ─────────────────────────────────────────────────────────────────────────────

// AER describes the post-execution result record.
type AER struct {
	Kind          string         `json:"kind"` // "verdifax.artifact.aer.v1"
	EnvelopeID    string         `json:"envelope_id"`
	SequenceID    string         `json:"sequence_id"`
	ExecutionIDs  []string       `json:"execution_ids"` // 6 entries, canonical order
	FinalState    string         `json:"final_state"`   // "committed" | "halted"
	Decision      DecisionRecord `json:"decision"`
	Hash          string         `json:"hash"`
	Seal          SealReference  `json:"seal"`
}

type DecisionRecord struct {
	Source       string `json:"source"`       // "caller_attested" | "self_attested_deterministic"
	Kind         string `json:"kind,omitempty"`
	Result       string `json:"result,omitempty"`
	Note         string `json:"note,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. TRANSCRIPT (L7)
// ─────────────────────────────────────────────────────────────────────────────

// Transcript is the L7 transcript artifact: the Fiat-Shamir transcript
// over which the ZKSP proof is computed. The full transcript bytes are
// not stored in the audit bundle (they can be many KB); only the hash,
// shape metadata, and a short scaffold note for the Phase 6 upgrade.
type Transcript struct {
	Kind           string         `json:"kind"` // "verdifax.artifact.transcript.v1"
	ProofHashInput string         `json:"proof_hash_input"`  // the hash that fed L7
	TranscriptHash string         `json:"transcript_hash"`   // computed by ZKSP
	Scaffold       ScaffoldNote   `json:"scaffold"`
	Hash           string         `json:"hash"`
	Seal           SealReference  `json:"seal"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. HARDWARE ATTESTATION (L8)
// ─────────────────────────────────────────────────────────────────────────────

// HardwareAttestation is the L8 hardware-attestation artifact. In the
// current build this is the policy-scaffold record described in
// PHASE5_HARDWARE_REQUIREMENTS.md; the real TPM2 / SEV-SNP quote lands
// in Phase 7. The audit bundle is honest about this.
type HardwareAttestation struct {
	Kind                  string         `json:"kind"` // "verdifax.artifact.hw_attestation.v1"
	AttestationMode       string         `json:"attestation_mode"` // "policy_scaffold" | "tpm2" | "sev_snp"
	EnclaveMeasurement    string         `json:"enclave_measurement"`
	FirmwareClass         string         `json:"firmware_class"`
	SecureBootState       string         `json:"secure_boot_state"`
	ExecutionEnvironment  string         `json:"execution_environment"`
	PCRSelection          string         `json:"pcr_selection"`
	Tier4Blockers         []string       `json:"tier4_blockers"`
	Scaffold              ScaffoldNote   `json:"scaffold"`
	Hash                  string         `json:"hash"`
	Seal                  SealReference  `json:"seal"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. LEAKAGE BUNDLE (L9)
// ─────────────────────────────────────────────────────────────────────────────

type LeakageBundle struct {
	Kind                   string         `json:"kind"` // "verdifax.artifact.leakage.v1"
	ConstantTimeCompliant  bool           `json:"constant_time_compliant"`
	TimingVarianceObserved bool           `json:"timing_variance_observed"`
	Mitigations            []string       `json:"mitigations"`
	Hash                   string         `json:"hash"`
	Seal                   SealReference  `json:"seal"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. ZKSP BINDING
// ─────────────────────────────────────────────────────────────────────────────

type ZkspBinding struct {
	Kind                 string         `json:"kind"` // "verdifax.artifact.zksp_binding.v1"
	ProvingSystem        string         `json:"proving_system"`
	VerificationStatus   string         `json:"verification_status"` // "VERIFIED_SOUND_COMPLETE_ZK" | ...
	BindsTo              []string       `json:"binds_to"` // ["envelope_id", "aer_hash", "program_id", "registry_record_hash"]
	Scaffold             ScaffoldNote   `json:"scaffold"`
	Hash                 string         `json:"hash"`
	Seal                 SealReference  `json:"seal"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. MIGRATION TOKEN
// ─────────────────────────────────────────────────────────────────────────────

type MigrationToken struct {
	Kind        string         `json:"kind"` // "verdifax.artifact.migration_token.v1"
	FromVersion string         `json:"from_version"`
	ToVersion   string         `json:"to_version"`
	StateHash   string         `json:"state_hash"`
	Hash        string         `json:"hash"`
	Seal        SealReference  `json:"seal"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. REPLAY FINGERPRINT
// ─────────────────────────────────────────────────────────────────────────────

type ReplayFingerprint struct {
	Kind                string         `json:"kind"` // "verdifax.artifact.replay.v1"
	DeterministicInputs []string       `json:"deterministic_inputs"`
	ExpectedOutputHash  string         `json:"expected_output_hash"`
	Hash                string         `json:"hash"`
	Seal                SealReference  `json:"seal"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. POTE PROOF
// ─────────────────────────────────────────────────────────────────────────────

type PoteProof struct {
	Kind                string         `json:"kind"` // "verdifax.artifact.pote.v1"
	ProofType           string         `json:"proof_type"`
	ExecutionTraceHash  string         `json:"execution_trace_hash"`
	LogEntryID          string         `json:"log_entry_id"` // rekor entry
	Scaffold            ScaffoldNote   `json:"scaffold"`
	Hash                string         `json:"hash"`
	Seal                SealReference  `json:"seal"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. FINAL VFA
// ─────────────────────────────────────────────────────────────────────────────

type FinalVFA struct {
	Kind                string         `json:"kind"` // "verdifax.artifact.final_vfa.v1"
	EnvelopeHash        string         `json:"envelope_hash"`
	TransportHash       string         `json:"transport_hash"`
	EpaHash             string         `json:"epa_hash"`
	EfaHash             string         `json:"efa_hash"`
	AerHash             string         `json:"aer_hash"`
	TranscriptHash      string         `json:"transcript_hash"`
	HardwareAttestHash  string         `json:"hardware_attestation_hash"`
	LeakageBundleHash   string         `json:"leakage_bundle_hash"`
	ZkspBindingHash     string         `json:"zksp_binding_hash"`
	MigrationTokenHash  string         `json:"migration_token_hash"`
	ReplayFingerprint   string         `json:"replay_fingerprint"`
	PoteProofHash       string         `json:"pote_proof_hash"`
	IndependentVerified bool           `json:"independent_verified"`
	Hash                string         `json:"hash"`
	Seal                SealReference  `json:"seal"`
}

// ─────────────────────────────────────────────────────────────────────────────
// AuditBundle — the top-level artifact that wraps all 14 canonical artifacts.
// ─────────────────────────────────────────────────────────────────────────────

// AuditBundle is the complete Verdifax Audit Projection record for a
// single run. It is what the new GET /runs/{id}/artifacts endpoint
// returns and what the dashboard / PDF renderers consume.
type AuditBundle struct {
	Kind          string `json:"kind"` // "verdifax.audit_bundle.v1"
	SchemaVersion string `json:"schema_version"`

	RunID        int    `json:"run_id"`
	Status       string `json:"status"`
	ManifestHash string `json:"manifest_hash"`
	GeneratedAt  string `json:"generated_at"` // RFC3339

	// The 14 canonical artifacts, in canonical order.
	Payload             Payload             `json:"payload"`
	Envelope            Envelope            `json:"envelope"`
	Transport           Transport           `json:"transport"`
	EPA                 EPA                 `json:"epa"`
	EFA                 EFA                 `json:"efa"`
	AER                 AER                 `json:"aer"`
	Transcript          Transcript          `json:"transcript"`
	HardwareAttestation HardwareAttestation `json:"hardware_attestation"`
	LeakageBundle       LeakageBundle       `json:"leakage_bundle"`
	ZkspBinding         ZkspBinding         `json:"zksp_binding"`
	MigrationToken      MigrationToken      `json:"migration_token"`
	ReplayFingerprint   ReplayFingerprint   `json:"replay_fingerprint"`
	PoteProof           PoteProof           `json:"pote_proof"`
	FinalVFA            FinalVFA            `json:"final_vfa"`

	// Five extension categories that turn the bundle into a complete
	// auditor-ready record. Each is optional at the protocol level —
	// callers that don't supply one get an honest "not declared" record
	// rather than fabricated data. SystemProvenance is server-detected.
	RequestSubstance       RequestSubstance       `json:"request_substance"`
	AuthorizationChain     AuthorizationChain     `json:"authorization_chain"`
	RegulatoryScaffolding  RegulatoryScaffolding  `json:"regulatory_scaffolding"`
	CausalGraph            CausalGraph            `json:"causal_graph"`
	SystemProvenance       SystemProvenance       `json:"system_provenance"`
	ReproducibilityContext ReproducibilityContext `json:"reproducibility_context"`

	// RekorAnchor carries the Sigstore Rekor inclusion-proof evidence
	// for runs sealed under LedgerBackend == "rekor". When the
	// orchestrator is running in mock-ledger mode the field is the
	// zero value (Backend == "mock", InclusionPath empty); the
	// verifier interprets that as "no public-log claim made for this
	// run" and skips the offline Rekor verification check.
	//
	// When Backend == "rekor", the verifier passes the contents of
	// this field to internal/rekorverify.VerifyAnchor() to confirm
	// offline that the leaf hash is committed under a Rekor-signed
	// root, with no network access required.
	RekorAnchor RekorAnchor `json:"rekor_anchor"`

	// AivpT4 carries the Tier-4 governance evidence for runs that
	// passed through Stage 3.7 (AIVP-T4). For runs that ran with
	// AivpOutcome == "release" the section records the PIA hash, the
	// adapter that produced the decision, and the §0 hash of the AI
	// output text governed. For runs that halted at AIVP-T4 the
	// HaltReceiptHash points to the sealed AivpT4HaltReceipt
	// retrievable via /runs/{id}/aivp-t4-halt-receipt.
	//
	// Empty (zero-valued, Outcome == "skipped") for runs that didn't
	// engage AIVP-T4 — either because the orchestrator wasn't wired
	// for it (pre-Phase-13) or because the caller didn't declare an
	// AI output to govern.
	AivpT4 AivpT4Section `json:"aivp_t4"`

	// Nrep carries the Phase-15 Ed25519 actor-signing evidence. For
	// authenticated runs this section holds the API key holder's
	// stable actor identity, base64-encoded Ed25519 public key, and
	// signature over the canonical preimage (see internal/nrep). For
	// anonymous (open-mode) runs all three fields are empty —
	// "skipped" as a legitimate state, mirroring the manifest. The
	// signature itself is verifiable by anyone holding the public
	// key plus the run's envelope_id and aer_hash; no Verdifax
	// cooperation required.
	Nrep NrepSection `json:"nrep"`

	// BundleHash seals the audit bundle itself (independent of the
	// manifest hash).
	BundleHash string `json:"bundle_hash"`
}

// NrepSection is the audit-bundle representation of one Phase-15
// NREP signing pass. Mirrors the manifest's NrepActorID +
// NrepActorPublicKey + NrepSignature fields.
//
// All three fields are empty for anonymous (open-mode) runs and for
// runs that halted before AER was built (NREP signs after AER, so
// pre-AER halts produce no signature). A truly empty NREP section
// is a legitimate state — verifiers must NOT treat empty fields as
// "skipped means valid"; they signal "no actor signature claimed"
// and the run's authority must be established by surrounding-system
// audit logs.
type NrepSection struct {
	// ActorID is the API key holder's stable identifier. Empty when
	// no actor signature was claimed (anonymous run, pre-Phase-15
	// run, or run halted before NREP stage).
	ActorID string `json:"actor_id"`

	// PublicKey is base64-std of the actor's 32-byte Ed25519 public
	// key. Empty when ActorID is empty.
	PublicKey string `json:"public_key"`

	// Signature is base64-std of the 64-byte Ed25519 signature over
	// "verdifax.nrep.v1" || envelope_id || aer_hash || actor_id ||
	// run_clock. Verifiable using internal/nrep.Verify with the
	// PublicKey above and the bundle's envelope_id + aer_hash.
	// Empty when ActorID is empty.
	Signature string `json:"signature"`
}

// AivpT4Section is the audit-bundle representation of one AIVP-T4
// governance pass. Mirrors the manifest's six AIVP-T4 fields plus the
// halt-receipt hash (when applicable) into a single canonical record.
//
// The §0 invariants this section preserves:
//
//   - PiaHash is the canonical Tier-4 governance seal — anyone holding
//     the AI output text plus the AIVP-T4 binary can recompute this
//     hash and confirm it matches.
//   - AiOutputHash is the §0 SHA-256 of the input text the governance
//     pipeline ran on, computed Go-side and bound into the manifest
//     so the chain-of-custody extends from caller input through halt
//     without storing the raw text.
//   - AdapterID names which model adapter produced the decision
//     ("mock-claude", "live-claude-api", or future identifiers) so
//     verifiers can scope their trust evaluation appropriately —
//     mock-mode runs should not be presented to third parties as
//     evidence of real-model governance.
type AivpT4Section struct {
	// Outcome is one of "release", "halted", "skipped". Mirrors the
	// manifest's AivpOutcome field.
	Outcome string `json:"outcome"`

	// PiaHash is the §0 SHA-256 hex of the canonical Tier-4
	// governance preimage. 64 lowercase hex characters when AIVP-T4
	// ran; empty when Outcome == "skipped".
	PiaHash string `json:"pia_hash"`

	// AdapterID names the model adapter that produced the decision.
	// "mock-claude" / "live-claude-api" / future identifiers. Empty
	// when Outcome == "skipped".
	AdapterID string `json:"adapter_id"`

	// AiOutputHash is the §0 SHA-256 hex of the AI output text the
	// governance pipeline ran on. Empty string when the caller didn't
	// declare an AI output (Outcome == "release" with empty hash) or
	// when AIVP-T4 was skipped entirely.
	AiOutputHash string `json:"ai_output_hash"`

	// Decision is the lowercase decision kind. "release" on allow;
	// "deny" / "halt" / "defer" on halt outcomes. Empty when Outcome
	// == "skipped".
	Decision string `json:"decision"`

	// HaltReceiptHash is the §0 SHA-256 hex of the sealed
	// AivpT4HaltReceipt artifact. Empty unless Outcome == "halted".
	// When non-empty, the full receipt is retrievable via
	// /runs/{id}/aivp-t4-halt-receipt.
	HaltReceiptHash string `json:"halt_receipt_hash"`
}

// RekorAnchor is the public-transparency-log evidence bundled
// alongside the audit artifacts. Mirrors the manifest's
// LedgerInclusionProof + LedgerBackend + LedgerLeafHash + LogEntryID
// for self-contained offline verification.
//
// Empty for mock-ledger runs (Backend = "mock", everything else
// zero-valued). For Rekor-anchored runs every field is populated
// from the response Rekor returned at submit time.
type RekorAnchor struct {
	// Backend identifies the ledger that produced this anchor:
	// "mock" or "rekor". Verifiers dispatch on this field.
	Backend string `json:"backend"`

	// LogEntryID is the numeric Rekor log index as a decimal string
	// (matches the manifest's Stage-7 LogEntryID).
	LogEntryID string `json:"log_entry_id"`

	// LogID is the hex SHA-256 of Rekor's public-key DER. The
	// verifier confirms its embedded Rekor public key produces this
	// same LogID.
	LogID string `json:"log_id"`

	// LeafHashHex is the hex SHA-256 of the canonical leaf bytes
	// committed to Rekor. Anyone reading the bundle can recompute the
	// leaf bytes from the manifest's envelope_id + aer_hash +
	// zksp_binding_hash and confirm they hash to this value.
	LeafHashHex string `json:"leaf_hash"`

	// LogIndex is the leaf's 0-based position in the Rekor Merkle
	// tree (numeric form of LogEntryID).
	LogIndex int64 `json:"log_index"`

	// TreeSize is the total number of leaves in the Rekor tree at
	// the time this proof was issued.
	TreeSize int64 `json:"tree_size"`

	// RootHashHex is the claimed Merkle root hex SHA-256 the inclusion
	// proof recomputes to.
	RootHashHex string `json:"root_hash"`

	// InclusionPath is the ordered list of hex sibling hashes the
	// verifier walks from leaf up to root.
	InclusionPath []string `json:"inclusion_path"`

	// Checkpoint is the c2sp.org/tlog-checkpoint signed note over
	// (root_hash, tree_size). The verifier checks this signature
	// against the embedded Rekor public key.
	Checkpoint string `json:"checkpoint"`

	// SignedEntryTimestamp is the per-entry Rekor signature (SET).
	SignedEntryTimestamp string `json:"signed_entry_timestamp"`

	// IntegratedTime is the unix epoch seconds at which Rekor
	// integrated the leaf into the tree.
	IntegratedTime int64 `json:"integrated_time"`
}
