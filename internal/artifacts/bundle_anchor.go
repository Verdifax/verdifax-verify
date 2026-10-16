package artifacts

// Anchored record digest and bundle leaf (bundle anchor v1).
//
// THIS FILE IS BYTE-IDENTICAL IN THE ORCHESTRATOR AND THE PUBLIC
// VERIFIER (internal/artifacts/bundle_anchor.go in both repositories).
// TestBundleAnchorGoldenVector pins the same expected hex in both, so
// any drift between producer and verifier fails a test on each side.
//
// # WHY IT EXISTS
//
// Round six of the external review rewrote aer.decision,
// request_substance, authorization_chain, causal_graph.effect_log and
// system_provenance on a live anchored record, recomputed the section
// hashes and bundle_hash, and the verifier still printed VERIFIED AND
// ANCHORED. The run's first public-log entry (the v5 leaf) binds the
// run identity and a 33-value pre-anchor table; it never bound
// bundle_hash, and several sections sit outside bundle_hash entirely.
// Every hash the verifier recomputed could therefore be rewritten
// together offline.
//
// The fix is a SECOND public-log entry per run, made after the bundle
// is fully built, whose leaf binds a digest of the complete record.
// The first entry and its recipe are untouched.
//
// # THE RECIPE (frozen; changing any byte orphans every anchored entry)
//
//	anchored_record_digest = hex(sha256(join("\x00",
//	    "verdifax.bundle.anchor.v1",
//	    name_1, value_1, name_2, value_2, ..., name_13, value_13)))
//
// over these thirteen named pairs, in exactly this order. Every value
// is a lowercase hex SHA-256 the verifier RECOMPUTES from the bundle's
// own contents; none is read from a stored digest field. Values are
// hex and names are fixed ASCII, so no value can contain the "\x00"
// separator and the join is unambiguous.
//
//	 1 bundle_hash           RecomputeBundleHash: kind, schema_version,
//	                         manifest_hash and the 20 section hashes it
//	                         lists. Each listed section hash is itself
//	                         recomputed from content by the verifier
//	                         (reproducibility_context gained its row in
//	                         verifier v0.10.0), so this pair binds the
//	                         14 pipeline artifacts and 6 categories.
//	 2 pre_anchor_digest     ComputePreAnchorDigestFromTable over the
//	                         stored table (outside bundle_hash).
//	 3 nrep_section          ComputeNrepSectionHash over the four actor
//	                         fields (outside bundle_hash).
//	 4 aivp_t4_section       ComputeAivpT4SectionHash, all six fields,
//	                         including aivp_t4.decision, which no
//	                         earlier seal covered.
//	 5 formal_verification   RecomputeFormalVerificationHash (a zero
//	                         section hashes to a stable constant).
//	 6 execution_record      ComputeExecutionRecordSectionHash, all
//	                         eleven fields, or the absent constant.
//	 7 runtime_timing        ComputeRuntimeTimingHash over the stored
//	                         stage durations (bundle-sealed until now).
//	 8 hardware_evidence     ComputeHardwareEvidenceHash: the SEV-SNP
//	                         quote, certificates, report data, recipe
//	                         and verification claim, none of which the
//	                         hardware_attestation section hash covers.
//	 9 pote_ledger           ComputePoteLedgerHash: pote_proof.kind and
//	                         the ledger fields the v1 pote hash omits.
//	10 scaffold_notes        ComputeScaffoldNotesHash: all five
//	                         scaffold notes (flag, activated_by, note).
//	11 seal_references       ComputeSealReferencesHash: all 18 seal
//	                         references (manifest_hash, seal_field,
//	                         sealed_hash), in the verifier's order.
//	12 section_residue       ComputeSectionResidueHash: the fields the
//	                         per-section hashes do not cover, namely
//	                         payload.content_inline and the kind field
//	                         of envelope, transport, transcript and
//	                         migration_token (their hashes write a
//	                         constant kind instead of the field).
//	13 record_metadata       ComputeRecordMetadataHash: run_id, status,
//	                         generated_at and the five stored top-level
//	                         digest strings.
//
// EXCLUDED, deliberately: rekor_anchor and bundle_anchor. Both are
// proofs, not content. rekor_anchor carries its own Merkle proof and
// signed checkpoint, its leaf is recomputed from the record by the
// v5 leaf check, and the server applies read-time corrections to it
// (entry_body backfill, global index, nonce quoting) that must not
// invalidate this digest. bundle_anchor cannot cover itself.
//
// # THE LEAF
//
//	bundle_leaf_hash = hex(sha256("verdifax.ledger.bundle.v1" + "." +
//	                              envelope_id + "." +
//	                              anchored_record_digest))
//
// Both variable components are dot-free (envelope_id is minted as
// "env-" plus hex, the digest is hex), which ValidateBundleLeafFields
// enforces before anything is hashed, so the dot-join is injective.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// BundleAnchorKind is bundle_anchor.kind.
	BundleAnchorKind = "verdifax.bundle_anchor.v1"
	// BundleAnchorDigestForm is bundle_anchor.digest_form and the
	// domain tag of the anchored record digest.
	BundleAnchorDigestForm = "verdifax.bundle.anchor.v1"
	// BundleLeafDomain is the domain tag of the bundle leaf.
	BundleLeafDomain = "verdifax.ledger.bundle.v1"

	aivpT4SectionForm    = "verdifax.aivp_t4.section.v1"
	executionRecordForm  = "verdifax.execution_record.section.v1"
	hardwareEvidenceForm = "verdifax.hardware_evidence.v1"
	poteLedgerForm       = "verdifax.pote_ledger.v1"
	scaffoldNotesForm    = "verdifax.scaffold_notes.v1"
	sealReferencesForm   = "verdifax.seal_references.v1"
	sectionResidueForm   = "verdifax.section_residue.v1"
	recordMetadataForm   = "verdifax.record_metadata.v1"
)

// BundleAnchor is the second public-log entry of a run: it anchors the
// complete sealed record. The anchor fields carry exactly the names
// and meanings of rekor_anchor's. LogEntryID is the GLOBAL Rekor index
// from the submit response (what search.sigstore.dev resolves);
// LogIndex is the shard-local position from the inclusion proof (what
// the Merkle walk uses). They differ on the sharded production log and
// must never be conflated.
type BundleAnchor struct {
	Kind           string `json:"kind"`
	DigestForm     string `json:"digest_form"`
	AnchoredDigest string `json:"anchored_digest"`

	Backend              string   `json:"backend"`
	LogEntryID           string   `json:"log_entry_id"`
	LogID                string   `json:"log_id"`
	LeafHashHex          string   `json:"leaf_hash"`
	LogIndex             int64    `json:"log_index"`
	TreeSize             int64    `json:"tree_size"`
	RootHashHex          string   `json:"root_hash"`
	InclusionPath        []string `json:"inclusion_path"`
	Checkpoint           string   `json:"checkpoint"`
	SignedEntryTimestamp string   `json:"signed_entry_timestamp"`
	IntegratedTime       int64    `json:"integrated_time"`
	EntryBody            string   `json:"entry_body,omitempty"`
}

// AnchoredRecordPair is one named value of the anchored record digest.
type AnchoredRecordPair struct {
	Name  string
	Value string
}

// AnchoredRecordNames is the frozen pair order.
var AnchoredRecordNames = []string{
	"bundle_hash", "pre_anchor_digest", "nrep_section", "aivp_t4_section",
	"formal_verification", "execution_record", "runtime_timing",
	"hardware_evidence", "pote_ledger", "scaffold_notes",
	"seal_references", "section_residue", "record_metadata",
}

// AnchoredRecordPairs recomputes every pair from the bundle's content.
func AnchoredRecordPairs(b *AuditBundle) []AnchoredRecordPair {
	values := []string{
		RecomputeBundleHash(b),
		ComputePreAnchorDigestFromTable(b.PreAnchor),
		ComputeNrepSectionHash(b.Nrep.ActorID, b.Nrep.PublicKey, b.Nrep.Signature, b.Nrep.SignedAt),
		ComputeAivpT4SectionHash(b.AivpT4),
		RecomputeFormalVerificationHash(b.FormalVerification),
		ComputeExecutionRecordSectionHash(b.ExecutionRecord),
		ComputeRuntimeTimingHash(b.RuntimeTiming),
		ComputeHardwareEvidenceHash(b.HardwareAttestation),
		ComputePoteLedgerHash(b.PoteProof),
		ComputeScaffoldNotesHash(b),
		ComputeSealReferencesHash(b),
		ComputeSectionResidueHash(b),
		ComputeRecordMetadataHash(b),
	}
	out := make([]AnchoredRecordPair, len(AnchoredRecordNames))
	for i, n := range AnchoredRecordNames {
		out[i] = AnchoredRecordPair{Name: n, Value: values[i]}
	}
	return out
}

// ComputeAnchoredRecordDigest is the digest the bundle leaf binds.
func ComputeAnchoredRecordDigest(b *AuditBundle) string {
	pairs := AnchoredRecordPairs(b)
	parts := make([]string, 0, 2*len(pairs)+1)
	parts = append(parts, BundleAnchorDigestForm)
	for _, p := range pairs {
		parts = append(parts, p.Name, p.Value)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// ValidateBundleLeafFields enforces the leaf recipe's one structural
// assumption: both variable components are non-empty and dot-free,
// and the digest is 64 lowercase hex characters.
func ValidateBundleLeafFields(envelopeID, anchoredDigest string) error {
	if envelopeID == "" {
		return fmt.Errorf("bundle leaf: envelope_id is empty")
	}
	if strings.Contains(envelopeID, ".") {
		return fmt.Errorf("bundle leaf: envelope_id contains a dot, which would make the dot-join preimage ambiguous; refusing to hash it")
	}
	if len(anchoredDigest) != 64 {
		return fmt.Errorf("bundle leaf: anchored digest must be 64 hex characters, got %d", len(anchoredDigest))
	}
	for _, c := range anchoredDigest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("bundle leaf: anchored digest must be lowercase hex")
		}
	}
	return nil
}

// BundleLeafPreimage is the exact string the bundle leaf hashes.
func BundleLeafPreimage(envelopeID, anchoredDigest string) string {
	return strings.Join([]string{BundleLeafDomain, envelopeID, anchoredDigest}, ".")
}

// ComputeBundleLeafHash returns hex(sha256(BundleLeafPreimage(...))).
func ComputeBundleLeafHash(envelopeID, anchoredDigest string) string {
	sum := sha256.Sum256([]byte(BundleLeafPreimage(envelopeID, anchoredDigest)))
	return hex.EncodeToString(sum[:])
}

// ComputeAivpT4SectionHash digests all six AIVP-T4 fields.
func ComputeAivpT4SectionHash(a AivpT4Section) string {
	return MustCanonicalHash(struct {
		Form            string `json:"form"`
		Outcome         string `json:"outcome"`
		PiaHash         string `json:"pia_hash"`
		AdapterID       string `json:"adapter_id"`
		AiOutputHash    string `json:"ai_output_hash"`
		Decision        string `json:"decision"`
		HaltReceiptHash string `json:"halt_receipt_hash"`
	}{aivpT4SectionForm, a.Outcome, a.PiaHash, a.AdapterID, a.AiOutputHash, a.Decision, a.HaltReceiptHash})
}

// ComputeExecutionRecordSectionHash digests every execution-record
// field; an absent record (nil) digests to a distinct constant.
func ComputeExecutionRecordSectionHash(r *ExecutionRecord) string {
	if r == nil {
		return MustCanonicalHash(struct {
			Form    string `json:"form"`
			Present bool   `json:"present"`
		}{executionRecordForm, false})
	}
	return MustCanonicalHash(struct {
		Form                    string   `json:"form"`
		Present                 bool     `json:"present"`
		Kind                    string   `json:"kind"`
		Formula                 string   `json:"formula"`
		InputHash               string   `json:"input_hash"`
		TransportHash           string   `json:"transport_hash"`
		ExecutionControlHash    string   `json:"execution_control_hash"`
		ProgramHash             string   `json:"program_hash"`
		KernelOutputIDs         []string `json:"kernel_output_ids"`
		HardwareAttestationHash string   `json:"hardware_attestation_hash"`
		HardwareAttested        bool     `json:"hardware_attested"`
		AerHash                 string   `json:"aer_hash"`
		ProofHash               string   `json:"proof_hash"`
	}{executionRecordForm, true, r.Kind, r.Formula, r.InputHash, r.TransportHash,
		r.ExecutionControlHash, r.ProgramHash, r.KernelOutputIDs,
		r.HardwareAttestationHash, r.HardwareAttested, r.AerHash, r.ProofHash})
}

// ComputeHardwareEvidenceHash digests the SEV-SNP evidence fields the
// hardware_attestation section hash does not cover. Verification is
// carried as-is: the orchestrator's attestation.VerifyResult and the
// verifier's SevSnpVerifyClaim have identical JSON field names and
// order, so both sides marshal the same bytes ("null" when absent).
func ComputeHardwareEvidenceHash(h HardwareAttestation) string {
	var verification any
	if h.Verification != nil {
		verification = h.Verification
	}
	return MustCanonicalHash(struct {
		Form             string `json:"form"`
		Platform         string `json:"platform"`
		QuoteB64         string `json:"quote_b64"`
		VLEKCertPEM      string `json:"vlek_cert_pem"`
		CertChainPEM     string `json:"cert_chain_pem"`
		ReportDataHex    string `json:"report_data_hex"`
		ReportDataRecipe string `json:"report_data_recipe"`
		Verification     any    `json:"verification"`
	}{hardwareEvidenceForm, h.Platform, h.QuoteB64, h.VLEKCertPEM, h.CertChainPEM,
		h.ReportDataHex, h.ReportDataRecipe, verification})
}

// ComputePoteLedgerHash digests pote_proof.kind and the ledger fields
// (the v1 pote hash covers none of them, the v2 hash all but kind and
// ledger_backend).
func ComputePoteLedgerHash(p PoteProof) string {
	return MustCanonicalHash(struct {
		Form                 string `json:"form"`
		Kind                 string `json:"kind"`
		LedgerBackend        string `json:"ledger_backend"`
		LedgerLogID          string `json:"ledger_log_id"`
		IntegratedTime       int64  `json:"integrated_time"`
		SignedEntryTimestamp string `json:"signed_entry_timestamp"`
		LedgerCheckpoint     string `json:"ledger_checkpoint"`
	}{poteLedgerForm, p.Kind, p.LedgerBackend, p.LedgerLogID, p.IntegratedTime,
		p.SignedEntryTimestamp, p.LedgerCheckpoint})
}

// ComputeScaffoldNotesHash digests the five scaffold notes in full.
func ComputeScaffoldNotesHash(b *AuditBundle) string {
	return MustCanonicalHash(struct {
		Form                string       `json:"form"`
		Transcript          ScaffoldNote `json:"transcript"`
		HardwareAttestation ScaffoldNote `json:"hardware_attestation"`
		LeakageBundle       ScaffoldNote `json:"leakage_bundle"`
		ZkspBinding         ScaffoldNote `json:"zksp_binding"`
		PoteProof           ScaffoldNote `json:"pote_proof"`
	}{scaffoldNotesForm, b.Transcript.Scaffold, b.HardwareAttestation.Scaffold,
		b.LeakageBundle.Scaffold, b.ZkspBinding.Scaffold, b.PoteProof.Scaffold})
}

type namedSeal struct {
	Section string        `json:"section"`
	Seal    SealReference `json:"seal"`
}

// ComputeSealReferencesHash digests all 18 seal references in the
// order the verifier reports them.
func ComputeSealReferencesHash(b *AuditBundle) string {
	return MustCanonicalHash(struct {
		Form  string      `json:"form"`
		Seals []namedSeal `json:"seals"`
	}{sealReferencesForm, []namedSeal{
		{"envelope", b.Envelope.Seal},
		{"transport", b.Transport.Seal},
		{"epa", b.EPA.Seal},
		{"efa", b.EFA.Seal},
		{"aer", b.AER.Seal},
		{"transcript", b.Transcript.Seal},
		{"hardware_attestation", b.HardwareAttestation.Seal},
		{"leakage_bundle", b.LeakageBundle.Seal},
		{"zksp_binding", b.ZkspBinding.Seal},
		{"migration_token", b.MigrationToken.Seal},
		{"replay_fingerprint", b.ReplayFingerprint.Seal},
		{"pote_proof", b.PoteProof.Seal},
		{"final_vfa", b.FinalVFA.Seal},
		{"request_substance", b.RequestSubstance.Seal},
		{"authorization_chain", b.AuthorizationChain.Seal},
		{"regulatory_scaffolding", b.RegulatoryScaffolding.Seal},
		{"causal_graph", b.CausalGraph.Seal},
		{"system_provenance", b.SystemProvenance.Seal},
	}})
}

// ComputeSectionResidueHash digests the section fields that their own
// section hashes do not cover.
func ComputeSectionResidueHash(b *AuditBundle) string {
	return MustCanonicalHash(struct {
		Form                 string `json:"form"`
		PayloadContentInline string `json:"payload_content_inline"`
		EnvelopeKind         string `json:"envelope_kind"`
		TransportKind        string `json:"transport_kind"`
		TranscriptKind       string `json:"transcript_kind"`
		MigrationTokenKind   string `json:"migration_token_kind"`
	}{sectionResidueForm, b.Payload.ContentInline, b.Envelope.Kind, b.Transport.Kind,
		b.Transcript.Kind, b.MigrationToken.Kind})
}

// ComputeRecordMetadataHash digests the top-level fields outside
// bundle_hash that are not themselves proofs.
func ComputeRecordMetadataHash(b *AuditBundle) string {
	return MustCanonicalHash(struct {
		Form              string `json:"form"`
		RunID             int    `json:"run_id"`
		Status            string `json:"status"`
		GeneratedAt       string `json:"generated_at"`
		NrepSectionHash   string `json:"nrep_section_hash"`
		ScaffoldFlagsHash string `json:"scaffold_flags_hash"`
		RuntimeTimingHash string `json:"runtime_timing_hash"`
		PreAnchorDigest   string `json:"pre_anchor_digest"`
		AttestedDigest    string `json:"attested_digest"`
	}{recordMetadataForm, b.RunID, b.Status, b.GeneratedAt, b.NrepSectionHash,
		b.ScaffoldFlagsHash, b.RuntimeTimingHash, b.PreAnchorDigest, b.AttestedDigest})
}

// RecomputeReproducibilityContextHash reproduces the builder's hash of
// category 6: the canonical hash of the section with Hash blanked.
func RecomputeReproducibilityContextHash(rc ReproducibilityContext) string {
	rc.Hash = ""
	return MustCanonicalHash(rc)
}
