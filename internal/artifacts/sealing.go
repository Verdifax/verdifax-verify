package artifacts

// Byte-identical port of the orchestrator's anchored-sealing digests
// (internal/artifacts/sealing.go there). These are the single source
// of truth for what the version-3 ledger leaf covers: the actor
// section and the scaffold flags, recomputed HERE from the bundle's
// own section contents so the anchor binds the contents, never a
// stored digest an editor could rewrite alongside them. The runtime
// timing digest is bundle-sealed only (per-run timings in the leaf
// would ride into the manifest hash and break replay determinism).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	nrepSectionDomain   = "verdifax.nrep.section.v1"
	scaffoldFlagsDomain = "verdifax.scaffold.flags.v1"
	runtimeTimingDomain = "verdifax.timing.v1"
)

// ComputeNrepSectionHash digests the four actor-section fields with
// null-byte separation; all-empty inputs produce a stable constant.
func ComputeNrepSectionHash(actorID, publicKey, signature, signedAt string) string {
	return nullJoinHash(nrepSectionDomain, actorID, publicKey, signature, signedAt)
}

// ComputeScaffoldFlagsHash digests the four pipeline-owned scaffold
// bits in fixed order: transcript, hardware attestation, zksp
// binding, leakage bundle. PoTE is deliberately absent: clearing it
// on a mock run means claiming an anchor the Rekor checks then fail
// to find.
func ComputeScaffoldFlagsHash(transcript, hardware, zksp, leakage bool) string {
	return nullJoinHash(scaffoldFlagsDomain,
		boolWord(transcript), boolWord(hardware), boolWord(zksp), boolWord(leakage))
}

// StageTiming is one measured pre-anchor pipeline stage duration:
// a real wall-clock measurement, not a declaration.
type StageTiming struct {
	Stage         string `json:"stage"`
	DurationNanos int64  `json:"duration_nanos"`
}

// ComputeRuntimeTimingHash digests the ordered measured durations.
func ComputeRuntimeTimingHash(stages []StageTiming) string {
	var parts []string
	parts = append(parts, runtimeTimingDomain)
	for _, s := range stages {
		parts = append(parts, fmt.Sprintf("%s=%d", s.Stage, s.DurationNanos))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func boolWord(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func nullJoinHash(domain string, fields ...string) string {
	parts := append([]string{domain}, fields...)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// ─────────────────────────────────────────────────────────────────────
// Pre-anchor digest (leaf v5): byte-identical port of the producing
// side. The bundle's pre_anchor table carries every pre-anchor value
// by frozen name; the v5 leaf anchors the digest of that table; and
// preanchor.go cross-checks each entry against the section that
// displays it. The runtime-timing digest is deliberately absent from
// the table (per-run values would break replay determinism through
// the manifest-covered leaf); timing stays bundle-sealed.
// ─────────────────────────────────────────────────────────────────────

const (
	preAnchorDomain       = "verdifax.preanchor.v1"
	attestedContextDomain = "verdifax.attested.v1"
)

// ComputeAttestedContextDigest canonically digests the caller-attested
// block, frozen field order.
func ComputeAttestedContextDigest(ac AttestedContext) string {
	temp := ""
	if ac.ModelTemperature != nil {
		temp = fmt.Sprintf("%g", *ac.ModelTemperature)
	}
	return nullJoinHash(attestedContextDomain,
		boolWord(ac.Attested),
		ac.ActorID, ac.ActorRole, ac.AuthorizationPolicy, ac.ActorSignature,
		ac.ModelProvider, ac.ModelName, ac.ModelVersion, temp, ac.PromptHash,
		ac.DecisionKind, ac.DecisionResult, ac.DecisionNote)
}

// PreAnchorNames is the frozen key order of the pre-anchor table.
var PreAnchorNames = []string{
	"program_id", "route_id", "registry_record_hash", "clock_epoch",
	"attested_digest", "input_hash", "envelope_id", "envelope_hash",
	"transport_hash", "epa_hash", "efa_hash", "aer_hash", "execution_ids",
	"pepg_outcome", "allow_token_hash", "deny_receipt_hash",
	"aivp_outcome", "aivp_adapter_id", "aivp_pia_hash",
	"aivp_ai_output_hash", "aivp_halt_receipt_hash", "transcript_hash",
	"hardware_attestation_hash", "leakage_bundle_hash", "zksp_binding_hash",
	"formal_verifier_status", "migration_token_hash", "replay_fingerprint",
	"nrep_actor_id", "nrep_public_key", "nrep_signature", "nrep_signed_at",
	"scaffold_flags_hash",
}

// ComputePreAnchorDigestFromTable digests the table in its own order;
// callers must first confirm the order matches PreAnchorNames.
func ComputePreAnchorDigestFromTable(table []PreAnchorEntry) string {
	var parts []string
	parts = append(parts, preAnchorDomain)
	for _, e := range table {
		parts = append(parts, e.Name, e.Value)
	}
	return nullJoinHashParts(parts)
}

func nullJoinHashParts(parts []string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// ─────────────────────────────────────────────────────────────────────
// Pre-anchor table v2 (leaf v6): byte-identical port of the producing
// side. Round seven showed that deleting bundle_anchor from a v5
// record downgrades it to the honest partial verdict an older record
// earns, so a forger who rewrites the descriptive sections and strips
// the second entry still exits 0. A v6 record closes that by stating,
// inside the values its FIRST public-log entry already anchors, that a
// complete-record anchor must exist: the v2 table is the frozen v1
// list plus one row, complete_record_anchor = "required". Removing or
// changing that row changes the table digest, the rebuilt v6 leaf
// stops matching the logged entry, and the record FAILS; leaving it in
// place makes a missing or failing bundle_anchor a FAILURE.
//
// The v1 recipe above is untouched: v5 records keep their exact
// verdicts, and the guarantee cannot be added to them after the fact.
//
// The bundle anchor's own recipe (bundle_anchor.go, pair 2) is frozen
// and digests the stored table with ComputePreAnchorDigestFromTable
// for every table form. For a v2 table that pair is the v1-domain
// digest over all 34 rows: a different number from pre_anchor_digest,
// but just as binding, since it is an injective function of the same
// rows.
// ─────────────────────────────────────────────────────────────────────

const (
	// PreAnchorFormV1 names the v1 table (leaf v5).
	PreAnchorFormV1 = "verdifax.preanchor.v1"
	// PreAnchorFormV2 names the v2 table (leaf v6) and is its digest
	// domain tag.
	PreAnchorFormV2 = "verdifax.preanchor.v2"

	// CompleteRecordAnchorRow is the row a v2 table adds.
	CompleteRecordAnchorRow = "complete_record_anchor"
	// CompleteRecordAnchorRequired is that row's only defined value.
	CompleteRecordAnchorRequired = "required"
)

// PreAnchorNamesV2 is the frozen key order of the v2 table: the v1
// list unchanged, then the requirement row. Spelled out rather than
// derived so a later edit to the v1 list cannot silently move it.
var PreAnchorNamesV2 = []string{
	"program_id", "route_id", "registry_record_hash", "clock_epoch",
	"attested_digest", "input_hash", "envelope_id", "envelope_hash",
	"transport_hash", "epa_hash", "efa_hash", "aer_hash", "execution_ids",
	"pepg_outcome", "allow_token_hash", "deny_receipt_hash",
	"aivp_outcome", "aivp_adapter_id", "aivp_pia_hash",
	"aivp_ai_output_hash", "aivp_halt_receipt_hash", "transcript_hash",
	"hardware_attestation_hash", "leakage_bundle_hash", "zksp_binding_hash",
	"formal_verifier_status", "migration_token_hash", "replay_fingerprint",
	"nrep_actor_id", "nrep_public_key", "nrep_signature", "nrep_signed_at",
	"scaffold_flags_hash",
	CompleteRecordAnchorRow,
}

// ComputePreAnchorDigestV2FromTable digests a v2 table in its own
// order under the v2 domain; callers must first confirm the order
// matches PreAnchorNamesV2.
func ComputePreAnchorDigestV2FromTable(table []PreAnchorEntry) string {
	var parts []string
	parts = append(parts, PreAnchorFormV2)
	for _, e := range table {
		parts = append(parts, e.Name, e.Value)
	}
	return nullJoinHashParts(parts)
}

// ─────────────────────────────────────────────────────────────────────
// Pre-anchor table v3 (leaf v7). Round seven of the external review
// showed that a public-log entry proves only that its leaf is in the
// log, not who logged it or when: a forger could rewrite a record and
// log it again. Verifier 0.12.0 closes the "who" half by pinning the
// Verdifax log-signing key and the "when" half by verifying Rekor's
// signed entry timestamp. Neither stops the key holder, Verdifax
// itself, from logging a rewritten record later. A v3 table states,
// inside the values its FIRST entry anchors, the window in seconds
// within which both entries must be logged after the run's sealed
// clock_epoch. A later re-log then falls outside the window; moving
// clock_epoch to match changes the record's own sealed time, so the
// record can no longer claim its original date.
//
// The v3 table is the v2 table unchanged plus one row. Removing or
// changing that row changes the table digest, the rebuilt v7 leaf
// stops matching the logged entry, and the record FAILS.
// ─────────────────────────────────────────────────────────────────────

const (
	// PreAnchorFormV3 names the v3 table (leaf v7) and is its digest
	// domain tag.
	PreAnchorFormV3 = "verdifax.preanchor.v3"

	// AnchoringWindowRow is the row a v3 table adds: the maximum
	// number of seconds between the run's clock_epoch and the
	// Rekor-authenticated time of either public-log entry.
	AnchoringWindowRow = "anchoring_window_seconds"
)

// PreAnchorNamesV3 is the frozen key order of the v3 table: the v2
// list unchanged, then the window row.
var PreAnchorNamesV3 = append(append([]string(nil), PreAnchorNamesV2...), AnchoringWindowRow)

// ComputePreAnchorDigestV3FromTable digests a v3 table in its own
// order under the v3 domain; callers must first confirm the order
// matches PreAnchorNamesV3.
func ComputePreAnchorDigestV3FromTable(table []PreAnchorEntry) string {
	var parts []string
	parts = append(parts, PreAnchorFormV3)
	for _, e := range table {
		parts = append(parts, e.Name, e.Value)
	}
	return nullJoinHashParts(parts)
}

// TableSealsAnchoringWindow reports whether a stored table carries the
// window row at any position, which selects the v3 form and the v7
// leaf. As with the requirement row, detection looks everywhere so a
// misplaced row is judged as v3 (and fails) rather than as v2.
func TableSealsAnchoringWindow(table []PreAnchorEntry) bool {
	for _, e := range table {
		if e.Name == AnchoringWindowRow {
			return true
		}
	}
	return false
}

// TableRequiresCompleteRecordAnchor reports whether a stored table
// carries the requirement row at any position, which is what selects
// the v2 table form and the v6 leaf. Position and value are enforced
// by the shape check; detection deliberately looks everywhere so a
// misplaced row is judged as v2 (and fails) rather than as v1.
func TableRequiresCompleteRecordAnchor(table []PreAnchorEntry) bool {
	for _, e := range table {
		if e.Name == CompleteRecordAnchorRow {
			return true
		}
	}
	return false
}

// PreAnchorTableForm returns the form of a stored table: v3 when it
// carries the window row, v2 when it carries the requirement row, v1
// otherwise.
func PreAnchorTableForm(table []PreAnchorEntry) string {
	if TableSealsAnchoringWindow(table) {
		return PreAnchorFormV3
	}
	if TableRequiresCompleteRecordAnchor(table) {
		return PreAnchorFormV2
	}
	return PreAnchorFormV1
}

// ComputePreAnchorDigestForTable digests a stored table under the
// domain of its own form: the digest the anchored leaf binds.
func ComputePreAnchorDigestForTable(table []PreAnchorEntry) string {
	if TableSealsAnchoringWindow(table) {
		return ComputePreAnchorDigestV3FromTable(table)
	}
	if TableRequiresCompleteRecordAnchor(table) {
		return ComputePreAnchorDigestV2FromTable(table)
	}
	return ComputePreAnchorDigestFromTable(table)
}
