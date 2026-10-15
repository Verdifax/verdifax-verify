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
	parts := make([]string, 0, len(stages)+1)
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
	parts := make([]string, 0, len(table)*2+1)
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
