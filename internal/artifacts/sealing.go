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
