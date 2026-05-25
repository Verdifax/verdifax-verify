package artifacts

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// CanonicalBytes returns the canonical-JSON serialization of v. v must be
// a struct (or pointer to one) whose fields are in their stable canonical
// order, that is, the order in which they should appear in the canonical
// bytes. encoding/json preserves struct field order, so a careful struct
// definition gives us deterministic byte output without writing a custom
// canonicalizer.
//
// Maps and slices: maps are NOT permitted in canonical structs (they have
// unstable iteration order in Go). Use a fixed-order slice or a struct
// instead. Slices of structs are fine, their canonical order is the
// caller-controlled element order.
func CanonicalBytes(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("artifacts: canonical marshal: %w", err)
	}
	return b, nil
}

// MustCanonicalBytes is CanonicalBytes that panics on error. Used by the
// builder functions where the input struct is fully controlled and a
// marshaling error would be a programming bug, not a runtime condition.
func MustCanonicalBytes(v any) []byte {
	b, err := CanonicalBytes(v)
	if err != nil {
		panic(err)
	}
	return b
}

// CanonicalHash returns the lowercase-hex SHA-256 of the canonical bytes
// of v. This is the hash that goes into the artifact's `hash` field and
// is what an external auditor would recompute to verify integrity.
func CanonicalHash(v any) (string, error) {
	b, err := CanonicalBytes(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum), nil
}

// MustCanonicalHash is CanonicalHash that panics on error.
func MustCanonicalHash(v any) string {
	h, err := CanonicalHash(v)
	if err != nil {
		panic(err)
	}
	return h
}

// SealReference describes how an artifact is sealed by the run's manifest
// hash. Every canonical artifact carries one so an auditor reading the
// artifact in isolation can locate the manifest that proved it.
type SealReference struct {
	// ManifestHash is the run-wide manifest hash that this artifact is
	// part of. The artifact is considered authentic only if this hash
	// is itself verifiable (e.g., recomputed by the orchestrator or
	// anchored via the ledger).
	ManifestHash string `json:"manifest_hash"`

	// SealField is the field name in the manifest under which this
	// artifact's hash appears. For example: "envelope_hash", "epa_hash".
	SealField string `json:"seal_field"`

	// SealedHash is the hash of this artifact as it appears in the
	// sealed manifest. It must equal CanonicalHash of the artifact's
	// payload, VerifyAgainstManifest checks this.
	SealedHash string `json:"sealed_hash"`
}

// ScaffoldNote flags fields whose real value lands in a later build phase.
// Empty when the field is real and live in the current build.
type ScaffoldNote struct {
	// IsScaffold is true when the value is a placeholder.
	IsScaffold bool `json:"is_scaffold"`

	// ActivatedBy names the build phase that turns this field real.
	// Examples: "phase 6 cryptographer (winterfell)", "phase 7 live cloud (TPM2)".
	// Empty when IsScaffold is false.
	ActivatedBy string `json:"activated_by,omitempty"`

	// Note is a one-sentence operator-readable explanation of what is
	// missing. Optional. Empty when IsScaffold is false.
	Note string `json:"note,omitempty"`
}
