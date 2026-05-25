// Package artifacts implements the Verdifax Audit Projection (VAP) layer.
//
// VAP sits on top of the existing pipeline manifest. The pipeline produces
// a manifest of hashes (one per stage) that prove what happened. VAP
// produces, alongside that manifest, a structured human-readable bundle
// of canonical artifacts that describe what happened. Together they form
// the complete audit record:
//
//   - manifest hash      = "I can prove this happened"
//   - audit bundle       = "Here is what happened, in human-meaningful form"
//
// The two are linked: every canonical artifact in the bundle records the
// manifest hash that sealed it, and every hash in the manifest has a
// corresponding artifact that resolves it.
//
// # Canonicalization
//
// Each artifact type is a Go struct with stable field order and explicit
// json tags. Canonical bytes are produced by encoding/json with no indent
// and no extra whitespace. The hash of an artifact is sha256(canonical_bytes)
// in lowercase hex. For the structs defined here this matches the spirit
// of RFC 8785: deterministic, byte-stable, and reproducible from the
// declared schema.
//
// # Caller-attested context
//
// Some fields in the audit bundle (model_provider, actor_id, policy_id,
// etc.) cannot come from Verdifax itself, Verdifax does not call any AI
// or run any business policy. They are caller-attested: provided by the
// integration in the /execute request and recorded verbatim. When absent,
// the corresponding fields are populated as "self_attested_deterministic"
// with a clear flag indicating the caller did not supply context. See
// the AttestedContext type in this package.
//
// # Scaffold honesty
//
// Several fields (TPM quote, Rekor entry, ZK proof bytes) are scaffold
// today, the real values land in Phase 6/7. The audit bundle never
// pretends these fields are real. They are emitted with a "scaffold: true"
// flag and a short note explaining what activates the real value.
package artifacts
