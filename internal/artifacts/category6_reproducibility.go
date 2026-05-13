package artifacts

// ─────────────────────────────────────────────────────────────────────────────
// 6. REPRODUCIBILITY CONTEXT
// ─────────────────────────────────────────────────────────────────────────────
//
// ReproducibilityContext is the caller-supplied "what runtime environment
// was this computation executed in" block. Like AttestedContext, every
// field is optional and Verdifax records the block verbatim into the
// audit bundle — Verdifax does NOT inspect or validate the container,
// dependencies, or git state; the caller is responsible for accurate
// declaration.
//
// The value of this block is that the bundle hash includes the
// ReproducibilityContext canonical bytes. Two runs with identical
// payload + identical context produce identical bundle hashes. Two
// runs with the same payload but different dependency pins produce
// DIFFERENT bundle hashes — surfacing environment drift as a
// verifiable property, not a hidden source of non-reproducibility.
//
// Use cases:
//   - Computational research (Nature / Cell / NeurIPS reproducibility
//     supplements): the bundle hash a peer reviewer recomputes is the
//     evidence that the published code, in the published environment,
//     produces the published result.
//   - Regulated ML model retraining: every retraining run captures the
//     exact training-environment fingerprint; auditors compare across
//     retraining cycles to detect undisclosed environment shifts.
//   - Scientific FDA submissions (digital health / SaMD): pre-clinical
//     and clinical analysis pipelines attest their environment so the
//     FDA reviewer can verify the pipeline ran in the declared state.
//
// Empty zero-value is the honest "not declared" record. The bundle's
// reproducibility section then renders as "declared: false" — distinct
// from a fabricated environment claim.

// ReproducibilityContext captures the runtime environment fingerprint a
// caller declares for a /execute run. Empty values mean "not declared"
// rather than "declared empty"; the Declared field is true when the
// caller supplied at least one of the optional fields below.
type ReproducibilityContext struct {
	// Declared is true when the caller supplied at least one of the
	// fields below. Mirrors AttestedContext.Attested. When false, the
	// bundle's reproducibility section renders as "not declared" rather
	// than fabricating a zero environment claim.
	Declared bool `json:"declared"`

	// ContainerImageHash is the SHA-256 of the OCI / Docker container
	// image that hosted the execution. Anyone replaying the same
	// payload inside the same image must produce the same bundle
	// hash; a different image → different bundle hash, surfacing
	// environment drift. Format: 64-char hex (no "sha256:" prefix);
	// callers using the standard OCI form should strip it before
	// passing.
	ContainerImageHash string `json:"container_image_hash,omitempty"`

	// RuntimeName identifies the language runtime — e.g. "python",
	// "R", "julia", "node", "go", "rust". Stable lowercase string;
	// recommended but not enforced.
	RuntimeName string `json:"runtime_name,omitempty"`

	// RuntimeVersion is the pinned runtime version (e.g. "3.11.5",
	// "4.3.2"). Free-form string; the standard is the runtime's
	// canonical version-print format (python --version etc).
	RuntimeVersion string `json:"runtime_version,omitempty"`

	// PinnedDependencies lists every direct + transitive dependency
	// in canonical "name==version" form. Sorted by name so the
	// canonical JSON is deterministic. For Python this is the output
	// of `pip freeze`; for R, `installed.packages()`; for Julia,
	// `Pkg.status()`. The caller should produce a fully-pinned list,
	// not a top-level requirements.txt.
	PinnedDependencies []string `json:"pinned_dependencies,omitempty"`

	// GitCommitSHA is the 40-char (or 64-char for SHA-256-mode git)
	// hex commit hash of the source code that produced this run.
	// Optional but strongly recommended for research reproducibility:
	// the bundle then binds (commit, environment, payload) together
	// and a peer reviewer can fetch the exact source by hash.
	GitCommitSHA string `json:"git_commit_sha,omitempty"`

	// RandomSeeds lists PRNG seed declarations made at run setup.
	// Each entry is "library_name=seed_value" — e.g. "numpy=42",
	// "torch=1337", "tensorflow=2024". Sorted by library name for
	// canonical determinism. The caller is responsible for actually
	// applying these seeds in their code; Verdifax records the
	// declaration verbatim.
	RandomSeeds []string `json:"random_seeds,omitempty"`

	// Platform is the GOOS/GOARCH-style platform descriptor — e.g.
	// "linux/amd64", "darwin/arm64", "linux/arm64". Floating-point
	// determinism depends on platform; recording it surfaces
	// hardware drift as a verifiable property of the bundle hash.
	Platform string `json:"platform,omitempty"`

	// Hash is filled in by Build() on the audit bundle: it is the
	// canonical-JSON SHA-256 of this struct (with Hash itself
	// blanked during the hash). Independent verifiers recompute it
	// to confirm the section hasn't been altered after sealing.
	Hash string `json:"hash"`
}
