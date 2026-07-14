package artifacts

// RecomputeFormalVerificationHash derives the canonical hash of the
// formal-verification record from its contents (everything except the
// Hash field itself). Must stay byte-identical to the orchestrator's
// internal/artifacts/formal_verification.go.
func RecomputeFormalVerificationHash(fv FormalVerification) string {
	return MustCanonicalHash(struct {
		Kind           string   `json:"kind"`
		Repo           string   `json:"repo"`
		CommitSHA      string   `json:"commit_sha"`
		Toolchain      string   `json:"toolchain"`
		Modules        []string `json:"modules"`
		Theorems       []string `json:"theorems"`
		AxiomFootprint string   `json:"axiom_footprint"`
		Scope          string   `json:"scope"`
		ManifestHash   string   `json:"manifest_hash"`
	}{fv.Kind, fv.Repo, fv.CommitSHA, fv.Toolchain, fv.Modules, fv.Theorems, fv.AxiomFootprint, fv.Scope, fv.ManifestHash})
}
