package artifacts

// Category 5, System Provenance
//
// Records exactly which version of Verdifax produced this run: orchestrator
// version, git SHA, build provenance, kernel versions, runtime environment.
// The point is the difference between "we ran some code" and "we ran THIS
// EXACT code, built THIS EXACT way, on THIS EXACT host, at THIS EXACT time."
//
// All fields are server-detected. The caller does not supply this data.
// Most fields are populated at compile time via Go ldflags; runtime fields
// (region, instance) come from environment variables.

// SystemProvenance is the orchestrator's self-attestation about its own
// build and runtime environment.
type SystemProvenance struct {
	Kind string `json:"kind"` // "verdifax.system_provenance.v1"

	OrchestratorVersion string             `json:"orchestrator_version"`
	OrchestratorGitSHA  string             `json:"orchestrator_git_sha"`
	BuildProvenance     BuildProvenance    `json:"build_provenance"`
	ConfigHash          string             `json:"config_hash,omitempty"`
	KernelVersions      []KernelVersion    `json:"kernel_versions"`
	DependencyManifestHash string          `json:"dependency_manifest_hash,omitempty"`
	Environment         RuntimeEnvironment `json:"environment"`

	Hash string        `json:"hash"`
	Seal SealReference `json:"seal,omitempty"`
}

// BuildProvenance, supply-chain provenance for the running orchestrator.
type BuildProvenance struct {
	// SLSALevel, Supply-chain Levels for Software Artifacts.
	// 0 = no provenance. 1 = build script exists. 2 = hosted build.
	// 3 = builder hardened + non-falsifiable provenance. 4 = two-party review.
	SLSALevel int `json:"slsa_level"`

	// SigstoreCertificate, base64 cert from cosign / sigstore (or empty).
	SigstoreCertificate string `json:"sigstore_certificate,omitempty"`

	// SBOMHash, sha256 of the Software Bill of Materials.
	SBOMHash string `json:"sbom_hash,omitempty"`
	SBOMURL  string `json:"sbom_url,omitempty"`

	// Builder, who built it.
	BuilderID         string `json:"builder_id,omitempty"`         // "github_actions" | "local"
	BuildInvocationID string `json:"build_invocation_id,omitempty"` // CI run id
	BuildStartedAt    string `json:"build_started_at,omitempty"`
	BuildFinishedAt   string `json:"build_finished_at,omitempty"`

	// SourceRepo, where the code came from.
	SourceRepo      string `json:"source_repo,omitempty"`
	SourceCommitSHA string `json:"source_commit_sha,omitempty"`
}

// KernelVersion, one row of the per-kernel version table.
type KernelVersion struct {
	Kernel  string `json:"kernel"`  // "DSE" | "TOK" | "DSC" | "NREP" | "AIVP" | "DCAE"
	Version string `json:"version"` // semantic version
	Hash    string `json:"hash,omitempty"` // canonical kernel-binary hash if known
}

// RuntimeEnvironment, where the orchestrator is running right now.
type RuntimeEnvironment struct {
	Cloud                string `json:"cloud"`                  // "fly" | "self_hosted" | "aws" | "gcp" | "azure"
	Region               string `json:"region"`                 // e.g. "iad", "us-east-1"
	InstanceID           string `json:"instance_id,omitempty"`  // cloud-specific id
	InstanceType         string `json:"instance_type,omitempty"`
	ContainerImageDigest string `json:"container_image_digest,omitempty"` // e.g. "ghcr.io/verdifax/verdifax-api@sha256:..."
	OS                   string `json:"os"`                     // "linux" | "darwin"
	Arch                 string `json:"arch"`                   // "amd64" | "arm64"
	GoVersion            string `json:"go_version"`
	Hostname             string `json:"hostname,omitempty"`
	Uptime               int64  `json:"uptime_seconds,omitempty"`
}
