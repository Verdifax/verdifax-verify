package artifacts

import (
	"os"
	"runtime"
)

// Build-time variables. These are set via Go ldflags during the docker
// build. The Dockerfile passes commit + build metadata into the build
// step so the running orchestrator can self-attest.
//
// The defaults below are the dev-build values when the binary is built
// outside of CI without -ldflags. They are intentionally honest:
// "unknown" rather than fabricated.
var (
	buildOrchestratorVersion = "0.3.0-dev"
	buildOrchestratorGitSHA  = "unknown"
	buildSLSALevel           = "0"
	buildBuilderID           = "local"
	buildInvocationID        = ""
	buildContainerDigest     = ""
)

func getOrchestratorVersion() string  { return buildOrchestratorVersion }
func getOrchestratorGitSHA() string   { return buildOrchestratorGitSHA }
func getBuilderID() string            { return buildBuilderID }
func getBuildInvocationID() string    { return buildInvocationID }
func getContainerImageDigest() string { return buildContainerDigest }

// Exported accessors for the running orchestrator's build-time provenance.
// Used by the API's /health endpoint so the customer dashboard, status
// pages, and uptime monitors can confirm which binary is actually serving
// traffic, independent of the API contract version (ServiceVersion).
func OrchestratorVersion() string { return buildOrchestratorVersion }
func OrchestratorGitSHA() string  { return buildOrchestratorGitSHA }

func getSLSALevel() int {
	switch buildSLSALevel {
	case "1":
		return 1
	case "2":
		return 2
	case "3":
		return 3
	case "4":
		return 4
	default:
		return 0
	}
}

// inferCloud returns the cloud platform name from environment variables.
// Order of precedence: explicit Verdifax env, Fly.io, AWS, GCP, Azure.
func inferCloud() string {
	if v := os.Getenv("VERDIFAX_CLOUD"); v != "" {
		return v
	}
	if os.Getenv("FLY_REGION") != "" || os.Getenv("FLY_APP_NAME") != "" {
		return "fly"
	}
	if os.Getenv("AWS_REGION") != "" || os.Getenv("AWS_EXECUTION_ENV") != "" {
		return "aws"
	}
	if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" || os.Getenv("K_SERVICE") != "" {
		return "gcp"
	}
	if os.Getenv("AZURE_CLIENT_ID") != "" || os.Getenv("WEBSITE_INSTANCE_ID") != "" {
		return "azure"
	}
	return "self_hosted"
}

func getInstanceID() string {
	if v := os.Getenv("FLY_MACHINE_ID"); v != "" {
		return v
	}
	if v := os.Getenv("HOSTNAME"); v != "" {
		return v
	}
	return ""
}

func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// Thin wrappers around runtime so they can be overridden in tests if needed.
func runtimeGOOS() string    { return runtime.GOOS }
func runtimeGOARCH() string  { return runtime.GOARCH }
func runtimeVersion() string { return runtime.Version() }
