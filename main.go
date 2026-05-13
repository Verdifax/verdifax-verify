// Command verdifax-verify is the standalone independent verifier for
// Verdifax audit bundles.
//
// It is the operationalization of the patent's "no access to execution
// system required" claim: given just a bundle JSON file, this binary
// recomputes every canonical hash from the bundle's content and reports
// whether the recorded values match. No network access, no Verdifax
// credentials, no trust in the API server.
//
// USAGE
//
//	verdifax-verify bundle.json           # verify a file, print human report
//	cat bundle.json | verdifax-verify     # verify from stdin
//	verdifax-verify --json bundle.json    # machine-readable output
//	verdifax-verify --strict bundle.json  # also fail on any scaffold-flagged value
//	verdifax-verify --version
//
// EXIT CODES
//
//	0   All hashes verified, no failures.
//	1   One or more verification checks failed (or --strict + scaffold).
//	2   Could not parse the bundle.
//
// LICENSE
//
// MIT (see cmd/verdifax-verify/LICENSE). The verifier is intentionally
// open-source so auditors can read the code that adjudicates evidence.
// The verifier produces no attestations of its own; it only checks that
// a received bundle is internally consistent.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/rekorverify"
)

// Version of the verifier binary. Independent of the orchestrator
// version because the verifier ships separately and a single verifier
// version may verify bundles produced by multiple orchestrator versions
// (within a single bundle schema major version).
const Version = "0.3.0"

// HashCheck records one recompute-and-compare verdict.
type HashCheck struct {
	Name     string `json:"name"`
	Recorded string `json:"recorded_hash"`
	Computed string `json:"computed_hash"`
	Match    bool   `json:"match"`
	Scaffold bool   `json:"is_scaffold,omitempty"`
}

// SealCheck records one seal-reference verdict. Each artifact's seal
// must point to the bundle's manifest_hash; a mismatch here indicates
// the artifact was lifted from a different bundle.
type SealCheck struct {
	Field            string `json:"seal_field"`
	ExpectedManifest string `json:"expected_manifest_hash"`
	SealManifest     string `json:"seal_manifest_hash"`
	Match            bool   `json:"match"`
}

// RekorAnchorCheck records the verdict of an offline Sigstore Rekor
// inclusion-proof verification. Present only when the bundle's
// RekorAnchor.Backend is "rekor"; absent (zero value) for mock or
// missing anchors. A failed RekorAnchorCheck flips AllPassed to false.
type RekorAnchorCheck struct {
	Performed bool   `json:"performed"`
	Backend   string `json:"backend"`
	LogIndex  int64  `json:"log_index"`
	Match     bool   `json:"match"`
	Reason    string `json:"reason,omitempty"`
}

// Report is the structured verdict emitted by --json mode.
type Report struct {
	Tool          string           `json:"tool"`
	ToolVersion   string           `json:"tool_version"`
	BundleSchema  string           `json:"bundle_schema"`
	BundleHashOK  bool             `json:"bundle_hash_ok"`
	Artifacts     []HashCheck      `json:"artifacts"`
	Categories    []HashCheck      `json:"categories"`
	BundleHash    HashCheck        `json:"bundle_hash"`
	Seals         []SealCheck      `json:"seal_references"`
	RekorAnchor   RekorAnchorCheck `json:"rekor_anchor"`
	AllPassed     bool             `json:"all_passed"`
	HasScaffold   bool             `json:"has_scaffold"`
	ScaffoldList  []string         `json:"scaffold_list,omitempty"`
}

func main() {
	var (
		jsonOutput  = flag.Bool("json", false, "emit machine-readable JSON instead of human report")
		strictMode  = flag.Bool("strict", false, "fail (exit 1) on any scaffold-flagged value")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = printUsage
	flag.Parse()

	if *showVersion {
		fmt.Println("verdifax-verify version", Version)
		return
	}

	bundle, err := readBundle()
	if err != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify:", err)
		os.Exit(2)
	}

	report := verify(bundle)

	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
	} else {
		printHumanReport(bundle, report)
	}

	if !report.AllPassed || (*strictMode && report.HasScaffold) {
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `verdifax-verify — independent verifier for Verdifax audit bundles

USAGE
  verdifax-verify [flags] <bundle.json>
  cat bundle.json | verdifax-verify [flags]

FLAGS
  -json     emit machine-readable JSON output
  -strict   fail on any scaffold-flagged value
  -version  print version and exit

EXIT
  0  all hashes verified
  1  one or more checks failed (or --strict + scaffold)
  2  could not parse the bundle`)
}

func readBundle() (*artifacts.AuditBundle, error) {
	var data []byte
	var err error
	if flag.NArg() > 0 {
		data, err = os.ReadFile(flag.Arg(0))
		if err != nil {
			return nil, fmt.Errorf("read failed: %w", err)
		}
	} else {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("stdin read failed: %w", err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("no bundle provided (pass a file path or pipe to stdin; --help for usage)")
		}
	}
	var b artifacts.AuditBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("invalid bundle JSON: %w", err)
	}
	if b.Kind == "" || b.ManifestHash == "" {
		return nil, fmt.Errorf("not a Verdifax audit bundle (missing kind or manifest_hash)")
	}
	return &b, nil
}

func verify(b *artifacts.AuditBundle) *Report {
	r := &Report{
		Tool:         "verdifax-verify",
		ToolVersion:  Version,
		BundleSchema: b.Kind,
	}

	// Pipeline artifacts
	r.Artifacts = []HashCheck{
		mk("payload", b.Payload.Hash, artifacts.RecomputePayloadHash(b.Payload), false),
		mk("envelope", b.Envelope.Hash, artifacts.RecomputeEnvelopeHash(b.Envelope), false),
		mk("transport", b.Transport.Hash, artifacts.RecomputeTransportHash(b.Transport), false),
		mk("epa", b.EPA.Hash, artifacts.RecomputeEPAHash(b.EPA), false),
		mk("efa", b.EFA.Hash, artifacts.RecomputeEFAHash(b.EFA), false),
		mk("aer", b.AER.Hash, artifacts.RecomputeAERHash(b.AER), false),
		mk("transcript", b.Transcript.Hash, artifacts.RecomputeTranscriptHash(b.Transcript), b.Transcript.Scaffold.IsScaffold),
		mk("hardware_attestation", b.HardwareAttestation.Hash, artifacts.RecomputeHardwareAttestationHash(b.HardwareAttestation), b.HardwareAttestation.Scaffold.IsScaffold),
		mk("leakage_bundle", b.LeakageBundle.Hash, artifacts.RecomputeLeakageBundleHash(b.LeakageBundle), false),
		mk("zksp_binding", b.ZkspBinding.Hash, artifacts.RecomputeZkspBindingHash(b.ZkspBinding), b.ZkspBinding.Scaffold.IsScaffold),
		mk("migration_token", b.MigrationToken.Hash, artifacts.RecomputeMigrationTokenHash(b.MigrationToken), false),
		mk("replay_fingerprint", b.ReplayFingerprint.Hash, artifacts.RecomputeReplayFingerprintHash(b.ReplayFingerprint), false),
		mk("pote_proof", b.PoteProof.Hash, artifacts.RecomputePoteProofHash(b.PoteProof), b.PoteProof.Scaffold.IsScaffold),
		mk("final_vfa", b.FinalVFA.Hash, artifacts.RecomputeFinalVFAHash(b.FinalVFA), false),
	}

	// Categories
	r.Categories = []HashCheck{
		mk("request_substance", b.RequestSubstance.Hash, artifacts.RecomputeRequestSubstanceHash(b.RequestSubstance), false),
		mk("authorization_chain", b.AuthorizationChain.Hash, artifacts.RecomputeAuthorizationChainHash(b.AuthorizationChain), false),
		mk("regulatory_scaffolding", b.RegulatoryScaffolding.Hash, artifacts.RecomputeRegulatoryScaffoldingHash(b.RegulatoryScaffolding), false),
		mk("causal_graph", b.CausalGraph.Hash, artifacts.RecomputeCausalGraphHash(b.CausalGraph), false),
		mk("system_provenance", b.SystemProvenance.Hash, artifacts.RecomputeSystemProvenanceHash(b.SystemProvenance), false),
	}

	// Bundle
	r.BundleHash = mk("bundle", b.BundleHash, artifacts.RecomputeBundleHash(b), false)
	r.BundleHashOK = r.BundleHash.Match

	// Seal references — every artifact's seal must point to the bundle's
	// manifest_hash. A mismatch indicates the artifact was lifted from
	// another bundle, or the bundle's manifest_hash was edited after seal.
	type sealed struct {
		field string
		seal  artifacts.SealReference
	}
	allSeals := []sealed{
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
	}
	for _, s := range allSeals {
		r.Seals = append(r.Seals, SealCheck{
			Field:            s.field,
			ExpectedManifest: b.ManifestHash,
			SealManifest:     s.seal.ManifestHash,
			Match:            s.seal.ManifestHash == b.ManifestHash,
		})
	}

	// Day-3+ Rekor anchor verification — runs only when the bundle was
	// sealed under VERDIFAX_LEDGER_MODE=rekor (Backend == "rekor").
	// Mock-ledger bundles skip this check; the report surfaces
	// Performed=false so a reader can see the run wasn't anchored on
	// a public log.
	r.RekorAnchor = verifyRekorAnchor(b.RekorAnchor)

	// Roll-up.
	allPassed := r.BundleHashOK
	for _, c := range r.Artifacts {
		if !c.Match {
			allPassed = false
		}
		if c.Scaffold {
			r.HasScaffold = true
			r.ScaffoldList = append(r.ScaffoldList, c.Name)
		}
	}
	for _, c := range r.Categories {
		if !c.Match {
			allPassed = false
		}
	}
	for _, s := range r.Seals {
		if !s.Match {
			allPassed = false
		}
	}
	if r.RekorAnchor.Performed && !r.RekorAnchor.Match {
		allPassed = false
	}
	r.AllPassed = allPassed
	return r
}

// verifyRekorAnchor runs offline Sigstore Rekor inclusion proof
// verification against the bundle's RekorAnchor field. Returns a
// RekorAnchorCheck describing the outcome:
//
//   - Performed=false when the bundle is mock-anchored (Backend
//     other than "rekor"). No claim made; not a failure.
//   - Performed=true, Match=true when the inclusion proof recomputes
//     to the claimed Merkle root AND the signed checkpoint verifies
//     against the embedded Rekor public key.
//   - Performed=true, Match=false when any check fails. Reason names
//     which check failed.
func verifyRekorAnchor(a artifacts.RekorAnchor) RekorAnchorCheck {
	if a.Backend != "rekor" {
		return RekorAnchorCheck{Performed: false, Backend: a.Backend}
	}
	err := rekorverify.VerifyAnchor(rekorverify.AnchorInput{
		LeafHashHex:   a.LeafHashHex,
		LogIndex:      a.LogIndex,
		TreeSize:      a.TreeSize,
		RootHashHex:   a.RootHashHex,
		InclusionPath: a.InclusionPath,
		Checkpoint:    a.Checkpoint,
		LogID:         a.LogID,
	})
	if err != nil {
		return RekorAnchorCheck{
			Performed: true,
			Backend:   a.Backend,
			LogIndex:  a.LogIndex,
			Match:     false,
			Reason:    err.Error(),
		}
	}
	return RekorAnchorCheck{
		Performed: true,
		Backend:   a.Backend,
		LogIndex:  a.LogIndex,
		Match:     true,
	}
}

func mk(name, recorded, computed string, scaffold bool) HashCheck {
	return HashCheck{
		Name:     name,
		Recorded: recorded,
		Computed: computed,
		Match:    recorded == computed,
		Scaffold: scaffold,
	}
}

func printHumanReport(b *artifacts.AuditBundle, r *Report) {
	fmt.Println()
	fmt.Println("verdifax-verify", Version, "—", b.Kind)
	fmt.Println()
	fmt.Println("Manifest hash:", b.ManifestHash)
	fmt.Println("Bundle hash:  ", b.BundleHash)
	if b.RunID != 0 {
		fmt.Printf("Run id:        #%d\n", b.RunID)
	}
	fmt.Println()

	fmt.Println("PIPELINE ARTIFACTS")
	for _, c := range r.Artifacts {
		printCheck(c)
	}
	fmt.Println()

	fmt.Println("AUDIT PROJECTION CATEGORIES")
	for _, c := range r.Categories {
		printCheck(c)
	}
	fmt.Println()

	fmt.Println("SEAL REFERENCES")
	for _, s := range r.Seals {
		mark := "✓"
		if !s.Match {
			mark = "✗"
		}
		fmt.Printf("  %s  %-25s seal points to %s\n", mark, s.Field, truncate(s.SealManifest, 16))
	}
	fmt.Println()

	fmt.Println("BUNDLE HASH")
	printCheck(r.BundleHash)
	fmt.Println()

	fmt.Println("SIGSTORE REKOR ANCHOR")
	printRekorAnchor(r.RekorAnchor, b.RekorAnchor.LogEntryID)
	fmt.Println()

	switch {
	case r.AllPassed && !r.HasScaffold:
		fmt.Println("VERDICT: ✓ VERIFIED — every hash recomputes correctly, no scaffold values flagged.")
	case r.AllPassed && r.HasScaffold:
		fmt.Println("VERDICT: ✓ VERIFIED (with scaffold flags)")
		fmt.Println("  Scaffold artifacts (will be activated in Phase 6/7):")
		for _, s := range r.ScaffoldList {
			fmt.Println("    ·", s)
		}
		fmt.Println("  These are honestly self-declared by the orchestrator. Use --strict to fail on them.")
	default:
		fmt.Println("VERDICT: ✗ FAILED — at least one hash did not recompute correctly.")
		fmt.Println("  This bundle has been tampered with, or was produced by a tool that is")
		fmt.Println("  out of sync with this verifier's schema. Investigate before relying on it.")
	}
	fmt.Println()
}

func printCheck(c HashCheck) {
	mark := "✓"
	if !c.Match {
		mark = "✗"
	}
	tag := ""
	if c.Scaffold {
		tag = "  [scaffold]"
	}
	fmt.Printf("  %s  %-25s %s%s\n", mark, c.Name, truncate(c.Recorded, 16), tag)
	if !c.Match {
		fmt.Printf("       recorded: %s\n", c.Recorded)
		fmt.Printf("       computed: %s\n", c.Computed)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// printRekorAnchor renders the Rekor verification verdict in the
// human-readable report. Three states:
//
//   - Performed=false: the bundle was sealed in mock-ledger mode. The
//     report names the backend explicitly so the reader knows no
//     public-log claim is being made.
//   - Performed=true, Match=true: offline verification passed; the
//     leaf is provably committed under a Rekor-signed root.
//   - Performed=true, Match=false: at least one check (Merkle proof
//     or signed checkpoint) failed. Reason names which.
func printRekorAnchor(a RekorAnchorCheck, logEntryID string) {
	if !a.Performed {
		backend := a.Backend
		if backend == "" {
			backend = "(none)"
		}
		fmt.Printf("  ·  no public-log anchor (backend = %s)\n", backend)
		fmt.Println("     Run was not anchored on the Sigstore Rekor transparency log.")
		return
	}

	if a.Match {
		fmt.Printf("  ✓  rekor anchor verified offline — log index %d\n", a.LogIndex)
		fmt.Printf("     Inclusion proof and signed checkpoint both verify under the\n")
		fmt.Printf("     embedded Rekor public key. View on https://search.sigstore.dev/?logIndex=%s\n", logEntryID)
		return
	}

	fmt.Printf("  ✗  rekor anchor FAILED — log index %d\n", a.LogIndex)
	fmt.Printf("     Reason: %s\n", a.Reason)
	fmt.Println("     This bundle's public-log claim does not verify. Either the")
	fmt.Println("     anchor was tampered with, the embedded Rekor public key is")
	fmt.Println("     stale (rotation announced via the Sigstore TUF root), or the")
	fmt.Println("     bundle was produced by a non-canonical orchestrator.")
}
