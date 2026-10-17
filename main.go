// Command verdifax-verify is the standalone independent verifier for
// Verdifax audit bundles.
//
// It is the offline-verification path for Verdifax bundles: given just
// a bundle JSON file, this binary recomputes every section hash, the
// bundle hash, the pre-anchor digest, the anchored leaf, and (from
// v0.10.0) the anchored record digest and bundle leaf of the
// complete-record anchor from the bundle's content (and, from v0.11.0,
// fails a record sealed with the v6 leaf whose anchored values require
// that complete-record anchor when it is missing), confirms that each
// logged entry body names the leaf it is claimed for, confirms every
// section binds the same manifest hash, and reports whether the
// recorded values match. The manifest
// hash itself is not recomputed: its preimage lives in the
// orchestrator's stored manifest.
// Verification makes no network calls, needs no Verdifax credentials,
// and places no trust in the API server; the Rekor inclusion proof is
// checked against an embedded public key. The one network operation is
// optional input retrieval: an http:// or https:// argument is fetched
// with a single GET before being verified exactly like a local file.
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
// # LICENSE
//
// The Clear BSD License (BSD-3-Clause-Clear, see LICENSE) from v0.5.0;
// releases through v0.4.0 were MIT. The verifier is intentionally
// open-source so auditors can read the code that adjudicates evidence.
// The verifier produces no attestations of its own; it only checks that
// a received bundle is internally consistent.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/rekorverify"
	"github.com/Verdifax/verdifax-verify/internal/sevsnp"
)

// Version of the verifier binary. Independent of the orchestrator
// version because the verifier ships separately and a single verifier
// version may verify bundles produced by multiple orchestrator versions
// (within a single bundle schema major version).
const Version = "0.14.5"

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
	// Unverifiable is true for a rekor-backend anchor that carries no
	// entry body: nothing binds its leaf to the Merkle proof, so it is
	// reported as not anchored (Performed=false) rather than verified.
	Unverifiable bool `json:"unverifiable,omitempty"`
	// StaleEntryNumber is true when the failure is a copy that stores
	// the shard position as its entry number (see staleIndexReason).
	StaleEntryNumber bool `json:"stale_entry_number,omitempty"`
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
	LeafBinding   LeafBindingCheck `json:"leaf_binding"`
	NrepSignature NrepCheck        `json:"nrep_signature"`
	RuntimeTiming TimingCheck      `json:"runtime_timing"`
	PreAnchor     PreAnchorCheck   `json:"pre_anchor"`
	// BundleAnchor is the complete-record anchor (v0.10.0).
	BundleAnchor BundleAnchorCheck `json:"bundle_anchor"`
	// CompleteRecordRequirement is the leaf v6 guarantee (v0.11.0):
	// whether the record's anchored values require a complete-record
	// anchor, and whether that requirement holds.
	CompleteRecordRequirement CompleteRecordRequirementCheck `json:"complete_record_requirement"`
	// EntryAuth is who logged the run's public-log entries and when
	// (v0.12.0): pinned signer, signed entry timestamps, and the sealed
	// anchoring window on table v3 records.
	EntryAuth EntryAuthCheck `json:"entry_authentication"`
	// RecordValues are the decision-bearing values as checked (v0.12.1).
	RecordValues RecordValues `json:"record_values"`
	CrossChecks  []string     `json:"cross_check_failures,omitempty"`
	AllPassed    bool         `json:"all_passed"`
	Anchored     bool         `json:"anchored"`
	VerdictTier  string       `json:"verdict_tier"`
	// RecordCoverage says how much of the record the public log binds:
	// "complete_record_anchored", "partial_descriptive_sections_bundle_sealed",
	// "partial_pre_v5_identity_only", "not_anchored" or "failed".
	RecordCoverage string   `json:"record_coverage"`
	HasScaffold    bool     `json:"has_scaffold"`
	ScaffoldList   []string `json:"scaffold_list,omitempty"`

	// passedExceptRequirement is the roll-up before the complete-record
	// requirement is applied, so the verdict can name the requirement
	// as the reason when it is the only failure.
	passedExceptRequirement bool
}

func main() {
	var (
		jsonOutput      = flag.Bool("json", false, "emit machine-readable JSON instead of human report")
		strictMode      = flag.Bool("strict", false, "fail (exit 1) on any scaffold-flagged value")
		allowUnanchored = flag.Bool("allow-unanchored", false, "exit 0 for a bundle with no public-log anchor; without this flag, unanchored bundles fail, because every sealing property this tool checks hangs off the anchor and an attacker can strip an anchor claim by editing one unprotected field (the documented downgrade attack)")
		showVersion     = flag.Bool("version", false, "print version and exit")
		selfHosted      = flag.Bool("self-hosted-receipt", false, "the receipt was issued by a test or self-hosted deployment that does not anchor receipts on the public log, not by the Verdifax API; exempts it from the rules that receipts dated from run 241 on must carry a public-log anchor and receipts dated from run 242 on must seal anchor_required")
		showEvidence    = flag.Bool("show-evidence-summary", false, "print a one-glance maturity summary (real vs scaffold counts, Rekor anchor status, PoTE preimage version, strict-mode gate disposition) and exit; combine with --json for machine-readable form")
	)
	flag.Usage = printUsage
	flag.Parse()

	if *showVersion {
		fmt.Println("verdifax-verify version", Version)
		return
	}

	// Error model of this binary: a CLI with no logger; an unreadable
	// input is reported on stderr with exit code 2.
	data, inputErr := readInput()
	if inputErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify:", inputErr)
		os.Exit(2)
	}
	// A refused or halted run's receipt document (v0.13.0).
	if isReceiptDocument(data) {
		doc, docErr := artifacts.DecodeReceiptStrict(data)
		if errors.Is(docErr, artifacts.ErrNotStrictJSON) {
			reportAmbiguousJSON(docErr, "receipt", *jsonOutput)
			os.Exit(1)
		}
		if docErr != nil {
			fmt.Fprintln(os.Stderr, "verdifax-verify: invalid receipt JSON:", docErr)
			os.Exit(2)
		}
		rr := verifyReceiptDocumentWith(doc, receiptOptions{selfHosted: *selfHosted})
		if *jsonOutput {
			emitReceiptJSON(rr)
		} else {
			printReceiptReport(rr)
		}
		if receiptExitShouldFail(rr, *allowUnanchored) {
			os.Exit(1)
		}
		return
	}
	bundle, err := decodeBundle(data)
	if errors.Is(err, artifacts.ErrNotStrictJSON) {
		// An ambiguous bundle is a failed verification, not unreadable
		// input: other readers would see different values than this
		// tool checks. Report it as FAILED, exit 1, like any forgery.
		reportAmbiguousJSON(err, "bundle", *jsonOutput)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify:", err)
		os.Exit(2)
	}

	report := verify(bundle)

	// --show-evidence-summary short-circuits the normal output paths so
	// CPTOs / reviewers / CI scripts can get a one-glance read on the
	// bundle's maturity posture without parsing the full hash-by-hash
	// report. Exit code semantics still apply (non-zero on failed
	// verification, or on --strict + scaffold) so the flag composes
	// naturally with CI pipelines that already gate on verdifax-verify.
	if *showEvidence {
		summary := buildEvidenceSummary(bundle, report, *strictMode)
		if *jsonOutput {
			_ = json.NewEncoder(os.Stdout).Encode(summary)
		} else {
			printEvidenceSummary(summary)
		}
		if exitShouldFail(report, *strictMode, *allowUnanchored) {
			os.Exit(1)
		}
		return
	}

	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
	} else {
		printHumanReport(bundle, report)
	}

	if exitShouldFail(report, *strictMode, *allowUnanchored) {
		os.Exit(1)
	}
}

// exitShouldFail is the single exit-code policy (v0.8.1). Unanchored
// bundles fail without --allow-unanchored: production never seals in
// mock mode, so an unanchored bundle in the wild is either a dev
// artifact (pass the flag) or a stripped anchor (the point).
func exitShouldFail(r *Report, strict, allowUnanchored bool) bool {
	if !r.AllPassed {
		return true
	}
	if strict && r.HasScaffold {
		return true
	}
	if !r.Anchored && !allowUnanchored {
		return true
	}
	return false
}

// EvidenceSummary is the structured one-glance view emitted by
// --show-evidence-summary. Designed to read well as both a 10-line
// human report and as a tiny JSON blob for CI scripts.
type EvidenceSummary struct {
	BundleSchema   string   `json:"bundle_schema"`
	ManifestHash   string   `json:"manifest_hash"`
	RunStatus      string   `json:"run_status"`
	TotalArtifacts int      `json:"total_artifacts"`
	RealArtifacts  int      `json:"real_artifacts"`
	ScaffoldCount  int      `json:"scaffold_count"`
	ScaffoldList   []string `json:"scaffold_list,omitempty"`
	RekorAnchored  bool     `json:"rekor_anchored"`
	RekorLogIndex  int64    `json:"rekor_log_index,omitempty"`
	// RekorLogEntryID is the global index search.sigstore.dev resolves;
	// RekorLogIndex is the shard-local position the inclusion proof uses.
	RekorLogEntryID string `json:"rekor_log_entry_id,omitempty"`
	RekorVerified   string `json:"rekor_verified"` // "verified" | "failed" | "not_verifiable" | "not_anchored"

	// LeafBound answers the question rekor_verified does NOT answer:
	// whether the anchored entry belongs to this run. "bound" | "foreign"
	// | "not_checked".
	//
	// Both are needed and neither substitutes for the other. An entry can
	// be genuinely in Rekor's tree and belong to somebody else, so a
	// consumer reading only rekor_verified=verified would conclude more
	// than the evidence supports. This field was absent from the summary
	// in both the public and the private verifier, which meant the
	// strongest check either tool performs was invisible to any tooling
	// reading the machine output.
	LeafBound string `json:"leaf_bound"`
	// RecordAnchor is the complete-record anchor state (v0.10.0):
	// "complete" when the second public-log entry verifies over this
	// record, "failed" when present but not holding, "not_public" when
	// present on a non-public backend, "absent" otherwise (descriptive
	// sections bundle-sealed, not anchored).
	RecordAnchor   string `json:"record_anchor"`
	RecordCoverage string `json:"record_coverage"`
	// RecordAnchorRequirement is "satisfied", "failed" or "not_sealed"
	// (v0.11.0): whether the record's anchored values require a
	// complete-record anchor and whether it holds.
	RecordAnchorRequirement string `json:"record_anchor_requirement"`
	PoteHashVersion         string `json:"pote_hash_version"`
	// FormalVerification summarizes the bundle's formal-verification
	// binding: "bound" with repo and commit when the record is present
	// and belongs to this run, or "absent (no claim)" for bundles
	// produced before the section shipped. Model-level scope is
	// carried verbatim in the bundle's formal_verification.scope.
	FormalVerification string `json:"formal_verification"`
	// HardwareAttest summarizes the L8 hardware-attestation state:
	// "sev_snp re-verified · <measurement12> · pinned AMD Milan root"
	// when this tool independently re-checked the embedded quote,
	// "sev_snp claimed but FAILED re-verification" when the claim did
	// not hold, or "policy scaffold (honest disclosure)" otherwise.
	HardwareAttest   string `json:"hardware_attestation"`
	HashesAllMatch   bool   `json:"hashes_all_match"`
	StrictModeWanted bool   `json:"strict_mode_wanted"`
	StrictModeGate   string `json:"strict_mode_gate"` // "pass" | "fail"
}

func buildEvidenceSummary(b *artifacts.AuditBundle, r *Report, strictWanted bool) EvidenceSummary {
	s := EvidenceSummary{
		BundleSchema:     b.Kind,
		ManifestHash:     b.ManifestHash,
		TotalArtifacts:   len(r.Artifacts),
		ScaffoldCount:    len(r.ScaffoldList),
		ScaffoldList:     append([]string(nil), r.ScaffoldList...),
		RekorAnchored:    r.RekorAnchor.Performed,
		HashesAllMatch:   r.AllPassed,
		StrictModeWanted: strictWanted,
	}
	s.RealArtifacts = s.TotalArtifacts - s.ScaffoldCount
	if b.Status != "" {
		s.RunStatus = b.Status
	}
	switch {
	case r.RekorAnchor.Performed && r.RekorAnchor.Match:
		s.RekorVerified = "verified"
		s.RekorLogIndex = b.RekorAnchor.LogIndex
		s.RekorLogEntryID = b.RekorAnchor.LogEntryID
	case r.RekorAnchor.Performed && !r.RekorAnchor.Match:
		s.RekorVerified = "failed"
		s.RekorLogIndex = b.RekorAnchor.LogIndex
		s.RekorLogEntryID = b.RekorAnchor.LogEntryID
	case r.RekorAnchor.Unverifiable:
		s.RekorVerified = "not_verifiable"
		s.RekorLogIndex = b.RekorAnchor.LogIndex
		s.RekorLogEntryID = b.RekorAnchor.LogEntryID
	default:
		s.RekorVerified = "not_anchored"
	}
	switch {
	case r.LeafBinding.Performed && r.LeafBinding.Match:
		s.LeafBound = "bound"
	case r.LeafBinding.Performed && !r.LeafBinding.Match:
		s.LeafBound = "foreign"
	default:
		s.LeafBound = "not_checked"
	}
	switch c := r.BundleAnchor; {
	case !c.Present:
		s.RecordAnchor = "absent"
	case !c.Match:
		s.RecordAnchor = "failed"
	case !c.Performed:
		s.RecordAnchor = "not_public"
	default:
		s.RecordAnchor = "complete"
	}
	s.RecordCoverage = r.RecordCoverage
	switch c := r.CompleteRecordRequirement; {
	case c.Sealed && c.Satisfied:
		s.RecordAnchorRequirement = "satisfied"
	case c.Sealed:
		s.RecordAnchorRequirement = "failed"
	default:
		s.RecordAnchorRequirement = "not_sealed"
	}
	switch b.PoteProof.Kind {
	case "verdifax.artifact.pote.v2":
		s.PoteHashVersion = "v2 (binds Rekor temporal claim)"
	case "verdifax.artifact.pote.v1", "":
		s.PoteHashVersion = "v1 (legacy / mock)"
	default:
		s.PoteHashVersion = b.PoteProof.Kind
	}
	if b.FormalVerification.Kind != "" {
		commit := b.FormalVerification.CommitSHA
		if len(commit) > 12 {
			commit = commit[:12]
		}
		s.FormalVerification = fmt.Sprintf("bound · %s @ %s · model-level (see formal_verification.scope)",
			b.FormalVerification.Repo, commit)
	} else {
		s.FormalVerification = "absent (no claim)"
	}
	switch {
	case b.HardwareAttestation.AttestationMode == "sev_snp":
		s.HardwareAttest = "sev_snp claimed but FAILED re-verification"
		for _, c := range r.Categories {
			if c.Name == "hardware_attestation_sevsnp_quote" && c.Match {
				meas := b.HardwareAttestation.EnclaveMeasurement
				if len(meas) > 12 {
					meas = meas[:12]
				}
				s.HardwareAttest = "sev_snp re-verified · measurement " + meas + "… · pinned AMD Milan root"
			}
		}
	case b.HardwareAttestation.Kind != "":
		s.HardwareAttest = "policy scaffold (honest disclosure)"
	default:
		s.HardwareAttest = "absent (no claim)"
	}
	if !r.AllPassed || (strictWanted && r.HasScaffold) {
		s.StrictModeGate = "fail"
	} else {
		s.StrictModeGate = "pass"
	}
	return s
}

func printEvidenceSummary(s EvidenceSummary) {
	fmt.Println("EVIDENCE MATURITY SUMMARY")
	fmt.Printf("  Bundle schema:    %s\n", s.BundleSchema)
	fmt.Printf("  Manifest hash:    %s\n", s.ManifestHash)
	if s.RunStatus != "" {
		fmt.Printf("  Run status:       %s\n", s.RunStatus)
	}
	fmt.Printf("  Artifacts:        %d total · %d real · %d scaffold\n",
		s.TotalArtifacts, s.RealArtifacts, s.ScaffoldCount)
	if s.ScaffoldCount > 0 {
		fmt.Printf("  Scaffolded:       %s\n", strings.Join(s.ScaffoldList, ", "))
	}
	switch s.RekorVerified {
	case "verified":
		fmt.Printf("  Rekor anchor:     verified · %s\n", rekorIndexText(s))
	case "failed":
		fmt.Printf("  Rekor anchor:     FAILED · %s\n", rekorIndexText(s))
	case "not_verifiable":
		fmt.Printf("  Rekor anchor:     NOT VERIFIABLE · no entry_body binds the leaf to the proof\n")
	default:
		fmt.Printf("  Rekor anchor:     not anchored (mock-ledger run)\n")
	}
	// Printed on its own line rather than folded into the anchor line,
	// because a reader skimming for one tick must not be able to take
	// "anchor verified" as also meaning "anchor is mine".
	switch s.LeafBound {
	case "bound":
		fmt.Printf("  Anchored leaf:    is this run's\n")
	case "foreign":
		fmt.Printf("  Anchored leaf:    NOT this run's\n")
	default:
		fmt.Printf("  Anchored leaf:    not checked (no public-log claim)\n")
	}
	switch s.RecordAnchor {
	case "complete":
		fmt.Printf("  Record anchor:    complete record anchored (second entry)\n")
	case "failed":
		fmt.Printf("  Record anchor:    FAILED · record changed after anchoring or entry invalid\n")
	case "not_public":
		fmt.Printf("  Record anchor:    present, not on a public log\n")
	default:
		fmt.Printf("  Record anchor:    absent · descriptive sections bundle-sealed, not anchored\n")
	}
	switch s.RecordAnchorRequirement {
	case "satisfied":
		fmt.Printf("  Anchor required:  sealed (leaf v6) and satisfied\n")
	case "failed":
		fmt.Printf("  Anchor required:  FAILED · sealed (leaf v6), record anchor missing or invalid\n")
	default:
		fmt.Printf("  Anchor required:  not sealed (pre-v6 record; deletion not detectable)\n")
	}
	fmt.Printf("  PoTE hash:        %s\n", s.PoteHashVersion)
	fmt.Printf("  Formal verify:    %s\n", s.FormalVerification)
	fmt.Printf("  Hardware attest:  %s\n", s.HardwareAttest)
	// Verdict line carries an explicit reason so a reader who is not
	// familiar with the verifier's gating semantics does not mistake a
	// scaffold-driven strict failure for a cryptographic failure.
	//
	// Three outcomes:
	//   1. pass: every hash recomputed and matched, and either no
	//      scaffolds were present or --strict was not requested.
	//   2. fail (strict + scaffold): every hash matched, but --strict
	//      was set and the bundle carries at least one scaffold flag.
	//      This is by-design CI-gating behavior, not a cryptographic
	//      failure. The bundle is still cryptographically valid.
	//   3. fail (hash mismatch): a recomputed hash did not match the
	//      stored value. This IS a cryptographic failure.
	gate := s.StrictModeGate
	switch {
	case s.StrictModeGate == "pass":
		gate = gate + " (all cryptographic checks verified)"
	case s.StrictModeWanted && s.HashesAllMatch:
		gate = gate + " (--strict requested; cryptography passed, scaffold flags trip the strict gate by design)"
	case !s.HashesAllMatch:
		gate = gate + " (cryptographic mismatch detected; bundle did not verify)"
	default:
		// Fallback: should not normally land here, but cover it.
		if s.StrictModeWanted {
			gate = gate + " (--strict requested)"
		} else {
			gate = gate + " (--strict not requested; scaffolds tolerated)"
		}
	}
	fmt.Printf("  Verdict:          %s\n", gate)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `verdifax-verify, independent verifier for Verdifax audit bundles and receipts

USAGE
  verdifax-verify [flags] <bundle.json | receipt.json>
  cat bundle.json | verdifax-verify [flags]

FLAGS
  -json                   emit machine-readable JSON output
  -strict                 fail on any scaffold-flagged value
  -allow-unanchored       exit 0 for a bundle or receipt that is
                          consistent but not anchored on the public log
  -self-hosted-receipt    the receipt came from a test or self-hosted
                          deployment, not the Verdifax API; exempts it
                          from the rules that receipts dated from run
                          241 on must carry a public-log anchor and
                          from run 242 on must seal anchor_required
  -show-evidence-summary  print a one-glance maturity summary (real vs
                          scaffold counts, Rekor anchor status, PoTE
                          preimage version, strict-mode gate) and exit
  -version                print version and exit

EXIT
  0  all checks passed
  1  one or more checks failed, or the record is not anchored and
     -allow-unanchored was not passed (or -strict + scaffold)
  2  could not parse the input`)
}

// readInput returns the raw bytes of the file, URL or stdin argument.
func readInput() ([]byte, error) {
	if flag.NArg() > 0 {
		arg := flag.Arg(0)
		if isHTTPURL(arg) {
			return fetchBundleHTTP(arg)
		}
		data, readErr := os.ReadFile(arg)
		if readErr != nil {
			return nil, fmt.Errorf("read failed: %w", readErr)
		}
		return data, nil
	}
	data, readErr := io.ReadAll(os.Stdin)
	if readErr != nil {
		return nil, fmt.Errorf("stdin read failed: %w", readErr)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("no bundle provided (pass a file path, an https:// URL, or pipe to stdin; --help for usage)")
	}
	return data, nil
}

// isReceiptDocument reports whether the input's top level names a
// receipt the way the Verdifax API serves one. Keys are compared
// exactly, and only the first JSON value is read, so data after it is
// refused by the strict decoder of the right kind rather than routing
// the input elsewhere; the strict decoder then judges the whole document.
func isReceiptDocument(data []byte) bool {
	var top map[string]json.RawMessage
	if json.NewDecoder(bytes.NewReader(data)).Decode(&top) != nil {
		return false
	}
	if _, isBundle := top["manifest_hash"]; isBundle {
		return false
	}
	for _, kind := range artifacts.ReceiptKinds {
		if _, ok := top[kind]; ok {
			return true
		}
	}
	return false
}

func decodeBundle(data []byte) (*artifacts.AuditBundle, error) {
	// Strict decoding (v0.12.1): a key that is ambiguous across JSON
	// readers, or not modeled here, is refused before any hash is
	// computed, so the record this tool verifies is the record every
	// other reader sees (round eight of the external review).
	b, decodeErr := artifacts.DecodeBundleStrict(data)
	if decodeErr != nil {
		return nil, fmt.Errorf("invalid bundle JSON: %w", decodeErr)
	}
	if b.Kind == "" || b.ManifestHash == "" {
		return nil, fmt.Errorf("not a Verdifax audit bundle or receipt document (missing kind or manifest_hash)")
	}
	return b, nil
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
		mk("leakage_bundle", b.LeakageBundle.Hash, artifacts.RecomputeLeakageBundleHash(b.LeakageBundle), b.LeakageBundle.Scaffold.IsScaffold),
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
		// Category 6 is inside bundle_hash but went unrecomputed
		// until v0.10.0, so its stored hash vouched for content no
		// check read.
		mk("reproducibility_context", b.ReproducibilityContext.Hash, artifacts.RecomputeReproducibilityContextHash(b.ReproducibilityContext), false),
	}

	// Bundle
	r.BundleHash = mk("bundle", b.BundleHash, artifacts.RecomputeBundleHash(b), false)
	r.BundleHashOK = r.BundleHash.Match

	// Seal references, every artifact's seal must point to the bundle's
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

	// Formal-verification binding (extension section). Bundles
	// produced before the section shipped carry no record: absence
	// means "no formal-verification claim made for this run", not a
	// failure. When present, the record's hash must recompute from
	// its contents and its manifest_hash must match this bundle's,
	// proving the record is intact and belongs to this run.
	if b.FormalVerification.Kind != "" {
		r.Categories = append(r.Categories,
			mk("formal_verification", b.FormalVerification.Hash,
				artifacts.RecomputeFormalVerificationHash(b.FormalVerification), false))
		r.Seals = append(r.Seals, SealCheck{
			Field:            "formal_verification",
			ExpectedManifest: b.ManifestHash,
			SealManifest:     b.FormalVerification.ManifestHash,
			Match:            b.FormalVerification.ManifestHash == b.ManifestHash,
		})
	}

	// Execution record (extension section). Bundles sealed before the
	// record shipped carry none: absence means no record claim is made,
	// not a failure. When present, every row must match.
	if b.ExecutionRecord != nil {
		r.Categories = append(r.Categories, verifyExecutionRecord(b)...)
	}

	// SEV-SNP hardware attestation, INDEPENDENT re-verification.
	// When the bundle claims a real "sev_snp" quote, this tool never
	// takes the orchestrator's word for it: the raw report, VLEK leaf,
	// and AMD chain embedded in the bundle are re-verified here against
	// this binary's OWN pinned ARK-Milan root, and the report_data
	// binding is recomputed from the bundle's envelope + AER hashes.
	// A bundle claiming "sev_snp" whose quote fails any check is a
	// verification FAILURE (surfaced as a mismatching category row),
	// not a soft note: the claim was checkable and false. Bundles in
	// policy_scaffold mode skip this entirely (absent = no claim).
	if b.HardwareAttestation.AttestationMode == "sev_snp" {
		r.Categories = append(r.Categories, verifySevSnpQuote(b))
	}

	// Day-3+ Rekor anchor verification, runs only when the bundle was
	// sealed under VERDIFAX_LEDGER_MODE=rekor (Backend == "rekor").
	// Mock-ledger bundles skip this check; the report surfaces
	// Performed=false so a reader can see the run wasn't anchored on
	// a public log.
	r.RekorAnchor = verifyRekorAnchor(b.RekorAnchor)

	// The anchor check above proves a leaf sits under a Rekor-signed
	// root. It does not prove the leaf is THIS run's. Without the next
	// line a bundle naming a genuine but unrelated Rekor entry passes
	// every check in this tool.
	r.LeafBinding = verifyLeafBinding(b)
	r.NrepSignature = verifyNrepSignature(b, r.LeafBinding)
	r.RuntimeTiming = verifyRuntimeTiming(b)
	r.PreAnchor = verifyPreAnchor(b)
	r.CrossChecks = verifyCrossGeneration(b)
	r.BundleAnchor = verifyBundleAnchor(b)
	r.CompleteRecordRequirement = verifyCompleteRecordRequirement(b, r.BundleAnchor)
	r.EntryAuth = verifyEntryAuthentication(b, r)
	r.RecordValues = recordValuesOf(b)

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
	// A failed binding is a FAILURE, not an advisory note. An anchored
	// bundle whose leaf belongs to some other run is precisely the
	// forgery this tool exists to catch, and reporting it as a warning
	// beside a passing verdict would be the same defect as filing a
	// finding under "what this report does not show".
	if r.LeafBinding.Performed && !r.LeafBinding.Match {
		allPassed = false
	}
	// A claimed actor binding that does not validate is a forgery
	// signal of the same rank as a mismatched leaf: a failure, never
	// an advisory note.
	if r.NrepSignature.Performed && !r.NrepSignature.Match {
		allPassed = false
	}
	// A timing digest that does not match the durations it claims to
	// seal is tampering or corruption, a failure either way.
	if r.RuntimeTiming.Performed && !r.RuntimeTiming.Match {
		allPassed = false
	}
	// A table that disagrees with the record, or a cross-generation
	// consistency failure, is tampering: a failure, never a note.
	if r.PreAnchor.Performed && !r.PreAnchor.Match {
		allPassed = false
	}
	if len(r.CrossChecks) > 0 {
		allPassed = false
	}
	// A complete-record anchor that is present but does not hold is a
	// rewrite of the record after anchoring: a failure, never a note.
	if r.BundleAnchor.Present && !r.BundleAnchor.Match {
		allPassed = false
	}
	// An entry logged by a key that is not a pinned Verdifax key, two
	// entries with different signers, or an entry outside the sealed
	// anchoring window is a re-logged record: a failure, never a note.
	if r.EntryAuth.Performed && !r.EntryAuth.Match {
		allPassed = false
	}
	// A record whose own anchored values require a complete-record
	// anchor, and that does not carry one which holds, is a record
	// whose second entry was deleted or swapped: a failure, never the
	// partial verdict an older record honestly earns.
	r.passedExceptRequirement = allPassed
	if r.CompleteRecordRequirement.Sealed && !r.CompleteRecordRequirement.Satisfied {
		allPassed = false
	}
	r.AllPassed = allPassed

	// Verdict tiering (v0.8.1), the answer to the demonstrated
	// downgrade attack: the v3 sealing only runs for anchored
	// bundles, and the backend field that declares anchoring is
	// itself unprotected, so flipping it to "mock" switched every
	// seal off while the verdict still read VERIFIED. An offline
	// tool cannot cryptographically distinguish an honestly
	// mock-sealed bundle from an anchored one with its anchor
	// stripped; what it CAN do is refuse to give them the same
	// verdict. An unanchored bundle is at most SELF-CONSISTENT:
	// every hash in it can be rewritten together offline, and the
	// report and exit code now say so instead of printing the same
	// checkmark an anchored bundle earns.
	r.Anchored = r.RekorAnchor.Performed && r.RekorAnchor.Match &&
		r.LeafBinding.Performed && r.LeafBinding.Match
	switch {
	case !allPassed:
		r.VerdictTier = "FAILED"
	case r.Anchored:
		r.VerdictTier = "VERIFIED_ANCHORED"
	default:
		r.VerdictTier = "SELF_CONSISTENT_NOT_ANCHORED"
	}
	r.RecordCoverage = recordCoverage(r)
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
	err := rekorAnchorVerifier(rekorverify.AnchorInput{
		LeafHashHex:   a.LeafHashHex,
		EntryBody:     a.EntryBody,
		LogIndex:      a.LogIndex,
		TreeSize:      a.TreeSize,
		RootHashHex:   a.RootHashHex,
		InclusionPath: a.InclusionPath,
		Checkpoint:    a.Checkpoint,
		LogID:         a.LogID,

		LogEntryID:           a.LogEntryID,
		IntegratedTime:       a.IntegratedTime,
		SignedEntryTimestamp: a.SignedEntryTimestamp,
	})
	if isNoEntryBody(err) {
		// Not a forgery signal by itself, and not evidence either:
		// without the body nothing binds leaf_hash to the proof, so
		// the anchor is reported as not verifiable and the bundle
		// cannot reach the anchored tier.
		return RekorAnchorCheck{
			Performed:    false,
			Backend:      a.Backend,
			LogIndex:     a.LogIndex,
			Unverifiable: true,
			Reason:       err.Error(),
		}
	}
	if err != nil {
		reason := err.Error()
		stale, isStale := staleIndexReason(err, a.LogEntryID, a.LogIndex)
		if isStale {
			reason = stale
		}
		return RekorAnchorCheck{
			Performed:        true,
			Backend:          a.Backend,
			LogIndex:         a.LogIndex,
			Match:            false,
			Reason:           reason,
			StaleEntryNumber: isStale,
		}
	}
	return RekorAnchorCheck{
		Performed: true,
		Backend:   a.Backend,
		LogIndex:  a.LogIndex,
		Match:     true,
	}
}

// verifySevSnpQuote re-verifies a claimed sev_snp hardware quote from
// the raw evidence in the bundle. Returns a HashCheck whose
// recorded/computed pair encodes the outcome: both "verified" on
// success (Match=true), or "verified" vs "FAILED: <reason>" on any
// failure (Match=false, which fails the whole verification).
func verifySevSnpQuote(b *artifacts.AuditBundle) HashCheck {
	const name = "hardware_attestation_sevsnp_quote"
	fail := func(reason string) HashCheck {
		return HashCheck{Name: name, Recorded: "verified", Computed: "FAILED: " + reason, Match: false}
	}
	hwa := b.HardwareAttestation
	if hwa.QuoteB64 == "" || hwa.VLEKCertPEM == "" || hwa.CertChainPEM == "" {
		return fail("sev_snp mode claimed but quote evidence missing from bundle")
	}
	raw, err := base64.StdEncoding.DecodeString(hwa.QuoteB64)
	if err != nil {
		return fail("quote_b64 undecodable: " + err.Error())
	}
	// A record that carries the hardware measurement had its quote taken
	// before the record existed, so the quote binds the record's other
	// preimage fields. Older bundles bound the quote after the run, to
	// the envelope and record hashes.
	var binding [64]byte
	if rec := b.ExecutionRecord; rec != nil && rec.HardwareAttested {
		binding = sevsnp.PreRecordReportData(rec.InputHash, rec.TransportHash,
			rec.ExecutionControlHash, rec.ProgramHash, rec.KernelOutputIDs)
	} else {
		envHash := b.FinalVFA.EnvelopeHash
		aerHash := b.FinalVFA.AerHash
		if envHash == "" || aerHash == "" {
			return fail("bundle missing envelope/aer hashes for binding recompute")
		}
		binding = sevsnp.BindingReportData(envHash, aerHash)
	}
	if _, err := sevsnp.Verify(raw, []byte(hwa.VLEKCertPEM), []byte(hwa.CertChainPEM), binding[:]); err != nil {
		return fail(err.Error())
	}
	return HashCheck{Name: name, Recorded: "verified", Computed: "verified", Match: true}
}

// verifyExecutionRecord recomputes the run's attestation execution
// record (aer.v1) and its proof (proof.v1) from the bundle's disclosed
// preimage fields, then confirms the section belongs to this bundle:
// its record hash must equal the one the final VFA seals, and its
// kernel ids must equal the AER artifact's. The hardware row: a record
// that claims hardware must hold exactly the hash of the bundle's
// SEV-SNP quote; a record built without hardware is honest about it,
// so that row is a scaffold note, never a failure, unless the
// section's own claim is false.
func verifyExecutionRecord(b *artifacts.AuditBundle) []HashCheck {
	rec := *b.ExecutionRecord
	aer, proof, err := artifacts.RecomputeExecutionRecord(rec)
	if err != nil {
		aer = "error: " + err.Error()
		proof = aer
	}
	noHardware := rec.HardwareAttestationHash == artifacts.NoHardwareAttestationHash
	hardware := mk("execution_record_hardware",
		fmt.Sprintf("hardware_attested=%t", rec.HardwareAttested),
		fmt.Sprintf("hardware_attested=%t", !noHardware), noHardware)
	if rec.HardwareAttested {
		quoteHash, err := artifacts.ExecutionRecordHardwareHash(b)
		if err != nil {
			quoteHash = "error: " + err.Error()
		}
		hardware = mk("execution_record_hardware", rec.HardwareAttestationHash, quoteHash, false)
	}
	return []HashCheck{
		mk("execution_record", rec.AerHash, aer, false),
		mk("execution_record_proof", rec.ProofHash, proof, false),
		mk("execution_record_binding", b.FinalVFA.AerHash, rec.AerHash, false),
		mk("execution_record_kernel_ids",
			strings.Join(b.AER.ExecutionIDs, ","), strings.Join(rec.KernelOutputIDs, ","), false),
		hardware,
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
	fmt.Println("verdifax-verify", Version, ", ", b.Kind)
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
	printLeafBinding(r.LeafBinding)
	printNrepCheck(r.NrepSignature)
	printTimingCheck(r.RuntimeTiming)
	printPreAnchor(r.PreAnchor)
	printBundleAnchor(r.BundleAnchor)
	printCompleteRecordRequirement(r.CompleteRecordRequirement, len(b.PreAnchor) > 0)
	printEntryAuth(r.EntryAuth)
	printRecordValues(r.RecordValues)
	for _, f := range r.CrossChecks {
		fmt.Printf("  Cross-check:      ✗ FAILED · %s\n", f)
	}
	fmt.Println()

	switch {
	case r.AllPassed && !r.Anchored && r.RekorAnchor.Unverifiable:
		fmt.Println("VERDICT: ⚠ SELF-CONSISTENT ONLY, NOT ANCHORED.")
		fmt.Println("  Every hash recomputes, and the bundle claims a Rekor anchor, but it")
		fmt.Println("  carries no entry_body, so nothing binds its leaf hash to the inclusion")
		fmt.Println("  proof and the anchor cannot be verified offline. Every hash in it could")
		fmt.Println("  have been rewritten together. Exit code fails without --allow-unanchored.")
	case r.AllPassed && !r.Anchored:
		fmt.Println("VERDICT: ⚠ SELF-CONSISTENT ONLY, NOT ANCHORED.")
		fmt.Println("  Every hash recomputes, but this bundle claims no public-log anchor,")
		fmt.Println("  so every hash in it could have been rewritten together offline,")
		fmt.Println("  including this bundle's own statement that it was never anchored.")
		fmt.Println("  Production seals are always anchored: treat an unanchored bundle as")
		fmt.Println("  a dev artifact or a stripped anchor. Exit code fails without")
		fmt.Println("  --allow-unanchored.")
	case completeRecordAnchored(r):
		fmt.Printf("VERDICT: ✓ VERIFIED AND ANCHORED, COMPLETE RECORD ANCHORED%s\n", scaffoldSuffix(r))
		fmt.Println("  The run identity and pre-anchor table are bound by the first public-log")
		fmt.Println("  entry and every section of the record by the second.")
		printScaffoldList(r)
	case r.AllPassed && r.PreAnchor.Performed:
		fmt.Printf("VERDICT: ✓ VERIFIED AND ANCHORED, PARTIAL COVERAGE%s\n", scaffoldSuffix(r))
		fmt.Println("  The run identity and the pre-anchor table are anchored. The descriptive")
		fmt.Println("  sections (decision record, request substance, authorization chain,")
		fmt.Println("  causal graph, system provenance and the rest) are bundle-sealed, NOT")
		fmt.Println("  anchored: this record has no verified complete-record anchor, so those")
		fmt.Println("  sections could have been rewritten together with their hashes.")
		printScaffoldList(r)
	case r.AllPassed:
		note := ""
		if r.HasScaffold {
			note = "; with scaffold flags"
		}
		fmt.Printf("VERDICT: ✓ VERIFIED AND ANCHORED (PARTIAL COVERAGE: pre-v5 record; the anchor binds the run identity, not every field%s)\n", note)
		printScaffoldList(r)
	case r.CompleteRecordRequirement.Sealed && !r.CompleteRecordRequirement.Satisfied &&
		r.passedExceptRequirement:
		if !r.BundleAnchor.Present {
			fmt.Println("VERDICT: ✗ FAILED, this record's own anchored values require a complete-record")
			fmt.Println("  anchor, and it is missing.")
		} else {
			fmt.Println("VERDICT: ✗ FAILED, this record's own anchored values require a complete-record")
			fmt.Println("  anchor, and the one it carries does not satisfy that requirement.")
		}
		fmt.Println("  Records sealed with leaf v6 state, inside the values their first public-log")
		fmt.Println("  entry anchors, that a second entry anchoring the complete record must exist.")
		fmt.Println("  Without it, the descriptive sections could have been rewritten together with")
		fmt.Println("  their hashes and the second entry deleted. Do not rely on this record.")
	case r.RekorAnchor.StaleEntryNumber || r.BundleAnchor.StaleEntryNumber:
		fmt.Println("VERDICT: ✗ FAILED, this copy carries an outdated entry number, so its")
		fmt.Println("  public-log timestamp cannot be checked. Copies of some records downloaded")
		fmt.Println("  before 2026-10-16 look like this: download the record again from its")
		fmt.Println("  public link and verify that copy.")
	default:
		fmt.Println("VERDICT: ✗ FAILED, at least one check did not pass (the ✗ lines above say which).")
		fmt.Println("  This bundle has been tampered with, or was produced by a tool that is")
		fmt.Println("  out of sync with this verifier's schema. Investigate before relying on it.")
	}
	fmt.Println()
}

// scaffoldSuffix is the verdict-line tail naming scaffold state.
func scaffoldSuffix(r *Report) string {
	if r.HasScaffold {
		return " (with scaffold flags)"
	}
	return ", no scaffold values flagged."
}

// printScaffoldList names the scaffold-flagged artifacts under any
// passing verdict that has them.
func printScaffoldList(r *Report) {
	if !r.HasScaffold {
		return
	}
	fmt.Println("  Scaffold artifacts (closing paths at docs.verdifax.com/concepts/scaffold-gaps/):")
	for _, s := range r.ScaffoldList {
		fmt.Println("    ·", s)
	}
	fmt.Println("  These are honestly self-declared by the orchestrator. Use --strict to fail on them.")
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
	if a.Unverifiable {
		fmt.Println("  ·  rekor anchor NOT VERIFIABLE offline: the bundle carries no entry_body")
		fmt.Println("     Without the logged entry body nothing binds the claimed leaf hash")
		fmt.Println("     to the inclusion proof, so this anchor is not counted. Fetch the")
		fmt.Println("     bundle from the API, which backfills entry_body, and verify again.")
		return
	}
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
		fmt.Printf("  ✓  rekor anchor verified offline, log index %d\n", a.LogIndex)
		fmt.Printf("     Inclusion proof and signed checkpoint both verify under the\n")
		// The two index fields are BOTH correct and mean different
		// things, because rekor.sigstore.dev is sharded. log_entry_id is
		// the global index across all shards, which is what
		// search.sigstore.dev resolves. log_index is the position inside
		// the current shard's tree, which is what the inclusion proof is
		// verified against. For run 208 they are 1703229140 and
		// 1581324878; the difference is the size of the prior shards.
		//
		// This comment exists because a change on 2026-09-08 "fixed" the
		// link to use log_index, on the reasoning that the entry id
		// exceeded the shard's tree size and so could not be a position
		// in it. True, and irrelevant: it was never a shard position.
		// The mistaken fix was published for under an hour and caught by
		// fetching the entry from the live log, whose hashedrekord at
		// the global index carries this bundle's exact leaf hash. Verify
		// semantics against the system, not only arithmetic against the
		// data in hand.
		fmt.Printf("     embedded Rekor public key. View on https://search.sigstore.dev/?logIndex=%s\n", logEntryID)
		if logEntryID != "" && logEntryID != strconv.FormatInt(a.LogIndex, 10) {
			fmt.Printf("     (%s is the global index across shards; %d is this entry's\n", logEntryID, a.LogIndex)
			fmt.Printf("     position inside the current shard's tree, used by the proof.)\n")
		}
		return
	}

	fmt.Printf("  ✗  rekor anchor FAILED, log index %d\n", a.LogIndex)
	fmt.Printf("     Reason: %s\n", a.Reason)
	fmt.Println("     This bundle's public-log claim does not verify. Either the")
	fmt.Println("     anchor was tampered with, the embedded Rekor public key is")
	fmt.Println("     stale (rotation announced via the Sigstore TUF root), or the")
	fmt.Println("     bundle was produced by a non-canonical orchestrator.")
}

// printLeafBinding renders whether the anchored leaf belongs to THIS
// run. Printed directly beneath the anchor result because the two are
// only meaningful together: the anchor says a leaf is in the log, this
// says the leaf is yours. A reader who sees one tick and assumes the
// other has been misled, so neither is shown alone.
//
// Omitting this printer was the first thing found when the public and
// private verifiers were diffed. The check ran, and correctly failed the
// verdict, while saying nothing in the human report. A result the reader
// cannot see is the same defect as filing a finding under "what this
// report does not show".
func printLeafBinding(c LeafBindingCheck) {
	if !c.Performed {
		return
	}
	if c.Match {
		// The v1 preimage has no nonce. Naming one anyway, as the
		// orchestrator's copy of this printer does, tells an auditor the
		// tool checked an input that does not exist in that form. Small,
		// and exactly the kind of inaccuracy that costs a reader's trust
		// in the lines they cannot check themselves.
		inputs := "envelope_id, aer_hash and binding_hash"
		if c.Form == leafDomainV2 {
			inputs = "envelope_id, aer_hash, binding_hash and input_nonce"
		}
		fmt.Println("  ✓  the anchored leaf is this run's")
		fmt.Printf("     Recomputed from this bundle's %s\n", inputs)
		fmt.Printf("     under %s; matches the anchored leaf hash.\n", c.Form)
		return
	}
	fmt.Println("  ✗  the anchored leaf is NOT this run's")
	fmt.Printf("     Reason: %s\n", c.Reason)
	if c.Computed != "" {
		fmt.Printf("     This run's inputs produce %s\n", truncate(c.Computed, 24))
		fmt.Printf("     The bundle claims the anchor is %s\n", truncate(c.Recorded, 24))
	}
}

// isHTTPURL reports whether s parses as an absolute http or https URL.
// The verifier accepts URL arguments so an auditor can run
//
//	verdifax-verify --strict https://api.verdifax.com/runs/N/bundle.json
//
// directly, without first piping curl into stdin. The corollary is
// that an argument starting with "http://" or "https://" is never
// interpreted as a local file path.
func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.IsAbs() && (u.Scheme == "http" || u.Scheme == "https")
}

// fetchBundleHTTP retrieves the bundle JSON from the given URL with a
// modest timeout and a size cap. The timeout prevents the verifier
// from hanging on a slow endpoint; the size cap (32 MiB) prevents a
// pathological response from consuming all memory. The returned
// bytes are passed unchanged into the existing JSON parser.
func fetchBundleHTTP(rawURL string) ([]byte, error) {
	const maxBundleBytes = 32 * 1024 * 1024 // 32 MiB
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("http request build failed: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "verdifax-verify/"+Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http fetch returned %s (expected 2xx) for %s",
			resp.Status, rawURL)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("http body read failed: %w", err)
	}
	if int64(len(body)) > maxBundleBytes {
		return nil, fmt.Errorf("bundle exceeds %d byte size limit", maxBundleBytes)
	}
	return body, nil
}

// rekorIndexText names the global index (what search.sigstore.dev and
// the audit PDF cite) first, and the shard position only when it differs.
func rekorIndexText(s EvidenceSummary) string {
	shard := strconv.FormatInt(s.RekorLogIndex, 10)
	if s.RekorLogEntryID == "" || s.RekorLogEntryID == shard {
		return "log index " + shard
	}
	return "log entry " + s.RekorLogEntryID + " (shard index " + shard + ")"
}

// reportAmbiguousJSON prints the FAILED verdict for a bundle or receipt
// document refused by strict decoding, in the requested output form.
// what is "bundle" or "receipt", so the message names what was read.
func reportAmbiguousJSON(err error, what string, jsonOut bool) {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"tool":            "verdifax-verify",
			"tool_version":    Version,
			"all_passed":      false,
			"anchored":        false,
			"verdict_tier":    "FAILED",
			"record_coverage": "failed",
			"reason":          err.Error(),
		})
		return
	}
	label := "  Bundle JSON:      "
	if what == "receipt" {
		label = "  Receipt JSON:     "
	}
	fmt.Println(label + "✗ FAILED · " + strings.TrimPrefix(err.Error(), "invalid bundle JSON: "))
	fmt.Println("VERDICT: ✗ FAILED, the " + what + "'s JSON is ambiguous or carries unmodeled fields, so")
	fmt.Println("         other readers would see values this tool did not check.")
}
