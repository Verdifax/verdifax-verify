package main

// Round-seven regression suite: deleting the complete-record anchor.
//
// Fixtures in testdata/round7:
//
//	run-238-intact.json        the live run 238 bundle exactly as served
//	                           (sha256 98197fdb...c4a9e8): a v5 record
//	                           carrying a genuine bundle_anchor.
//	run-238-STRIP_V*.json      run 238 with a story section rewritten,
//	                           every section hash and bundle_hash
//	                           recomputed, and bundle_anchor deleted.
//	                           v0.10.0 printed VERIFIED AND ANCHORED,
//	                           PARTIAL COVERAGE with exit 0, the verdict
//	                           an older record honestly earns. They are
//	                           v5 records and stay partial forever: the
//	                           requirement cannot be added after sealing.
//	v6-intact-test-log.json    SYNTHETIC: run 238 resealed as a leaf v6
//	                           record (table v2 with the requirement
//	                           row), both entries on this suite's fixed
//	                           test log. Must be COMPLETE.
//	v6-strip-test-log.json     SYNTHETIC: the same record with
//	                           bundle_anchor deleted. Must FAIL, and for
//	                           that reason alone.
//	orchestrator-e2e-v6-mock.json  the orchestrator's end-to-end v6 dump
//	                           (internal/api, VFX_BUNDLE_OUT) on its mock
//	                           ledger: SELF-CONSISTENT intact, FAILED
//	                           once bundle_anchor is deleted.
//
// The synthetic fixtures verify only against the fixed test log key
// below, never the embedded Rekor key, so the CLI on its own rejects
// them at the first anchor; the tests install the key.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

var run238Strips = []string{
	"run-238-STRIP_V1_aer_decision.json",
	"run-238-STRIP_V2_request_substance.json",
	"run-238-STRIP_V3_authorization_chain.json",
	"run-238-STRIP_V4_causal_graph_effect.json",
	"run-238-STRIP_V5_system_provenance.json",
	"run-238-STRIP_V6_all.json",
}

func loadRound7(t *testing.T, name string) *artifacts.AuditBundle {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "round7", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var b artifacts.AuditBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return &b
}

// fixedTestLog is a test transparency log whose key is derived from a
// constant, so fixtures anchored on it stay verifiable across runs.
// TEST USE ONLY: the scalar is public by construction.
func fixedTestLog(t *testing.T) *testLog {
	t.Helper()
	seed := sha256.Sum256([]byte("verdifax-verify round7 fixed test log key, test use only"))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seed[:])
	if err != nil {
		t.Fatalf("derive test log key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal test log key: %v", err)
	}
	sum := sha256.Sum256(der)
	return &testLog{key: k, logID: hex.EncodeToString(sum[:])}
}

// anchorRun puts b's run leaf on log l as its first entry, exactly as
// anchorRecord puts the record leaf there as its second.
func anchorRun(t *testing.T, l *testLog, b *artifacts.AuditBundle) {
	t.Helper()
	e := l.entry(t, strings.Repeat("0", 64), b.RekorAnchor.LeafHashHex)
	a := &b.RekorAnchor
	a.Backend, a.LogID, a.EntryBody = "rekor", e.LogID, e.EntryBody
	a.LogIndex, a.TreeSize, a.RootHashHex = e.LogIndex, e.TreeSize, e.RootHashHex
	a.InclusionPath, a.Checkpoint = e.InclusionPath, e.Checkpoint
}

// v6Leaf rebuilds the v6 leaf from the record's own fields.
func v6Leaf(b *artifacts.AuditBundle) string {
	sum := sha256.Sum256([]byte(joinLeafParts(leafDomainV6, b.Envelope.EnvelopeID,
		b.AER.Seal.SealedHash, b.ZkspBinding.Seal.SealedHash,
		strconv.FormatInt(int64(b.RekorAnchor.InputNonce), 10),
		artifacts.ComputePreAnchorDigestV2FromTable(b.PreAnchor))))
	return hex.EncodeToString(sum[:])
}

// resealAsV6 turns run 238 into the record a leaf v6 producer would
// have sealed: the requirement row appended, the v2 digest stored, the
// v6 leaf anchored on l, and the complete record anchored after it.
func resealAsV6(t *testing.T, l *testLog) *artifacts.AuditBundle {
	t.Helper()
	b := loadRound7(t, "run-238-intact.json")
	b.PreAnchor = append(b.PreAnchor, artifacts.PreAnchorEntry{
		Name: artifacts.CompleteRecordAnchorRow, Value: artifacts.CompleteRecordAnchorRequired})
	b.PreAnchorDigest = artifacts.ComputePreAnchorDigestV2FromTable(b.PreAnchor)
	b.RekorAnchor.LeafHashHex = v6Leaf(b)
	anchorRun(t, l, b)
	anchorRecord(t, l, b)
	return b
}

// TestWriteRound7Fixtures regenerates the synthetic fixtures. It runs
// only with VFX_WRITE_ROUND7=1, so the committed files stay fixed.
func TestWriteRound7Fixtures(t *testing.T) {
	if os.Getenv("VFX_WRITE_ROUND7") != "1" {
		t.Skip("set VFX_WRITE_ROUND7=1 to regenerate the synthetic round-seven fixtures")
	}
	l := fixedTestLog(t)
	b := resealAsV6(t, l)
	write := func(name string, b *artifacts.AuditBundle) {
		raw, err := json.MarshalIndent(b, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", "round7", name), append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("v6-intact-test-log.json", b)
	b.BundleAnchor = nil
	write("v6-strip-test-log.json", b)
}

// ── v5 records keep their v0.10.0 verdicts exactly ───────────────────

func TestV5RecordsKeepTheirV010Verdicts(t *testing.T) {
	const (
		complete = "VERDICT: ✓ VERIFIED AND ANCHORED, COMPLETE RECORD ANCHORED (with scaffold flags)"
		partial  = "VERDICT: ✓ VERIFIED AND ANCHORED, PARTIAL COVERAGE (with scaffold flags)"
	)
	cases := []struct {
		dir, name, tier, coverage, verdict string
	}{
		{"round7", "run-238-intact.json", "VERIFIED_ANCHORED", "complete_record_anchored", complete},
		{"round6", "run-237-intact.json", "VERIFIED_ANCHORED", "partial_descriptive_sections_bundle_sealed", partial},
	}
	for _, name := range run238Strips {
		cases = append(cases, struct{ dir, name, tier, coverage, verdict string }{
			"round7", name, "VERIFIED_ANCHORED", "partial_descriptive_sections_bundle_sealed", partial})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b *artifacts.AuditBundle
			if c.dir == "round7" {
				b = loadRound7(t, c.name)
			} else {
				b = loadRound6(t, c.name)
			}
			r := verify(b)
			if r.VerdictTier != c.tier || r.RecordCoverage != c.coverage || !r.AllPassed {
				t.Fatalf("tier=%s coverage=%s all_passed=%v, want %s %s true",
					r.VerdictTier, r.RecordCoverage, r.AllPassed, c.tier, c.coverage)
			}
			if exitShouldFail(r, false, false) {
				t.Fatal("a v5 record that passed under v0.10.0 must still exit 0")
			}
			if r.CompleteRecordRequirement.Sealed {
				t.Fatal("a v5 record carries no requirement and must not be judged as if it did")
			}
			if r.LeafBinding.Form != leafDomainV5 || r.PreAnchor.Form != artifacts.PreAnchorFormV1 {
				t.Fatalf("v5 record judged as %s / %s", r.LeafBinding.Form, r.PreAnchor.Form)
			}
			out := captureHumanReport(t, b, r)
			if !strings.Contains(out, c.verdict+"\n") {
				t.Fatalf("verdict line changed from v0.10.0, want %q:\n%s", c.verdict, out)
			}
			if !strings.Contains(out, "Anchor required:  not sealed (pre-v6 record") {
				t.Fatalf("a v5 record must say a deleted record anchor is not detectable:\n%s", out)
			}
		})
	}
}

// ── leaf v6: the strip attack is detected ────────────────────────────

func TestV6IntactRecordIsCompleteRecordAnchored(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := loadRound7(t, "v6-intact-test-log.json")
	r := verify(b)
	if r.LeafBinding.Form != leafDomainV6 || !r.LeafBinding.Match {
		t.Fatalf("leaf binding: %+v", r.LeafBinding)
	}
	if r.PreAnchor.Form != artifacts.PreAnchorFormV2 || !r.PreAnchor.Match || r.PreAnchor.Rows != 34 {
		t.Fatalf("pre-anchor: %+v", r.PreAnchor)
	}
	if !r.CompleteRecordRequirement.Sealed || !r.CompleteRecordRequirement.Satisfied {
		t.Fatalf("requirement: %+v", r.CompleteRecordRequirement)
	}
	if !completeRecordAnchored(r) || r.RecordCoverage != "complete_record_anchored" || exitShouldFail(r, false, false) {
		t.Fatalf("tier=%s coverage=%s", r.VerdictTier, r.RecordCoverage)
	}
	out := captureHumanReport(t, b, r)
	if !strings.Contains(out, "VERDICT: ✓ VERIFIED AND ANCHORED, COMPLETE RECORD ANCHORED") {
		t.Fatalf("missing complete verdict:\n%s", out)
	}

	// The committed fixture is exactly what resealing produces, so it
	// was not hand-edited.
	fresh := resealAsV6(t, l)
	if fresh.RekorAnchor.LeafHashHex != b.RekorAnchor.LeafHashHex ||
		fresh.BundleAnchor.AnchoredDigest != b.BundleAnchor.AnchoredDigest {
		t.Fatal("fixture drifted from the resealing recipe")
	}
}

func TestV6StripAttackFails(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := loadRound7(t, "v6-strip-test-log.json")
	if b.BundleAnchor != nil {
		t.Fatal("strip fixture unexpectedly carries a bundle_anchor")
	}
	r := verify(b)
	// Everything else holds: the failure is the deletion, nothing else.
	if !r.Anchored || !r.LeafBinding.Match || !r.PreAnchor.Match || !r.BundleHashOK || !r.passedExceptRequirement {
		t.Fatalf("strip fixture must be otherwise intact: anchored=%v leaf=%v table=%v",
			r.Anchored, r.LeafBinding.Match, r.PreAnchor.Match)
	}
	if r.AllPassed || r.VerdictTier != "FAILED" || r.RecordCoverage != "failed" {
		t.Fatalf("strip attack must FAIL: tier=%s coverage=%s", r.VerdictTier, r.RecordCoverage)
	}
	if !exitShouldFail(r, false, true) {
		t.Fatal("must exit 1 even with --allow-unanchored")
	}
	if !strings.Contains(r.CompleteRecordRequirement.Reason, "require a complete-record anchor, and it is missing") {
		t.Fatalf("reason must say plainly what is missing: %q", r.CompleteRecordRequirement.Reason)
	}
	out := captureHumanReport(t, b, r)
	if !strings.Contains(out, "VERDICT: ✗ FAILED, this record's own anchored values require a complete-record\n  anchor, and it is missing.") {
		t.Fatalf("verdict must name the missing anchor:\n%s", out)
	}
	if strings.Contains(out, "PARTIAL COVERAGE") {
		t.Fatalf("a stripped v6 record must never get the partial verdict:\n%s", out)
	}
}

// The full round-seven forgery against a v6 record: rewrite a story
// section, recompute every hash, delete the second entry.
func TestV6StoryRewriteWithStripFails(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := loadRound7(t, "v6-strip-test-log.json")
	b.AER.Decision.Result = "deny"
	b.AER.Hash = artifacts.RecomputeAERHash(b.AER)
	b.SystemProvenance.Hash = artifacts.RecomputeSystemProvenanceHash(b.SystemProvenance)
	b.BundleHash = artifacts.RecomputeBundleHash(b)
	r := verify(b)
	if r.AllPassed || r.VerdictTier != "FAILED" || !exitShouldFail(r, false, true) {
		t.Fatalf("rewrite plus strip must FAIL: tier=%s", r.VerdictTier)
	}
}

// Removing the requirement row, or changing its value, breaks the
// FIRST public-log entry, whatever the forger recomputes around it.
func TestRewritingTheRequirementRowBreaksTheMainAnchor(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	cases := map[string]func(b *artifacts.AuditBundle){
		"row removed, v1 digest recomputed": func(b *artifacts.AuditBundle) {
			b.PreAnchor = b.PreAnchor[:33]
			b.PreAnchorDigest = artifacts.ComputePreAnchorDigestFromTable(b.PreAnchor)
		},
		"value changed, v2 digest recomputed": func(b *artifacts.AuditBundle) {
			b.PreAnchor[33].Value = "not_required"
			b.PreAnchorDigest = artifacts.ComputePreAnchorDigestV2FromTable(b.PreAnchor)
		},
		"row renamed, v1 digest recomputed": func(b *artifacts.AuditBundle) {
			b.PreAnchor[33].Name = "complete_record_anchor_optional"
			b.PreAnchorDigest = artifacts.ComputePreAnchorDigestFromTable(b.PreAnchor)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := loadRound7(t, "v6-strip-test-log.json")
			mutate(b)
			r := verify(b)
			if r.LeafBinding.Match {
				t.Fatalf("the leaf still matches after %s: the row is not bound", name)
			}
			if r.AllPassed || r.VerdictTier != "FAILED" || !exitShouldFail(r, false, true) {
				t.Fatalf("must FAIL: tier=%s", r.VerdictTier)
			}
		})
	}
}

// A misplaced requirement row is judged as table v2 and fails the
// shape check, rather than passing as a v1 table with an extra row.
func TestMisplacedRequirementRowFailsTheShape(t *testing.T) {
	b := loadRound7(t, "v6-intact-test-log.json")
	row := b.PreAnchor[33]
	b.PreAnchor = append([]artifacts.PreAnchorEntry{row}, b.PreAnchor[:33]...)
	if pa := verifyPreAnchor(b); pa.Match || pa.Form != artifacts.PreAnchorFormV2 {
		t.Fatalf("misplaced row must fail as v2: %+v", pa)
	}
}

// Swapping the genuine Rekor record anchor for a self-consistent one
// on a non-public backend must not satisfy a public-log run.
func TestV6NonPublicRecordAnchorDoesNotSatisfyAPublicLogRun(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := loadRound7(t, "v6-strip-test-log.json")
	digest := artifacts.ComputeAnchoredRecordDigest(b)
	b.BundleAnchor = &artifacts.BundleAnchor{
		Kind: artifacts.BundleAnchorKind, DigestForm: artifacts.BundleAnchorDigestForm,
		AnchoredDigest: digest, Backend: "mock", LogEntryID: "mock-0000000000000000",
		LeafHashHex: artifacts.ComputeBundleLeafHash(b.Envelope.EnvelopeID, digest),
	}
	r := verify(b)
	if !r.BundleAnchor.Match || r.BundleAnchor.Performed {
		t.Fatalf("the swapped anchor is consistent but not public: %+v", r.BundleAnchor)
	}
	if r.CompleteRecordRequirement.Satisfied || r.AllPassed || !exitShouldFail(r, false, true) {
		t.Fatalf("a mock record anchor must not satisfy a Rekor-anchored v6 run: %+v", r.CompleteRecordRequirement)
	}
	if !strings.Contains(r.CompleteRecordRequirement.Reason, `backend "mock"`) {
		t.Fatalf("reason must name the backend: %q", r.CompleteRecordRequirement.Reason)
	}
}

// The producer's own end-to-end v6 record, on its mock ledger.
func TestOrchestratorV6RecordCrossVerifies(t *testing.T) {
	b := loadRound7(t, "orchestrator-e2e-v6-mock.json")
	r := verify(b)
	if r.LeafBinding.Performed {
		t.Fatal("a mock-ledger record makes no public-log claim to bind")
	}
	if !r.AllPassed || r.PreAnchor.Form != artifacts.PreAnchorFormV2 || !r.PreAnchor.Match ||
		!r.CompleteRecordRequirement.Satisfied || r.VerdictTier != "SELF_CONSISTENT_NOT_ANCHORED" {
		t.Fatalf("intact producer record: tier=%s table=%+v req=%+v", r.VerdictTier, r.PreAnchor, r.CompleteRecordRequirement)
	}
	if exitShouldFail(r, false, true) {
		t.Fatal("intact mock record must pass with --allow-unanchored")
	}
	// The run leaf the producer computed is the v6 leaf this verifier
	// rebuilds, even though no public log holds it.
	if got := v6Leaf(b); got != b.RekorAnchor.LeafHashHex {
		t.Fatalf("producer leaf %s, verifier v6 recipe %s", b.RekorAnchor.LeafHashHex, got)
	}

	b.BundleAnchor = nil
	r = verify(b)
	if r.AllPassed || r.VerdictTier != "FAILED" || !exitShouldFail(r, false, true) {
		t.Fatalf("stripped producer record must FAIL: tier=%s", r.VerdictTier)
	}
}
