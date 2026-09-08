package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// HOW THESE DIFFER FROM THE ORCHESTRATOR'S COPY, AND WHY IT MATTERS
//
// The orchestrator's version of this suite round-trips against
// adapters.MockLedgerAdapter, the real producing code, so a drift in the
// producer fails the verifier's tests. This repository is a verifier
// only and has no access to the producer, so that coupling is not
// available here.
//
// Restating the recipe in the test would then prove only that this file
// agrees with itself. So the anchor case instead verifies a REAL sealed
// bundle from production run 208, already in this repository as
// testdata. If the producer changes the preimage, that fixture stops
// verifying and this suite fails, which recovers most of the coupling
// the round-trip gave.
//
// What is NOT recovered: a producer change accompanied by a regenerated
// fixture would pass. Stated plainly rather than papered over. The
// mitigation is that the fixture is a signed production artifact, not
// something regenerated casually.

func goldenBundle(t *testing.T) *artifacts.AuditBundle {
	t.Helper()
	path := filepath.Join("internal", "artifacts", "testdata",
		"golden-bundle-run-208.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden bundle: %v", err)
	}
	var b artifacts.AuditBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse golden bundle: %v", err)
	}
	if b.RekorAnchor.Backend != "rekor" || b.RekorAnchor.LeafHashHex == "" {
		t.Fatal("fixture is not rekor-anchored; this suite would prove nothing")
	}
	return &b
}

// ── the case that must pass ──────────────────────────────────────────

func TestLeafBindingVerifiesARealProductionBundle(t *testing.T) {
	got := verifyLeafBinding(goldenBundle(t))
	if !got.Performed {
		t.Fatal("check skipped a rekor-anchored production bundle")
	}
	if !got.Match {
		t.Fatalf("a genuine production bundle failed leaf binding:\n"+
			"  recorded %s\n  computed %s\n  reason   %s",
			got.Recorded, got.Computed, got.Reason)
	}
	if got.Form != leafDomainV1 {
		t.Errorf("run 208 predates the nonce, so it must verify under v1; got %q", got.Form)
	}
}

// ── the case that must fail, which is the whole point ────────────────

func TestLeafBindingRejectsAnotherRunsAnchor(t *testing.T) {
	b := goldenBundle(t)
	// A real leaf hash, just not this run's. Before this check existed
	// the bundle below passed every test in the tool, because the Rekor
	// inclusion proof for such an entry is genuine.
	b.RekorAnchor.LeafHashHex =
		"0000000000000000000000000000000000000000000000000000000000000000"

	got := verifyLeafBinding(b)
	if got.Match {
		t.Fatal("a bundle naming a foreign anchor passed leaf binding; " +
			"this is exactly the forgery the check exists to catch")
	}
	if got.Reason == "" {
		t.Error("a failure with no reason tells the reader nothing")
	}
}

// ── every input must be load-bearing ─────────────────────────────────

func TestLeafBindingEveryInputIsBound(t *testing.T) {
	cases := map[string]func(*artifacts.AuditBundle){
		"envelope_id":       func(b *artifacts.AuditBundle) { b.Envelope.EnvelopeID = "env-0000000000000000" },
		"aer sealed_hash":   func(b *artifacts.AuditBundle) { b.AER.Seal.SealedHash = strings.Repeat("a", 64) },
		"zksp sealed_hash":  func(b *artifacts.AuditBundle) { b.ZkspBinding.Seal.SealedHash = strings.Repeat("b", 64) },
		"input_nonce added": func(b *artifacts.AuditBundle) { b.RekorAnchor.InputNonce = 1757001600123456789 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := goldenBundle(t)
			mutate(b)
			if verifyLeafBinding(b).Match {
				t.Fatalf("changing %s did not change the computed leaf; "+
					"that input is not actually bound", name)
			}
		})
	}
}

// ── the trap named in leafbinding.go's own comment ───────────────────

func TestLeafBindingUsesTheSealedHashNotTheArtifactHash(t *testing.T) {
	b := goldenBundle(t)
	// AER.Hash is the artifact's own canonical hash. The manifest's
	// aer_hash is AER.Seal.SealedHash. Reaching for .Hash compiles,
	// reads correctly, and fails on every genuine bundle. Setting .Hash
	// to nonsense must NOT affect this check.
	b.AER.Hash = "NOT-the-manifest-aer-hash"
	b.ZkspBinding.Hash = "NOT-the-manifest-binding-hash"
	if !verifyLeafBinding(b).Match {
		t.Fatal("the check is reading .Hash instead of .Seal.SealedHash")
	}
}

// ── form selection is driven by data, not assumed ────────────────────

func TestLeafBindingUsesV1ForPreNonceBundles(t *testing.T) {
	b := goldenBundle(t)
	if b.RekorAnchor.InputNonce != 0 {
		t.Skip("fixture carries a nonce; this case needs a pre-nonce bundle")
	}
	got := verifyLeafBinding(b)
	if got.Form != leafDomainV1 || !got.Match {
		t.Fatalf("a legacy bundle must verify under v1, not be reported as forged: "+
			"form=%q match=%v", got.Form, got.Match)
	}
}

// ── absence and abstention ───────────────────────────────────────────

func TestLeafBindingSkipsBundlesThatClaimNoAnchor(t *testing.T) {
	b := goldenBundle(t)
	b.RekorAnchor.Backend = "mock"
	if got := verifyLeafBinding(b); got.Performed {
		t.Fatal("a mock-ledger bundle makes no public-log claim; " +
			"failing it would punish honesty about not being anchored")
	}
}

func TestLeafBindingFailsWhenTheInputsAreMissing(t *testing.T) {
	// This test asserts on the REASON, not merely on failure.
	//
	// An earlier version checked only that the verdict was not a pass,
	// and mutation testing showed it survived deleting the missing-input
	// guard entirely: with the guard gone the check hashes an empty
	// field, gets a mismatch, and fails anyway. Same verdict, completely
	// different claim. A malformed bundle would have been reported as
	// "the log entry is real, but it does not belong to this run", which
	// accuses a producer of forgery for what is a defect in their
	// output. In an auditor-facing tool those are not interchangeable.
	cases := map[string]struct {
		mutate func(*artifacts.AuditBundle)
		names  string
	}{
		"envelope": {func(b *artifacts.AuditBundle) { b.Envelope.EnvelopeID = "" },
			"envelope.envelope_id"},
		"aer": {func(b *artifacts.AuditBundle) { b.AER.Seal.SealedHash = "" },
			"aer.seal.sealed_hash"},
		"zksp": {func(b *artifacts.AuditBundle) { b.ZkspBinding.Seal.SealedHash = "" },
			"zksp_binding.seal.sealed_hash"},
		"leaf": {func(b *artifacts.AuditBundle) { b.RekorAnchor.LeafHashHex = "" },
			"rekor_anchor.leaf_hash"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := goldenBundle(t)
			c.mutate(b)
			got := verifyLeafBinding(b)

			if !got.Performed || got.Match {
				t.Fatal("a bundle that claims an anchor but omits the inputs " +
					"needed to check it must FAIL, not skip; skipping would let " +
					"a producer dodge the check by dropping a field")
			}
			if !strings.Contains(got.Reason, c.names) {
				t.Errorf("the reason must name the missing field so the producer "+
					"can fix it.\n  want it to mention: %s\n  got: %s",
					c.names, got.Reason)
			}
			if strings.Contains(got.Reason, "does not belong to this run") {
				t.Errorf("a malformed bundle was reported as a foreign anchor. "+
					"That accuses the producer of forgery for what is a defect "+
					"in their output.\n  got: %s", got.Reason)
			}
			if got.Computed != "" {
				t.Errorf("no leaf should be computed from absent inputs; "+
					"publishing one invites comparison against it. got %q",
					got.Computed)
			}
		})
	}
}

func TestLeafBindingIgnoresHexCase(t *testing.T) {
	b := goldenBundle(t)
	b.RekorAnchor.LeafHashHex = strings.ToUpper(b.RekorAnchor.LeafHashHex)
	if !verifyLeafBinding(b).Match {
		t.Fatal("hex case must not decide a verdict")
	}
}

// ── the property that makes this formula safe to publish ─────────────

func TestNoLeafFieldCanContainTheSeparator(t *testing.T) {
	// Publishing leafbinding.go publishes the preimage formula, and the
	// formula is strings.Join(parts, ".") with no length prefixing.
	// Reconstruction sidesteps the PARSING ambiguity, but it would not
	// prevent a COLLISION: if a joined field could itself contain a dot,
	// two different input tuples would produce one preimage and one
	// leaf.
	//
	// They cannot, because every field is fixed-alphabet. This test
	// holds that so it cannot decay into a comment somebody stops
	// believing. It is the first thing an expert reviewer looks for.
	b := goldenBundle(t)
	fields := map[string]string{
		"envelope_id":        b.Envelope.EnvelopeID,
		"aer sealed_hash":    b.AER.Seal.SealedHash,
		"zksp sealed_hash":   b.ZkspBinding.Seal.SealedHash,
		"recorded leaf_hash": b.RekorAnchor.LeafHashHex,
	}
	for name, v := range fields {
		if v == "" {
			t.Errorf("%s is empty in the fixture; the property is untested for it", name)
			continue
		}
		if strings.Contains(v, ".") {
			t.Errorf("%s contains the separator (%q); two different input tuples "+
				"could then produce the same leaf", name, v)
		}
	}
	// envelope_id is the only field a request could plausibly influence.
	// It is minted as "env-" plus sixteen hex characters by the admission
	// adapter and is never caller-supplied.
	if !strings.HasPrefix(b.Envelope.EnvelopeID, "env-") ||
		len(b.Envelope.EnvelopeID) != len("env-")+16 {
		t.Errorf("envelope_id %q is not the expected env-<16 hex> shape; "+
			"the no-separator argument rests on that shape",
			b.Envelope.EnvelopeID)
	}
}

// ── the wiring, not just the function ────────────────────────────────

func TestAFailedBindingFailsTheWholeVerdict(t *testing.T) {
	// A check whose result never reaches AllPassed is decorative. This
	// is the same defect class as a report filing its best finding under
	// "what this report does not show".
	b := goldenBundle(t)
	b.RekorAnchor.LeafHashHex =
		"0000000000000000000000000000000000000000000000000000000000000000"

	r := verify(b)
	if r.AllPassed {
		t.Fatal("the bundle names a foreign anchor and the overall verdict " +
			"still passed; the binding result is not wired into the roll-up")
	}
}
