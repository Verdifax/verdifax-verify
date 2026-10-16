package main

// Round seven of the external review, kept as permanent tests. The
// reviewer showed that verifier 0.11.0 never asked who logged a
// public-log entry or when: a rewritten record re-logged under any key
// verified as COMPLETE RECORD ANCHORED, and integrated_time,
// log_entry_id and signed_entry_timestamp could be edited freely.
// v0.12.0 pins the Verdifax log-signing keys, verifies every entry's
// signature and Rekor's signed entry timestamp, and enforces the
// anchoring window a table v3 (leaf v7) record seals.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

func loadRound8(t *testing.T, name string) *artifacts.AuditBundle {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "round8", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var b artifacts.AuditBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return &b
}

// otherSigner is a key that is not pinned: anyone's key.
func otherSigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// storyRewrite is the reviewer's rewrite of the descriptive sections,
// with every section hash and the bundle hash recomputed.
func storyRewrite(b *artifacts.AuditBundle) {
	b.AER.Decision.Result = "deny"
	yes := true
	b.RequestSubstance.Authentication.MFASatisfied = &yes
	b.RequestSubstance.Authentication.MFAMethod = "webauthn"
	if len(b.AuthorizationChain.Approvers) > 0 {
		b.AuthorizationChain.Approvers[0].ActorID = "chief-risk-officer@examplebank.com"
	}
	b.AuthorizationChain.HumanInLoop.Performed = true
	b.CausalGraph.EffectLog = append(b.CausalGraph.EffectLog, artifacts.EffectEntry{
		EffectKind: "payment_instruction", Target: "ledger:txn_250000_usd", Status: "confirmed"})
	b.SystemProvenance.BuildProvenance.SLSALevel = 3
	b.SystemProvenance.BuildProvenance.BuilderID = "github_actions"
	b.AER.Hash = artifacts.RecomputeAERHash(b.AER)
	b.RequestSubstance.Hash = artifacts.RecomputeRequestSubstanceHash(b.RequestSubstance)
	b.AuthorizationChain.Hash = artifacts.RecomputeAuthorizationChainHash(b.AuthorizationChain)
	b.CausalGraph.Hash = artifacts.RecomputeCausalGraphHash(b.CausalGraph)
	b.SystemProvenance.Hash = artifacts.RecomputeSystemProvenanceHash(b.SystemProvenance)
	b.BundleHash = artifacts.RecomputeBundleHash(b)
}

// v7Leaf rebuilds the v7 leaf from the record's own fields.
func v7Leaf(b *artifacts.AuditBundle) string {
	sum := sha256.Sum256([]byte(joinLeafParts(leafDomainV7, b.Envelope.EnvelopeID,
		b.AER.Seal.SealedHash, b.ZkspBinding.Seal.SealedHash,
		strconv.FormatInt(int64(b.RekorAnchor.InputNonce), 10),
		artifacts.ComputePreAnchorDigestV3FromTable(b.PreAnchor))))
	return hex.EncodeToString(sum[:])
}

func clockOf(t *testing.T, b *artifacts.AuditBundle) time.Time {
	t.Helper()
	v, ok := preAnchorValue(b.PreAnchor, "clock_epoch")
	if !ok {
		t.Fatal("record has no clock_epoch")
	}
	c, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		t.Fatalf("clock_epoch: %v", err)
	}
	return c
}

// resealAsV7 turns run 238 into the record a leaf v7 producer seals:
// requirement and window rows appended, the v3 digest stored, and both
// entries logged on l at loggedAfter past the run's clock.
func resealAsV7(t *testing.T, l *testLog, window string, loggedAfter time.Duration) *artifacts.AuditBundle {
	t.Helper()
	b := loadRound7(t, "run-238-intact.json")
	b.PreAnchor = append(b.PreAnchor,
		artifacts.PreAnchorEntry{Name: artifacts.CompleteRecordAnchorRow, Value: artifacts.CompleteRecordAnchorRequired},
		artifacts.PreAnchorEntry{Name: artifacts.AnchoringWindowRow, Value: window})
	b.PreAnchorDigest = artifacts.ComputePreAnchorDigestV3FromTable(b.PreAnchor)
	b.RekorAnchor.LeafHashHex = v7Leaf(b)
	l.integratedTime = clockOf(t, b).Add(loggedAfter).Unix()
	anchorRun(t, l, b)
	anchorRecord(t, l, b)
	return b
}

// relog logs both of b's entries again on l, as a forger would after
// rewriting it: the run leaf rebuilt for b's table form, then the record.
func relog(t *testing.T, l *testLog, b *artifacts.AuditBundle) {
	t.Helper()
	switch {
	case artifacts.TableSealsAnchoringWindow(b.PreAnchor):
		b.PreAnchorDigest = artifacts.ComputePreAnchorDigestV3FromTable(b.PreAnchor)
		b.RekorAnchor.LeafHashHex = v7Leaf(b)
	default:
		b.PreAnchorDigest = artifacts.ComputePreAnchorDigestV2FromTable(b.PreAnchor)
		b.RekorAnchor.LeafHashHex = v6Leaf(b)
	}
	anchorRun(t, l, b)
	anchorRecord(t, l, b)
}

func mustFail(t *testing.T, what string, r *Report) {
	t.Helper()
	if r.AllPassed || completeRecordAnchored(r) || !exitShouldFail(r, false, true) {
		t.Fatalf("%s must FAIL, even with --allow-unanchored: coverage=%s tier=%s entry=%+v",
			what, r.RecordCoverage, r.VerdictTier, r.EntryAuth)
	}
}

func mustBeComplete(t *testing.T, what string, r *Report) {
	t.Helper()
	if !completeRecordAnchored(r) || exitShouldFail(r, false, false) {
		t.Fatalf("%s must be COMPLETE RECORD ANCHORED, exit 0: coverage=%s entry=%+v pre=%+v req=%+v",
			what, r.RecordCoverage, r.EntryAuth, r.PreAnchor, r.CompleteRecordRequirement)
	}
}

// The real run 239, as served by production: both entries signed by
// Verdifax key 1, real signed entry timestamps, 20 seconds after its
// clock. Its table predates the window, so the gap is reported, not
// enforced.
func TestRealRun239IsLoggedByVerdifaxKey1(t *testing.T) {
	r := verify(loadRound8(t, "run-239-intact.json"))
	mustBeComplete(t, "real run 239", r)
	e := r.EntryAuth
	if !e.Match || e.SignerFingerprint != verdifaxLogSigningKey1Fingerprint || e.WindowSealed {
		t.Fatalf("run 239 entry authentication: %+v", e)
	}
	if e.GapSeconds == nil || *e.GapSeconds < 0 || *e.GapSeconds > 60 {
		t.Fatalf("run 239 gap must be its real ~20s: %+v", e)
	}
}

// The October 2026 hardware evidence run, logged by key 2 inside its
// one-hour acceptance period, with its global entry number repaired
// from the public log.
func TestRealHardwareRunIsLoggedByVerdifaxKey2(t *testing.T) {
	r := verify(loadRound8(t, "hardware-run-2026-10.json"))
	if !r.AllPassed || !r.Anchored || !r.EntryAuth.Match ||
		r.EntryAuth.SignerFingerprint != verdifaxLogSigningKey2Fingerprint {
		t.Fatalf("hardware run: tier=%s entry=%+v anchor=%+v", r.VerdictTier, r.EntryAuth, r.RekorAnchor)
	}
}

// Reviewer R7-2: rewrite the story, keep the real first entry, and log
// a new record entry under an unrelated key.
func TestR7RewriteWithRecordEntryFromAnyKeyFails(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := resealAsV6(t, l)
	mustBeComplete(t, "intact v6 record", verify(b))

	storyRewrite(b)
	l.signer = otherSigner(t)
	anchorRecord(t, l, b)
	mustFail(t, "rewritten record re-logged by an unrelated key", verify(b))
}

// Reviewer R7-3: change the attested decision INSIDE the anchored
// table, rewrite the story, re-log BOTH entries under an unrelated key,
// and copy the original times back.
func TestR7TableRewriteBothEntriesRelogged(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := resealAsV6(t, l)
	t1, t2 := b.RekorAnchor.IntegratedTime, b.BundleAnchor.IntegratedTime

	b.EPA.AttestedContext.DecisionResult = "deny"
	b.EPA.Hash = artifacts.RecomputeEPAHash(b.EPA)
	b.AttestedDigest = artifacts.ComputeAttestedContextDigest(b.EPA.AttestedContext)
	for i := range b.PreAnchor {
		if b.PreAnchor[i].Name == "attested_digest" {
			b.PreAnchor[i].Value = b.AttestedDigest
		}
	}
	storyRewrite(b)
	l.signer = otherSigner(t)
	relog(t, l, b)
	b.RekorAnchor.IntegratedTime, b.BundleAnchor.IntegratedTime = t1, t2
	mustFail(t, "table rewrite re-logged by an unrelated key", verify(b))
}

// The same re-log by the PINNED key, so only the time can catch it:
// edited times break the signed entry timestamps.
func TestEditedAnchoringTimesBreakTheSignedTimestamp(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := resealAsV6(t, l)
	for name, edit := range map[string]func(*artifacts.AuditBundle){
		"run integrated_time":    func(x *artifacts.AuditBundle) { x.RekorAnchor.IntegratedTime-- },
		"record integrated_time": func(x *artifacts.AuditBundle) { x.BundleAnchor.IntegratedTime-- },
		"run log_entry_id":       func(x *artifacts.AuditBundle) { x.RekorAnchor.LogEntryID = "123456789004" },
		"record log_entry_id":    func(x *artifacts.AuditBundle) { x.BundleAnchor.LogEntryID = "1" },
		"run SET removed":        func(x *artifacts.AuditBundle) { x.RekorAnchor.SignedEntryTimestamp = "" },
		"record SET swapped": func(x *artifacts.AuditBundle) {
			x.BundleAnchor.SignedEntryTimestamp = x.RekorAnchor.SignedEntryTimestamp
		},
	} {
		c := cloneBundle(t, b)
		edit(c)
		mustFail(t, name, verify(c))
	}
}

func cloneBundle(t *testing.T, b *artifacts.AuditBundle) *artifacts.AuditBundle {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var c artifacts.AuditBundle
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &c
}

// The reviewer's sweep, repeated: with v0.11.0 six fields could be
// changed freely. Every leaf field of an intact record must now break
// the complete-record verdict.
func TestEveryFieldOfAnIntactRecordIsBound(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	raw, err := json.Marshal(resealAsV7(t, l, "600", 20*time.Second))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var paths []string
	leafPathsR8(root, "", &paths)
	sort.Strings(paths)
	var unbound []string
	for _, p := range paths {
		var doc any
		_ = json.Unmarshal(raw, &doc)
		if !mutateAtR8(doc, strings.Split(strings.TrimPrefix(p, "."), ".")) {
			continue
		}
		mraw, _ := json.Marshal(doc)
		var mb artifacts.AuditBundle
		if json.Unmarshal(mraw, &mb) != nil {
			continue
		}
		mr := verify(&mb)
		if completeRecordAnchored(mr) && !exitShouldFail(mr, false, false) {
			unbound = append(unbound, p)
		}
	}
	if len(paths) < 500 {
		t.Fatalf("sweep covered only %d fields", len(paths))
	}
	if len(unbound) > 0 {
		t.Fatalf("%d of %d fields can change without breaking the record: %v", len(unbound), len(paths), unbound)
	}
}

func leafPathsR8(v any, prefix string, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			leafPathsR8(c, prefix+"."+k, out)
		}
	case []any:
		for i, c := range x {
			leafPathsR8(c, fmt.Sprintf("%s[%d]", prefix, i), out)
		}
	default:
		*out = append(*out, prefix)
	}
}

func mutateAtR8(v any, path []string) bool {
	m, ok := v.(map[string]any)
	if !ok || len(path) == 0 {
		return false
	}
	head, idx := path[0], -1
	if i := strings.Index(head, "["); i >= 0 {
		fmt.Sscanf(head[i:], "[%d]", &idx)
		head = head[:i]
	}
	child := m[head]
	if idx >= 0 {
		arr, ok := child.([]any)
		if !ok {
			return false
		}
		if len(path) == 1 {
			arr[idx] = flipR8(arr[idx])
			return true
		}
		return mutateAtR8(arr[idx], path[1:])
	}
	if len(path) == 1 {
		m[head] = flipR8(child)
		return true
	}
	return mutateAtR8(child, path[1:])
}

func flipR8(v any) any {
	switch x := v.(type) {
	case string:
		if x == "" {
			return "x"
		}
		r := []byte(x)
		if r[len(r)-1] == '0' {
			r[len(r)-1] = '1'
		} else {
			r[len(r)-1] = '0'
		}
		return string(r)
	case float64:
		return x + 1
	case bool:
		return !x
	case nil:
		return "x"
	}
	return v
}

// A v7 record logged 20 seconds after its clock, inside its sealed
// 600-second window, is complete.
func TestV7RecordInsideItsWindowIsComplete(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	r := verify(resealAsV7(t, l, "600", 20*time.Second))
	mustBeComplete(t, "v7 record inside its window", r)
	if !r.EntryAuth.WindowSealed || r.EntryAuth.WindowSeconds != 600 || r.PreAnchor.Form != artifacts.PreAnchorFormV3 {
		t.Fatalf("v7 window must be sealed and reported: %+v %+v", r.EntryAuth, r.PreAnchor)
	}
}

// The key holder's attack on a v7 record: rewrite it a day later and
// re-log it with the PINNED key. Rekor records the later time, so the
// entries fall outside the sealed window.
func TestV7RelogByTheKeyHolderLaterFails(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := resealAsV7(t, l, "600", 20*time.Second)
	storyRewrite(b)
	l.integratedTime = clockOf(t, b).Add(24 * time.Hour).Unix()
	relog(t, l, b)
	r := verify(b)
	mustFail(t, "a re-log by the key holder a day later", r)
	if !strings.Contains(r.EntryAuth.Reason, "outside the sealed 600-second window") {
		t.Fatalf("failure must name the window: %+v", r.EntryAuth)
	}
}

// Moving the clock to match the re-log keeps the window, but changes
// the record's own sealed date: the record can no longer claim its
// original time. The test pins that this is what happens, so no one
// reads the window as more than it is.
func TestV7RelogWithMovedClockShowsTheNewDate(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := resealAsV7(t, l, "600", 20*time.Second)
	original := clockOf(t, b)
	later := original.Add(24 * time.Hour)
	for i := range b.PreAnchor {
		if b.PreAnchor[i].Name == "clock_epoch" {
			b.PreAnchor[i].Value = later.Format(time.RFC3339Nano)
		}
	}
	l.integratedTime = later.Add(20 * time.Second).Unix()
	relog(t, l, b)
	r := verify(b)
	if r.EntryAuth.ClockEpoch == original.Format(time.RFC3339Nano) {
		t.Fatal("a re-logged record cannot keep its original sealed clock")
	}
}

// A window row that cannot be read, or one too wide to mean anything,
// is a table this verifier does not know: a failure.
func TestV7BadWindowRowFails(t *testing.T) {
	for _, w := range []string{"", "ten", "-5", "0", "600.0", "86400"} {
		l := fixedTestLog(t)
		l.install(t)
		mustFail(t, "window "+strconv.Quote(w), verify(resealAsV7(t, l, w, 20*time.Second)))
	}
}

// Removing the window row from a v7 record changes the table form,
// the digest and the leaf: the first entry no longer matches.
func TestV7RemovingTheWindowRowBreaksTheRunEntry(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := resealAsV7(t, l, "600", 20*time.Second)
	b.PreAnchor = b.PreAnchor[:len(b.PreAnchor)-1]
	b.PreAnchorDigest = artifacts.ComputePreAnchorDigestV2FromTable(b.PreAnchor)
	mustFail(t, "a v7 record with its window row removed", verify(b))
}

// The record entry may never predate the run entry.
func TestRecordEntryBeforeRunEntryFails(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := resealAsV6(t, l)
	l.integratedTime = b.RekorAnchor.IntegratedTime - 1
	anchorRecord(t, l, b)
	r := verify(b)
	mustFail(t, "a record entry older than the run entry", r)
	if !strings.Contains(r.EntryAuth.Reason, "predates") {
		t.Fatalf("failure must say the record entry predates the run entry: %+v", r.EntryAuth)
	}
}

// A pinned key is accepted only within its period: key 2's single
// entry passes, the same key one day later would not.
func TestPinnedKeyOutsideItsPeriodFails(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	b := resealAsV6(t, l)
	fp := signerFingerprint(t, l.signer)
	k := pinnedEntrySigners[fp]
	k.NotAfter = b.RekorAnchor.IntegratedTime - 1
	pinnedEntrySigners[fp] = k
	mustFail(t, "an entry logged after its key's period", verify(b))
}

// Every real public record keeps verifying: run 239 by key 1 is above;
// the hardware run by key 2 is above. Records with no signed entry
// timestamp cannot reach the anchored tier.
func TestAnchorWithoutSignedTimestampIsNotAnchored(t *testing.T) {
	b := loadRound8(t, "run-239-intact.json")
	b.RekorAnchor.SignedEntryTimestamp = ""
	r := verify(b)
	if r.Anchored || !r.RekorAnchor.Performed || r.RekorAnchor.Match {
		t.Fatalf("an anchor without a SET must fail: %+v", r.RekorAnchor)
	}
}

// A record the orchestrator's leaf v7 producer sealed (mock ledger, so
// no public-log claim) cross-verifies: table v3, the v7 leaf this
// verifier rebuilds, and a stripped record anchor still fails.
func TestOrchestratorV7RecordCrossVerifies(t *testing.T) {
	b := loadRound8(t, "orchestrator-e2e-v7-mock.json")
	r := verify(b)
	if !r.AllPassed || r.PreAnchor.Form != artifacts.PreAnchorFormV3 || !r.PreAnchor.Match ||
		!r.CompleteRecordRequirement.Satisfied || r.VerdictTier != "SELF_CONSISTENT_NOT_ANCHORED" {
		t.Fatalf("intact producer record: tier=%s table=%+v req=%+v", r.VerdictTier, r.PreAnchor, r.CompleteRecordRequirement)
	}
	if got := v7Leaf(b); got != b.RekorAnchor.LeafHashHex {
		t.Fatalf("producer leaf %s, verifier v7 recipe %s", b.RekorAnchor.LeafHashHex, got)
	}
	if w, ok := preAnchorValue(b.PreAnchor, artifacts.AnchoringWindowRow); !ok || w != "600" {
		t.Fatalf("producer window row = %q", w)
	}
	b.BundleAnchor = nil
	if r = verify(b); r.AllPassed || !exitShouldFail(r, false, true) {
		t.Fatalf("stripped producer record must FAIL: tier=%s", r.VerdictTier)
	}
}
