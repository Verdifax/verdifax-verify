package main

// Round-six regression suite: the complete-record anchor.
//
// Fixtures in testdata/round6:
//
//	run-237-intact.json  the live run 237 bundle exactly as served
//	                     (sha256 f13f5a6e...a9246d), a v5 record
//	                     sealed before bundle_anchor shipped.
//	V1..V6_*.json        the external reviewer's six round-six
//	                     forgeries of run 237: descriptive sections
//	                     rewritten, section hashes and bundle_hash
//	                     recomputed. v0.9.0 printed VERIFIED AND
//	                     ANCHORED, FULL PRE-ANCHOR COVERAGE for all six.
//	L1_*.json            an anchored pre-anchor value rewritten
//	                     (aivp_adapter_id, table and section), the
//	                     table digest and v5 leaf recomputed, and the
//	                     new leaf written into rekor_anchor.leaf_hash
//	                     beside the GENUINE entry_body, proof and
//	                     checkpoint. v0.9.0 passed it, because nothing
//	                     compared leaf_hash to the logged body.
//
// The forgeries carry no bundle_anchor, so on their own they can only
// earn the honest partial verdict. The tests below then give run 237
// a genuine bundle_anchor on a test transparency log and replay every
// rewrite against it: each one must FAIL.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/rekorverify"
)

var round6Forgeries = []string{
	"V1_aer_decision_flipped_to_deny.json",
	"V2_request_substance_rewritten.json",
	"V3_authorization_chain_rewritten.json",
	"V4_causal_graph_effect_added.json",
	"V5_system_provenance_upgraded.json",
	"V6_story_rewrite_all.json",
}

func loadRound6(t *testing.T, name string) *artifacts.AuditBundle {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "round6", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var b artifacts.AuditBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return &b
}

// testLog is a minimal transparency log with its own P-256 key: it
// issues hashedrekord bodies, RFC 6962 inclusion proofs and c2sp
// signed checkpoints exactly in Rekor's formats, so the verifier's
// complete offline path runs against it.
type testLog struct {
	key   *ecdsa.PrivateKey
	logID string
	// signer is the key the test producer logs entries with, standing
	// in for the Verdifax log-signing key; install pins it.
	signer *ecdsa.PrivateKey
	// integratedTime is the time the log records for new entries
	// (0 means a fixed default).
	integratedTime int64
}

// testSigner derives a deterministic entry-signing key, so fixtures
// stay verifiable across runs. TEST USE ONLY: the scalar is public.
func testSigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("verdifax-verify test entry signer, test use only"))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seed[:])
	if err != nil {
		t.Fatalf("derive test signer: %v", err)
	}
	return k
}

// signerFingerprint is the hex SHA-256 of a key's DER SPKI, the form
// pinnedEntrySigners is keyed by.
func signerFingerprint(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal signer: %v", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func newTestLog(t *testing.T) *testLog {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate log key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal log key: %v", err)
	}
	sum := sha256.Sum256(der)
	return &testLog{key: k, logID: hex.EncodeToString(sum[:]), signer: testSigner(t)}
}

// install routes anchors naming this log's id to its key and every
// other anchor (run 237's real first entry) to the embedded Rekor key.
func (l *testLog) install(t *testing.T) {
	t.Helper()
	prev := rekorAnchorVerifier
	rekorAnchorVerifier = func(in rekorverify.AnchorInput) error {
		if strings.EqualFold(in.LogID, l.logID) {
			return rekorverify.VerifyAnchorWithKey(in, &l.key.PublicKey)
		}
		return rekorverify.VerifyAnchor(in)
	}
	// Pin the test producer's key beside the published Verdifax keys,
	// exactly as a published key is pinned.
	prevSigners := pinnedEntrySigners
	pinned := make(map[string]pinnedSigner, len(prevSigners)+1)
	for fp, k := range prevSigners {
		pinned[fp] = k
	}
	pinned[signerFingerprint(t, l.signer)] = pinnedSigner{Name: "test entry signer"}
	pinnedEntrySigners = pinned
	t.Cleanup(func() {
		rekorAnchorVerifier = prev
		pinnedEntrySigners = prevSigners
	})
}

// signedHashedRekordBody is a hashedrekord body for leafHex whose
// signature and public key belong to signer, as a real producer's do.
func signedHashedRekordBody(t *testing.T, leafHex string, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&signer.PublicKey)
	if err != nil {
		t.Fatalf("marshal signer: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	digest, err := hex.DecodeString(leafHex)
	if err != nil {
		t.Fatalf("leaf hex: %v", err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest)
	if err != nil {
		t.Fatalf("sign entry: %v", err)
	}
	return []byte(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{"hash":` +
		`{"algorithm":"sha256","value":"` + leafHex + `"}},"signature":{"content":"` +
		base64.StdEncoding.EncodeToString(sig) + `","publicKey":{"content":"` +
		base64.StdEncoding.EncodeToString(pubPEM) + `"}}}}`)
}

// signedEntryTimestamp is what a log returns as the SET: its signature
// over the canonical (body, integratedTime, logID, global index).
func (l *testLog) signedEntryTimestamp(t *testing.T, bodyB64 string, integratedTime int64, globalIndex string) string {
	t.Helper()
	payload := fmt.Sprintf(`{"body":%q,"integratedTime":%d,"logID":%q,"logIndex":%s}`,
		bodyB64, integratedTime, l.logID, globalIndex)
	sum := sha256.Sum256([]byte(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, sum[:])
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func hashedRekordBody(leafHex string) []byte {
	return []byte(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{"hash":` +
		`{"algorithm":"sha256","value":"` + leafHex + `"}},"signature":{"content":"dGVzdA==",` +
		`"publicKey":{"content":"dGVzdA=="}}}}`)
}

func rfc6962Leaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

func rfc6962Node(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func merkleRoot(hs [][]byte) []byte {
	if len(hs) == 1 {
		return hs[0]
	}
	k := 1
	for k*2 < len(hs) {
		k *= 2
	}
	return rfc6962Node(merkleRoot(hs[:k]), merkleRoot(hs[k:]))
}

func merklePath(hs [][]byte, i int) [][]byte {
	if len(hs) <= 1 {
		return nil
	}
	k := 1
	for k*2 < len(hs) {
		k *= 2
	}
	if i < k {
		return append(merklePath(hs[:k], i), merkleRoot(hs[k:]))
	}
	return append(merklePath(hs[k:], i-k), merkleRoot(hs[:k]))
}

// entry logs a hashedrekord for leafHex at position 5 of a 7-leaf tree
// and returns a bundle_anchor carrying the proof and checkpoint.
func (l *testLog) entry(t *testing.T, digest, leafHex string) *artifacts.BundleAnchor {
	t.Helper()
	body := signedHashedRekordBody(t, leafHex, l.signer)
	const index, size = 5, 7
	leaves := make([][]byte, size)
	for i := range leaves {
		leaves[i] = rfc6962Leaf([]byte(fmt.Sprintf("other entry %d", i)))
	}
	leaves[index] = rfc6962Leaf(body)
	root := merkleRoot(leaves)
	var path []string
	for _, p := range merklePath(leaves, index) {
		path = append(path, hex.EncodeToString(p))
	}

	note := fmt.Sprintf("test-log - 1\n%d\n%s\n", size, base64.StdEncoding.EncodeToString(root))
	sum := sha256.Sum256([]byte(note))
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, sum[:])
	if err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&l.key.PublicKey)
	hint := sha256.Sum256(der)
	blob := append(append([]byte(nil), hint[:4]...), sig...)
	// The c2sp signed-note line prefix is U+2014 then a space; built
	// from its code point so this source file carries no literal dash.
	checkpoint := note + "\n" + string(rune(0x2014)) + " test-log " + base64.StdEncoding.EncodeToString(blob) + "\n"

	const globalIndex = "123456789005" // deliberately not the shard position
	bodyB64 := base64.StdEncoding.EncodeToString(body)
	integrated := l.integratedTime
	if integrated == 0 {
		integrated = 1792159600
	}
	return &artifacts.BundleAnchor{
		Kind:                 artifacts.BundleAnchorKind,
		DigestForm:           artifacts.BundleAnchorDigestForm,
		AnchoredDigest:       digest,
		Backend:              "rekor",
		LogEntryID:           globalIndex,
		LogID:                l.logID,
		LeafHashHex:          leafHex,
		LogIndex:             index,
		TreeSize:             size,
		RootHashHex:          hex.EncodeToString(root),
		InclusionPath:        path,
		Checkpoint:           checkpoint,
		SignedEntryTimestamp: l.signedEntryTimestamp(t, bodyB64, integrated, globalIndex),
		IntegratedTime:       integrated,
		EntryBody:            bodyB64,
	}
}

// anchorRecord gives b a genuine complete-record anchor on log l.
func anchorRecord(t *testing.T, l *testLog, b *artifacts.AuditBundle) {
	t.Helper()
	digest := artifacts.ComputeAnchoredRecordDigest(b)
	if err := artifacts.ValidateBundleLeafFields(b.Envelope.EnvelopeID, digest); err != nil {
		t.Fatalf("leaf fields: %v", err)
	}
	b.BundleAnchor = l.entry(t, digest, artifacts.ComputeBundleLeafHash(b.Envelope.EnvelopeID, digest))
}

func TestRound6IntactRun237WithoutBundleAnchorIsHonestlyPartial(t *testing.T) {
	r := verify(loadRound6(t, "run-237-intact.json"))
	if !r.AllPassed || !r.Anchored || r.VerdictTier != "VERIFIED_ANCHORED" {
		t.Fatalf("intact run 237 must still verify and be anchored: tier=%s %+v", r.VerdictTier, r.RekorAnchor)
	}
	if r.BundleAnchor.Present || completeRecordAnchored(r) {
		t.Fatal("a record without bundle_anchor must never read as complete")
	}
	if r.RecordCoverage != "partial_descriptive_sections_bundle_sealed" {
		t.Fatalf("coverage = %q", r.RecordCoverage)
	}
}

func TestRound6ForgeriesWithoutBundleAnchorGetPartialNotFull(t *testing.T) {
	for _, name := range round6Forgeries {
		t.Run(name, func(t *testing.T) {
			b := loadRound6(t, name)
			if b.BundleAnchor != nil {
				t.Fatal("reviewer fixture unexpectedly carries a bundle_anchor")
			}
			r := verify(b)
			if r.RecordCoverage == "complete_record_anchored" {
				t.Fatal("a rewritten record without bundle_anchor must not read as complete")
			}
			out := captureHumanReport(t, b, r)
			if strings.Contains(out, "FULL") || strings.Contains(out, "COMPLETE RECORD") {
				t.Fatalf("verdict overstates coverage:\n%s", out)
			}
			if !strings.Contains(out, "bundle-sealed, NOT") {
				t.Fatalf("verdict must say the descriptive sections are bundle-sealed, not anchored:\n%s", out)
			}
		})
	}
}

func TestRound6LeafSwapWithGenuineEntryBodyFails(t *testing.T) {
	r := verify(loadRound6(t, "L1_leaf_hash_swapped_genuine_entry_body.json"))
	if r.AllPassed || r.Anchored || r.VerdictTier != "FAILED" {
		t.Fatalf("a leaf_hash the logged body does not name must FAIL: tier=%s anchor=%+v",
			r.VerdictTier, r.RekorAnchor)
	}
	if !strings.Contains(r.RekorAnchor.Reason, "entry_body records leaf") {
		t.Fatalf("failure must name the body/leaf disagreement: %q", r.RekorAnchor.Reason)
	}
}

func TestRekorAnchorWithoutEntryBodyIsNotAnchored(t *testing.T) {
	b := loadRound6(t, "run-237-intact.json")
	b.RekorAnchor.EntryBody = ""
	r := verify(b)
	if r.Anchored || r.RekorAnchor.Performed || !r.RekorAnchor.Unverifiable {
		t.Fatalf("an anchor with no body binding its leaf must not count: %+v", r.RekorAnchor)
	}
	if r.VerdictTier == "VERIFIED_ANCHORED" || !exitShouldFail(r, false, false) {
		t.Fatalf("tier %s must not be anchored and must fail the default exit", r.VerdictTier)
	}
}

func TestRound6IntactRecordWithBundleAnchorIsComplete(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	b := loadRound6(t, "run-237-intact.json")
	// Both entries on the test log under one signer, as a producer
	// makes them. (Run 237's real first entry is signed by Verdifax
	// key 1, which the test producer cannot sign the second entry with;
	// that mixed record must fail, see the next test.)
	anchorRun(t, l, b)
	anchorRecord(t, l, b)

	r := verify(b)
	if !r.BundleAnchor.Performed || !r.BundleAnchor.Match {
		t.Fatalf("genuine bundle anchor must verify: %+v", r.BundleAnchor)
	}
	if !completeRecordAnchored(r) || r.RecordCoverage != "complete_record_anchored" {
		t.Fatalf("intact anchored record must be complete: coverage=%s tier=%s", r.RecordCoverage, r.VerdictTier)
	}
	if exitShouldFail(r, false, false) {
		t.Fatal("intact complete record must exit 0")
	}
	out := captureHumanReport(t, b, r)
	if !strings.Contains(out, "VERIFIED AND ANCHORED, COMPLETE RECORD ANCHORED") {
		t.Fatalf("missing complete-record verdict:\n%s", out)
	}

	// The anchor survives a JSON round trip through the typed struct.
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var back artifacts.AuditBundle
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if r2 := verify(&back); !completeRecordAnchored(r2) {
		t.Fatalf("round-tripped bundle must stay complete: %+v", r2.BundleAnchor)
	}
}

// Each forgery is replayed carrying the genuine anchor of the intact
// record: the attacker can rewrite content but cannot re-log the
// second entry.
// TestRecordEntryFromAnotherSignerFails is round seven's attack in its
// simplest form: the run's real first entry, signed by Verdifax key 1,
// next to a record entry logged by a different key. Before v0.12.0 it
// verified as COMPLETE RECORD ANCHORED.
func TestRecordEntryFromAnotherSignerFails(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	b := loadRound6(t, "run-237-intact.json")
	anchorRecord(t, l, b)

	r := verify(b)
	if !r.BundleAnchor.Match {
		t.Fatalf("the second entry itself is a valid log entry: %+v", r.BundleAnchor)
	}
	if r.EntryAuth.Match || !strings.Contains(r.EntryAuth.Reason, "not by") {
		t.Fatalf("entries with different signers must fail: %+v", r.EntryAuth)
	}
	if r.AllPassed || !exitShouldFail(r, false, true) {
		t.Fatalf("mixed-signer record must FAIL, even with --allow-unanchored: tier=%s", r.VerdictTier)
	}
}

func TestRound6EveryRewriteFailsOnceBundleAnchorIsPresent(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	intact := loadRound6(t, "run-237-intact.json")
	anchorRecord(t, l, intact)
	genuine := *intact.BundleAnchor

	for _, name := range round6Forgeries {
		t.Run(name, func(t *testing.T) {
			// Variant A: rewritten content, genuine anchor kept.
			b := loadRound6(t, name)
			a := genuine
			b.BundleAnchor = &a
			r := verify(b)
			if r.AllPassed || r.VerdictTier != "FAILED" || r.BundleAnchor.Match {
				t.Fatalf("rewrite with genuine anchor must FAIL: tier=%s anchor=%+v", r.VerdictTier, r.BundleAnchor)
			}
			if !exitShouldFail(r, false, true) {
				t.Fatal("must exit 1 even with --allow-unanchored")
			}

			// Variant B: the attacker also rewrites the anchored
			// digest and leaf to match, keeping the logged body,
			// proof and checkpoint. The body names the old leaf.
			b2 := loadRound6(t, name)
			a2 := genuine
			a2.AnchoredDigest = artifacts.ComputeAnchoredRecordDigest(b2)
			a2.LeafHashHex = artifacts.ComputeBundleLeafHash(b2.Envelope.EnvelopeID, a2.AnchoredDigest)
			b2.BundleAnchor = &a2
			r2 := verify(b2)
			if r2.AllPassed || r2.BundleAnchor.Match {
				t.Fatalf("rewrite with recomputed digest and leaf must FAIL: %+v", r2.BundleAnchor)
			}
			if !strings.Contains(r2.BundleAnchor.Reason, "entry_body records leaf") {
				t.Fatalf("variant B must fail on the body binding: %q", r2.BundleAnchor.Reason)
			}
		})
	}
}

func TestBundleAnchorRejectsTamperedProofAndForeignLog(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	base := loadRound6(t, "run-237-intact.json")
	anchorRecord(t, l, base)

	cases := map[string]func(a *artifacts.BundleAnchor){
		"sibling":     func(a *artifacts.BundleAnchor) { a.InclusionPath[0] = strings.Repeat("0", 64) },
		"root":        func(a *artifacts.BundleAnchor) { a.RootHashHex = strings.Repeat("1", 64) },
		"index":       func(a *artifacts.BundleAnchor) { a.LogIndex = 4 },
		"no body":     func(a *artifacts.BundleAnchor) { a.EntryBody = "" },
		"kind":        func(a *artifacts.BundleAnchor) { a.Kind = "verdifax.bundle_anchor.v0" },
		"form":        func(a *artifacts.BundleAnchor) { a.DigestForm = "verdifax.bundle.anchor.v0" },
		"foreign log": func(a *artifacts.BundleAnchor) { a.LogID = strings.Repeat("ab", 32) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := loadRound6(t, "run-237-intact.json")
			a := *base.BundleAnchor
			a.InclusionPath = append([]string(nil), base.BundleAnchor.InclusionPath...)
			mutate(&a)
			b.BundleAnchor = &a
			if r := verify(b); r.AllPassed || r.BundleAnchor.Match {
				t.Fatalf("%s: tampered bundle anchor must FAIL: %+v", name, r.BundleAnchor)
			}
		})
	}
}

// Every field the recipe claims to cover must move the digest. One
// edit per covered region, each outside the per-section hashes or
// outside bundle_hash, which is exactly where round six struck.
func TestAnchoredRecordDigestCoversEveryRegion(t *testing.T) {
	base := artifacts.ComputeAnchoredRecordDigest(loadRound6(t, "run-237-intact.json"))
	edits := map[string]func(b *artifacts.AuditBundle){
		"aer.decision": func(b *artifacts.AuditBundle) {
			b.AER.Decision.Result = "deny"
			b.AER.Hash = artifacts.RecomputeAERHash(b.AER)
		},
		"request_substance":       func(b *artifacts.AuditBundle) { b.RequestSubstance.Hash = strings.Repeat("e", 64) },
		"reproducibility_context": func(b *artifacts.AuditBundle) { b.ReproducibilityContext.Hash = strings.Repeat("e", 64) },
		"aivp_t4.decision":        func(b *artifacts.AuditBundle) { b.AivpT4.Decision = "halt" },
		"nrep.actor_id":           func(b *artifacts.AuditBundle) { b.Nrep.ActorID = "someone-else" },
		"pre_anchor value":        func(b *artifacts.AuditBundle) { b.PreAnchor[0].Value = "forged" },
		"formal_verification":     func(b *artifacts.AuditBundle) { b.FormalVerification.Scope = "forged" },
		"execution_record":        func(b *artifacts.AuditBundle) { b.ExecutionRecord.Formula = "forged" },
		"runtime_timing":          func(b *artifacts.AuditBundle) { b.RuntimeTiming[0].DurationNanos++ },
		"hardware evidence":       func(b *artifacts.AuditBundle) { b.HardwareAttestation.ReportDataRecipe = "forged" },
		"pote ledger_backend":     func(b *artifacts.AuditBundle) { b.PoteProof.LedgerBackend = "mock" },
		"scaffold note":           func(b *artifacts.AuditBundle) { b.Transcript.Scaffold.Note = "forged" },
		"seal field":              func(b *artifacts.AuditBundle) { b.CausalGraph.Seal.SealField = "forged" },
		"payload content_inline":  func(b *artifacts.AuditBundle) { b.Payload.ContentInline = "Zm9yZ2Vk" },
		"envelope kind":           func(b *artifacts.AuditBundle) { b.Envelope.Kind = "forged" },
		"run_id":                  func(b *artifacts.AuditBundle) { b.RunID++ },
		"generated_at":            func(b *artifacts.AuditBundle) { b.GeneratedAt = "2000-01-01T00:00:00Z" },
		"attested_digest":         func(b *artifacts.AuditBundle) { b.AttestedDigest = "forged" },
	}
	for name, edit := range edits {
		b := loadRound6(t, "run-237-intact.json")
		edit(b)
		if artifacts.ComputeAnchoredRecordDigest(b) == base {
			t.Errorf("%s: edit did not change the anchored record digest", name)
		}
	}

	// And the two proofs are excluded: the server's read-time anchor
	// corrections must not invalidate the record anchor.
	b := loadRound6(t, "run-237-intact.json")
	b.RekorAnchor.LogEntryID = "1"
	b.RekorAnchor.EntryBody = ""
	b.BundleAnchor = &artifacts.BundleAnchor{AnchoredDigest: "x"}
	if artifacts.ComputeAnchoredRecordDigest(b) != base {
		t.Error("rekor_anchor and bundle_anchor must not feed the anchored record digest")
	}
}

func captureHumanReport(t *testing.T, b *artifacts.AuditBundle, r *Report) string {
	t.Helper()
	old := os.Stdout
	rd, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	printHumanReport(b, r)
	w.Close()
	os.Stdout = old
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := rd.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
