package main

// Round eight of the external review, kept as permanent tests. Go's
// encoding/json matches keys case-insensitively and lets the last
// match win; jq, Python and JavaScript do not. A bundle carrying a
// forged value under the exact key and the original under a case
// variant verified under v0.12.0 while every other reader saw the
// forgery. v0.12.1 decodes strictly: fold-equal keys and keys this
// verifier does not model are refused before any hash is computed.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

func mustRefuse(t *testing.T, what string, data []byte) {
	t.Helper()
	if _, err := artifacts.DecodeBundleStrict(data); !errors.Is(err, artifacts.ErrNotStrictJSON) {
		t.Fatalf("%s must be refused by strict decoding, got %v", what, err)
	}
}

// The reviewer's file: the real run 239 record with five case-variant
// edits, which v0.12.0 verified as COMPLETE RECORD ANCHORED.
func TestR8ReviewerCaseVariantRecordIsRefused(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round9", "run-239-case-variant-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "the reviewer's case-variant run 239", raw)

	// What the old decoder did with it: the record still verified.
	var b artifacts.AuditBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if r := verify(&b); !completeRecordAnchored(r) {
		t.Skip("the permissive decode no longer verifies; the strict refusal above is what matters")
	}
}

func TestR8EveryAmbiguousOrUnmodeledKeyIsRefused(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round8", "run-239-intact.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.DecodeBundleStrict(raw); err != nil {
		t.Fatalf("the genuine record must decode strictly: %v", err)
	}
	old := []byte(`"result":"approve"`)
	if bytes.Count(raw, old) != 1 {
		t.Fatalf("fixture shape changed: %d decision results", bytes.Count(raw, old))
	}
	for name, repl := range map[string]string{
		"upper-case copy after":  `"result":"deny","RESULT":"approve"`,
		"title-case copy before": `"Result":"approve","result":"deny"`,
		"Unicode long s fold":    `"result":"deny","re` + "ſ" + `ult":"approve"`,
		"exact duplicate":        `"result":"deny","result":"approve"`,
		"case variant alone":     `"Result":"approve"`,
		"unmodeled extra key":    `"result":"approve","zz_shown_elsewhere":"deny"`,
	} {
		mustRefuse(t, name, bytes.Replace(raw, old, []byte(repl), 1))
	}
	// Inside an array element (an approver) and at the top level.
	actor := []byte(`"actor_id":"robert@verdifax.com","actor_role"`)
	if bytes.Contains(raw, actor) {
		mustRefuse(t, "case variant in an approver",
			bytes.Replace(raw, actor, []byte(`"actor_id":"cro@examplebank.com","ACTOR_ID":"robert@verdifax.com","actor_role"`), 1))
	}
	mustRefuse(t, "top-level case variant", bytes.Replace(raw, []byte(`"status":"ok"`), []byte(`"status":"ok","STATUS":"ok"`), 1))
	mustRefuse(t, "trailing data", append(append([]byte(nil), raw...), []byte(`{"kind":"x"}`)...))
}

// Every committed bundle, genuine or forged in other ways, uses only
// exact, modeled keys: strict decoding refuses no real record.
func TestR8EveryCommittedBundleDecodesStrictly(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "round*", "*.json"))
	more, _ := filepath.Glob(filepath.Join("internal", "artifacts", "testdata", "*bundle*.json"))
	files = append(files, more...)
	checked := 0
	for _, f := range files {
		if strings.Contains(f, "case-variant") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte(`"manifest_hash"`)) {
			continue
		}
		if _, err := artifacts.DecodeBundleStrict(raw); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		checked++
	}
	if checked < 10 {
		t.Fatalf("only %d bundles checked", checked)
	}
}

// The same attack on a v7 record (run 240's format), as the reviewer
// built it with resealAsV7.
func TestR8CaseVariantOnV7IsRefused(t *testing.T) {
	l := fixedTestLog(t)
	l.install(t)
	raw, err := json.Marshal(resealAsV7(t, l, "600", 20*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.DecodeBundleStrict(raw); err != nil {
		t.Fatalf("the intact v7 record must decode strictly: %v", err)
	}
	mustRefuse(t, "v7 case variant", bytes.Replace(raw, []byte(`"result":"approve"`),
		[]byte(`"result":"deny","RESULT":"approve"`), 1))
}

// A copy stored before the 2026-10-16 repair keeps the shard position
// as its entry number. It still fails, but says so instead of
// implying an edit.
func TestR8StaleEntryNumberIsNamedNotCalledTampering(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("internal", "artifacts", "testdata", "run-235-v3-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := artifacts.DecodeBundleStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := verify(b)
	if r.AllPassed || !r.RekorAnchor.StaleEntryNumber ||
		!strings.Contains(r.RekorAnchor.Reason, "download the record again") {
		t.Fatalf("stale copy must fail and say why: %+v", r.RekorAnchor)
	}
	if out := captureHumanReport(t, b, r); !strings.Contains(out, "outdated entry number") {
		t.Fatalf("verdict must name the outdated entry number:\n%s", out)
	}
}

// The report shows the decision-bearing values it checked.
func TestR8ReportShowsTheCheckedValues(t *testing.T) {
	b := loadRound8(t, "run-239-intact.json")
	r := verify(b)
	v := r.RecordValues
	if v.Decision != b.AER.Decision.Result || v.AivpDecision != b.AivpT4.Decision ||
		len(v.Approvers) != len(b.AuthorizationChain.Approvers) {
		t.Fatalf("record values do not mirror the record: %+v", v)
	}
	out := captureHumanReport(t, b, r)
	if !strings.Contains(out, "Record says") || !strings.Contains(out, "decision:          "+v.Decision) {
		t.Fatalf("human report must print the checked values:\n%s", out)
	}
}
