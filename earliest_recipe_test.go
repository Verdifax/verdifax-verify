package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// earliestRecord turns the mock fixture into the shape of a record sealed
// before category 6 existed (runs 132 to 157): no reproducibility_context
// key, generated before ReproducibilityContextAdded, and a bundle hash by
// the recipe of that time.
func earliestRecord(t *testing.T, generated time.Time, dropKey bool) *artifacts.AuditBundle {
	t.Helper()
	raw, readErr := os.ReadFile(filepath.Join("testdata", "policy-gate", "orchestrator-mock-allowed-run.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if decErr := dec.Decode(&doc); decErr != nil {
		t.Fatal(decErr)
	}
	if dropKey {
		delete(doc, "reproducibility_context")
	}
	// The fixture is an October record; its complete-record anchor would
	// hold the current recipe's bundle hash, which no May record has.
	delete(doc, "bundle_anchor")
	clock := generated.UTC().Format(time.RFC3339Nano)
	doc["generated_at"] = clock
	doc["envelope"].(map[string]any)["timestamp"] = clock
	if epa, ok := doc["epa"].(map[string]any); ok {
		if snap, ok := epa["environment_snapshot"].(map[string]any); ok {
			snap["time"] = clock
		}
	}
	out, marshalErr := json.Marshal(doc)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	b, strictErr := artifacts.DecodeBundleStrict(out)
	if strictErr != nil {
		t.Fatal(strictErr)
	}
	b.Envelope.Hash = artifacts.RecomputeEnvelopeHash(b.Envelope)
	b.EPA.Hash = artifacts.RecomputeEPAHash(b.EPA)
	b.BundleHash = artifacts.RecomputeBundleHashWithoutReproducibilityContext(b)
	return b
}

func hasCategory(r *Report, name string) bool {
	for _, c := range r.Categories {
		if c.Name == name {
			return true
		}
	}
	return false
}

// v0.30.0: a record sealed before 2026-05-11T02:02:16Z carries no
// reproducibility section and an earlier bundle hash recipe; its bundle
// hash and every section hash verify, and the report names the recipe.
// The fixture is an October record reshaped, so checks that belong to
// October's sections are not judged here; the verdict map judges the
// stored May records themselves.
func TestARecordSealedBeforeTheReproducibilitySectionVerifies(t *testing.T) {
	b := earliestRecord(t, time.Date(2026, 5, 10, 21, 27, 18, 0, time.UTC), true)
	if !b.ReproducibilityContextAbsent {
		t.Fatal("the strict reader must mark the section absent")
	}
	r := verify(b)
	if !r.BundleHashOK || r.BundleHashRecipe == "" || hasCategory(r, "reproducibility_context") {
		t.Fatalf("bundle=%+v recipe=%q categories=%v", r.BundleHash, r.BundleHashRecipe, r.Categories)
	}
	for _, c := range append(append([]HashCheck{}, r.Artifacts...), r.Categories...) {
		if !c.Match {
			t.Errorf("%s does not match: %+v", c.Name, c)
		}
	}
	// The same record read with the current recipe fails, which is how
	// every release before v0.30.0 read it.
	if artifacts.RecomputeBundleHash(b) == b.BundleHash {
		t.Fatal("the two recipes must differ")
	}
}

// The earlier recipe is never a way to drop a later record's section.
func TestTheEarlierRecipeAppliesOnlyToARecordFromBeforeTheSection(t *testing.T) {
	cases := map[string]*artifacts.AuditBundle{
		// generated at or after the cutover
		"a later record with its section removed": earliestRecord(t, artifacts.ReproducibilityContextAdded, false),
		// the section is present, even empty
		"a section present but empty": func() *artifacts.AuditBundle {
			b := earliestRecord(t, time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC), false)
			b.ReproducibilityContext = artifacts.ReproducibilityContext{}
			b.BundleHash = artifacts.RecomputeBundleHashWithoutReproducibilityContext(b)
			return b
		}(),
	}
	later := earliestRecord(t, artifacts.ReproducibilityContextAdded.Add(time.Hour), true)
	cases["a later generated_at"] = later
	logged := earliestRecord(t, time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC), true)
	logged.RekorAnchor.Backend = "rekor"
	logged.RekorAnchor.IntegratedTime = artifacts.ReproducibilityContextAdded.Add(time.Minute).Unix()
	cases["a log entry integrated after the section existed"] = logged
	unlogged := earliestRecord(t, time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC), true)
	unlogged.RekorAnchor.Backend = "rekor"
	unlogged.RekorAnchor.IntegratedTime = 0
	cases["a log anchor with no integrated time"] = unlogged
	for name, b := range cases {
		if sealedBeforeReproducibilityContext(b) {
			t.Errorf("%s: the earlier recipe must not apply", name)
		}
		if r := verify(b); r.BundleHash.Match && r.BundleHashRecipe != "" {
			t.Errorf("%s: verified with the earlier recipe", name)
		}
	}
	if b := earliestRecord(t, artifacts.ReproducibilityContextAdded.Add(-time.Second), true); !sealedBeforeReproducibilityContext(b) {
		t.Error("a record generated one second before the cutover, on no log, is from before the section")
	}
}

// The cutover is the commit that added the section, and it falls between
// the last record sealed without it (run 157) and the first with it (run
// 158), as the verdict map of every stored record shows.
func TestTheCutoverFallsBetweenRuns157And158(t *testing.T) {
	last := time.Date(2026, 5, 10, 21, 27, 18, 30798758, time.UTC)
	first := time.Date(2026, 5, 11, 2, 12, 9, 0, time.UTC)
	if !last.Before(artifacts.ReproducibilityContextAdded) || !artifacts.ReproducibilityContextAdded.Before(first) {
		t.Fatalf("cutover %s is not between run 157 and run 158", artifacts.ReproducibilityContextAdded)
	}
}
