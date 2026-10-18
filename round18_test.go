package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Run 249 is a production record sealed under leaf v7. Its pre-anchor
// table carries the actor section's four values, so the actor section is
// sealed to the anchor, and the report says so.
func TestR18ActorSectionIsSealedThroughThePreAnchorTable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "round18", "run-249-production.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := artifacts.DecodeBundleStrict(raw)
	if err != nil {
		t.Fatalf("run 249 must decode strictly: %v", err)
	}
	r := verify(b)
	if r.LeafBinding.Form != leafDomainV7 || !r.LeafBinding.Match {
		t.Fatalf("run 249 must bind a v7 leaf: %+v", r.LeafBinding)
	}
	if !r.PreAnchor.Match {
		t.Fatalf("run 249's pre-anchor table must be consistent: %+v", r.PreAnchor)
	}
	if !r.NrepSignature.Match || !r.NrepSignature.Sealed {
		t.Fatalf("run 249's actor section must report sealed: %+v", r.NrepSignature)
	}
}

// The upgrade needs every condition: a verified signature, this run's
// leaf in a version that binds the table, and a consistent table.
func TestR18SealedByPreAnchorNeedsEveryCondition(t *testing.T) {
	ok := NrepCheck{Performed: true, Match: true, ActorID: "a"}
	leaf := LeafBindingCheck{Performed: true, Match: true, Form: leafDomainV7}
	pre := PreAnchorCheck{Performed: true, Match: true}
	if !sealedByPreAnchor(ok, leaf, pre).Sealed {
		t.Fatal("all conditions met: want sealed")
	}
	for name, tc := range map[string]struct {
		c    NrepCheck
		leaf LeafBindingCheck
		pre  PreAnchorCheck
	}{
		"bad signature":      {NrepCheck{Performed: true, Match: false}, leaf, pre},
		"leaf mismatch":      {ok, LeafBindingCheck{Performed: true, Match: false, Form: leafDomainV7}, pre},
		"leaf v2":            {ok, LeafBindingCheck{Performed: true, Match: true, Form: leafDomainV2}, pre},
		"table inconsistent": {ok, leaf, PreAnchorCheck{Performed: true, Match: false}},
		"no table":           {ok, leaf, PreAnchorCheck{}},
	} {
		if sealedByPreAnchor(tc.c, tc.leaf, tc.pre).Sealed {
			t.Errorf("%s: must not report sealed", name)
		}
	}
}
