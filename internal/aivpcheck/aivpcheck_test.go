package aivpcheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vectorFinding struct {
	NodeA    string `json:"node_a"`
	NodeB    string `json:"node_b"`
	Term     string `json:"term"`
	Opposite string `json:"opposite"`
}

// TestKeywordV1MatchesTheEngine runs the Go check on every trace in the
// vector file and requires the engine's own result, finding or none.
func TestKeywordV1MatchesTheEngine(t *testing.T) {
	raw, readErr := os.ReadFile(filepath.Join("testdata", "keyword-v1-vectors.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var file struct {
		Checker string `json:"checker"`
		Vectors []struct {
			Text    string         `json:"text"`
			Finding *vectorFinding `json:"finding"`
		} `json:"vectors"`
	}
	if decodeErr := json.Unmarshal(raw, &file); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if file.Checker != CheckerKeywordV1 || len(file.Vectors) < 900 {
		t.Fatalf("vector file is for %q with %d vectors", file.Checker, len(file.Vectors))
	}
	found := 0
	for i, v := range file.Vectors {
		got := KeywordV1(ParseTrace(v.Text))
		switch {
		case v.Finding == nil && got != nil:
			t.Errorf("vector %d: engine found nothing, Go found %+v in %q", i, *got, v.Text)
		case v.Finding != nil && got == nil:
			t.Errorf("vector %d: engine found %+v, Go found nothing in %q", i, *v.Finding, v.Text)
		case v.Finding != nil:
			found++
			if (vectorFinding{got.NodeA, got.NodeB, got.Term, got.Opposite}) != *v.Finding {
				t.Errorf("vector %d: engine found %+v, Go found %+v", i, *v.Finding, *got)
			}
		}
	}
	if found == 0 {
		t.Fatal("no vector carries a finding, so the comparison proves nothing")
	}
}
