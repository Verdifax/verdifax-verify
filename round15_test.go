package main

// The October 2026 Gemini review's verifier edge cases, kept as
// permanent tests: invalid UTF-8, unpaired surrogates and NUL are
// refused; "-0" is refused; small and large numbers follow the
// canonical (RFC 8785) spelling Go's encoder produces.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

func run242Raw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "round10", "deny-receipt-run242-production-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestG1StringTextIsRefusedWhenReadersWouldDisagree(t *testing.T) {
	raw := run242Raw(t)
	orig := []byte(`"fired_rule_id": "mcd-llm-001"`)
	if !bytes.Contains(raw, orig) {
		t.Fatal("fixture shape changed")
	}
	for name, repl := range map[string]string{
		"NUL escape":          `"fired_rule_id": "mcd-llm-001\u0000x"`,
		"lone high surrogate": `"fired_rule_id": "mcd-llm-001\ud800"`,
		"lone low surrogate":  `"fired_rule_id": "mcd-llm-001\udc00"`,
		"high then non-low":   `"fired_rule_id": "mcd-llm-001\ud800A"`,
		"invalid UTF-8 byte":  "\"fired_rule_id\": \"mcd-llm-001\xff\"",
	} {
		edited := bytes.Replace(raw, orig, []byte(repl), 1)
		if _, err := artifacts.DecodeReceiptStrict(edited); !errors.Is(err, artifacts.ErrNotStrictJSON) {
			t.Fatalf("%s must be refused by strict reading, got %v", name, err)
		}
	}
	// A valid surrogate pair and ordinary escapes still read normally
	// (the hash then fails, which is a different, correct verdict).
	for name, repl := range map[string]string{
		"valid surrogate pair": `"fired_rule_id": "mcd-llm-001😀"`,
		"escaped quote":        `"fired_rule_id": "mcd-llm-001\"x"`,
		"escaped backslash u":  `"fired_rule_id": "mcd-llm-001\\u0000"`,
	} {
		edited := bytes.Replace(raw, orig, []byte(repl), 1)
		if _, err := artifacts.DecodeReceiptStrict(edited); err != nil {
			t.Fatalf("%s must still decode, got %v", name, err)
		}
	}
}

func TestG2NumberSpellings(t *testing.T) {
	raw := run242Raw(t)
	orig := []byte(`"run_id": 242`)
	if !bytes.Contains(raw, orig) {
		t.Fatal("fixture shape changed")
	}
	if _, err := artifacts.DecodeReceiptStrict(bytes.Replace(raw, orig, []byte(`"run_id": -0`), 1)); !errors.Is(err, artifacts.ErrNotStrictJSON) {
		t.Fatalf("-0 must be refused, got %v", err)
	}
	// Canonical small and large numbers, as Go's encoder and RFC 8785
	// write them, pass the number rule; their non-canonical spellings
	// do not. run_id is an integer field, so use a float-typed place
	// via the walker directly.
	for text, ok := range map[string]bool{"0.00005": true, "5e-05": false, "5e-7": true, "5e-07": false, "1e+21": true, "1e21": false} {
		doc := []byte(`{"deny_receipt":{"version":"x"},"ok":true,"run_id":1,"receipt_anchor":{"kind":"x","integrated_time":` + text + `}}`)
		_, err := artifacts.DecodeReceiptStrict(doc)
		refused := errors.Is(err, artifacts.ErrNotStrictJSON)
		if ok == refused {
			t.Fatalf("number %s: refused=%v, want refused=%v (%v)", text, refused, !ok, err)
		}
	}
}
