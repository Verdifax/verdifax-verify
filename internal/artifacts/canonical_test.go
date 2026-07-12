package artifacts

import "testing"

// TestCanonicalHash_KnownAnswer pins the canonical hash of a fixed
// struct. The expected value was computed independently (compact JSON
// of {"a":"x","b":7}, SHA-256) so this is a true known-answer check on
// the verifier's canonical-hash primitive — the routine every other
// verification in the binary depends on.
func TestCanonicalHash_KnownAnswer(t *testing.T) {
	type kv struct {
		A string `json:"a"`
		B int    `json:"b"`
	}
	got, err := CanonicalHash(kv{A: "x", B: 7})
	if err != nil {
		t.Fatalf("CanonicalHash error: %v", err)
	}
	const want = "cd9a8e098e6a7468a6daeb99dd6912ebeff7ba432a177c4fc325712763bf9f24"
	if got != want {
		t.Fatalf("canonical hash drift:\n  want %s\n  got  %s", want, got)
	}
}

// TestCanonicalHash_Deterministic proves repeated hashing of an equal
// value is stable — no map iteration, no time or pointer leakage.
func TestCanonicalHash_Deterministic(t *testing.T) {
	type kv struct {
		A string `json:"a"`
		B int    `json:"b"`
	}
	h1, err := CanonicalHash(kv{A: "x", B: 7})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := CanonicalHash(kv{A: "x", B: 7})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("non-deterministic canonical hash: %s vs %s", h1, h2)
	}
}

// TestCanonicalHash_FieldOrderMatters documents (and locks) the fact
// that canonical bytes follow struct field-declaration order: two
// structs with the same data but different field order hash
// differently. This is intentional — canonical order is defined by the
// struct definition, not by field name — and callers rely on it.
func TestCanonicalHash_FieldOrderMatters(t *testing.T) {
	type ab struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	type ba struct {
		B string `json:"b"`
		A string `json:"a"`
	}
	ha, _ := CanonicalHash(ab{A: "1", B: "2"})
	hb, _ := CanonicalHash(ba{B: "2", A: "1"})
	if ha == hb {
		t.Fatal("expected field-order to change the canonical hash; it did not")
	}
}

// TestMustCanonicalHash_PanicsOnUnmarshalable proves the Must* variant
// panics rather than silently returning a wrong/empty hash when handed
// a value encoding/json cannot marshal (a channel).
func TestMustCanonicalHash_PanicsOnUnmarshalable(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustCanonicalHash did not panic on unmarshalable input")
		}
	}()
	type bad struct {
		Ch chan int `json:"ch"`
	}
	_ = MustCanonicalHash(bad{Ch: make(chan int)})
}
