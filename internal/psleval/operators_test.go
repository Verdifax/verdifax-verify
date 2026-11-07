package psleval

import "testing"

// The levels, lowest first, as the policy language documents them.
var levelsInOrder = []ClassificationLevel{
	ClassificationPublic, ClassificationInternal, ClassificationConfidential,
	ClassificationRestricted, ClassificationTopSecret, ClassificationTSSCI,
}

func TestCompareClassificationFollowsTheDocumentedOrder(t *testing.T) {
	for i, a := range levelsInOrder {
		for j, b := range levelsInOrder {
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got, ok := CompareClassification(a, b); !ok || got != want {
				t.Fatalf("CompareClassification(%s, %s) = %d, %v; want %d, true", a, b, got, ok, want)
			}
		}
	}
	for _, unknown := range []ClassificationLevel{"", "SORT-OF", "internal"} {
		if _, ok := CompareClassification(unknown, ClassificationPublic); ok {
			t.Fatalf("%q compared as a known level", unknown)
		}
		if _, ok := CompareClassification(ClassificationPublic, unknown); ok {
			t.Fatalf("%q compared as a known level", unknown)
		}
	}
}

func TestKnownClassificationIsExactlyTheDocumentedLevels(t *testing.T) {
	for _, level := range levelsInOrder {
		if !KnownClassification(level) {
			t.Fatalf("%s is not known", level)
		}
	}
	for _, unknown := range []ClassificationLevel{"", "SORT-OF", "internal", "TOP SECRET"} {
		if KnownClassification(unknown) {
			t.Fatalf("%q is known", unknown)
		}
	}
}
