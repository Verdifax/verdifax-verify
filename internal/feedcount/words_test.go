package feedcount

import (
	"strings"
	"testing"
)

// R377 (round 64, N38): every figure the counting rules state, in the shared
// vector and with the v2 owner-stop split, has plain words, never its key;
// a code or receipt kind the figure names may follow the words as sealed.
func TestEveryFigureHasPlainWords(t *testing.T) {
	v := buildVector(t)
	names := []string{"account.stops.by:owner.signed", "account.stopped_seconds.by:owner.unsigned"}
	for _, f := range v.Figures {
		names = append(names, f.Name)
	}
	for _, name := range names {
		w := FigureWords(name)
		if w == name || strings.HasPrefix(w, "response_times.") || strings.Contains(w, name) {
			t.Errorf("figure %s has no plain words: %q", name, w)
		}
	}
}

// R376: the package holds exactly the two counting rule names it counts by.
func TestKnownCountingRules(t *testing.T) {
	for rules, want := range map[string]bool{CountingRules: true, CountingRulesV1: true, "verdifax.period-summary-counting.v9": false, "": false} {
		if KnownCountingRules(rules) != want {
			t.Errorf("KnownCountingRules(%q) = %v, want %v", rules, !want, want)
		}
	}
}
