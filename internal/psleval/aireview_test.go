package psleval

import "testing"

func TestTheContradictionModeComesFromTheRuleThenThePolicyThenHalt(t *testing.T) {
	record, halt := &AIReview{Contradiction: ContradictionRecord}, &AIReview{Contradiction: ContradictionHalt}
	for _, c := range []struct {
		fired  *Rule
		policy *AIReview
		want   ContradictionMode
	}{
		{nil, nil, ContradictionHalt},
		{&Rule{}, nil, ContradictionHalt},
		{&Rule{}, record, ContradictionRecord},
		{&Rule{AIReview: halt}, record, ContradictionHalt},
		{&Rule{AIReview: record}, halt, ContradictionRecord},
		{nil, record, ContradictionRecord},
	} {
		if got := ContradictionModeFor(c.fired, c.policy); got != c.want {
			t.Errorf("rule %+v policy %+v: %s, want %s", c.fired, c.policy, got, c.want)
		}
	}
	for mode, known := range map[ContradictionMode]bool{"halt": true, "record": true, "": false, "warn": false, "Halt": false} {
		if KnownContradictionMode(mode) != known {
			t.Errorf("KnownContradictionMode(%q) = %v", mode, !known)
		}
	}
}
