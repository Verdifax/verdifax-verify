package artifacts

import (
	"strings"
	"testing"
)

// periodSummaryVector is the round 64 test vector for
// verdifax.period-summary.v1; its digests and hashes were computed apart from
// this package, from the recipe alone, and the verifier and SDKs pin the same.
func periodSummaryVector() *PeriodSummary {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	s := &PeriodSummary{Format: PeriodSummaryFormat, Account: "account-7", From: "2026-11-01T00:00:00Z", To: "2026-12-01T00:00:00Z",
		CountingRules: "period-summary-counting.v1", HeadSequence: 40, HeadHash: strings.Repeat("c", 64),
		HeadStatementHash: strings.Repeat("d", 64), StatedAt: "2026-12-01T00:05:00Z",
		Figures: []SummaryFigure{
			// Given out of feed order: the digest sorts by sequence.
			{Name: "refused.deny_receipt", Value: 2, EventsDigest: SummaryEventsDigest([]SummaryEvent{{12, b}, {3, a}})},
			{Name: "runs.sealed", Value: 0, EventsDigest: SummaryEventsDigest(nil)},
		}}
	s.SummaryHash = s.ComputeHash()
	return s
}

const (
	periodSummaryEmptyDigest = "9f006592ab6ba6e79a1c4864f051a73c7d077be2caae0bf11ff393b07cf61a33"
	periodSummaryTwoDigest   = "3c2757775d9610ebaacd512d8706f6824cda094e867c87407f397bea9f8f8376"
	periodSummaryVectorHash  = "698b85d01da22abebee3a9e2ff0544e26a0c544f633ba82e8828dd40cb582201"
	periodSummaryVectorLeaf  = "754cf91fadcd53765f4471b686b7eaa1d4c581c1d9dc054edf6194f5ce062710"
)

// Round 64, R303: a period summary's recipe is pinned by a vector, its hash
// covers every stated value and each figure's event list, and its leaf binds
// the account and the feed head it was counted up to.
func TestPeriodSummaryVector(t *testing.T) {
	s := periodSummaryVector()
	if got := s.Figures[1].EventsDigest; got != periodSummaryEmptyDigest {
		t.Fatalf("empty event list digest %s, want %s", got, periodSummaryEmptyDigest)
	}
	if got := s.Figures[0].EventsDigest; got != periodSummaryTwoDigest {
		t.Fatalf("event list digest %s, want %s", got, periodSummaryTwoDigest)
	}
	if s.SummaryHash != periodSummaryVectorHash {
		t.Fatalf("summary hash %s, want %s", s.SummaryHash, periodSummaryVectorHash)
	}
	if got := s.LeafHash(); got != periodSummaryVectorLeaf {
		t.Fatalf("leaf %s, want %s", got, periodSummaryVectorLeaf)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("the vector must be valid: %v", err)
	}
	if err := ValidateReceiptLeafFieldsV3(PeriodSummaryKind, s.Account, s.SummaryHash, s.HeadSequence, s.HeadHash); err != nil {
		t.Fatalf("a summary's entry must be loggable: %v", err)
	}
}

func TestPeriodSummaryHashCoversEveryValue(t *testing.T) {
	base := periodSummaryVector()
	for name, mutate := range map[string]func(x *PeriodSummary){
		"account":        func(x *PeriodSummary) { x.Account = "account-8" },
		"from":           func(x *PeriodSummary) { x.From = "2026-11-02T00:00:00Z" },
		"to":             func(x *PeriodSummary) { x.To = "2026-12-02T00:00:00Z" },
		"counting rules": func(x *PeriodSummary) { x.CountingRules = "period-summary-counting.v2" },
		"head sequence":  func(x *PeriodSummary) { x.HeadSequence = 41 },
		"head hash":      func(x *PeriodSummary) { x.HeadHash = strings.Repeat("e", 64) },
		"head statement": func(x *PeriodSummary) { x.HeadStatementHash = strings.Repeat("e", 64) },
		"stated time":    func(x *PeriodSummary) { x.StatedAt = "2026-12-01T00:05:01Z" },
		"a figure value": func(x *PeriodSummary) {
			x.Figures = []SummaryFigure{{"refused.deny_receipt", 3, x.Figures[0].EventsDigest}, x.Figures[1]}
		},
		"a figure name": func(x *PeriodSummary) {
			x.Figures = []SummaryFigure{{"refused.halt", 2, x.Figures[0].EventsDigest}, x.Figures[1]}
		},
		"a figure's list": func(x *PeriodSummary) {
			x.Figures = []SummaryFigure{{"refused.deny_receipt", 2, periodSummaryEmptyDigest}, x.Figures[1]}
		},
		"a figure less": func(x *PeriodSummary) { x.Figures = x.Figures[:1] },
	} {
		x := *base
		mutate(&x)
		if x.ComputeHash() == base.SummaryHash {
			t.Errorf("the hash must cover %s", name)
		}
	}
	other := SummaryEventsDigest([]SummaryEvent{{3, strings.Repeat("a", 64)}, {13, strings.Repeat("b", 64)}})
	if other == periodSummaryTwoDigest {
		t.Error("the event digest must cover each event's place")
	}
}

func TestPeriodSummaryValidateRefusesABadShape(t *testing.T) {
	for name, mutate := range map[string]func(x *PeriodSummary){
		"format":         func(x *PeriodSummary) { x.Format = FeedHeadFormat },
		"account":        func(x *PeriodSummary) { x.Account = "acct-7" },
		"from":           func(x *PeriodSummary) { x.From = "November" },
		"empty period":   func(x *PeriodSummary) { x.To = x.From },
		"counting rules": func(x *PeriodSummary) { x.CountingRules = "" },
		"head sequence":  func(x *PeriodSummary) { x.HeadSequence = 0 },
		"head hash":      func(x *PeriodSummary) { x.HeadHash = "x" },
		"head statement": func(x *PeriodSummary) { x.HeadStatementHash = "" },
		"stated time":    func(x *PeriodSummary) { x.StatedAt = "" },
		"summary hash":   func(x *PeriodSummary) { x.SummaryHash = "" },
		"figure order":   func(x *PeriodSummary) { x.Figures = []SummaryFigure{x.Figures[1], x.Figures[0]} },
		"figure twice":   func(x *PeriodSummary) { x.Figures = []SummaryFigure{x.Figures[0], x.Figures[0]} },
		"figure name":    func(x *PeriodSummary) { x.Figures = []SummaryFigure{{"Runs Sealed", 1, periodSummaryEmptyDigest}} },
		"negative":       func(x *PeriodSummary) { x.Figures = []SummaryFigure{{"runs.sealed", -1, periodSummaryEmptyDigest}} },
		"figure digest":  func(x *PeriodSummary) { x.Figures = []SummaryFigure{{"runs.sealed", 1, "x"}} },
	} {
		x := *periodSummaryVector()
		mutate(&x)
		if x.Validate() == nil {
			t.Errorf("a summary with a bad %s must be refused", name)
		}
	}
	feedHead := &FeedHead{Format: FeedHeadFormat, Account: "account-7", Sequence: 40, HeadHash: strings.Repeat("c", 64),
		HeadStatementHash: periodSummaryVectorHash}
	if feedHead.LeafHash() == periodSummaryVectorLeaf {
		t.Fatal("a feed head's leaf must never stand for a period summary's")
	}
}
