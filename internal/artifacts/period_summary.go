package artifacts

import (
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The period summary (round 64, board summary). A summary is a statement
// Verdifax makes beside an account's signal feed, never an event in it: the
// figures for one period, each committed to the exact list of feed events it
// counts, and the feed head stated after the period, so a verifier holding the
// feed recounts every figure and finds the same list. It is anchored on the
// public log as a feed head is. Every figure comes from the feed; the summary
// states counts and times, and judges none of them.
const (
	// PeriodSummaryFormat is the format field of a period summary.
	PeriodSummaryFormat = "verdifax.period-summary.v1"
	// PeriodSummaryKind is the leaf kind of its public-log entry.
	PeriodSummaryKind = "period_summary"
	// PeriodSummaryEventsFormat opens the digest of a figure's event list.
	PeriodSummaryEventsFormat = "verdifax.period-summary-events.v1"
)

// PeriodSummary states an account's figures for the period from From
// (included) to To (excluded), counted from its feed up to the head named.
type PeriodSummary struct {
	Format        string `json:"format"`
	Account       string `json:"account"`
	From          string `json:"from"`
	To            string `json:"to"`
	CountingRules string `json:"counting_rules"`
	// HeadSequence, HeadHash and HeadStatementHash name the feed-head
	// statement, made after the period, that the figures were counted up to.
	HeadSequence      int64           `json:"head_sequence"`
	HeadHash          string          `json:"head_hash"`
	HeadStatementHash string          `json:"head_statement_hash"`
	Figures           []SummaryFigure `json:"figures"`
	StatedAt          string          `json:"stated_at"`
	SummaryHash       string          `json:"summary_hash"`
	Anchor            *ReceiptAnchor  `json:"anchor,omitempty"`
}

// SummaryFigure is one figure: its name, its value (a count, or whole seconds
// for a figure whose name ends in _seconds), and the digest of the events it
// counts. A count is never negative; a figure of seconds is a time measured
// between two entries and is stated as measured, negative included.
type SummaryFigure struct {
	Name         string `json:"name"`
	Value        int64  `json:"value"`
	EventsDigest string `json:"events_digest"`
}

// SummaryEvent is one feed event a figure counts: its place and its hash.
type SummaryEvent struct {
	Sequence  int64
	EventHash string
}

// SummaryEventsDigest is the digest a figure commits to: the events in
// ascending feed order, each written sequence:event_hash, length-prefixed
// after the format. An empty list has a digest too.
func SummaryEventsDigest(events []SummaryEvent) string {
	sorted := append([]SummaryEvent(nil), events...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Sequence < sorted[j].Sequence })
	fields := []string{PeriodSummaryEventsFormat}
	for _, e := range sorted {
		fields = append(fields, strconv.FormatInt(e.Sequence, 10)+":"+e.EventHash)
	}
	return lengthPrefixedHash(fields)
}

// ComputeHash returns the summary's hash: every field but the hash and the
// anchor, each length-prefixed, the figures in their stated order after their
// number.
func (s *PeriodSummary) ComputeHash() string {
	fields := []string{s.Format, s.Account, s.From, s.To, s.CountingRules, strconv.FormatInt(s.HeadSequence, 10),
		s.HeadHash, s.HeadStatementHash, s.StatedAt, strconv.Itoa(len(s.Figures))}
	for _, f := range s.Figures {
		fields = append(fields, f.Name, strconv.FormatInt(f.Value, 10), f.EventsDigest)
	}
	return lengthPrefixedHash(fields)
}

var summaryFigureName = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

// Validate checks the summary's shape: a known format and account, a period
// that ends after it starts, a positive head, and figures named once each in
// ascending name order, none negative.
func (s *PeriodSummary) Validate() error {
	from, fromErr := time.Parse(time.RFC3339, s.From)
	to, toErr := time.Parse(time.RFC3339, s.To)
	switch {
	case s.Format != PeriodSummaryFormat:
		return errors.New("period summary: unknown format")
	case !signalAccount.MatchString(s.Account):
		return errors.New("period summary: account must be an account, account-N")
	case fromErr != nil || toErr != nil:
		return errors.New("period summary: from and to must be RFC 3339 times")
	case !to.After(from):
		return errors.New("period summary: the period must end after it starts")
	case s.CountingRules == "":
		return errors.New("period summary: counting_rules is required")
	case s.HeadSequence <= 0:
		return errors.New("period summary: head_sequence must be positive")
	case !jobHashPattern.MatchString(s.HeadHash):
		return errors.New("period summary: head_hash must be 64 lowercase hex characters")
	case !jobHashPattern.MatchString(s.HeadStatementHash):
		return errors.New("period summary: head_statement_hash must be 64 lowercase hex characters")
	case s.StatedAt == "":
		return errors.New("period summary: stated_at is required")
	case !jobHashPattern.MatchString(s.SummaryHash):
		return errors.New("period summary: summary_hash must be 64 lowercase hex characters")
	}
	for i, f := range s.Figures {
		switch {
		case !summaryFigureName.MatchString(f.Name):
			return errors.New("period summary: a figure name must be lowercase letters, digits, dots, colons, underscores or hyphens")
		case i > 0 && f.Name <= s.Figures[i-1].Name:
			return errors.New("period summary: figures must be named once each, in ascending name order")
		case f.Value < 0 && !strings.HasSuffix(f.Name, "_seconds"):
			return errors.New("period summary: only a figure of seconds can be negative, a time measured between two log entries as it was measured")
		case !jobHashPattern.MatchString(f.EventsDigest):
			return errors.New("period summary: events_digest must be 64 lowercase hex characters")
		}
	}
	return nil
}

// LeafHash is the public-log leaf that binds the summary: its hash, the
// account, and the feed head it was counted up to.
func (s *PeriodSummary) LeafHash() string {
	return ComputeReceiptLeafHashV3(PeriodSummaryKind, s.Account, s.SummaryHash, s.HeadSequence, s.HeadHash)
}
