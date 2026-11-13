package artifacts

import (
	"errors"
	"strconv"
)

// The head of an account's signal feed (round 61, N23). Each event names the
// one before it, so a feed shows nothing was removed, reordered or rewritten
// before its newest event, but not that no later event exists. The head is a
// statement Verdifax makes when it serves the feed's end: the feed's highest
// event and that event's hash. It is anchored on the public log, whose
// integration time the audited party cannot backdate, so a verifier can say
// the feed it was given is complete as of that time, and a feed cut short
// before a later event fails.
const (
	// FeedHeadFormat is the format field of a feed-head statement.
	FeedHeadFormat = "verdifax.feed-head.v1"
	// FeedHeadKind is the leaf kind of its public-log entry.
	FeedHeadKind = "feed_head"
)

// FeedHead states an account's feed as Verdifax served it at StatedAt: its
// highest event and that event's hash.
type FeedHead struct {
	Format            string         `json:"format"`
	Account           string         `json:"account"`
	Sequence          int64          `json:"sequence"`
	HeadHash          string         `json:"head_hash"`
	StatedAt          string         `json:"stated_at"`
	HeadStatementHash string         `json:"head_statement_hash"`
	Anchor            *ReceiptAnchor `json:"anchor,omitempty"`
}

// ComputeHash returns the statement's hash: every field but the hash and the
// anchor, each length-prefixed.
func (h *FeedHead) ComputeHash() string {
	return lengthPrefixedHash([]string{h.Format, h.Account, strconv.FormatInt(h.Sequence, 10), h.HeadHash, h.StatedAt})
}

// Validate checks the statement's shape.
func (h *FeedHead) Validate() error {
	switch {
	case h.Format != FeedHeadFormat:
		return errors.New("feed head: unknown format")
	case !signalAccount.MatchString(h.Account):
		return errors.New("feed head: account must be an account, account-N")
	case h.Sequence <= 0:
		return errors.New("feed head: sequence must be positive")
	case !jobHashPattern.MatchString(h.HeadHash):
		return errors.New("feed head: head_hash must be 64 lowercase hex characters")
	case h.StatedAt == "":
		return errors.New("feed head: stated_at is required")
	case !jobHashPattern.MatchString(h.HeadStatementHash):
		return errors.New("feed head: head_statement_hash must be 64 lowercase hex characters")
	}
	return nil
}

// LeafHash is the public-log leaf that binds the statement: its hash, the
// account and its highest event, and that event's hash.
func (h *FeedHead) LeafHash() string {
	return ComputeReceiptLeafHashV3(FeedHeadKind, h.Account, h.HeadStatementHash, h.Sequence, h.HeadHash)
}
