package artifacts

import (
	"errors"
	"strconv"
)

// The head of an account's sign-off chain (round 59, N16). A sign-off links
// back to the one before it, so a history shows nothing was removed, reordered
// or rewritten before its newest entry, but not that no later sign-off exists.
// The head is a statement Verdifax makes when it serves the history: the
// account's highest place and the hash of its newest sign-off. It is anchored on
// the public log, whose integration time the audited party cannot backdate,
// so a verifier can say the history it was given is complete as of that time.
const (
	// SignOffHeadFormat is the format field of a chain-head statement.
	SignOffHeadFormat = "verdifax.signoff-head.v1"
	// SignOffHeadKind is the leaf kind of its public-log entry.
	SignOffHeadKind = "signoff_head"
)

// SignOffHead states an account's sign-off chain as Verdifax held it at
// StatedAt: its highest place, taken by a sign-off or skipped by a restore gap
// or an interrupted record, and the hash of its newest sign-off.
type SignOffHead struct {
	Format            string         `json:"format"`
	ChainID           string         `json:"chain_id"`
	Sequence          int64          `json:"sequence"`
	HeadHash          string         `json:"head_hash"`
	StatedAt          string         `json:"stated_at"`
	HeadStatementHash string         `json:"head_statement_hash"`
	Anchor            *ReceiptAnchor `json:"anchor,omitempty"`
}

// ComputeHash returns the statement's hash: every field but the hash and the
// anchor, each length-prefixed.
func (h *SignOffHead) ComputeHash() string {
	return lengthPrefixedHash([]string{h.Format, h.ChainID, strconv.FormatInt(h.Sequence, 10), h.HeadHash, h.StatedAt})
}

// Validate checks the statement's shape.
func (h *SignOffHead) Validate() error {
	switch {
	case h.Format != SignOffHeadFormat:
		return errors.New("sign-off head: unknown format")
	case !signOffChain.MatchString(h.ChainID):
		return errors.New("sign-off head: chain_id must be an account, account-N")
	case h.Sequence <= 0:
		return errors.New("sign-off head: sequence must be positive")
	case !jobHashPattern.MatchString(h.HeadHash):
		return errors.New("sign-off head: head_hash must be 64 lowercase hex characters")
	case h.StatedAt == "":
		return errors.New("sign-off head: stated_at is required")
	case !jobHashPattern.MatchString(h.HeadStatementHash):
		return errors.New("sign-off head: head_statement_hash must be 64 lowercase hex characters")
	}
	return nil
}

// LeafHash is the public-log leaf that binds the statement: its hash, the
// account and its highest place, and the hash of its newest sign-off.
func (h *SignOffHead) LeafHash() string {
	return ComputeReceiptLeafHashV3(SignOffHeadKind, h.ChainID, h.HeadStatementHash, h.Sequence, h.HeadHash)
}
