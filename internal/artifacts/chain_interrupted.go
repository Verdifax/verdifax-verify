package artifacts

import (
	"errors"
	"strconv"
)

// Round 57, N2. A sign-off or a policy change takes its numbered place in
// its chain before its public-log entry is made, and is recorded only once
// the log confirms it. When the log never confirms (the server stopped, or a
// submission went unanswered) and the planned entry cannot be found on the
// log afterwards, the place is closed by one interrupted record, sealed and
// anchored on the public log as its own entry. It names the place, the kind
// of record that was being logged, that record's hash and the leaf its entry
// would carry, so an entry a Verdifax key may have signed for it is still
// named by a sealed record, and the chain continues after the place. A
// verifier accepts a skipped place in a chain only where such a record (or a
// restore gap) names it.

const (
	// ChainInterruptedFormat is the format field of an interrupted record.
	ChainInterruptedFormat = "verdifax.chain-interrupted.v1"
	// ChainInterruptedKind is the leaf kind of its public-log entry.
	ChainInterruptedKind = "chain_interrupted"
	// SignalChainInterrupted is its event kind in the account's feed.
	SignalChainInterrupted = "chain.interrupted"
)

// ChainInterrupted closes one place of a sign-off or policy chain whose
// record was never confirmed on the public log. KeyID names the key whose
// policy chain it is, for the policy chain only.
type ChainInterrupted struct {
	Format            string         `json:"format"`
	Chain             string         `json:"chain"`
	KeyID             int64          `json:"key_id,omitempty"`
	Place             int64          `json:"place"`
	RecordKind        string         `json:"record_kind"`
	PlannedRecordHash string         `json:"planned_record_hash"`
	PlannedLeaf       string         `json:"planned_leaf"`
	RecordedAt        string         `json:"recorded_at"`
	Signal            SignalLink     `json:"signal"`
	InterruptedHash   string         `json:"interrupted_hash"`
	Anchor            *ReceiptAnchor `json:"anchor,omitempty"`
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed.
func (c *ChainInterrupted) ComputeHash() string {
	fields := append([]string{c.Format, c.Chain, strconv.FormatInt(c.KeyID, 10), strconv.FormatInt(c.Place, 10),
		c.RecordKind, c.PlannedRecordHash, c.PlannedLeaf, c.RecordedAt}, c.Signal.fields()...)
	return lengthPrefixedHash(fields)
}

// Validate checks the record's shape: every value its hash and leaf are
// built from.
func (c *ChainInterrupted) Validate() error {
	switch {
	case c.Format != ChainInterruptedFormat:
		return errors.New("interrupted record: unknown format")
	case c.Chain != GapChainSignOffs && c.Chain != GapChainPolicy && c.Chain != GapChainAccountPolicy:
		return errors.New("interrupted record: chain must be signoffs, policy or account-policy")
	case (c.Chain == GapChainPolicy) != (c.KeyID > 0):
		return errors.New("interrupted record: a policy chain names its key, and only a policy chain does")
	case c.Place <= 0:
		return errors.New("interrupted record: place must be positive")
	case (c.Chain == GapChainSignOffs) != (c.RecordKind == SignOffKind):
		return errors.New("interrupted record: a sign-off chain interrupts a sign-off, and a policy chain a policy activation")
	case c.RecordKind != SignOffKind && c.RecordKind != PolicyActivationKind:
		return errors.New("interrupted record: record_kind must be signoff or policy_activation")
	case !jobHashPattern.MatchString(c.PlannedRecordHash):
		return errors.New("interrupted record: planned_record_hash must be 64 lowercase hex characters")
	case !jobHashPattern.MatchString(c.PlannedLeaf):
		return errors.New("interrupted record: planned_leaf must be 64 lowercase hex characters")
	case c.RecordedAt == "":
		return errors.New("interrupted record: recorded_at is required")
	case !jobHashPattern.MatchString(c.InterruptedHash):
		return errors.New("interrupted record: interrupted_hash must be 64 lowercase hex characters")
	}
	return c.Signal.Validate()
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (c *ChainInterrupted) LeafHash() string {
	return ComputeReceiptLeafHashV3(ChainInterruptedKind, c.Signal.Account, c.InterruptedHash, c.Signal.Sequence, c.Signal.PreviousSignalHash)
}
