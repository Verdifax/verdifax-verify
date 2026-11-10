package artifacts

import (
	"errors"
	"strconv"
)

// Round 56, E4. A restore from the backup can lose the last seconds of
// writes, and an account's chain entries in that window may already sit on
// the public log. The chain is never forked by reusing those places and
// never left with a silent hole: one restore-gap record, sealed and anchored
// on the public log as its own entry, names the places that were lost, and
// the chain continues after them. A verifier accepts a jump in a chain only
// where such a record names exactly the places skipped.

const (
	// RestoreGapFormat is the format field of a restore-gap record.
	RestoreGapFormat = "verdifax.restore-gap.v1"
	// RestoreGapKind is the leaf kind of its public-log entry.
	RestoreGapKind = "restore_gap"
	// SignalChainGap is its event kind in the account's feed.
	SignalChainGap = "chain.gap"

	// The chains a restore gap can name.
	GapChainSignals       = "signals"
	GapChainSignOffs      = "signoffs"
	GapChainPolicy        = "policy"
	GapChainAccountPolicy = "account-policy"
)

// RestoreGap names the places a restore lost from one chain of an account:
// LostFrom to LostTo, inclusive. KeyID names the key whose policy chain it
// is, for the policy chain only.
type RestoreGap struct {
	Format         string         `json:"format"`
	Chain          string         `json:"chain"`
	KeyID          int64          `json:"key_id,omitempty"`
	LostFrom       int64          `json:"lost_from"`
	LostTo         int64          `json:"lost_to"`
	RecordedAt     string         `json:"recorded_at"`
	Signal         SignalLink     `json:"signal"`
	RestoreGapHash string         `json:"restore_gap_hash"`
	Anchor         *ReceiptAnchor `json:"anchor,omitempty"`
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed.
func (g *RestoreGap) ComputeHash() string {
	fields := append([]string{g.Format, g.Chain, strconv.FormatInt(g.KeyID, 10), strconv.FormatInt(g.LostFrom, 10),
		strconv.FormatInt(g.LostTo, 10), g.RecordedAt}, g.Signal.fields()...)
	return lengthPrefixedHash(fields)
}

// Validate checks the record's shape: every value its hash and leaf are
// built from.
func (g *RestoreGap) Validate() error {
	switch {
	case g.Format != RestoreGapFormat:
		return errors.New("restore gap: unknown format")
	case g.Chain != GapChainSignals && g.Chain != GapChainSignOffs && g.Chain != GapChainPolicy && g.Chain != GapChainAccountPolicy:
		return errors.New("restore gap: chain must be signals, signoffs, policy or account-policy")
	case (g.Chain == GapChainPolicy) != (g.KeyID > 0):
		return errors.New("restore gap: a policy chain names its key, and only a policy chain does")
	case g.LostFrom <= 0 || g.LostTo < g.LostFrom:
		return errors.New("restore gap: lost_from must be positive and lost_to at least lost_from")
	case g.RecordedAt == "":
		return errors.New("restore gap: recorded_at is required")
	case g.Chain == GapChainSignals && g.Signal.Sequence != g.LostTo+1:
		return errors.New("restore gap: a gap in the feed takes the first place after the places it names")
	case !jobHashPattern.MatchString(g.RestoreGapHash):
		return errors.New("restore gap: restore_gap_hash must be 64 lowercase hex characters")
	}
	if g.Chain == GapChainSignals && g.LostFrom == 1 {
		// A restore that lost an account's whole feed: the gap follows no
		// event, at the first place after the ones it skips.
		if g.Signal.PreviousSignalHash != NoPreviousSignal || !signalAccount.MatchString(g.Signal.Account) {
			return errors.New("restore gap: a gap from the feed's first place follows no event")
		}
		return nil
	}
	return g.Signal.Validate()
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (g *RestoreGap) LeafHash() string {
	return ComputeReceiptLeafHashV3(RestoreGapKind, g.Signal.Account, g.RestoreGapHash, g.Signal.Sequence, g.Signal.PreviousSignalHash)
}
