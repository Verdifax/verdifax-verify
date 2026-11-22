package artifacts

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
)

// Sign-off refusals (round 64, design 03, approved item 7). While a stop
// whose scope refuses sign-offs stands, a sign-off an active approver signed
// on one of the account's results is refused, and the refusal is sealed: one
// record, verdifax.signoff-refusal.v1, anchored on the public log under its
// own leaf kind and carrying its place in the account's feed (signoff.refused).
// It keeps the approver's signed attempt whole, so a reader can check that the
// approver signed it, and names the stop it fell under, so a verifier can
// place every refused sign-off inside a stop period. It records that the
// sign-off was refused because of the stop, and nothing about the decision.
const (
	// SignOffRefusalFormat is the format field of a sign-off refusal.
	SignOffRefusalFormat = "verdifax.signoff-refusal.v1"
	// SignOffRefusalKind is the leaf kind of its public-log entry.
	SignOffRefusalKind = "signoff_refusal"
	// SignalSignOffRefused is the feed kind of its event.
	SignalSignOffRefused = "signoff.refused"
)

// SignOffRefusal is one sign-off refused because the account was stopped.
type SignOffRefusal struct {
	Format string `json:"format"`
	// ChainID, PreviousSignOffHash, Target, Decision, NoteHash, ApproverKey,
	// Signature, SignedAt and Nonce are the attempted sign-off exactly as the
	// approver signed it (SignOffPreimage).
	ChainID             string        `json:"chain_id"`
	PreviousSignOffHash string        `json:"previous_signoff_hash"`
	Target              SignOffTarget `json:"target"`
	Decision            string        `json:"decision"`
	NoteHash            string        `json:"note_hash,omitempty"`
	ApproverKey         string        `json:"approver_key"`
	// ApproverID is the approver key's registration in the account.
	ApproverID int64  `json:"approver_id"`
	Signature  string `json:"signature"`
	SignedAt   string `json:"signed_at"`
	Nonce      string `json:"nonce"`
	// StopSequence is the feed place of the standing stop whose scope
	// refuses sign-offs; ReasonCode is always StopReasonCode.
	StopSequence       int64          `json:"stop_sequence"`
	ReasonCode         string         `json:"reason_code"`
	RefusedAt          string         `json:"refused_at"`
	Signal             SignalLink     `json:"signal"`
	SignOffRefusalHash string         `json:"signoff_refusal_hash"`
	Anchor             *ReceiptAnchor `json:"anchor,omitempty"`
}

// Preimage is what the approver signed for the refused sign-off.
func (r *SignOffRefusal) Preimage() []byte {
	return SignOffPreimage(r.ChainID, r.PreviousSignOffHash, r.Target, r.Decision, r.NoteHash, r.SignedAt, r.Nonce)
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed.
func (r *SignOffRefusal) ComputeHash() string {
	fields := []string{r.Format, r.ChainID, r.PreviousSignOffHash, r.Target.Kind, strconv.FormatInt(r.Target.RunID, 10), r.Target.Digest,
		r.Target.JobID, r.Decision, r.NoteHash, r.ApproverKey, strconv.FormatInt(r.ApproverID, 10), r.Signature, r.SignedAt, r.Nonce,
		strconv.FormatInt(r.StopSequence, 10), r.ReasonCode, r.RefusedAt}
	return lengthPrefixedHash(append(fields, r.Signal.fields()...))
}

// Validate checks the record's shape, the approver's signature over the
// attempted sign-off, and that it names an earlier stop of its own account.
func (r *SignOffRefusal) Validate() error {
	attempt := &SignOff{Format: SignOffFormat, ChainID: r.ChainID, Sequence: 1, PreviousSignOffHash: r.PreviousSignOffHash, Target: r.Target,
		Decision: r.Decision, NoteHash: r.NoteHash, ApproverKey: r.ApproverKey, Signature: r.Signature, SignedAt: r.SignedAt, Nonce: r.Nonce,
		RecordedAt: r.RefusedAt, SignOffHash: r.SignOffRefusalHash}
	switch {
	case r.Format != SignOffRefusalFormat:
		return errors.New("signoff refusal: unknown format")
	case r.ApproverID <= 0:
		return errors.New("signoff refusal: approver_id must name the approver's registration")
	case r.ReasonCode != StopReasonCode:
		return errors.New("signoff refusal: reason_code must be " + StopReasonCode)
	case r.Signal.Account != r.ChainID:
		return errors.New("signoff refusal: its feed place names another account")
	case r.StopSequence <= 0 || r.StopSequence >= r.Signal.Sequence:
		return errors.New("signoff refusal: stop_sequence must be an earlier place in the feed")
	}
	if shapeErr := attempt.Validate(); shapeErr != nil {
		return errors.New("signoff refusal: the attempted " + shapeErr.Error())
	}
	pub, _ := base64.StdEncoding.DecodeString(r.ApproverKey)
	sig, _ := base64.StdEncoding.DecodeString(r.Signature)
	if !ed25519.Verify(pub, r.Preimage(), sig) {
		return errors.New("signoff refusal: the approver's signature does not verify over the attempted sign-off")
	}
	return r.Signal.Validate()
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (r *SignOffRefusal) LeafHash() string {
	return ComputeReceiptLeafHashV3(SignOffRefusalKind, r.Signal.Account, r.SignOffRefusalHash, r.Signal.Sequence, r.Signal.PreviousSignalHash)
}
