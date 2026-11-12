package artifacts

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Customer sign-off on results. A sign-off is one approver's decision, approve
// or reject, on one exact result: a completed run's record, a refused or halted
// run's receipt, or a whole job by its final step. The approver signs it on the
// customer's machine with a key the account registered; Verdifax never holds
// that key. Each sign-off links to the account's previous one and is anchored on
// the public log, so a removed or reordered sign-off breaks the chain, and a
// changed decision is a new link that supersedes the earlier one.
//
// A sign-off shows that the holder of a registered approver key signed that
// decision on that result, and that Verdifax logged it. It does not show the
// review was careful, the result was right, or who the person is.
const (
	// SignOffFormat is the format field of a sign-off record.
	SignOffFormat = "verdifax.signoff.v1"
	// SignOffKind is the leaf kind of its public-log entry.
	SignOffKind = "signoff"
	// SignOffSignatureForm opens what the approver key signs.
	SignOffSignatureForm = "verdifax.signoff.v1"
	// ApproverKeyProofForm opens what a new approver key signs to show its
	// holder has the private key: the form, a zero byte, the base64 key.
	ApproverKeyProofForm = "verdifax.approver-key.v1"
	// NoPreviousSignOff is the previous hash of an account's first sign-off.
	NoPreviousSignOff = "0000000000000000000000000000000000000000000000000000000000000000"

	// The three kinds of result a sign-off can name.
	SignOffTargetRecord  = "record"
	SignOffTargetReceipt = "receipt"
	SignOffTargetJob     = "job"

	// The two decisions.
	SignOffApprove = "approve"
	SignOffReject  = "reject"
)

var signOffChain = regexp.MustCompile(`^account-[1-9][0-9]{0,18}$`)

// SignOffTarget names the exact result signed off, by what its public-log
// entry covers: a record's complete-record anchored digest, a receipt's hash,
// or, for a job, the final step's record digest.
type SignOffTarget struct {
	Kind   string `json:"kind"`
	RunID  int64  `json:"run_id"`
	Digest string `json:"digest"`
	JobID  string `json:"job_id,omitempty"`
}

// SignOff is one approver's decision on one result.
type SignOff struct {
	Format              string        `json:"format"`
	ChainID             string        `json:"chain_id"`
	Sequence            int64         `json:"sequence"`
	PreviousSignOffHash string        `json:"previous_signoff_hash"`
	Target              SignOffTarget `json:"target"`
	Decision            string        `json:"decision"`
	NoteHash            string        `json:"note_hash,omitempty"`
	ApproverKey         string        `json:"approver_key"`
	Signature           string        `json:"signature"`
	SignedAt            string        `json:"signed_at"`
	Nonce               string        `json:"nonce"`
	RecordedAt          string        `json:"recorded_at"`
	// Signal is the sign-off's place in the account's signal feed, added by
	// the server outside what the approver signs; it joins the hash under its
	// own label, only when present.
	Signal      *SignalLink    `json:"signal,omitempty"`
	SignOffHash string         `json:"signoff_hash"`
	Anchor      *ReceiptAnchor `json:"anchor,omitempty"`
}

// SignOffPreimage is what the approver key signs: the account's chain, the
// place in it, the exact result and the decision, so a signature cannot be
// moved to another account, another result or another point in the chain.
func SignOffPreimage(chainID, previousHash string, target SignOffTarget, decision, noteHash, signedAt, nonce string) []byte {
	return []byte(strings.Join([]string{SignOffSignatureForm, chainID, previousHash, target.Kind,
		strconv.FormatInt(target.RunID, 10), target.Digest, target.JobID, decision, noteHash, signedAt, nonce}, "\x00"))
}

// ApproverKeyProofPreimage is what an approver key signs when the owner
// registers it, so no one can register a key they do not hold.
func ApproverKeyProofPreimage(publicKey string) []byte {
	return []byte(ApproverKeyProofForm + "\x00" + publicKey)
}

// Preimage is the record's own signature preimage.
func (s *SignOff) Preimage() []byte {
	return SignOffPreimage(s.ChainID, s.PreviousSignOffHash, s.Target, s.Decision, s.NoteHash, s.SignedAt, s.Nonce)
}

// ComputeHash returns the record's hash. Every field but the hash itself and
// the anchor goes in, each length-prefixed so that no field can run into the
// next. The anchor is made from this hash, so it cannot be inside it.
func (s *SignOff) ComputeHash() string {
	fields := []string{s.Format, s.ChainID, strconv.FormatInt(s.Sequence, 10), s.PreviousSignOffHash,
		s.Target.Kind, strconv.FormatInt(s.Target.RunID, 10), s.Target.Digest, s.Target.JobID,
		s.Decision, s.NoteHash, s.ApproverKey, s.Signature, s.SignedAt, s.Nonce, s.RecordedAt}
	if s.Signal != nil {
		fields = append(fields, s.Signal.fields()...)
	}
	digest := sha256.New()
	for _, f := range fields {
		digest.Write([]byte(strconv.Itoa(len(f)) + ":" + f))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// Validate checks the record's shape: every value its hash, its signature and
// its leaf are built from.
func (s *SignOff) Validate() error {
	switch {
	case s.Format != SignOffFormat:
		return errors.New("signoff: unknown format")
	case !signOffChain.MatchString(s.ChainID):
		return errors.New("signoff: chain_id must be an account, account-N")
	case s.Sequence <= 0:
		return errors.New("signoff: sequence must be positive")
	case !jobHashPattern.MatchString(s.PreviousSignOffHash):
		return errors.New("signoff: previous hash must be 64 lowercase hex characters")
	case s.Target.Kind != SignOffTargetRecord && s.Target.Kind != SignOffTargetReceipt && s.Target.Kind != SignOffTargetJob:
		return errors.New("signoff: target kind must be record, receipt or job")
	case s.Target.RunID <= 0:
		return errors.New("signoff: target run_id must be positive")
	case !jobHashPattern.MatchString(s.Target.Digest):
		return errors.New("signoff: target digest must be 64 lowercase hex characters")
	case (s.Target.Kind == SignOffTargetJob) != (s.Target.JobID != ""):
		return errors.New("signoff: a job target names its job_id, and only a job target does")
	case s.Decision != SignOffApprove && s.Decision != SignOffReject:
		return errors.New("signoff: decision must be approve or reject")
	case s.NoteHash != "" && !jobHashPattern.MatchString(s.NoteHash):
		return errors.New("signoff: note_hash must be empty or 64 lowercase hex characters")
	case !validBase64Len(s.ApproverKey, 32) || !validBase64Len(s.Signature, 64):
		return errors.New("signoff: approver_key and signature must be a base64 Ed25519 key and signature")
	case s.SignedAt == "" || s.RecordedAt == "":
		return errors.New("signoff: signed_at and recorded_at are required")
	case len(s.Nonce) != 32 || !isLowerHex(s.Nonce):
		return errors.New("signoff: nonce must be 32 lowercase hex characters")
	case !jobHashPattern.MatchString(s.SignOffHash):
		return errors.New("signoff: signoff hash must be 64 lowercase hex characters")
	}
	if s.Signal != nil {
		if s.Signal.Account != s.ChainID {
			return errors.New("signoff: its signal feed place names another account")
		}
		return s.Signal.Validate()
	}
	return nil
}

// LeafHash is the public-log leaf that binds this record: its hash, its place
// in the account's chain and the sign-off before it.
func (s *SignOff) LeafHash() string {
	return ComputeReceiptLeafHashV3(SignOffKind, s.ChainID, s.SignOffHash, s.Sequence, s.PreviousSignOffHash)
}

func validBase64Len(v string, n int) bool {
	raw, err := base64.StdEncoding.DecodeString(v)
	return err == nil && len(raw) == n
}

func isLowerHex(v string) bool {
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// SignOffResult is a result a sign-off can be on: a completed run's record or
// a refused or halted run's receipt, by its run and the digest its public-log
// entry covers.
type SignOffResult struct {
	Kind   string // SignOffTargetRecord or SignOffTargetReceipt
	RunID  int64
	Digest string
}

// NamesResult reports whether a sign-off's target names the result. A
// receipt is named only by a receipt sign-off. A record is named by a record
// sign-off, and by a job sign-off, which is on the job's final step's record,
// on the same run and digest. Every check and display of sign-offs on a result
// uses this one definition (round 59, N15).
func (t SignOffTarget) NamesResult(r SignOffResult) bool {
	if t.RunID != r.RunID || t.Digest != r.Digest {
		return false
	}
	switch r.Kind {
	case SignOffTargetReceipt:
		return t.Kind == SignOffTargetReceipt
	case SignOffTargetRecord:
		return t.Kind == SignOffTargetRecord || t.Kind == SignOffTargetJob
	}
	return false
}

// DecisionInForce returns, from sign-offs in chain order, the one whose
// decision is in force on the result, and the result's own decision when a
// job's decision governs instead. A later sign-off supersedes an earlier one
// of the same kind. On a job's final step the job's decision governs when there
// is one, and the latest record sign-off is returned as own, to be shown under
// it (round 59, N19). Both are nil when no sign-off names the result.
func DecisionInForce(list []SignOff, r SignOffResult) (inForce, own *SignOff) {
	var job, other *SignOff
	for i := range list {
		if !list[i].Target.NamesResult(r) {
			continue
		}
		if list[i].Target.Kind == SignOffTargetJob {
			job = &list[i]
		} else {
			other = &list[i]
		}
	}
	if job != nil {
		return job, other
	}
	return other, nil
}
