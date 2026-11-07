package artifacts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func signedOff(t *testing.T) (*SignOff, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	note := sha256.Sum256([]byte("checked against the loan file"))
	s := &SignOff{Format: SignOffFormat, ChainID: "account-7", Sequence: 1, PreviousSignOffHash: NoPreviousSignOff,
		Target:   SignOffTarget{Kind: SignOffTargetRecord, RunID: 42, Digest: strings.Repeat("a", 64)},
		Decision: SignOffApprove, NoteHash: hex.EncodeToString(note[:]),
		ApproverKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		SignedAt:    "2026-11-07T12:00:00Z", Nonce: strings.Repeat("0f", 16), RecordedAt: "2026-11-07T12:00:01Z"}
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, s.Preimage()))
	s.SignOffHash = s.ComputeHash()
	return s, priv
}

// A genuine sign-off validates, its signature verifies over its own preimage,
// and its leaf is a known kind.
func TestASignOffValidatesAndItsSignatureCoversTheResult(t *testing.T) {
	s, priv := signedOff(t)
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(s.Signature)
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), s.Preimage(), sig) {
		t.Fatal("the signature does not verify over the preimage")
	}
	if err := ValidateReceiptLeafFields(SignOffKind, s.ChainID, s.SignOffHash); err != nil {
		t.Fatal(err)
	}
	if s.LeafHash() == "" {
		t.Fatal("no leaf")
	}
}

// Every signed value is in the preimage, so the signature cannot be moved to
// another account, result, place in the chain or decision; every field is in
// the hash.
func TestEverySignOffFieldIsSignedAndHashed(t *testing.T) {
	for name, change := range map[string]func(*SignOff){
		"chain":    func(s *SignOff) { s.ChainID = "account-8" },
		"previous": func(s *SignOff) { s.PreviousSignOffHash = strings.Repeat("b", 64) },
		"kind":     func(s *SignOff) { s.Target.Kind = SignOffTargetReceipt },
		"run":      func(s *SignOff) { s.Target.RunID = 43 },
		"digest":   func(s *SignOff) { s.Target.Digest = strings.Repeat("c", 64) },
		"job":      func(s *SignOff) { s.Target.JobID = "loan-1" },
		"decision": func(s *SignOff) { s.Decision = SignOffReject },
		"note":     func(s *SignOff) { s.NoteHash = "" },
		"signed":   func(s *SignOff) { s.SignedAt = "2026-11-07T12:00:02Z" },
		"nonce":    func(s *SignOff) { s.Nonce = strings.Repeat("1f", 16) },
	} {
		t.Run(name, func(t *testing.T) {
			s, priv := signedOff(t)
			before, hash := s.Preimage(), s.ComputeHash()
			change(s)
			if string(s.Preimage()) == string(before) {
				t.Fatal("the signature does not cover it")
			}
			sig, _ := base64.StdEncoding.DecodeString(s.Signature)
			if ed25519.Verify(priv.Public().(ed25519.PublicKey), s.Preimage(), sig) {
				t.Fatal("the old signature still verifies")
			}
			if s.ComputeHash() == hash {
				t.Fatal("the hash does not cover it")
			}
		})
	}
	for name, change := range map[string]func(*SignOff){
		"approver": func(s *SignOff) { s.ApproverKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
		"recorded": func(s *SignOff) { s.RecordedAt = "2026-11-07T12:00:09Z" },
	} {
		s, _ := signedOff(t)
		hash := s.ComputeHash()
		change(s)
		if s.ComputeHash() == hash {
			t.Fatalf("%s: the hash does not cover it", name)
		}
	}
}

// Shapes a sign-off must never have.
func TestStrangeSignOffsAreRefused(t *testing.T) {
	for name, change := range map[string]func(*SignOff){
		"format":           func(s *SignOff) { s.Format = "verdifax.signoff.v0" },
		"a key chain":      func(s *SignOff) { s.ChainID = "api-key-7" },
		"no sequence":      func(s *SignOff) { s.Sequence = 0 },
		"another kind":     func(s *SignOff) { s.Target.Kind = "bundle" },
		"no run":           func(s *SignOff) { s.Target.RunID = 0 },
		"a short digest":   func(s *SignOff) { s.Target.Digest = "abc" },
		"a job id alone":   func(s *SignOff) { s.Target.JobID = "loan-1" },
		"a job with no id": func(s *SignOff) { s.Target.Kind = SignOffTargetJob },
		"maybe":            func(s *SignOff) { s.Decision = "maybe" },
		"a note in text":   func(s *SignOff) { s.NoteHash = "checked" },
		"no key":           func(s *SignOff) { s.ApproverKey = "" },
		"a short nonce":    func(s *SignOff) { s.Nonce = "0f" },
		"no recorded time": func(s *SignOff) { s.RecordedAt = "" },
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := signedOff(t)
			change(s)
			if s.Validate() == nil {
				t.Fatal("accepted")
			}
		})
	}
}
