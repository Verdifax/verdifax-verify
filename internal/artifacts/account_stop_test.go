package artifacts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// recipeHash is the length-prefixed SHA-256 written out apart from
// lengthPrefixedHash, so the record's recipe is fixed by this test alone.
func recipeHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(strconv.Itoa(len(p)) + ":" + p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sealedStop(action, decidedBy string, mutate func(*AccountStop)) *AccountStop {
	s := &AccountStop{Format: AccountStopFormat, Action: action, DecidedBy: decidedBy, ChangedAt: "2026-11-17T18:00:00Z", Signal: testLink()}
	if decidedBy == DecidedByOwner {
		s.KeyID = 12
	}
	if action == StopActionStop {
		s.Scope = &StopScope{Signoffs: StopSignoffsAccept, Webhooks: StopWebhooksContinue}
	} else {
		s.LiftsSequence = 2
	}
	if mutate != nil {
		mutate(s)
	}
	s.AccountStopHash = s.ComputeHash()
	return s
}

// R312: the account-stop record's hash follows its published recipe, field
// by field, the optional parts behind their labels.
func TestAccountStopVector(t *testing.T) {
	stop := sealedStop(StopActionStop, DecidedByOwner, func(s *AccountStop) { s.Unsigned, s.RunsInProgress = StopUnsigned, 3 })
	want := recipeHash(AccountStopFormat, "stop", "owner", "12", "scope", "accept", "continue", "", "3", "0", "unsigned", StopUnsigned,
		"2026-11-17T18:00:00Z", "signal", "account-7", "4", testLink().PreviousSignalHash)
	if stop.AccountStopHash != want {
		t.Fatalf("stop hash %s, the recipe gives %s", stop.AccountStopHash, want)
	}
	resume := sealedStop(StopActionResume, DecidedByVerdifax, nil)
	want = recipeHash(AccountStopFormat, "resume", "verdifax_admin", "0", "no_scope", "", "0", "2", "no_signature",
		"2026-11-17T18:00:00Z", "signal", "account-7", "4", testLink().PreviousSignalHash)
	if resume.AccountStopHash != want || resume.Validate() != nil {
		t.Fatalf("resume hash %s, the recipe gives %s (%v)", resume.AccountStopHash, want, resume.Validate())
	}
	if got := StopSubject(StopActionStop, 12, stop.Scope, 0, ""); got != "stop key=12 signoffs=accept webhooks=continue reason_sha256=" {
		t.Fatalf("stop subject %q", got)
	}
	if got := StopSubject(StopActionResume, 12, nil, 9, ""); got != "resume key=12 lifts=9 reason_sha256=" {
		t.Fatalf("resume subject %q", got)
	}
	if stop.LeafHash() != ComputeReceiptLeafHashV3(AccountStopKind, "account-7", stop.AccountStopHash, 4, testLink().PreviousSignalHash) {
		t.Fatal("the leaf binds the record under account_stop")
	}
}

// R313: who may make which record: an owner's stop is signed or sealed
// unsigned, an owner's resume is always signed, a Verdifax record carries
// neither, and each record's shape is held.
func TestAccountStopShapes(t *testing.T) {
	signed := func(action string, lifts int64) func(*AccountStop) {
		return func(s *AccountStop) {
			s.LiftsSequence = lifts
			kind := SignalAccountStopped
			if action == StopActionResume {
				kind = SignalAccountResumed
			}
			s.OwnerSignature = ownerSign(kind, s.Subject())
		}
	}
	good := map[string]*AccountStop{
		"an unsigned owner stop": sealedStop(StopActionStop, DecidedByOwner, func(s *AccountStop) { s.Unsigned = StopUnsigned }),
		"a signed owner stop":    sealedStop(StopActionStop, DecidedByOwner, signed(StopActionStop, 0)),
		"a signed owner resume":  sealedStop(StopActionResume, DecidedByOwner, signed(StopActionResume, 2)),
		"a Verdifax stop":        sealedStop(StopActionStop, DecidedByVerdifax, nil),
		"a Verdifax resume":      sealedStop(StopActionResume, DecidedByVerdifax, nil),
	}
	for what, s := range good {
		if err := s.Validate(); err != nil {
			t.Errorf("%s must be valid: %v", what, err)
		}
	}
	bad := map[string]*AccountStop{
		"an unsigned owner resume":         sealedStop(StopActionResume, DecidedByOwner, func(s *AccountStop) { s.Unsigned = StopUnsigned }),
		"an owner stop with no statement":  sealedStop(StopActionStop, DecidedByOwner, nil),
		"an owner stop, another statement": sealedStop(StopActionStop, DecidedByOwner, func(s *AccountStop) { s.Unsigned = "trust me" }),
		"a Verdifax stop marked unsigned":  sealedStop(StopActionStop, DecidedByVerdifax, func(s *AccountStop) { s.Unsigned = StopUnsigned }),
		"a Verdifax stop with a signature": sealedStop(StopActionStop, DecidedByVerdifax, func(s *AccountStop) { s.OwnerSignature = ownerSign(SignalAccountStopped, s.Subject()) }),
		"a Verdifax stop naming a key":     sealedStop(StopActionStop, DecidedByVerdifax, func(s *AccountStop) { s.KeyID = 3 }),
		"an owner stop naming no key":      sealedStop(StopActionStop, DecidedByOwner, func(s *AccountStop) { s.KeyID, s.Unsigned = 0, StopUnsigned }),
		"a stop with no scope":             sealedStop(StopActionStop, DecidedByVerdifax, func(s *AccountStop) { s.Scope = nil }),
		"a stop with an unknown scope":     sealedStop(StopActionStop, DecidedByVerdifax, func(s *AccountStop) { s.Scope.Webhooks = "drop" }),
		"a resume with a scope":            sealedStop(StopActionResume, DecidedByVerdifax, func(s *AccountStop) { s.Scope = &StopScope{"accept", "continue"} }),
		"a resume naming no stop":          sealedStop(StopActionResume, DecidedByVerdifax, func(s *AccountStop) { s.LiftsSequence = 0 }),
		"a resume naming a later place":    sealedStop(StopActionResume, DecidedByVerdifax, func(s *AccountStop) { s.LiftsSequence = 4 }),
		"a resume counting runs":           sealedStop(StopActionResume, DecidedByVerdifax, func(s *AccountStop) { s.RunsInProgress = 1 }),
		"a stop naming a lift":             sealedStop(StopActionStop, DecidedByVerdifax, func(s *AccountStop) { s.LiftsSequence = 1 }),
		"a resume signed over a stop":      sealedStop(StopActionResume, DecidedByOwner, func(s *AccountStop) { s.OwnerSignature = ownerSign(SignalAccountStopped, s.Subject()) }),
		"a resume signed over another lift": sealedStop(StopActionResume, DecidedByOwner, func(s *AccountStop) {
			s.OwnerSignature = ownerSign(SignalAccountResumed, StopSubject(StopActionResume, 12, nil, 3, ""))
		}),
		"a malformed reason hash": sealedStop(StopActionStop, DecidedByVerdifax, func(s *AccountStop) { s.ReasonSHA256 = "abc" }),
		"an unknown action":       sealedStop("pause", DecidedByVerdifax, nil),
	}
	for what, s := range bad {
		if s.Validate() == nil {
			t.Errorf("%s must be refused", what)
		}
	}
}

// R316: the allowlist joins a key.created record's hash only when present,
// so a record without one hashes exactly as before; with one it is sealed
// sorted and only on a member key's key.created record.
func TestAKeyChangeAllowlistIsAbsentUnlessGranted(t *testing.T) {
	k := &KeyChange{Format: KeyChangeFormat, Action: SignalKeyCreated, DecidedBy: DecidedByOwner, KeyID: 9, KeyScope: KeyScopeRun,
		Name: "agent", ChangedAt: "2026-11-17T18:00:00Z", Signal: testLink()}
	before := recipeHash(KeyChangeFormat, SignalKeyCreated, DecidedByOwner, "9", KeyScopeRun, "", "agent", "2026-11-17T18:00:00Z",
		"signal", "account-7", "4", testLink().PreviousSignalHash)
	if k.ComputeHash() != before {
		t.Fatal("a key change without an allowlist must hash as before round 64")
	}
	k.AllowedTools = []string{"account_stop", "seal_decision"}
	with := recipeHash(KeyChangeFormat, SignalKeyCreated, DecidedByOwner, "9", KeyScopeRun, "", "agent", "2026-11-17T18:00:00Z",
		"allowed_tools", "2", "account_stop", "seal_decision", "signal", "account-7", "4", testLink().PreviousSignalHash)
	if k.ComputeHash() != with {
		t.Fatal("the allowlist joins behind its label and count")
	}
	k.KeyChangeHash = k.ComputeHash()
	if err := k.Validate(); err != nil {
		t.Fatalf("a member key's allowlist: %v", err)
	}
	for what, mutate := range map[string]func(*KeyChange){
		"unsorted":            func(c *KeyChange) { c.AllowedTools = []string{"seal_decision", "account_stop"} },
		"an unknown tool":     func(c *KeyChange) { c.AllowedTools = []string{"account_resume"} },
		"empty":               func(c *KeyChange) { c.AllowedTools = []string{} },
		"on a feed key":       func(c *KeyChange) { c.KeyScope = KeyScopeSignals },
		"on a key revocation": func(c *KeyChange) { c.Action = SignalKeyRevoked },
	} {
		c := *k
		mutate(&c)
		c.KeyChangeHash = c.ComputeHash()
		if c.Validate() == nil {
			t.Errorf("an allowlist %s must be refused", what)
		}
	}
}

// R318: the sign-off refusal's hash follows its recipe, it keeps the
// approver's signed attempt (a forged or altered attempt fails), and it names
// an earlier stop of its own account and the code ACCOUNT_STOPPED.
func TestSignOffRefusalVectorAndShape(t *testing.T) {
	target := SignOffTarget{Kind: SignOffTargetRecord, RunID: 5, Digest: strings.Repeat("c", 64)}
	build := func(mutate func(*SignOffRefusal)) *SignOffRefusal {
		r := &SignOffRefusal{Format: SignOffRefusalFormat, ChainID: "account-7", PreviousSignOffHash: NoPreviousSignOff, Target: target,
			Decision: SignOffApprove, ApproverKey: base64.StdEncoding.EncodeToString(testOwnerKey.Public().(ed25519.PublicKey)),
			ApproverID: 3, SignedAt: "2026-11-17T18:00:00Z", Nonce: strings.Repeat("0a", 16), StopSequence: 2,
			ReasonCode: StopReasonCode, RefusedAt: "2026-11-17T18:00:01Z", Signal: testLink()}
		r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(testOwnerKey, r.Preimage()))
		if mutate != nil {
			mutate(r)
		}
		r.SignOffRefusalHash = r.ComputeHash()
		return r
	}
	r := build(nil)
	want := recipeHash(SignOffRefusalFormat, "account-7", NoPreviousSignOff, SignOffTargetRecord, "5", strings.Repeat("c", 64), "",
		SignOffApprove, "", r.ApproverKey, "3", r.Signature, "2026-11-17T18:00:00Z", strings.Repeat("0a", 16), "2", StopReasonCode,
		"2026-11-17T18:00:01Z", "signal", "account-7", "4", testLink().PreviousSignalHash)
	if r.SignOffRefusalHash != want || r.Validate() != nil {
		t.Fatalf("refusal hash %s, the recipe gives %s (%v)", r.SignOffRefusalHash, want, r.Validate())
	}
	if r.LeafHash() != ComputeReceiptLeafHashV3(SignOffRefusalKind, "account-7", r.SignOffRefusalHash, 4, testLink().PreviousSignalHash) {
		t.Fatal("the leaf binds the record under signoff_refusal")
	}
	for what, mutate := range map[string]func(*SignOffRefusal){
		"an altered decision":     func(x *SignOffRefusal) { x.Decision = SignOffReject },
		"an altered target":       func(x *SignOffRefusal) { x.Target.RunID = 6 },
		"another reason":          func(x *SignOffRefusal) { x.ReasonCode = "RULE_DENIED" },
		"no stop":                 func(x *SignOffRefusal) { x.StopSequence = 0 },
		"a later stop":            func(x *SignOffRefusal) { x.StopSequence = 4 },
		"no approver":             func(x *SignOffRefusal) { x.ApproverID = 0 },
		"another account's place": func(x *SignOffRefusal) { x.Signal.Account = "account-8" },
		"an unknown format":       func(x *SignOffRefusal) { x.Format = "verdifax.signoff-refusal.v0" },
	} {
		if build(mutate).Validate() == nil {
			t.Errorf("a refusal with %s must be refused", what)
		}
	}
}
