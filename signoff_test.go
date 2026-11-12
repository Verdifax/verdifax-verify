package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// approver is a test approver key.
type approver struct {
	pub  string
	priv ed25519.PrivateKey
}

func newApprover(t *testing.T) approver {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return approver{base64.StdEncoding.EncodeToString(pub), priv}
}

// signOffChain signs and logs one sign-off per target, linked in order, as the
// server records them.
func signOffChain(t *testing.T, l *testLog, account string, a approver, targets []artifacts.SignOffTarget, decisions []string) []artifacts.SignOff {
	t.Helper()
	out := make([]artifacts.SignOff, len(targets))
	previous := artifacts.NoPreviousSignOff
	start := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	for i, target := range targets {
		at := start.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		s := artifacts.SignOff{Format: artifacts.SignOffFormat, ChainID: account, Sequence: int64(i + 1), PreviousSignOffHash: previous,
			Target: target, Decision: decisions[i], ApproverKey: a.pub, SignedAt: at,
			Nonce: strings.Repeat("0", 31) + string(rune('0'+i)), RecordedAt: at}
		s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(a.priv, s.Preimage()))
		sealSignOff(t, l, &s)
		out[i] = s
		previous = s.SignOffHash
	}
	return out
}

// sealSignOff hashes a sign-off and logs it, as a forger with the log could.
func sealSignOff(t *testing.T, l *testLog, s *artifacts.SignOff) {
	t.Helper()
	s.SignOffHash = s.ComputeHash()
	at, clockErr := time.Parse(time.RFC3339, s.RecordedAt)
	if clockErr != nil {
		t.Fatal(clockErr)
	}
	l.integratedTime = at.Add(20 * time.Second).Unix()
	e := l.entry(t, strings.Repeat("0", 64), s.LeafHash())
	s.Anchor = &artifacts.ReceiptAnchor{Kind: artifacts.ReceiptAnchorKindV3, ReceiptKind: artifacts.SignOffKind, ReceiptHash: s.SignOffHash,
		Backend: "rekor", LogEntryID: e.LogEntryID, LogID: e.LogID, LeafHashHex: e.LeafHashHex, LogIndex: e.LogIndex, TreeSize: e.TreeSize,
		RootHashHex: e.RootHashHex, InclusionPath: e.InclusionPath, Checkpoint: e.Checkpoint,
		SignedEntryTimestamp: e.SignedEntryTimestamp, IntegratedTime: e.IntegratedTime, EntryBody: e.EntryBody}
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The record a sign-off names: an account record and its anchored digest.
func signOffRecord(t *testing.T) (*artifacts.AuditBundle, signOffSubject) {
	t.Helper()
	b := accountBundle(t, strings.Repeat("a", 64))
	r := verify(b)
	if !r.BundleAnchor.Match || b.BundleAnchor == nil {
		t.Fatal("the fixture's anchored digest does not verify")
	}
	return b, signOffSubject{account: b.Nrep.AccountID, kind: artifacts.SignOffTargetRecord, runID: int64(b.RunID), digest: b.BundleAnchor.AnchoredDigest}
}

func TestASignOffOnTheRecordVerifiesAndTheLatestDecides(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	_, subject := signOffRecord(t)
	a := newApprover(t)
	target := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: subject.runID, Digest: subject.digest}
	chain := signOffChain(t, l, subject.account, a, []artifacts.SignOffTarget{target, target}, []string{artifacts.SignOffReject, artifacts.SignOffApprove})
	c := checkSignOffs(encode(t, chain), subject)
	if !c.OK || c.Latest != artifacts.SignOffApprove || c.LatestApprover != a.pub || !c.Entries[0].Superseded || c.Entries[1].Superseded {
		t.Fatalf("%+v", c)
	}
	if c.LatestMeaning != "the approver agrees with this record's result" {
		t.Fatalf("meaning %q", c.LatestMeaning)
	}
	printSignOffs(&c, nil)
}

// R159: a decision means the same on every kind of result. Approve agrees
// with what the result shows, a receipt's stop included; reject judges it
// wrong. The demo once signed reject on a correct refusal meaning "the
// draft stays rejected", and reject on a wrong halt meaning "this stop was
// wrong".
func TestADecisionMeansTheSameOnEveryKindOfResult(t *testing.T) {
	for _, c := range []struct{ decision, kind, want string }{
		{artifacts.SignOffApprove, artifacts.SignOffTargetReceipt, "the approver agrees with the stop this receipt records"},
		{artifacts.SignOffReject, artifacts.SignOffTargetReceipt, "the approver judges the stop this receipt records wrong"},
		{artifacts.SignOffApprove, artifacts.SignOffTargetJob, "the approver agrees with this job's result"},
		{artifacts.SignOffReject, artifacts.SignOffTargetRecord, "the approver judges this record's result wrong"},
	} {
		if got := signOffMeaning(c.decision, c.kind); got != c.want {
			t.Errorf("%s on a %s: %q, want %q", c.decision, c.kind, got, c.want)
		}
	}
}

// A sign-off must name this exact result, in this account, and verify.
func TestASignOffForAnotherResultFails(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	_, subject := signOffRecord(t)
	a := newApprover(t)
	good := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: subject.runID, Digest: subject.digest}
	for name, c := range map[string]struct {
		account string
		target  artifacts.SignOffTarget
	}{
		"another account": {"account-8", good},
		"another run":     {subject.account, artifacts.SignOffTarget{Kind: good.Kind, RunID: good.RunID + 1, Digest: good.Digest}},
		"another digest":  {subject.account, artifacts.SignOffTarget{Kind: good.Kind, RunID: good.RunID, Digest: strings.Repeat("9", 64)}},
		"a receipt":       {subject.account, artifacts.SignOffTarget{Kind: artifacts.SignOffTargetReceipt, RunID: good.RunID, Digest: good.Digest}},
	} {
		t.Run(name, func(t *testing.T) {
			chain := signOffChain(t, l, c.account, a, []artifacts.SignOffTarget{c.target}, []string{artifacts.SignOffApprove})
			if got := checkSignOffs(encode(t, chain), subject); got.OK {
				t.Fatalf("passed: %+v", got)
			}
		})
	}
	// A job sign-off names its final step, which is this record.
	job := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetJob, RunID: good.RunID, Digest: good.Digest, JobID: "loan-1"}
	if got := checkSignOffs(encode(t, signOffChain(t, l, subject.account, a, []artifacts.SignOffTarget{job}, []string{artifacts.SignOffApprove})), subject); !got.OK {
		t.Fatalf("a job sign-off on its final step failed: %s", got.Reason)
	}
}

// A changed decision, a forged signature, a removed entry or an unknown
// field all fail.
func TestAChangedSignOffFails(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	_, subject := signOffRecord(t)
	a := newApprover(t)
	target := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: subject.runID, Digest: subject.digest}
	for name, change := range map[string]func(*artifacts.SignOff){
		"the decision, hash recomputed": func(s *artifacts.SignOff) { s.Decision = artifacts.SignOffReject; s.SignOffHash = s.ComputeHash() },
		"another signer":                func(s *artifacts.SignOff) { s.ApproverKey = newApprover(t).pub; s.SignOffHash = s.ComputeHash() },
		"no public-log entry":           func(s *artifacts.SignOff) { s.Anchor = nil },
		"the entry of another":          func(s *artifacts.SignOff) { s.Anchor.ReceiptHash = strings.Repeat("1", 64) },
		"logged as a policy change":     func(s *artifacts.SignOff) { s.Anchor.ReceiptKind = artifacts.PolicyActivationKind },
	} {
		t.Run(name, func(t *testing.T) {
			chain := signOffChain(t, l, subject.account, a, []artifacts.SignOffTarget{target}, []string{artifacts.SignOffApprove})
			change(&chain[0])
			if got := checkSignOffs(encode(t, chain), subject); got.OK {
				t.Fatal("passed")
			}
		})
	}
	for _, text := range []string{``, `[]`, `{}`, `[{"format":"x","format":"y"}]`, `[{"unknown":1}]`} {
		if got := checkSignOffs([]byte(text), subject); got.OK {
			t.Errorf("%q passed", text)
		}
	}
	if got := checkSignOffs(encode(t, signOffChain(t, l, subject.account, a, []artifacts.SignOffTarget{target}, []string{artifacts.SignOffApprove})),
		signOffSubject{kind: subject.kind, runID: subject.runID, digest: subject.digest}); got.OK {
		t.Fatal("a sign-off passed on a record that names no account")
	}
}

// --approver-key passes only for the key that made the decision in force.
func TestTheApproverKeyIsPinned(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	_, subject := signOffRecord(t)
	a, other := newApprover(t), newApprover(t)
	target := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: subject.runID, Digest: subject.digest}
	data := encode(t, signOffChain(t, l, subject.account, a, []artifacts.SignOffTarget{target}, []string{artifacts.SignOffApprove}))
	right, wrong := writeTemp(t, "a.txt", []byte(a.pub+"\n")), writeTemp(t, "b.txt", []byte(other.pub))
	c := checkSignOffs(data, subject)
	pinApprover(&c, right)
	if !c.OK || !c.ApproverPinned {
		t.Fatalf("%+v", c)
	}
	c = checkSignOffs(data, subject)
	pinApprover(&c, wrong)
	if c.OK {
		t.Fatal("another approver's key passed")
	}
}

// The account's history: every link, one account; a removed, reordered or
// mixed-in sign-off fails. A later decision supersedes an earlier one.
func TestTheSignOffHistoryIsWhole(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	a := newApprover(t)
	one := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: 1, Digest: strings.Repeat("a", 64)}
	two := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetReceipt, RunID: 2, Digest: strings.Repeat("b", 64)}
	chain := signOffChain(t, l, "account-7", a, []artifacts.SignOffTarget{one, two, one}, []string{artifacts.SignOffApprove, artifacts.SignOffReject, artifacts.SignOffReject})
	c := checkSignOffHistory(encode(t, chain))
	if !c.OK || len(c.Entries) != 3 || !c.Entries[0].Superseded || c.Entries[1].Superseded || c.Entries[2].Superseded {
		t.Fatalf("%+v", c)
	}
	printSignOffs(nil, &c)
	for name, cut := range map[string][]artifacts.SignOff{
		"one removed": {chain[0], chain[2]},
		"reordered":   {chain[1], chain[0], chain[2]},
		"first gone":  {chain[1], chain[2]},
	} {
		if got := checkSignOffHistory(encode(t, cut)); got.OK {
			t.Errorf("%s passed", name)
		}
	}
	mixed := signOffChain(t, l, "account-8", a, []artifacts.SignOffTarget{one, two}, []string{artifacts.SignOffApprove, artifacts.SignOffApprove})
	if got := checkSignOffHistory(encode(t, []artifacts.SignOff{chain[0], mixed[1]})); got.OK {
		t.Error("another account's sign-off passed in the history")
	}
	path := writeTemp(t, "history.json", encode(t, chain))
	if code := runSignOffHistoryMode(path, true); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if code := runSignOffHistoryMode(writeTemp(t, "cut.json", encode(t, []artifacts.SignOff{chain[0], chain[2]})), true); code != 1 {
		t.Fatalf("a cut history gave exit %d", code)
	}
	if code := runSignOffHistoryMode(path+"x", true); code != 2 {
		t.Fatalf("a missing file gave exit %d", code)
	}
}

// --signoff and --signoff-history together: a sign-off given for the record
// must be in the account's history.
func TestASignOffMustBeInTheHistoryGiven(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	b, subject := signOffRecord(t)
	a := newApprover(t)
	target := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: subject.runID, Digest: subject.digest}
	other := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: subject.runID + 5, Digest: strings.Repeat("c", 64)}
	chain := signOffChain(t, l, subject.account, a, []artifacts.SignOffTarget{other, target}, []string{artifacts.SignOffApprove, artifacts.SignOffApprove})
	given := writeTemp(t, "given.json", encode(t, chain[1:]))
	whole := writeTemp(t, "whole.json", encode(t, chain))
	r := verify(b)
	applySignOffFlags(r, b, given, "", whole)
	if !r.AllPassed || !r.SignOffs.OK || !r.SignOffHistory.OK {
		t.Fatalf("%+v %+v", r.SignOffs, r.SignOffHistory)
	}
	short := writeTemp(t, "short.json", encode(t, chain[:1]))
	r = verify(b)
	applySignOffFlags(r, b, given, "", short)
	if r.AllPassed {
		t.Fatal("a sign-off missing from the history passed")
	}
	r = verify(b)
	applySignOffFlags(r, b, "", writeTemp(t, "k.txt", []byte(a.pub)), "")
	if r.AllPassed {
		t.Fatal("--approver-key alone passed")
	}
}

// --signoff and --signoff-history together: a later decision on the record
// that the sign-offs given leave out fails, so an earlier approval cannot be
// shown as the decision in force; and the history must be the record's
// account's, matched by each sign-off's own hash.
func TestALaterSignOffLeftOutOfTheGivenFails(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	b, subject := signOffRecord(t)
	a := newApprover(t)
	target := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: subject.runID, Digest: subject.digest}
	chain := signOffChain(t, l, subject.account, a, []artifacts.SignOffTarget{target, target}, []string{artifacts.SignOffApprove, artifacts.SignOffReject})
	whole := writeTemp(t, "whole.json", encode(t, chain))
	r := verify(b)
	applySignOffFlags(r, b, writeTemp(t, "both.json", encode(t, chain)), "", whole)
	if !r.AllPassed || r.SignOffs.Latest != artifacts.SignOffReject {
		t.Fatalf("the whole list: %+v %+v", r.SignOffs, r.SignOffHistory)
	}
	r = verify(b)
	applySignOffFlags(r, b, writeTemp(t, "first.json", encode(t, chain[:1])), "", whole)
	if r.AllPassed || r.SignOffHistory == nil || !strings.Contains(r.SignOffHistory.Reason, "leave out") {
		t.Fatalf("an approval with the later reject left out passed: %+v", r.SignOffHistory)
	}
	elsewhere := signOffChain(t, l, "account-9", a, []artifacts.SignOffTarget{target, target}, []string{artifacts.SignOffApprove, artifacts.SignOffReject})
	r = verify(b)
	applySignOffFlags(r, b, writeTemp(t, "both2.json", encode(t, chain)), "", writeTemp(t, "other.json", encode(t, elsewhere)))
	if r.AllPassed || r.SignOffHistory == nil || !strings.Contains(r.SignOffHistory.Reason, "belongs to account-9") {
		t.Fatalf("another account's history passed: %+v", r.SignOffHistory)
	}
}
