package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// sealHead makes Verdifax's head statement for a chain and logs it.
func sealHead(t *testing.T, l *testLog, account string, chain []artifacts.SignOff) *artifacts.SignOffHead {
	t.Helper()
	last := chain[len(chain)-1]
	at, _ := time.Parse(time.RFC3339, last.RecordedAt)
	h := &artifacts.SignOffHead{Format: artifacts.SignOffHeadFormat, ChainID: account, Sequence: last.Sequence,
		HeadHash: last.SignOffHash, StatedAt: at.Add(2 * time.Minute).Format(time.RFC3339)}
	h.HeadStatementHash = h.ComputeHash()
	l.integratedTime = at.Add(2*time.Minute + 20*time.Second).Unix()
	e := l.entry(t, strings.Repeat("0", 64), h.LeafHash())
	h.Anchor = &artifacts.ReceiptAnchor{Kind: artifacts.ReceiptAnchorKindV3, ReceiptKind: artifacts.SignOffHeadKind, ReceiptHash: h.HeadStatementHash,
		Backend: "rekor", LogEntryID: e.LogEntryID, LogID: e.LogID, LeafHashHex: e.LeafHashHex, LogIndex: e.LogIndex, TreeSize: e.TreeSize,
		RootHashHex: e.RootHashHex, InclusionPath: e.InclusionPath, Checkpoint: e.Checkpoint,
		SignedEntryTimestamp: e.SignedEntryTimestamp, IntegratedTime: e.IntegratedTime, EntryBody: e.EntryBody}
	return h
}

// history encodes sign-offs followed by extra entries, as the server serves it.
func history(t *testing.T, chain []artifacts.SignOff, extra ...any) []byte {
	t.Helper()
	items := make([]any, 0, len(chain)+len(extra))
	for i := range chain {
		items = append(items, chain[i])
	}
	return encode(t, append(items, extra...))
}

// Round 59, N16: a history ends with Verdifax's head statement on the public
// log, so a verifier can say it is complete as of the log's time, and a
// history cut short before a later sign-off fails.
func TestAHeadStatementShowsTheHistoryIsComplete(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	_, subject := signOffRecord(t)
	a := newApprover(t)
	target := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: subject.runID, Digest: subject.digest}
	chain := signOffChain(t, l, subject.account, a, []artifacts.SignOffTarget{target, target}, []string{artifacts.SignOffApprove, artifacts.SignOffReject})
	head := sealHead(t, l, subject.account, chain)

	whole := checkSignOffHistory(history(t, chain, head))
	if !whole.OK || whole.CompleteAsOf == "" {
		t.Fatalf("a whole history with its head: %+v", whole)
	}
	if plain := checkSignOffHistory(history(t, chain)); !plain.OK || plain.CompleteAsOf != "" {
		t.Fatalf("a history with no head verifies but is not complete: %+v", plain)
	}
	cut := checkSignOffHistory(history(t, chain[:1], head))
	if cut.OK || !strings.Contains(cut.Reason, "left out of the end") {
		t.Fatalf("a history cut short before its head's place must fail: %+v", cut)
	}
	if notLast := checkSignOffHistory(encode(t, []any{chain[0], head, chain[1]})); notLast.OK || !strings.Contains(notLast.Reason, "not its last entry") {
		t.Fatalf("a head that is not last must fail: %+v", notLast)
	}
	other := sealHead(t, l, "account-9", chain)
	if wrong := checkSignOffHistory(history(t, chain, other)); wrong.OK {
		t.Fatalf("another account's head must fail: %+v", wrong)
	}
	mock := *head
	mockAnchor := *head.Anchor
	mockAnchor.Backend = "mock"
	mock.Anchor = &mockAnchor
	if unlogged := checkSignOffHistory(history(t, chain, &mock)); unlogged.OK {
		t.Fatalf("a head not on the public log must fail: %+v", unlogged)
	}
	changed := *head
	changed.Sequence = 3
	if forged := checkSignOffHistory(history(t, chain, &changed)); forged.OK {
		t.Fatalf("a changed head must fail: %+v", forged)
	}
	if _, err := readChainItems(encode(t, []any{head}), reflectPolicyActivationForTest()); err == nil || !strings.Contains(err.Error(), "only a sign-off history") {
		t.Fatalf("a head in another chain's history must be refused: %v", err)
	}
}

func reflectPolicyActivationForTest() reflect.Type {
	return reflect.TypeOf(artifacts.PolicyActivation{})
}

// Round 59, N15: the sign-offs that name a record include a job sign-off on
// a job's final step; one left out of the sign-offs given fails whatever its
// kind, and on the final step the job's decision governs (N19).
func TestEveryKindOfSignOffOnAResultIsChecked(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	b, subject := signOffRecord(t)
	a := newApprover(t)
	record := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: subject.runID, Digest: subject.digest}
	job := artifacts.SignOffTarget{Kind: artifacts.SignOffTargetJob, RunID: subject.runID, Digest: subject.digest, JobID: "loan-9"}
	for name, pair := range map[string][2]artifacts.SignOffTarget{"job then job": {job, job}, "record then job": {record, job}, "job then record": {job, record}} {
		chain := signOffChain(t, l, subject.account, a, pair[:], []string{artifacts.SignOffApprove, artifacts.SignOffReject})
		r := verify(b)
		applySignOffFlags(r, b, writeTemp(t, "first.json", encode(t, chain[:1])), "", writeTemp(t, "whole.json", encode(t, chain)))
		if r.AllPassed || r.SignOffHistory == nil || !strings.Contains(r.SignOffHistory.Reason, "leave out") {
			t.Errorf("%s: a later sign-off left out of the given must fail: %+v", name, r.SignOffHistory)
		}
	}
	chain := signOffChain(t, l, subject.account, a, []artifacts.SignOffTarget{job, record}, []string{artifacts.SignOffApprove, artifacts.SignOffReject})
	r := verify(b)
	applySignOffFlags(r, b, writeTemp(t, "both.json", encode(t, chain)), "", writeTemp(t, "whole.json", encode(t, chain)))
	if !r.AllPassed || r.SignOffs.Latest != artifacts.SignOffApprove || r.SignOffs.OwnDecision != artifacts.SignOffReject {
		t.Fatalf("the job's decision governs the final step and the record's own is shown under it: %+v", r.SignOffs)
	}
	var raw []json.RawMessage
	_ = json.Unmarshal(encode(t, chain), &raw)
	if len(raw) != 2 {
		t.Fatal("fixture")
	}
}
