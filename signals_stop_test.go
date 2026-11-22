package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Round 64, part 2: account stops, sign-offs refused during a stop, passed
// response targets and tool allowlists in the signal feed.

const (
	stopOwnerKeyID  = int64(11)
	stopMemberKeyID = int64(12)
	stopApproverID  = int64(13)
)

// stopApprover signs the test feeds' sign-offs and refused sign-offs.
var stopApprover = ed25519.NewKeyFromSeed([]byte(strings.Repeat("a", 32)))

func stopApproverKey() string {
	return base64.StdEncoding.EncodeToString(stopApprover.Public().(ed25519.PublicKey))
}

// memberKeyCreated adds a member key with a tool allowlist.
func (f *feedBuilder) memberKeyCreated(keyID int64, tools []string) {
	link, at := f.next()
	k := artifacts.KeyChange{Format: artifacts.KeyChangeFormat, Action: artifacts.SignalKeyCreated, DecidedBy: artifacts.DecidedByOwner, KeyID: keyID,
		KeyScope: artifacts.KeyScopeRun, Name: "an agent", ChangedAt: at.Format(time.RFC3339Nano), Signal: link, AllowedTools: tools}
	k.KeyChangeHash = k.ComputeHash()
	k.Anchor = f.anchor(artifacts.KeyChangeKind, k.KeyChangeHash, k.LeafHash(), at)
	f.add(artifacts.SignalKeyCreated, link, k.KeyChangeHash, 0, k)
}

// approverRegistered adds the test approver's registration.
func (f *feedBuilder) approverRegistered() {
	link, at := f.next()
	k := artifacts.KeyChange{Format: artifacts.KeyChangeFormat, Action: artifacts.SignalApproverRegistered, DecidedBy: artifacts.DecidedByOwner,
		KeyID: stopApproverID, KeyScope: artifacts.KeyScopeApprover, PublicKey: stopApproverKey(), Name: "approver",
		ChangedAt: at.Format(time.RFC3339Nano), Signal: link}
	k.KeyChangeHash = k.ComputeHash()
	k.Anchor = f.anchor(artifacts.KeyChangeKind, k.KeyChangeHash, k.LeafHash(), at)
	f.add(artifacts.SignalApproverRegistered, link, k.KeyChangeHash, 0, k)
}

// approverRevoked adds the test approver's revocation.
func (f *feedBuilder) approverRevoked() {
	link, at := f.next()
	k := artifacts.KeyChange{Format: artifacts.KeyChangeFormat, Action: artifacts.SignalApproverRevoked, DecidedBy: artifacts.DecidedByOwner,
		KeyID: stopApproverID, KeyScope: artifacts.KeyScopeApprover, PublicKey: stopApproverKey(), Name: "approver",
		ChangedAt: at.Format(time.RFC3339Nano), Signal: link}
	k.KeyChangeHash = k.ComputeHash()
	k.Anchor = f.anchor(artifacts.KeyChangeKind, k.KeyChangeHash, k.LeafHash(), at)
	f.add(artifacts.SignalApproverRevoked, link, k.KeyChangeHash, 0, k)
}

// stopAccount adds a stop. holder is owner or verdifax; keyID the key that
// asked (owner's stops only); signed seals the owner's request-key
// signature, else the unsigned statement.
func (f *feedBuilder) stopAccount(holder string, keyID int64, signoffs string, runs int64, signed bool, mutate func(*artifacts.AccountStop)) int64 {
	link, at := f.next()
	s := artifacts.AccountStop{Format: artifacts.AccountStopFormat, Action: artifacts.StopActionStop, DecidedBy: artifacts.DecidedByOwner, KeyID: keyID,
		Scope: &artifacts.StopScope{Signoffs: signoffs, Webhooks: artifacts.StopWebhooksContinue}, RunsInProgress: runs,
		ChangedAt: at.Format(time.RFC3339Nano), Signal: link}
	if holder == "verdifax" {
		s.DecidedBy, s.KeyID = artifacts.DecidedByVerdifax, 0
	} else if signed {
		s.OwnerSignature = ownerSignature(artifacts.SignalAccountStopped, s.Subject())
	} else {
		s.Unsigned = artifacts.StopUnsigned
	}
	if mutate != nil {
		mutate(&s)
	}
	s.AccountStopHash = s.ComputeHash()
	s.Anchor = f.anchor(artifacts.AccountStopKind, s.AccountStopHash, s.LeafHash(), at)
	f.add(artifacts.SignalAccountStopped, link, s.AccountStopHash, 0, s)
	return link.Sequence
}

// resumeAccount adds a lift of the stop at lifts.
func (f *feedBuilder) resumeAccount(holder string, keyID, lifts int64, mutate func(*artifacts.AccountStop)) {
	link, at := f.next()
	s := artifacts.AccountStop{Format: artifacts.AccountStopFormat, Action: artifacts.StopActionResume, DecidedBy: artifacts.DecidedByOwner, KeyID: keyID,
		LiftsSequence: lifts, ChangedAt: at.Format(time.RFC3339Nano), Signal: link}
	if holder == "verdifax" {
		s.DecidedBy, s.KeyID = artifacts.DecidedByVerdifax, 0
	} else {
		s.OwnerSignature = ownerSignature(artifacts.SignalAccountResumed, s.Subject())
	}
	if mutate != nil {
		mutate(&s)
	}
	s.AccountStopHash = s.ComputeHash()
	s.Anchor = f.anchor(artifacts.AccountStopKind, s.AccountStopHash, s.LeafHash(), at)
	f.add(artifacts.SignalAccountResumed, link, s.AccountStopHash, 0, s)
}

// denyRun adds a refused run; stopped seals the stop's rule and code.
func (f *feedBuilder) denyRun(stopped bool, policyHash string) {
	link, at := f.next()
	f.runID++
	d := &artifacts.DenyReceipt{Version: "vfa.deny_receipt.v1", AnchorRequired: true, EnvelopeID: "env-" + strconv.FormatInt(f.runID, 10),
		PolicyHash: policyHash, EvaluationHash: strings.Repeat("9", 64), FiredRuleID: "no-claims", DecisionReasonCode: "RULE_DENIED",
		EvaluatorVersion: "pepg-0.1.0", DenyClock: at.Format(time.RFC3339Nano)}
	if stopped {
		d.FiredRuleID, d.DecisionReasonCode = artifacts.StopRuleID, artifacts.StopReasonCode
	}
	if _, err := artifacts.BuildDenyReceiptHash(d); err != nil {
		f.t.Fatal(err)
	}
	ctx := &artifacts.ReceiptContext{Request: artifacts.SealedRequestFields{PayloadHash: strings.Repeat("1", 64), ProgramID: strings.Repeat("2", 64),
		RouteID: "route-a", RegistryRecordHash: strings.Repeat("3", 64)}, AccountID: feedAccount, Signal: &link}
	leaf := artifacts.ComputeReceiptLeafHashV3("deny_receipt", d.EnvelopeID, d.Hash, f.runID, ctx.Hash())
	doc := artifacts.ReceiptDocument{OK: true, RunID: f.runID, DenyReceipt: d, ReceiptContext: ctx, ReceiptAnchor: f.anchor("deny_receipt", d.Hash, leaf, at)}
	f.add(artifacts.SignalRunRefused, link, d.Hash, f.runID, doc)
}

// runSealedTarget adds a successful run whose rule requires a sign-off and
// seals target; it returns its feed place.
func (f *feedBuilder) runSealedTarget(target *artifacts.SealedTarget) int64 {
	link, at := f.next()
	f.runID++
	r := artifacts.RunSealed{Format: artifacts.RunSealedFormat, RunID: f.runID, RecordHash: strings.Repeat("7", 64),
		SealedAt: at.Format(time.RFC3339Nano), SignOffRequired: true, SignOffTarget: target, Signal: link}
	r.RunSealedHash = r.ComputeHash()
	r.Anchor = f.anchor(artifacts.RunSealedKind, r.RunSealedHash, r.LeafHash(), at)
	f.add(artifacts.SignalRunSealed, link, r.RunSealedHash, f.runID, r)
	return link.Sequence
}

// approverSignOff is the test approver's signed sign-off on a run's record.
func approverSignOff(runID int64, decision, signedAt string) artifacts.SignOff {
	s := artifacts.SignOff{Format: artifacts.SignOffFormat, ChainID: feedAccount, Sequence: 1, PreviousSignOffHash: artifacts.NoPreviousSignOff,
		Target:   artifacts.SignOffTarget{Kind: artifacts.SignOffTargetRecord, RunID: runID, Digest: strings.Repeat("6", 64)},
		Decision: decision, ApproverKey: stopApproverKey(), SignedAt: signedAt, Nonce: strings.Repeat("0", 32)}
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(stopApprover, s.Preimage()))
	return s
}

// recordSignOff adds the test approver's sign-off on a run's record.
func (f *feedBuilder) recordSignOff(runID int64, decision string) {
	link, at := f.next()
	s := approverSignOff(runID, decision, at.Format(time.RFC3339))
	s.RecordedAt, s.Signal = at.Format(time.RFC3339), &link
	s.SignOffHash = s.ComputeHash()
	s.Anchor = f.anchor(artifacts.SignOffKind, s.SignOffHash, s.LeafHash(), at)
	f.add(artifacts.SignalSignOffRecorded, link, s.SignOffHash, runID, s)
}

// signOffRefused adds a sign-off refused under the stop at stopSeq.
func (f *feedBuilder) signOffRefused(runID, stopSeq int64, mutate func(*artifacts.SignOffRefusal)) {
	link, at := f.next()
	s := approverSignOff(runID, artifacts.SignOffApprove, at.Format(time.RFC3339))
	r := artifacts.SignOffRefusal{Format: artifacts.SignOffRefusalFormat, ChainID: feedAccount, PreviousSignOffHash: s.PreviousSignOffHash,
		Target: s.Target, Decision: s.Decision, ApproverKey: s.ApproverKey, ApproverID: stopApproverID, Signature: s.Signature, SignedAt: s.SignedAt,
		Nonce: s.Nonce, StopSequence: stopSeq, ReasonCode: artifacts.StopReasonCode, RefusedAt: at.Format(time.RFC3339Nano), Signal: link}
	if mutate != nil {
		mutate(&r)
	}
	r.SignOffRefusalHash = r.ComputeHash()
	r.Anchor = f.anchor(artifacts.SignOffRefusalKind, r.SignOffRefusalHash, r.LeafHash(), at)
	f.add(artifacts.SignalSignOffRefused, link, r.SignOffRefusalHash, runID, r)
}

// targetPassed adds the passed-target record of the record at resultSeq;
// anchorShift moves its public-log time.
func (f *feedBuilder) targetPassed(resultSeq int64, mutate func(*artifacts.SignOffTargetPassed), anchorShift time.Duration) {
	link, at := f.next()
	var result signalCloudEvent
	for _, e := range f.events {
		if e.Data.Sequence == resultSeq {
			result = e
		}
	}
	var rs artifacts.RunSealed
	if err := json.Unmarshal(result.Data.Entry, &rs); err != nil {
		f.t.Fatal(err)
	}
	start := time.Unix(rs.Anchor.IntegratedTime, 0).UTC().Format(time.RFC3339Nano)
	r := artifacts.SignOffTargetPassed{Format: artifacts.SignOffTargetPassedFormat, ResultKind: artifacts.TargetResultRecord, RunID: rs.RunID,
		ResultSequence: resultSeq, ResultHash: rs.RunSealedHash, Source: artifacts.TargetSourceSignOff, Within: rs.SignOffTarget.Within,
		Compare: rs.SignOffTarget.Compare, Notice: rs.SignOffTarget.Notice, StartBasis: artifacts.TargetStartPublicLog, Start: start,
		Statement: artifacts.SignOffTargetStatement, StatedAt: at.Format(time.RFC3339Nano), Signal: link}
	if mutate != nil {
		mutate(&r)
	}
	r.Deadline, _ = artifacts.TargetDeadline(r.Start, r.Within)
	r.TargetPassedHash = r.ComputeHash()
	r.Anchor = f.anchor(artifacts.SignOffTargetKind, r.TargetPassedHash, r.LeafHash(), at.Add(anchorShift))
	f.add(artifacts.SignalSignOffTargetPassed, link, r.TargetPassedHash, rs.RunID, r)
}

// stopFeedStart opens a stop test feed: the owner key, its request key, a
// member key with the given tools, and the test approver.
func stopFeedStart(t *testing.T, tools []string) *feedBuilder {
	f := newFeedBuilder(t)
	f.byVerdifax = true
	f.keyChangeFor(artifacts.SignalKeyCreated, artifacts.KeyScopeOwner, stopOwnerKeyID)
	f.byVerdifax = false
	f.requestKeyChange(artifacts.AccountRequestKeyRegistered, stopOwnerKeyID, base64.StdEncoding.EncodeToString(ownerKey.Public().(ed25519.PublicKey)), nil)
	f.memberKeyCreated(stopMemberKeyID, tools)
	f.approverRegistered()
	return f
}

// checkStopFeed checks a test feed with its head, at a time just after it.
func checkStopFeed(t *testing.T, f *feedBuilder, documents map[string][]byte) SignalFeedCheck {
	t.Helper()
	h := f.head()
	before := checkClock
	checkClock = func() time.Time { return time.Unix(h.Anchor.IntegratedTime, 0).Add(time.Minute) }
	t.Cleanup(func() { checkClock = before })
	return checkSignalFeedWith(pageWithHead(t, f.events, h), nil, nil, documents)
}

var grantedStop = []string{artifacts.AgentStopPermission, "read_feed"}

// R340: a feed with both holds, a member key's granted stop, a run that
// finishes after the stop, refusals inside it and both lifts verifies, and
// the report states each stopped period as sealed.
func TestAStoppedFeedVerifiesAndReportsEachPeriod(t *testing.T) {
	f := stopFeedStart(t, grantedStop)
	f.runSealedTarget(nil)
	record := f.runID
	owner := f.stopAccount("owner", stopMemberKeyID, artifacts.StopSignoffsRefuse, 1, false, nil)
	f.runSealed()
	f.denyRun(true, strings.Repeat("4", 64))
	verdifax := f.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
	f.signOffRefused(record, owner, nil)
	f.denyRun(true, strings.Repeat("4", 64))
	f.resumeAccount("verdifax", 0, verdifax, nil)
	f.resumeAccount("owner", stopOwnerKeyID, owner, nil)
	f.recordSignOff(record, artifacts.SignOffApprove)
	f.runSealed()
	c := checkStopFeed(t, f, nil)
	if !c.OK {
		t.Fatalf("a sound stopped feed fails: %s", c.Reason)
	}
	if len(c.StoppedPeriods) != 2 || c.SignOffsRefused != 1 {
		t.Fatalf("periods %+v, refused sign-offs %d", c.StoppedPeriods, c.SignOffsRefused)
	}
	o, v := c.StoppedPeriods[0], c.StoppedPeriods[1]
	if !o.ByMemberKey || o.Unsigned != artifacts.StopUnsigned || o.RunsRefused != 2 || o.SignOffsRefused != 1 || o.RunsEndedAfter != 1 || o.ResumeSequence == 0 ||
		v.Holder != "verdifax" || v.RunsRefused != 1 || v.SignOffsRefused != 1 || v.ResumeSequence == 0 {
		t.Fatalf("periods %+v %+v", o, v)
	}
	line := stopPeriodLine(&o, "")
	for _, want := range []string{"unsigned: the server's word", "member key 12", "sign-offs refuse", "1 run(s) in progress", "2 run(s) and 1 sign-off(s) refused"} {
		if !strings.Contains(line, want) {
			t.Errorf("period line %q lacks %q", line, want)
		}
	}
	if tools := c.Entries[2].AllowedTools; len(tools) != 2 || tools[0] != artifacts.AgentStopPermission {
		t.Errorf("the key's tool allowlist is not reported: %v", tools)
	}
	for _, e := range c.Entries {
		if e.Kind == artifacts.SignalSignOffRefused && !strings.Contains(e.SignOffRefused, "a registered approver key") {
			t.Errorf("refusal line %q", e.SignOffRefused)
		}
	}
	// A resume is read alone, with no other round 64 fact in the feed: the
	// release setting it was sealed under is not the feed's to show.
	g := stopFeedStart(t, nil)
	stop := g.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
	g.resumeAccount("verdifax", 0, stop, nil)
	if c := checkStopFeed(t, g, nil); !c.OK {
		t.Fatalf("a stop and its lift alone fail: %s", c.Reason)
	}
}

// R340: every break of the stop rules fails the feed, and says why.
func TestABrokenStopFeedFails(t *testing.T) {
	signer, _ := keyOfSeed("o")
	customer := strings.Replace(round64Policy, `"rule_id":"reviewed-claims"`, `"rule_id":"account_stop"`, 1)
	customerHash, hashErr := policyHashOf(customer)
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	sum := sha256.Sum256([]byte(customer))
	customerDocs := map[string][]byte{hex.EncodeToString(sum[:]): []byte(customer)}
	for name, b := range map[string]struct {
		tools []string
		build func(f *feedBuilder)
		docs  map[string][]byte
		want  string
	}{
		"a resume by the other holder": {grantedStop, func(f *feedBuilder) {
			s := f.stopAccount("owner", stopOwnerKeyID, artifacts.StopSignoffsAccept, 0, true, nil)
			f.resumeAccount("verdifax", 0, s, nil)
		}, nil, "each holder lifts only its own stop"},
		"a resume naming no stop": {grantedStop, func(f *feedBuilder) {
			f.runSealed()
			f.resumeAccount("verdifax", 0, f.events[len(f.events)-1].Data.Sequence, nil)
		}, nil, "not a stop"},
		"a resume of a lifted stop": {grantedStop, func(f *feedBuilder) {
			s := f.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
			f.resumeAccount("verdifax", 0, s, nil)
			f.resumeAccount("verdifax", 0, s, nil)
		}, nil, "already lifted"},
		"an unsigned owner resume": {grantedStop, func(f *feedBuilder) {
			s := f.stopAccount("owner", stopOwnerKeyID, artifacts.StopSignoffsAccept, 0, true, nil)
			f.resumeAccount("owner", stopOwnerKeyID, s, func(r *artifacts.AccountStop) { r.OwnerSignature = nil })
		}, nil, "the owner's resume carries the owner's request-key signature"},
		"a Verdifax stop under the owner's block": {grantedStop, func(f *feedBuilder) {
			f.ownerSetting(artifacts.AccountSettingVerdifaxStop, artifacts.SettingBlocked, signer)
			f.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
		}, nil, "blocked Verdifax stops"},
		"a member key stop with no grant": {[]string{"read_feed"}, func(f *feedBuilder) {
			f.stopAccount("owner", stopMemberKeyID, artifacts.StopSignoffsAccept, 0, false, nil)
		}, nil, "seals no account_stop grant"},
		"a member key stop with no allowlist": {nil, func(f *feedBuilder) {
			f.stopAccount("owner", stopMemberKeyID, artifacts.StopSignoffsAccept, 0, false, nil)
		}, nil, "seals no account_stop grant"},
		"a signed member key stop": {grantedStop, func(f *feedBuilder) {
			f.stopAccount("owner", stopMemberKeyID, artifacts.StopSignoffsAccept, 0, true, nil)
		}, nil, "a member key's stop is sealed unsigned"},
		"a member key resume": {grantedStop, func(f *feedBuilder) {
			s := f.stopAccount("owner", stopMemberKeyID, artifacts.StopSignoffsAccept, 0, false, nil)
			f.resumeAccount("owner", stopMemberKeyID, s, nil)
		}, nil, "a member key can never resume"},
		"a run refused for a stop with none standing": {grantedStop, func(f *feedBuilder) {
			f.denyRun(true, strings.Repeat("4", 64))
		}, nil, "no stop stood on the account then"},
		"a run refused for a stop after the lift": {grantedStop, func(f *feedBuilder) {
			s := f.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
			f.resumeAccount("verdifax", 0, s, nil)
			f.denyRun(true, strings.Repeat("4", 64))
		}, nil, "no stop stood on the account then"},
		"a stop's words in another policy, not given": {grantedStop, func(f *feedBuilder) {
			f.denyRun(true, customerHash)
		}, nil, "give it with --signals-policy"},
		"a sign-off refused under a stop that accepts them": {grantedStop, func(f *feedBuilder) {
			f.runSealedTarget(nil)
			s := f.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
			f.signOffRefused(f.runID, s, nil)
		}, nil, "that stop accepts sign-offs"},
		"a sign-off refused under no stop": {grantedStop, func(f *feedBuilder) {
			f.runSealedTarget(nil)
			f.signOffRefused(f.runID, 1, nil)
		}, nil, "not a stop"},
		"a sign-off refused after the lift": {grantedStop, func(f *feedBuilder) {
			f.runSealedTarget(nil)
			s := f.stopAccount("verdifax", 0, artifacts.StopSignoffsRefuse, 0, false, nil)
			f.resumeAccount("verdifax", 0, s, nil)
			f.signOffRefused(f.runID, s, nil)
		}, nil, "had already lifted"},
		"a refused sign-off by another key than its approver's": {grantedStop, func(f *feedBuilder) {
			f.runSealedTarget(nil)
			s := f.stopAccount("verdifax", 0, artifacts.StopSignoffsRefuse, 0, false, nil)
			other, otherKey := keyOfSeed("x")
			f.signOffRefused(f.runID, s, func(r *artifacts.SignOffRefusal) {
				r.ApproverKey = otherKey
				r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(other, r.Preimage()))
			})
		}, nil, "not the key the feed shows registered"},
		"a refused sign-off by a revoked approver": {grantedStop, func(f *feedBuilder) {
			f.runSealedTarget(nil)
			f.approverRevoked()
			s := f.stopAccount("verdifax", 0, artifacts.StopSignoffsRefuse, 0, false, nil)
			f.signOffRefused(f.runID, s, nil)
		}, nil, "revoked before it"},
		"a sign-off recorded during a stop that refuses them": {grantedStop, func(f *feedBuilder) {
			f.runSealedTarget(nil)
			f.stopAccount("verdifax", 0, artifacts.StopSignoffsRefuse, 0, false, nil)
			f.recordSignOff(f.runID, artifacts.SignOffApprove)
		}, nil, "that stop refuses sign-offs"},
		"more runs ended than the stop counted": {grantedStop, func(f *feedBuilder) {
			f.stopAccount("owner", stopOwnerKeyID, artifacts.StopSignoffsAccept, 1, true, nil)
			f.runSealed()
			f.failedRun()
		}, nil, "counted 1 run(s) in progress"},
		"a run ended after a later stop that counted none": {grantedStop, func(f *feedBuilder) {
			f.stopAccount("owner", stopOwnerKeyID, artifacts.StopSignoffsAccept, 2, true, nil)
			f.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
			f.runSealed()
		}, nil, "the Verdifax stop"},
		"a second stop by the same holder": {grantedStop, func(f *feedBuilder) {
			f.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
			f.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
		}, nil, "still stands"},
		"a refused run with the customer's own rule given": {grantedStop, func(f *feedBuilder) {
			f.denyRun(true, customerHash)
		}, customerDocs, ""},
	} {
		f := stopFeedStart(t, b.tools)
		b.build(f)
		c := checkStopFeed(t, f, b.docs)
		switch {
		case b.want == "":
			if !c.OK {
				t.Errorf("%s: fails: %s", name, c.Reason)
			}
		case c.OK || !strings.Contains(c.Reason, b.want):
			t.Errorf("%s: ok %v, reason %q, want %q", name, c.OK, c.Reason, b.want)
		}
	}
}

// R340: a feed read from a later point notes, and does not fail, a lift or
// a refusal whose stop is before the point.
func TestAStopBeforeThePointIsNoted(t *testing.T) {
	f := stopFeedStart(t, grantedStop)
	s := f.stopAccount("verdifax", 0, artifacts.StopSignoffsAccept, 0, false, nil)
	f.denyRun(true, strings.Repeat("4", 64))
	f.resumeAccount("verdifax", 0, s, nil)
	h := f.head()
	before := checkClock
	checkClock = func() time.Time { return time.Unix(h.Anchor.IntegratedTime, 0).Add(time.Minute) }
	t.Cleanup(func() { checkClock = before })
	point := f.events[s-1].Data
	c := checkSignalFeedPinned(pageWithHead(t, f.events[s:], h), &signalPoint{point.Sequence, point.EventHash}, nil)
	if !c.OK || !strings.Contains(strings.Join(c.Notes, " "), "earlier than the point checked") ||
		!strings.Contains(strings.Join(c.Notes, " "), "not in this part of the feed") {
		t.Fatalf("from a later point: %s %v", c.Reason, c.Notes)
	}
}

// R341: a passed response target is held to its result, its deadline and
// the sign-offs on its result.
func TestAPassedTargetIsHeldToItsResult(t *testing.T) {
	target := &artifacts.SealedTarget{Within: 60, Compare: artifacts.TargetCompareFirstSignOff, Notice: artifacts.TargetNoticeEvent}
	build := func(t *testing.T, mutate func(*artifacts.SignOffTargetPassed), shift time.Duration, signFirst, twice bool) SignalFeedCheck {
		f := stopFeedStart(t, nil)
		result := f.runSealedTarget(target)
		if signFirst {
			f.recordSignOff(f.runID, artifacts.SignOffReject)
		}
		f.runSealed()
		f.targetPassed(result, mutate, shift)
		if twice {
			f.targetPassed(result, nil, 0)
		}
		f.recordSignOff(f.runID-1, artifacts.SignOffApprove)
		return checkStopFeed(t, f, nil)
	}
	if c := build(t, nil, 20*time.Second, false, false); !c.OK || c.TargetsPassed != 1 || !strings.Contains(c.Entries[len(c.Entries)-2].TargetPassed, "customer's signoff.within target of 60 seconds") {
		t.Fatalf("a sound passed target fails: %s %d", c.Reason, c.TargetsPassed)
	}
	for name, b := range map[string]struct {
		mutate    func(*artifacts.SignOffTargetPassed)
		shift     time.Duration
		signFirst bool
		twice     bool
		want      string
	}{
		"logged before its deadline":     {nil, -80 * time.Second, false, false, "before that deadline"},
		"a sign-off logged by then":      {nil, 20 * time.Second, true, false, "a sign-off on that result"},
		"a start that is not the result": {func(r *artifacts.SignOffTargetPassed) { r.Start = "2026-11-08T12:05:00Z" }, 20 * time.Second, false, false, "its result's entry is on the public log"},
		"another result's hash":          {func(r *artifacts.SignOffTargetPassed) { r.ResultHash = strings.Repeat("8", 64) }, 20 * time.Second, false, false, "is run"},
		"a target its result did not seal": {func(r *artifacts.SignOffTargetPassed) {
			r.Within = 30
		}, 20 * time.Second, false, false, "not the one its result sealed"},
		"sealed twice":         {nil, 20 * time.Second, false, true, "second passed target"},
		"a receipt's source":   {func(r *artifacts.SignOffTargetPassed) { r.Source = artifacts.TargetSourceRefusals }, 20 * time.Second, false, false, "only a record's is"},
		"not a result's place": {func(r *artifacts.SignOffTargetPassed) { r.ResultSequence = 2 }, 20 * time.Second, false, false, "not a result"},
	} {
		c := build(t, b.mutate, b.shift, b.signFirst, b.twice)
		if c.OK || !strings.Contains(c.Reason, b.want) {
			t.Errorf("%s: ok %v, reason %q, want %q", name, c.OK, c.Reason, b.want)
		}
	}
}

// withEntry rewrites one event's entry through a JSON map.
func withEntry(t *testing.T, events []signalCloudEvent, seq int64, edit func(map[string]any)) []signalCloudEvent {
	t.Helper()
	out := append([]signalCloudEvent(nil), events...)
	for i := range out {
		if out[i].Data.Sequence != seq {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(out[i].Data.Entry, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		out[i].Data.Entry = raw
	}
	return out
}

// R340, R341: a key's tool allowlist, a result's sealed target and a
// receipt's response target are sealed facts: each read strictly, each in
// its record's hash, and an allowlist only on a member key's creation.
func TestRound64SealedFieldsAreInTheirHashes(t *testing.T) {
	f := stopFeedStart(t, grantedStop)
	result := f.runSealedTarget(&artifacts.SealedTarget{Within: 90, Compare: artifacts.TargetCompareDecisionInForce, Notice: artifacts.TargetNoticeHead})
	f.denyRunWithTarget(&artifacts.SealedTarget{Within: 45, Compare: artifacts.TargetCompareFirstSignOff, Notice: artifacts.TargetNoticeHead})
	refused := f.events[len(f.events)-1].Data.Sequence
	h := f.head()
	atCheck(t, time.Unix(h.Anchor.IntegratedTime, 0).Add(time.Minute))
	if c := checkSignalFeedWith(pageWithHead(t, f.events, h), nil, nil, nil); !c.OK {
		t.Fatalf("a sound feed fails: %s", c.Reason)
	}
	for name, b := range map[string]struct {
		seq  int64
		edit func(map[string]any)
		want string
	}{
		"a granted tool added":   {3, func(m map[string]any) { m["allowed_tools"] = []any{"account_stop", "read_feed", "verify_feed"} }, "hash recomputes"},
		"the grant dropped":      {3, func(m map[string]any) { delete(m, "allowed_tools") }, "hash recomputes"},
		"an owner power granted": {3, func(m map[string]any) { m["allowed_tools"] = []any{"account_resume"} }, "grantable"},
		"a result's target":      {result, func(m map[string]any) { m["signoff_target"].(map[string]any)["within"] = 900 }, "hash recomputes"},
		"a target field unknown": {result, func(m map[string]any) { m["signoff_target"].(map[string]any)["late"] = true }, "unknown field"},
		"a receipt's target": {refused, func(m map[string]any) {
			m["receipt_context"].(map[string]any)["response_target"].(map[string]any)["within"] = 4500
		}, "does not verify"},
	} {
		c := checkSignalFeedWith(pageWithHead(t, withEntry(t, f.events, b.seq, b.edit), h), nil, nil, nil)
		if c.OK || !strings.Contains(c.Reason, b.want) {
			t.Errorf("%s: ok %v, reason %q, want %q", name, c.OK, c.Reason, b.want)
		}
	}
}

// denyRunWithTarget adds a refused run whose receipt seals a response target.
func (f *feedBuilder) denyRunWithTarget(target *artifacts.SealedTarget) {
	link, at := f.next()
	f.runID++
	d := &artifacts.DenyReceipt{Version: "vfa.deny_receipt.v1", AnchorRequired: true, EnvelopeID: "env-" + strconv.FormatInt(f.runID, 10),
		PolicyHash: strings.Repeat("4", 64), EvaluationHash: strings.Repeat("9", 64), FiredRuleID: "no-claims", DecisionReasonCode: "RULE_DENIED",
		EvaluatorVersion: "pepg-0.1.0", DenyClock: at.Format(time.RFC3339Nano)}
	if _, err := artifacts.BuildDenyReceiptHash(d); err != nil {
		f.t.Fatal(err)
	}
	ctx := &artifacts.ReceiptContext{Request: artifacts.SealedRequestFields{PayloadHash: strings.Repeat("1", 64), ProgramID: strings.Repeat("2", 64),
		RouteID: "route-a", RegistryRecordHash: strings.Repeat("3", 64)}, AccountID: feedAccount, Signal: &link, ResponseTarget: target}
	leaf := artifacts.ComputeReceiptLeafHashV3("deny_receipt", d.EnvelopeID, d.Hash, f.runID, ctx.Hash())
	doc := artifacts.ReceiptDocument{OK: true, RunID: f.runID, DenyReceipt: d, ReceiptContext: ctx, ReceiptAnchor: f.anchor("deny_receipt", d.Hash, leaf, at)}
	f.add(artifacts.SignalRunRefused, link, d.Hash, f.runID, doc)
}

// R340: the stop and report flags apply only where they belong.
func TestRound64ReportFlagsApplyWhereTheyBelong(t *testing.T) {
	for args, want := range map[string]string{
		"--response-times": "check a feed given with --signals",
		"--summary s.json": "check a feed given with --signals",
		"--signals f.json --response-times --summary s.json":      "separate checks",
		"--signals f.json --target 4h":                            "only with --response-times",
		"--signals f.json --from 2026-11-01T00:00:00Z":            "only with --response-times",
		"--signals f.json --summary-head h.json":                  "only with --summary",
		"--signals f.json --response-times --target 4h":           "",
		"--signals f.json --summary s.json --summary-head h.json": "",
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		o := defineFlags(fs)
		if err := fs.Parse(strings.Fields(args)); err != nil {
			t.Fatal(err)
		}
		if got := round64FlagsMisused(o); (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", args, got, want)
		}
	}
	for v, want := range map[string]int64{"4h": 14400, "90": 90, "1s": 1} {
		if got, err := parseTargetFlag(v); err != nil || *got != want {
			t.Errorf("--target %s: %v %v", v, got, err)
		}
	}
	for _, v := range []string{"0", "1.5s", "400d", "-3", "9000h"} {
		if _, err := parseTargetFlag(v); err == nil {
			t.Errorf("--target %s was read", v)
		}
	}
}
