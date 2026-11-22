package main

// Round 64, part 2 (v0.38.0): account stops in the signal feed.
//
// The account's owner and Verdifax each hold a stop of their own on an
// account and lift only their own (account.stopped, account.resumed, records
// verdifax.account-stop.v1 under leaf kind account_stop). While a stop
// stands, every new run is refused with a normal sealed deny receipt
// (fired_rule_id account_stop, code ACCOUNT_STOPPED), runs already in
// progress finish and are counted by the stop, and, when the stop's scope
// refuses sign-offs, a sign-off on a sealed result is refused and the
// refusal sealed (signoff.refused, verdifax.signoff-refusal.v1, leaf kind
// signoff_refusal). A stop touches no key.
//
// --signals follows both holds through the feed and fails:
//   - a resume by the other holder, a resume naming no standing stop, and an
//     owner's resume without the owner's request-key signature (the record's
//     own check);
//   - a Verdifax stop placed while the owner's setting.verdifax_stop is
//     blocked (checkOwnerBlocks);
//   - a stop asked by a member key whose key.created record seals no
//     account_stop grant in its tool allowlist, a signed member-key stop, and
//     a resume by a member key;
//   - a run refused because the account was stopped, or a sign-off refused
//     during a stop, with no standing stop that covers it;
//   - a sign-off recorded while a stop that refuses sign-offs stood;
//   - more run outcomes sealed after a stop, while the account stayed
//     stopped, than the runs in progress the stop sealed.
//
// It reports each stopped period: when it began and ended (the sealed time
// and the public-log time), who decided, signed or "unsigned: the server's
// word", its scope, the runs in progress, and the refusals made while it
// stood. A resume is read whatever the server's release setting was when it
// was sealed: the setting governs only what the server accepts, never what a
// feed may hold. The report states what was sealed; it never says whether a
// stop was right.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
)

// StoppedPeriod is one stop the feed shows, and its lift when the feed shows
// one.
type StoppedPeriod struct {
	// Holder is whose stop it is: owner or Verdifax. DecidedBy is as sealed.
	Holder    string `json:"holder"`
	DecidedBy string `json:"decided_by"`
	// KeyID is the account key that asked for an owner's stop; ByMemberKey
	// says it was a member key the owner granted the stop.
	KeyID       int64 `json:"key_id,omitempty"`
	ByMemberKey bool  `json:"by_member_key,omitempty"`
	// SignedBy is the request key that signed the stop, or empty; Unsigned
	// is the statement an owner's stop sent without a signature seals: the
	// server's word.
	SignedBy string `json:"signed_by,omitempty"`
	Unsigned string `json:"unsigned,omitempty"`
	Signoffs string `json:"signoffs"`
	Webhooks string `json:"webhooks"`
	// RunsInProgress is the count the stop sealed; RunsEndedAfter the run
	// outcomes the feed shows sealed after it while the account stayed
	// stopped, each one of those runs finishing.
	RunsInProgress int64  `json:"runs_in_progress"`
	RunsEndedAfter int64  `json:"runs_ended_after"`
	StopSequence   int64  `json:"stop_sequence"`
	From           string `json:"from"`
	FromOnLog      string `json:"from_on_public_log,omitempty"`
	// ResumeSequence, To and ToOnLog are its lift, when the feed shows one.
	ResumeSequence int64  `json:"resume_sequence,omitempty"`
	To             string `json:"to,omitempty"`
	ToOnLog        string `json:"to_on_public_log,omitempty"`
	ResumeSignedBy string `json:"resume_signed_by,omitempty"`
	// RunsRefused and SignOffsRefused count the runs refused because the
	// account was stopped, and the sign-offs refused, while it stood.
	RunsRefused     int `json:"runs_refused"`
	SignOffsRefused int `json:"signoffs_refused"`
}

// feedKey is a key whose creation the feed shows.
type feedKey struct {
	scope    string
	tools    []string
	sequence int64
}

// stopFeed follows the two holds through one feed.
type stopFeed struct {
	// known is whether the feed is read from its start with no restore gap
	// in its own chain so far: only then is a stop the feed does not show
	// one that does not exist.
	known bool
	// present holds the kind of each event in the part of the feed given.
	present  map[int64]string
	holds    map[string]*StoppedPeriod
	stopAt   map[int64]*StoppedPeriod
	periods  []*StoppedPeriod
	stretch  []*StoppedPeriod
	keys     map[int64]*feedKey
	approver map[int64]string
	revoked  map[int64]bool
	// customerStopRules are the policies, by policy hash, given with
	// --signals-policy that hold a rule of their own named account_stop.
	customerStopRules map[string]bool
	refusedSignOffs   int
	notes             []string
}

func newStopFeed(fromStart bool, documents map[string][]byte) *stopFeed {
	f := &stopFeed{known: fromStart, present: map[int64]string{}, holds: map[string]*StoppedPeriod{}, stopAt: map[int64]*StoppedPeriod{},
		keys: map[int64]*feedKey{}, approver: map[int64]string{}, revoked: map[int64]bool{}, customerStopRules: map[string]bool{}}
	for _, doc := range documents {
		var rules struct {
			Rules []struct {
				RuleID string `json:"rule_id"`
			} `json:"rules"`
		}
		got, hashErr := policyhash.FromDocument(doc)
		if hashErr != nil || json.Unmarshal(doc, &rules) != nil {
			continue
		}
		for _, r := range rules.Rules {
			if r.RuleID == artifacts.StopRuleID {
				f.customerStopRules[got.PolicyHash] = true
			}
		}
	}
	return f
}

// holderName is a holder as the report says it.
func holderName(holder string) string {
	if holder == "verdifax" {
		return "Verdifax"
	}
	return holder
}

// checkStopFeedEntry checks the entry of a round 64 part 2 event as its own
// kind: its shape, hash, clock and public-log entry, and that it is the kind
// of event its record says.
func checkStopFeedEntry(ce *signalCloudEvent) (checkedEntry, error) {
	e := &ce.Data
	switch e.Kind {
	case artifacts.SignalAccountStopped, artifacts.SignalAccountResumed:
		var s artifacts.AccountStop
		if decodeErr := strictDecode(e.Entry, &s); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not an account stop: %w", decodeErr)
		}
		unlogged, checkErr := unloggedOr(checkSealedEntry(s.Validate(), s.ComputeHash(), s.AccountStopHash, s.ChangedAt, "changed_at",
			s.Anchor, artifacts.AccountStopKind, s.LeafHash()))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its account stop: %w", checkErr)
		}
		if s.Kind() != e.Kind {
			return checkedEntry{}, fmt.Errorf("it is a %s event, and its record is a %s", e.Kind, s.Action)
		}
		link := s.Signal
		got := checkedEntry{hash: s.AccountStopHash, at: s.ChangedAt, logEntry: logEntryOf(s.Anchor), link: &link, unlogged: unlogged,
			decidedBy: s.DecidedBy, keyID: s.KeyID, ownerKey: ownerKeyOf(s.OwnerSignature), stop: &s}
		if s.Anchor != nil {
			got.logged = s.Anchor.IntegratedTime
		}
		return got, nil
	case artifacts.SignalSignOffRefused:
		var r artifacts.SignOffRefusal
		if decodeErr := strictDecode(e.Entry, &r); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a sign-off refusal: %w", decodeErr)
		}
		unlogged, checkErr := unloggedOr(checkSealedEntry(r.Validate(), r.ComputeHash(), r.SignOffRefusalHash, r.RefusedAt, "refused_at",
			r.Anchor, artifacts.SignOffRefusalKind, r.LeafHash()))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its sign-off refusal: %w", checkErr)
		}
		link := r.Signal
		return checkedEntry{hash: r.SignOffRefusalHash, at: r.RefusedAt, logEntry: logEntryOf(r.Anchor), link: &link, runID: r.Target.RunID,
			unlogged: unlogged, refusal: &r}, nil
	case artifacts.SignalSignOffTargetPassed:
		var r artifacts.SignOffTargetPassed
		if decodeErr := strictDecode(e.Entry, &r); decodeErr != nil {
			return checkedEntry{}, fmt.Errorf("its entry is not a target-passed record: %w", decodeErr)
		}
		unlogged, checkErr := unloggedOr(checkSealedEntry(r.Validate(), r.ComputeHash(), r.TargetPassedHash, r.StatedAt, "stated_at",
			r.Anchor, artifacts.SignOffTargetKind, r.LeafHash()))
		if checkErr != nil {
			return checkedEntry{}, fmt.Errorf("its target-passed record: %w", checkErr)
		}
		link := r.Signal
		got := checkedEntry{hash: r.TargetPassedHash, at: r.StatedAt, logEntry: logEntryOf(r.Anchor), link: &link, runID: r.RunID,
			unlogged: unlogged, targetPassed: &r}
		if r.Anchor != nil {
			got.logged = r.Anchor.IntegratedTime
		}
		return got, nil
	}
	return checkedEntry{}, errors.New("it is not a round 64 stop or target kind")
}

// logTimeText is a public-log time as the report says it, or empty for none.
func logTimeText(integrated int64) string {
	if integrated <= 0 {
		return ""
	}
	return time.Unix(integrated, 0).UTC().Format(time.RFC3339)
}

// event applies one checked event, in feed order. isOwnerKey reports a key
// the feed has shown as the owner key. It returns a failure, or "".
func (f *stopFeed) event(kind string, seq int64, got *checkedEntry, isOwnerKey func(int64) bool) string {
	f.present[seq] = kind
	switch {
	case got.gap != nil && got.gap.Chain == artifacts.GapChainSignals:
		// A restore may have lost a stop or a lift: what stands is no longer
		// known from the feed alone.
		f.known = false
		f.notes = append(f.notes, fmt.Sprintf("after the restore gap at event %d, a stop or lift the restore lost cannot be shown, so stops are checked only as the feed shows them from there.", seq))
	case kind == artifacts.SignalKeyCreated:
		f.keys[got.keyID] = &feedKey{scope: got.keyScope, tools: got.allowedTools, sequence: seq}
	case kind == artifacts.SignalApproverRegistered:
		f.approver[got.keyID] = got.approverKey
	case kind == artifacts.SignalApproverRevoked:
		f.revoked[got.keyID] = true
	case got.stop != nil && got.stop.Action == artifacts.StopActionStop:
		return f.placed(seq, got, isOwnerKey)
	case got.stop != nil:
		return f.lifted(seq, got, isOwnerKey)
	case got.refusal != nil:
		return f.signOffRefused(seq, got.refusal)
	case got.signOff != nil:
		for _, p := range f.standing() {
			if p.Signoffs == artifacts.StopSignoffsRefuse {
				return fmt.Sprintf("a sign-off was recorded while the %s stop placed at event %d stood, and that stop refuses sign-offs", holderName(p.Holder), p.StopSequence)
			}
		}
	case got.stopRefusal:
		return f.runRefusedForStop(seq, got)
	case kind == artifacts.SignalRunSealed || kind == artifacts.SignalRunHalted || kind == artifacts.SignalRunFailed || kind == artifacts.SignalRunRefused:
		return f.runEnded(seq, got)
	}
	return ""
}

// standing lists the stops standing now, owner's first.
func (f *stopFeed) standing() []*StoppedPeriod {
	var out []*StoppedPeriod
	for _, h := range []string{"owner", "verdifax"} {
		if p := f.holds[h]; p != nil {
			out = append(out, p)
		}
	}
	return out
}

// placed applies a stop.
func (f *stopFeed) placed(seq int64, got *checkedEntry, isOwnerKey func(int64) bool) string {
	s := got.stop
	holder := s.Holder()
	if p := f.holds[holder]; p != nil {
		return fmt.Sprintf("it places the %s stop while the %s stop placed at event %d still stands; each holder lifts its own stop before placing another", holderName(holder), holderName(holder), p.StopSequence)
	}
	p := &StoppedPeriod{Holder: holder, DecidedBy: s.DecidedBy, KeyID: s.KeyID, Signoffs: s.Scope.Signoffs, Webhooks: s.Scope.Webhooks,
		RunsInProgress: s.RunsInProgress, StopSequence: seq, From: s.ChangedAt, FromOnLog: logTimeText(got.logged), SignedBy: ownerKeyOf(s.OwnerSignature),
		Unsigned: s.Unsigned}
	if holder == "owner" && !isOwnerKey(s.KeyID) {
		key, shown := f.keys[s.KeyID]
		switch {
		case !shown:
			f.notes = append(f.notes, fmt.Sprintf("key %d placed the owner's stop at event %d; its creation is not in this part of the feed, so whether it is the owner key or a member key granted the stop is not shown.", s.KeyID, seq))
		case key.scope != artifacts.KeyScopeRun || !containsString(key.tools, artifacts.AgentStopPermission):
			return fmt.Sprintf("key %d placed the owner's stop, and it is not the owner key; its key.created record (event %d) seals no %s grant in its tool allowlist", s.KeyID, key.sequence, artifacts.AgentStopPermission)
		case s.OwnerSignature != nil:
			return fmt.Sprintf("member key %d placed the owner's stop with a request-key signature; a member key's stop is sealed unsigned, and only the owner key's request key signs a stop", s.KeyID)
		default:
			p.ByMemberKey = true
		}
	}
	if len(f.holds) == 0 {
		f.stretch = nil
	}
	f.holds[holder], f.stopAt[seq] = p, p
	f.periods = append(f.periods, p)
	f.stretch = append(f.stretch, p)
	return ""
}

// lifted applies a resume: it must name the standing stop of its own holder.
func (f *stopFeed) lifted(seq int64, got *checkedEntry, isOwnerKey func(int64) bool) string {
	s := got.stop
	holder := s.Holder()
	if holder == "owner" {
		if key, shown := f.keys[s.KeyID]; shown && !isOwnerKey(s.KeyID) {
			return fmt.Sprintf("key %d lifted the owner's stop, and it is a member key (created at event %d); a member key can never resume the account", s.KeyID, key.sequence)
		}
	}
	p := f.stopAt[s.LiftsSequence]
	switch {
	case p == nil:
		if k, inFeed := f.present[s.LiftsSequence]; inFeed {
			return fmt.Sprintf("it lifts a stop at event %d, and event %d is a %s, not a stop", s.LiftsSequence, s.LiftsSequence, k)
		}
		if f.known {
			return fmt.Sprintf("it lifts a stop at event %d, which the feed does not show", s.LiftsSequence)
		}
		f.notes = append(f.notes, fmt.Sprintf("event %d lifts the %s stop at event %d, which is not in this part of the feed; check from the feed's start to see it.", seq, holderName(holder), s.LiftsSequence))
		delete(f.holds, holder)
	case p.Holder != holder:
		return fmt.Sprintf("%s lifts the %s stop placed at event %d; each holder lifts only its own stop", holderName(holder), holderName(p.Holder), p.StopSequence)
	case p.ResumeSequence != 0:
		return fmt.Sprintf("it lifts the stop at event %d, which event %d already lifted, so it names no standing stop", p.StopSequence, p.ResumeSequence)
	default:
		p.ResumeSequence, p.To, p.ToOnLog, p.ResumeSignedBy = seq, s.ChangedAt, logTimeText(got.logged), ownerKeyOf(s.OwnerSignature)
		delete(f.holds, holder)
	}
	if len(f.holds) == 0 {
		f.stretch = nil
	}
	return ""
}

// signOffRefused places a refused sign-off inside the standing stop it
// names, one whose scope refuses sign-offs, and holds its approver to the
// feed's registrations.
func (f *stopFeed) signOffRefused(seq int64, r *artifacts.SignOffRefusal) string {
	f.refusedSignOffs++
	p := f.stopAt[r.StopSequence]
	switch {
	case p == nil:
		if k, inFeed := f.present[r.StopSequence]; inFeed {
			return fmt.Sprintf("its sign-off was refused under a stop at event %d, and event %d is a %s, not a stop", r.StopSequence, r.StopSequence, k)
		}
		if f.known {
			return fmt.Sprintf("its sign-off was refused under a stop at event %d, which the feed does not show", r.StopSequence)
		}
		f.notes = append(f.notes, fmt.Sprintf("event %d refuses a sign-off under the stop at event %d, which is not in this part of the feed.", seq, r.StopSequence))
	case p.ResumeSequence != 0:
		return fmt.Sprintf("its sign-off was refused under the stop at event %d, which event %d had already lifted", p.StopSequence, p.ResumeSequence)
	case p.Signoffs != artifacts.StopSignoffsRefuse:
		return fmt.Sprintf("its sign-off was refused under the stop at event %d, and that stop accepts sign-offs", p.StopSequence)
	}
	if key, shown := f.approver[r.ApproverID]; shown && key != r.ApproverKey {
		return fmt.Sprintf("its refused sign-off names approver %d, and the key it carries is not the key the feed shows registered for that approver", r.ApproverID)
	}
	if f.revoked[r.ApproverID] {
		return fmt.Sprintf("its refused sign-off names approver %d, which the feed shows revoked before it", r.ApproverID)
	}
	for _, p := range f.standing() {
		p.SignOffsRefused++
	}
	return ""
}

// runRefusedForStop places a run refused because the account was stopped
// inside a standing stop: any stop refuses every new run.
func (f *stopFeed) runRefusedForStop(seq int64, got *checkedEntry) string {
	standing := f.standing()
	if len(standing) > 0 {
		for _, p := range standing {
			p.RunsRefused++
		}
		return ""
	}
	if f.customerStopRules[got.policyHash] {
		// The customer's own policy names a rule account_stop: its refusal
		// uses the same words and is not a stop's.
		return ""
	}
	if f.known {
		return fmt.Sprintf("run %d was refused because the account was stopped (%s), and no stop stood on the account then; if the customer's own policy has a rule named %s, give it with --signals-policy",
			got.runID, artifacts.StopReasonCode, artifacts.StopRuleID)
	}
	f.notes = append(f.notes, fmt.Sprintf("event %d is run %d refused because the account was stopped; no stop stands in this part of the feed before it, so the stop it fell under is earlier than the point checked.", seq, got.runID))
	return ""
}

// runEnded counts one run outcome against every stop placed since the
// account was last free of stops: a run admitted after a stop is refused, so
// no more runs end after a stop than it counted in progress.
func (f *stopFeed) runEnded(seq int64, got *checkedEntry) string {
	if len(f.holds) == 0 {
		return ""
	}
	if got.deletedBy != "" {
		f.notes = append(f.notes, fmt.Sprintf("event %d, a run whose record was deleted, was sealed while the account was stopped; whether it was refused for the stop is not shown, and it is not counted.", seq))
		return ""
	}
	for _, p := range f.stretch {
		p.RunsEndedAfter++
		if p.RunsEndedAfter > p.RunsInProgress {
			return fmt.Sprintf("the %s stop at event %d counted %d run(s) in progress, and this is the %d%s run outcome sealed after it while the account stayed stopped; a run admitted after a stop is refused",
				holderName(p.Holder), p.StopSequence, p.RunsInProgress, p.RunsEndedAfter, ordinalSuffix(p.RunsEndedAfter))
		}
	}
	return ""
}

func ordinalSuffix(n int64) string {
	switch {
	case n%100 >= 11 && n%100 <= 13:
		return "th"
	case n%10 == 1:
		return "st"
	case n%10 == 2:
		return "nd"
	case n%10 == 3:
		return "rd"
	}
	return "th"
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// report lists the stopped periods in feed order.
func (f *stopFeed) report() []StoppedPeriod {
	out := make([]StoppedPeriod, 0, len(f.periods))
	for _, p := range f.periods {
		out = append(out, *p)
	}
	return out
}

// stopPeriodLine says one stopped period in plain words.
func stopPeriodLine(p *StoppedPeriod, completeAsOf string) string {
	who := "the owner"
	switch {
	case p.Holder == "verdifax":
		who = "Verdifax"
	case p.ByMemberKey:
		who = fmt.Sprintf("the owner, asked by member key %d under its sealed %s grant", p.KeyID, artifacts.AgentStopPermission)
	case p.KeyID > 0:
		who = fmt.Sprintf("the owner (key %d)", p.KeyID)
	}
	signed := "signed by request key " + truncate(p.SignedBy, 12)
	switch {
	case p.Holder == "verdifax":
		signed = "decided by a Verdifax admin key"
	case p.SignedBy == "":
		signed = "unsigned: the server's word"
	}
	from := p.From
	if p.FromOnLog != "" {
		from += " (on the public log " + p.FromOnLog + ")"
	}
	to := "still standing at the end of the feed given"
	if completeAsOf != "" {
		to = "still standing as of " + completeAsOf
	}
	if p.ResumeSequence != 0 {
		to = fmt.Sprintf("lifted at event %d, %s", p.ResumeSequence, p.To)
		if p.ToOnLog != "" {
			to += " (on the public log " + p.ToOnLog + ")"
		}
	}
	return strings.Join([]string{
		fmt.Sprintf("event %d, stopped by %s, %s", p.StopSequence, who, signed),
		"from " + from + ", " + to,
		fmt.Sprintf("sign-offs %s, webhooks %s", p.Signoffs, p.Webhooks),
		fmt.Sprintf("%d run(s) in progress at the stop, %d ended after it while the account stayed stopped", p.RunsInProgress, p.RunsEndedAfter),
		fmt.Sprintf("%d run(s) and %d sign-off(s) refused while it stood", p.RunsRefused, p.SignOffsRefused),
	}, "; ")
}

// stopEntryText says a stop or lift on its event's line, or "" for another
// event.
func stopEntryText(got *checkedEntry) string {
	s := got.stop
	if s == nil {
		return ""
	}
	who := deciderName(s.DecidedBy)
	if s.DecidedBy == artifacts.DecidedByOwner && s.KeyID > 0 {
		who = fmt.Sprintf("owner (key %d)", s.KeyID)
	}
	signed := ""
	switch {
	case s.OwnerSignature != nil:
		signed = ", signed by request key " + truncate(s.OwnerSignature.PublicKey, 12)
	case s.Unsigned != "":
		signed = ", unsigned: the server's word"
	}
	if s.Action == artifacts.StopActionResume {
		return fmt.Sprintf("the %s stop placed at event %d lifted by %s%s", holderName(s.Holder()), s.LiftsSequence, who, signed)
	}
	return fmt.Sprintf("account stopped by %s%s; sign-offs %s, webhooks %s; %d run(s) in progress", who, signed, s.Scope.Signoffs, s.Scope.Webhooks, s.RunsInProgress)
}

// refusalEntryText says a refused sign-off on its event's line.
func refusalEntryText(r *artifacts.SignOffRefusal) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("a registered approver key (approver %d) signed %s on run %d's %s, refused under the stop at event %d (%s)",
		r.ApproverID, r.Decision, r.Target.RunID, r.Target.Kind, r.StopSequence, r.ReasonCode)
}

// targetEntryText says a passed response target on its event's line.
func targetEntryText(r *artifacts.SignOffTargetPassed) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("the customer's %s target of %d seconds on run %d's %s (event %d), counted from %s (%s), passed at %s with no %s sign-off on the public log by then",
		r.Source, r.Within, r.RunID, r.ResultKind, r.ResultSequence, r.Start, r.StartBasis, r.Deadline, r.Compare)
}
