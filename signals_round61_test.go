package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// keyOfSeed is a test request key and its base64 public key.
func keyOfSeed(seed string) (ed25519.PrivateKey, string) {
	priv := ed25519.NewKeyFromSeed([]byte(strings.Repeat(seed, 32)))
	return priv, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// keyChangeFor adds a key created or revoked, naming its key.
func (f *feedBuilder) keyChangeFor(action, scope string, keyID int64) {
	link, at := f.next()
	k := artifacts.KeyChange{Format: artifacts.KeyChangeFormat, Action: action, DecidedBy: f.decidedBy(), KeyID: keyID, KeyScope: scope,
		Name: "a key", ChangedAt: at.Format(time.RFC3339Nano), Signal: link}
	k.KeyChangeHash = k.ComputeHash()
	k.Anchor = f.anchor(artifacts.KeyChangeKind, k.KeyChangeHash, k.LeafHash(), at)
	f.add(action, link, k.KeyChangeHash, 0, k)
}

// requestKeyChange adds a key's request key registered, rotated or cleared;
// by approves it when the key holder replaces or clears its key.
func (f *feedBuilder) requestKeyChange(action string, keyID int64, value string, by ed25519.PrivateKey) {
	link, at := f.next()
	c := artifacts.AccountChange{Format: artifacts.AccountChangeFormat, Action: action, DecidedBy: f.decidedBy(), KeyID: keyID,
		Value: value, ChangedAt: at.Format(time.RFC3339Nano), Signal: link}
	if by != nil {
		a := &artifacts.RequestKeyApproval{PublicKey: base64.StdEncoding.EncodeToString(by.Public().(ed25519.PublicKey)),
			SignedAt: at.Format(time.RFC3339), Nonce: strings.Repeat("0d", 16)}
		a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(by, artifacts.RequestKeyChangePreimage(value, a.SignedAt, a.Nonce)))
		c.RequestKeyApproval = a
	}
	c.AccountChangeHash = c.ComputeHash()
	c.Anchor = f.anchor(artifacts.AccountChangeKind, c.AccountChangeHash, c.LeafHash(), at)
	f.add(artifacts.SignalAccountChanged, link, c.AccountChangeHash, 0, c)
}

// ownerSetting adds an owner's block signed by the given request key.
func (f *feedBuilder) ownerSetting(action, value string, signer ed25519.PrivateKey) {
	link, at := f.next()
	o := &artifacts.OwnerSignature{PublicKey: base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)),
		SignedAt: at.Format(time.RFC3339), Nonce: strings.Repeat("0e", 16)}
	o.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(signer, artifacts.OwnerChangePreimage(feedAccount, action, value, o.SignedAt, o.Nonce)))
	c := artifacts.AccountChange{Format: artifacts.AccountChangeFormat, Action: action, DecidedBy: artifacts.DecidedByOwner, Value: value,
		ChangedAt: at.Format(time.RFC3339Nano), OwnerSignature: o, Signal: link}
	c.AccountChangeHash = c.ComputeHash()
	c.Anchor = f.anchor(artifacts.AccountChangeKind, c.AccountChangeHash, c.LeafHash(), at)
	f.add(artifacts.SignalAccountChanged, link, c.AccountChangeHash, 0, c)
}

// head makes Verdifax's head statement for the feed so far, logged at the
// last event's time plus a minute.
func (f *feedBuilder) head() *artifacts.FeedHead {
	last := f.events[len(f.events)-1].Data
	at := feedStart.Add(time.Duration(last.Sequence)*time.Minute + time.Minute)
	h := &artifacts.FeedHead{Format: artifacts.FeedHeadFormat, Account: feedAccount, Sequence: last.Sequence, HeadHash: last.EventHash,
		StatedAt: at.Format(time.RFC3339Nano)}
	h.HeadStatementHash = h.ComputeHash()
	h.Anchor = f.anchor(artifacts.FeedHeadKind, h.HeadStatementHash, h.LeafHash(), at)
	return h
}

func pageWithHead(t *testing.T, events []signalCloudEvent, h *artifacts.FeedHead) []byte {
	t.Helper()
	return encode(t, signalFeedPage{Events: events, NextAfter: events[len(events)-1].Data.Sequence, Newest: events[len(events)-1].Data.Sequence, Head: h})
}

// Round 61, N22: each key's request keys are followed from their
// registration; a replacement must be approved by the key before it; an
// owner's change must be signed by the owner key's request key of its time;
// Verdifax's clear breaks the chain and the report says so.
func TestRequestKeyChainsAreFollowed(t *testing.T) {
	first, firstKey := keyOfSeed("1")
	second, secondKey := keyOfSeed("2")
	_, strangerKey := keyOfSeed("3")
	const owner, member = int64(11), int64(12)
	base := func() *feedBuilder {
		f := newFeedBuilder(t)
		f.byVerdifax = true
		f.accountChange(artifacts.AccountCreated, 0, "trial")
		f.keyChangeFor(artifacts.SignalKeyCreated, artifacts.KeyScopeOwner, owner)
		f.byVerdifax = false
		f.requestKeyChange(artifacts.AccountRequestKeyRegistered, owner, firstKey, nil)
		return f
	}
	f := base()
	f.ownerSetting(artifacts.AccountSettingVerdifaxDelete, artifacts.SettingBlocked, first)
	f.requestKeyChange(artifacts.AccountRequestKeyRotated, owner, secondKey, first)
	f.ownerSetting(artifacts.AccountSettingVerdifaxDelete, artifacts.SettingAllowed, second)
	f.keyChangeFor(artifacts.SignalKeyCreated, artifacts.KeyScopeRun, member)
	f.requestKeyChange(artifacts.AccountRequestKeyRegistered, member, strangerKey, nil)
	c := checkSignalFeed(feedBody(t, f.events), nil)
	if !c.OK || len(c.RequestKeyChains) != 2 || !c.RequestKeyChains[0].OwnerKey || c.RequestKeyChains[0].Current != secondKey ||
		len(c.RequestKeyChains[0].Events) != 2 || c.RequestKeyChains[1].Current != strangerKey || len(c.Notes) != 0 {
		t.Fatalf("a followed chain verifies and is reported by key: %+v", c)
	}
	encoded, _ := json.Marshal(c)
	if !strings.Contains(string(encoded), `"request_key_chains":[{"key_id":11,"owner_key":true`) {
		t.Fatalf("the JSON report lists each key's chain: %s", encoded)
	}
	cases := []struct {
		name  string
		build func(f *feedBuilder)
		fails string
	}{
		{"a rotation approved by a key the chain does not hold", func(f *feedBuilder) {
			f.requestKeyChange(artifacts.AccountRequestKeyRotated, owner, secondKey, second)
		}, "with the approval of"},
		{"an owner change signed by a key the owner key does not hold", func(f *feedBuilder) {
			f.ownerSetting(artifacts.AccountSettingOwnerReplace, artifacts.SettingBlocked, second)
		}, "the owner key's request key at this event is"},
		{"an owner change signed by the replaced key", func(f *feedBuilder) {
			f.requestKeyChange(artifacts.AccountRequestKeyRotated, owner, secondKey, first)
			f.ownerSetting(artifacts.AccountSettingOwnerReplace, artifacts.SettingBlocked, first)
		}, "the owner key's request key at this event is"},
		{"a second registration over a held key", func(f *feedBuilder) {
			f.requestKeyChange(artifacts.AccountRequestKeyRegistered, owner, secondKey, nil)
		}, "holds one already"},
		{"an owner change after the holder cleared the key", func(f *feedBuilder) {
			f.requestKeyChange(artifacts.AccountRequestKeyCleared, owner, "", first)
			f.ownerSetting(artifacts.AccountSettingOwnerReplace, artifacts.SettingBlocked, first)
		}, "holds no request key at this event"},
	}
	for _, tc := range cases {
		g := base()
		tc.build(g)
		if c := checkSignalFeed(feedBody(t, g.events), nil); c.OK || !strings.Contains(c.Reason, tc.fails) {
			t.Errorf("%s must fail with %q: %+v", tc.name, tc.fails, c)
		}
	}
	// Verdifax's clear breaks the chain: a later registration and the
	// owner's changes it signs pass, and the report says how to confirm
	// them; --owner-request-key then refuses a registration it does not name.
	g := base()
	g.byVerdifax = true
	g.requestKeyChange(artifacts.AccountRequestKeyCleared, owner, "", nil)
	g.byVerdifax = false
	g.requestKeyChange(artifacts.AccountRequestKeyRegistered, owner, secondKey, nil)
	g.ownerSetting(artifacts.AccountSettingVerdifaxDelete, artifacts.SettingBlocked, second)
	broken := checkSignalFeed(feedBody(t, g.events), nil)
	want := "the owner's key chain was cleared by Verdifax at event 4; pass --owner-request-key to confirm later owner changes."
	if !broken.OK || len(broken.Notes) != 1 || broken.Notes[0] != want || broken.RequestKeyChains[0].ClearedByVerdifax != 4 {
		t.Fatalf("a chain Verdifax cleared verifies with its note: %+v", broken)
	}
	// A registration the pin does not name fails even before any owner
	// change it signs: the pin confirms the chain's start, not only signers.
	registered := g.events[:5]
	if pinned := checkSignalFeedPinned(feedBody(t, registered), nil, []string{firstKey}); pinned.OK || !strings.Contains(pinned.Reason, "the owner key's request key set here") {
		t.Fatalf("a registration the pin does not name must fail: %+v", pinned)
	}
	if pinned := checkSignalFeedPinned(feedBody(t, g.events), nil, []string{firstKey}); pinned.OK {
		t.Fatalf("an owner change signed by a key the pin does not name must fail: %+v", pinned)
	}
	if pinned := checkSignalFeedPinned(feedBody(t, g.events), nil, []string{firstKey, secondKey}); !pinned.OK || len(pinned.Notes) != 0 {
		t.Fatalf("pinned keys confirm the chain: %+v", pinned)
	}
}

// Older feeds, sealed before registrations were, verify as before: an
// owner's change with no registration in the feed passes, and the report
// says the owner key was not registered in the feed and names the flag.
func TestAFeedWithNoRegistrationVerifiesAndSaysSo(t *testing.T) {
	f := newFeedBuilder(t)
	f.byVerdifax = true
	f.accountChange(artifacts.AccountCreated, 0, "trial")
	f.keyChange(artifacts.SignalKeyCreated, artifacts.KeyScopeOwner)
	f.byVerdifax = false
	f.accountChange(artifacts.AccountSettingVerdifaxDelete, 0, artifacts.SettingBlocked)
	c := checkSignalFeed(feedBody(t, f.events), nil)
	if !c.OK || len(c.Notes) != 1 || !strings.Contains(c.Notes[0], "not registered in this feed") || !strings.Contains(c.Notes[0], "--owner-request-key") {
		t.Fatalf("an older feed verifies and names the flag: %+v", c)
	}
}

// Round 61, N23 and N24: a feed page that ends with Verdifax's head statement
// is complete as of the head's time, shown with its age; a feed cut short
// before the head's event, one that goes past it, a rewritten end, another
// account's head, a head not on the log and a head older than the limit all
// fail; with no head the report says a later event may exist.
func TestTheFeedHeadShowsTheFeedIsComplete(t *testing.T) {
	f := newFeedBuilder(t)
	f.full()
	f.accountChange(artifacts.AccountSettingVerdifaxDelete, 0, artifacts.SettingBlocked)
	h := f.head()
	atClock(t, time.Unix(h.Anchor.IntegratedTime, 0).Add(2*time.Hour))
	c := checkSignalFeed(pageWithHead(t, f.events, h), nil)
	wantAsOf := time.Unix(h.Anchor.IntegratedTime, 0).UTC().Format(time.RFC3339)
	if !c.OK || c.HeadSequence != h.Sequence || c.CompleteAsOf != wantAsOf || c.CompleteAge != "2 hours before this check" ||
		c.BlocksHeldAsOf != wantAsOf || c.OwnerBlocks[artifacts.AccountSettingVerdifaxDelete] != artifacts.SettingBlocked {
		t.Fatalf("a feed with its head is complete as of the head's time: %+v", c)
	}
	plain := checkSignalFeed(feedBody(t, f.events), nil)
	if !plain.OK || plain.CompleteAsOf != "" || plain.BlocksHeldAsOf != "" || plain.OwnerBlocks == nil {
		t.Fatalf("a feed with no head verifies, and its blocks hold only through its last event: %+v", plain)
	}
	n := len(f.events)
	cut := checkSignalFeed(pageWithHead(t, f.events[:n-1], h), nil)
	wantCut := "the feed ends at event 6, and Verdifax's head statement of " + h.StatedAt + " says the feed's highest event is 7"
	if cut.OK || !strings.Contains(cut.Reason, wantCut) {
		t.Fatalf("a feed cut short before its head must fail: %+v", cut)
	}
	early := f.head()
	f.accountChange(artifacts.AccountSettingVerdifaxDelete, 0, artifacts.SettingAllowed)
	if past := checkSignalFeed(pageWithHead(t, f.events, early), nil); past.OK || !strings.Contains(past.Reason, "the head is not this feed's") {
		t.Fatalf("a feed that goes past its head must fail: %+v", past)
	}
	f.events = f.events[:n]
	rewritten := *h
	rewritten.HeadHash = strings.Repeat("9", 64)
	rewritten.HeadStatementHash = rewritten.ComputeHash()
	if bad := checkSignalFeed(pageWithHead(t, f.events, &rewritten), nil); bad.OK {
		t.Fatalf("a head whose hash was changed must fail: %+v", bad)
	}
	other := *h
	other.Account = "account-9"
	if bad := checkSignalFeed(pageWithHead(t, f.events, &other), nil); bad.OK {
		t.Fatalf("another account's head must fail: %+v", bad)
	}
	unlogged := *h
	mockAnchor := *h.Anchor
	mockAnchor.Backend = "mock"
	unlogged.Anchor = &mockAnchor
	if bad := checkSignalFeed(pageWithHead(t, f.events, &unlogged), nil); bad.OK {
		t.Fatalf("a head not on the public log must fail: %+v", bad)
	}
	noAnchor := *h
	noAnchor.Anchor = nil
	if bad := checkSignalFeed(pageWithHead(t, f.events, &noAnchor), nil); bad.OK {
		t.Fatalf("a head with no anchor must fail: %+v", bad)
	}
	atClock(t, time.Unix(h.Anchor.IntegratedTime, 0).Add(3*24*time.Hour))
	old := checkSignalFeed(pageWithHead(t, f.events, h), nil)
	if old.OK || !strings.Contains(old.Reason, "the head statement is older than the limit; fetch the feed again") || !strings.Contains(old.Reason, "--feed-head-max-age") {
		t.Fatalf("a head 3 days old fails the 24 hour limit: %+v", old)
	}
	feedHeadMaxAge = 4 * 24 * time.Hour
	t.Cleanup(func() { feedHeadMaxAge = defaultHeadMaxAge })
	if raised := checkSignalFeed(pageWithHead(t, f.events, h), nil); !raised.OK || raised.CompleteAge != "3 days before this check" {
		t.Fatalf("a raised limit admits it with its age: %+v", raised)
	}
}

// Round 61, N25: a deleted record's event reads at the time the feed served
// it, and names who deleted the record and the tombstone's own event.
func TestADeletedRecordsEventReadsInOrder(t *testing.T) {
	f := newFeedBuilder(t)
	f.failedRun()
	var doc artifacts.ReceiptDocument
	if err := json.Unmarshal(f.events[0].Data.Entry, &doc); err != nil {
		t.Fatal(err)
	}
	f.byVerdifax = true
	d := f.runDeletionOf(f.runID, doc.FailureReceipt.Hash)
	f.events[0].Data.Entry, f.events[0].Data.Deleted = json.RawMessage("null"), d
	f.events[0].Time = "2026-11-08T12:01:00.5Z"
	c := checkSignalFeed(feedBody(t, f.events), nil)
	if !c.OK || c.Entries[0].At != "2026-11-08T12:01:00.5Z" || c.Entries[0].RecordDeletedBy != artifacts.DecidedByVerdifax || c.Entries[0].TombstoneSequence != 2 {
		t.Fatalf("the event reads at its served time and names its tombstone: %+v", c.Entries)
	}
	out := captureStdout(t, func() { printSignalFeed(&c) })
	if !strings.Contains(out, "1. 2026-11-08T12:01:00.5Z  run.failed run 901, record deleted by Verdifax, tombstone at event 2") {
		t.Fatalf("the report reads the event in order:\n%s", out)
	}
}

// captureStdout returns what run prints.
func captureStdout(t *testing.T, run func()) string {
	t.Helper()
	old := os.Stdout
	rd, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(rd)
		done <- string(b)
	}()
	os.Stdout = w
	run()
	w.Close()
	os.Stdout = old
	return <-done
}

// Round 61, N24: a head age limit applies only with the input it limits and
// must be a positive duration; each is refused with exit 2 otherwise, never
// ignored.
func TestHeadAgeFlagsAreRefusedWhereTheyDoNotApply(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "verdifax-verify")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build: %v\n%s", buildErr, out)
	}
	record := filepath.Join("testdata", "round18", "run-249-production.json")
	feed := filepath.Join(t.TempDir(), "feed.json")
	if err := os.WriteFile(feed, []byte(`{"events":[],"next_after":0,"newest":0}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args   []string
		stderr string
	}{
		{[]string{"--feed-head-max-age", "1h", record}, "apply only with --signals"},
		{[]string{"--signoff-head-max-age", "1h", "--signals", feed}, "applies only with --signoff-history"},
		{[]string{"--signals", feed, "--feed-head-max-age", "a day"}, "must be a positive duration"},
		{[]string{"--signals", feed, "--feed-head-max-age", "0s"}, "must be a positive duration"},
	} {
		cmd := exec.Command(bin, c.args...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		runErr := cmd.Run()
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 2 || !strings.Contains(stderr.String(), c.stderr) {
			t.Errorf("%v: %v %q, want exit 2 and %q", c.args, runErr, stderr.String(), c.stderr)
		}
	}
}
