package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// activationChain builds n genuine, linked, signed and logged changes.
func activationChain(t *testing.T, l *testLog, n int) []artifacts.PolicyActivation {
	t.Helper()
	pub, priv, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	chain := make([]artifacts.PolicyActivation, n)
	previous := artifacts.NoPreviousActivation
	start := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for i := range chain {
		at := start.Add(time.Duration(i) * time.Hour).Format(time.RFC3339)
		document := strings.Repeat(string(rune('a'+i)), 64)
		nonce := strings.Repeat("0", 31) + string(rune('0'+i))
		chain[i] = artifacts.PolicyActivation{
			Format: artifacts.PolicyActivationFormat, ChainID: "api-key-7", Sequence: int64(i + 1), PreviousActivationHash: previous,
			PolicyID: "acme", PolicyVersion: string(rune('1' + i)), PolicyHash: strings.Repeat("c", 64), DocumentHash: document, ActivatedAt: at,
			Signature: &artifacts.PolicyActivationSignature{
				PublicKey: base64.StdEncoding.EncodeToString(pub), SignedAt: at, Nonce: nonce,
				Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, artifacts.PolicyActivationPreimage("api-key-7", document, previous, at, nonce))),
			},
		}
		sealActivation(t, l, &chain[i], 30*time.Second)
		previous = chain[i].ActivationHash
	}
	return chain
}

// sealActivation hashes a record and logs it, as a forger with the log could.
func sealActivation(t *testing.T, l *testLog, a *artifacts.PolicyActivation, loggedAfter time.Duration) {
	t.Helper()
	a.ActivationHash = a.ComputeHash()
	at, clockErr := time.Parse(time.RFC3339, a.ActivatedAt)
	if clockErr != nil {
		t.Fatal(clockErr)
	}
	l.integratedTime = at.Add(loggedAfter).Unix()
	e := l.entry(t, strings.Repeat("0", 64), a.LeafHash())
	a.Anchor = &artifacts.ReceiptAnchor{Kind: artifacts.ReceiptAnchorKindV3, ReceiptKind: artifacts.PolicyActivationKind, ReceiptHash: a.ActivationHash,
		Backend: "rekor", LogEntryID: e.LogEntryID, LogID: e.LogID, LeafHashHex: e.LeafHashHex, LogIndex: e.LogIndex, TreeSize: e.TreeSize,
		RootHashHex: e.RootHashHex, InclusionPath: e.InclusionPath, Checkpoint: e.Checkpoint,
		SignedEntryTimestamp: e.SignedEntryTimestamp, IntegratedTime: e.IntegratedTime, EntryBody: e.EntryBody}
}

func historyOf(t *testing.T, chain []artifacts.PolicyActivation) PolicyHistoryCheck {
	t.Helper()
	data, encodeErr := json.Marshal(chain)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	return checkPolicyHistory(data)
}

func TestAGenuineHistoryVerifiesAndLists(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	chain := activationChain(t, l, 3)
	got := historyOf(t, chain)
	if !got.OK || len(got.Entries) != 3 || got.Entries[2].SignedBy == "" {
		t.Fatalf("%+v", got)
	}
}

// The attack this exists for: loosen a policy, do a run, restore it, then hide it.
func TestAChangedHistoryFails(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	for name, c := range map[string]struct {
		change func(*testing.T, []artifacts.PolicyActivation) []artifacts.PolicyActivation
		reason string
	}{
		"a change removed from the middle": {func(_ *testing.T, ch []artifacts.PolicyActivation) []artifacts.PolicyActivation {
			return append(ch[:1:1], ch[2:]...)
		}, "sequence is 3"},
		"the first change removed": {func(_ *testing.T, ch []artifacts.PolicyActivation) []artifacts.PolicyActivation { return ch[1:] }, "sequence is 2"},
		"two changes swapped": {func(_ *testing.T, ch []artifacts.PolicyActivation) []artifacts.PolicyActivation {
			ch[1], ch[2] = ch[2], ch[1]
			return ch
		}, "sequence is 3"},
		"a change rewritten and rehashed": {func(_ *testing.T, ch []artifacts.PolicyActivation) []artifacts.PolicyActivation {
			ch[1].PolicyVersion = "9"
			ch[1].ActivationHash = ch[1].ComputeHash()
			return ch
		}, "does not bind"},
		"a field changed, hash kept": {func(_ *testing.T, ch []artifacts.PolicyActivation) []artifacts.PolicyActivation {
			ch[1].PolicyVersion = "9"
			return ch
		}, "recomputes"},
		"the entry deleted": {func(_ *testing.T, ch []artifacts.PolicyActivation) []artifacts.PolicyActivation {
			ch[1].Anchor = nil
			return ch
		}, "no public-log entry"},
		"an entry on another backend": {func(_ *testing.T, ch []artifacts.PolicyActivation) []artifacts.PolicyActivation {
			ch[1].Anchor.Backend = "mock"
			return ch
		}, "not the public log"},
		"a signature by another key": {func(t *testing.T, ch []artifacts.PolicyActivation) []artifacts.PolicyActivation {
			pub, _, keyErr := ed25519.GenerateKey(rand.Reader)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			ch[1].Signature.PublicKey = base64.StdEncoding.EncodeToString(pub)
			sealActivation(t, l, &ch[1], 30*time.Second)
			return ch
		}, "signature does not verify"},
		"a change logged late": {func(t *testing.T, ch []artifacts.PolicyActivation) []artifacts.PolicyActivation {
			sealActivation(t, l, &ch[2], 2*time.Hour)
			return ch
		}, "window"},
		"a change dated before the last": {func(t *testing.T, ch []artifacts.PolicyActivation) []artifacts.PolicyActivation {
			ch[1].ActivatedAt = "2026-11-06T11:00:00Z"
			ch[1].Signature = nil
			sealActivation(t, l, &ch[1], 30*time.Second)
			return ch
		}, "dated before"},
	} {
		t.Run(name, func(t *testing.T) {
			got := historyOf(t, c.change(t, activationChain(t, l, 3)))
			if got.OK || !strings.Contains(got.Reason, c.reason) {
				t.Fatalf("got ok=%v %q, want %q", got.OK, got.Reason, c.reason)
			}
		})
	}
}

// A chain anyone could log is no evidence: the entry must be a published key's.
func TestAnEntryByAnUnknownKeyFails(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	chain := activationChain(t, l, 1)
	delete(pinnedEntrySigners, signerFingerprint(t, l.signer))
	if got := historyOf(t, chain); got.OK || !strings.Contains(got.Reason, "not a published") {
		t.Fatalf("%+v", got)
	}
}

// A signature must not carry to another key's chain or another policy.
func TestTheSignatureBindsChainPolicyAndPlace(t *testing.T) {
	base := artifacts.PolicyActivationPreimage("a", "d", "p", "t", "n")
	for _, other := range [][]byte{
		artifacts.PolicyActivationPreimage("b", "d", "p", "t", "n"),
		artifacts.PolicyActivationPreimage("a", "e", "p", "t", "n"),
		artifacts.PolicyActivationPreimage("a", "d", "q", "t", "n"),
		artifacts.PolicyActivationPreimage("a", "d", "p", "u", "n"),
		artifacts.PolicyActivationPreimage("a", "d", "p", "t", "o"),
	} {
		if string(other) == string(base) {
			t.Fatal("a field is not bound")
		}
	}
}

func TestEveryRecordFieldIsInTheHash(t *testing.T) {
	a := artifacts.PolicyActivation{Format: "f", ChainID: "c", Sequence: 1, PreviousActivationHash: "p", PolicyID: "i", PolicyVersion: "v",
		PolicyHash: "h", DocumentHash: "d", ActivatedAt: "t", Signature: &artifacts.PolicyActivationSignature{PublicKey: "k", Signature: "s", SignedAt: "a", Nonce: "n"}}
	base := a.ComputeHash()
	for name, change := range map[string]func(*artifacts.PolicyActivation){
		"format": func(x *artifacts.PolicyActivation) { x.Format = "z" }, "chain": func(x *artifacts.PolicyActivation) { x.ChainID = "z" },
		"sequence": func(x *artifacts.PolicyActivation) { x.Sequence = 2 }, "previous": func(x *artifacts.PolicyActivation) { x.PreviousActivationHash = "z" },
		"id": func(x *artifacts.PolicyActivation) { x.PolicyID = "z" }, "version": func(x *artifacts.PolicyActivation) { x.PolicyVersion = "z" },
		"hash": func(x *artifacts.PolicyActivation) { x.PolicyHash = "z" }, "document": func(x *artifacts.PolicyActivation) { x.DocumentHash = "z" },
		"time": func(x *artifacts.PolicyActivation) { x.ActivatedAt = "z" }, "unsigned": func(x *artifacts.PolicyActivation) { x.Signature = nil },
	} {
		x := a
		change(&x)
		if x.ComputeHash() == base {
			t.Errorf("%s is not in the hash", name)
		}
	}
	// One field must not be able to spill into the next.
	y, z := a, a
	y.PolicyID, y.PolicyVersion = "ab", "c"
	z.PolicyID, z.PolicyVersion = "a", "bc"
	if y.ComputeHash() == z.ComputeHash() {
		t.Error("two fields can trade characters")
	}
}

func TestARecordMustNameAChangeInTheHistory(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	chain := activationChain(t, l, 2)
	in := historyOf(t, chain)
	recordInChain(&in, chain[1].ActivationHash)
	if !in.OK || !in.RecordInChain {
		t.Fatalf("%+v", in)
	}
	out := historyOf(t, chain)
	recordInChain(&out, strings.Repeat("9", 64))
	if out.OK {
		t.Fatal("a change outside the history passed")
	}
	none := historyOf(t, chain)
	recordInChain(&none, "")
	if none.OK {
		t.Fatal("a record naming no change passed")
	}
}

func TestStrangeHistoryFilesFail(t *testing.T) {
	for _, text := range []string{``, `{`, `[]`, `{"a":1}`, `[{"format":"x","format":"y"}]`, `[{"unknown":1}]`} {
		if got := checkPolicyHistory([]byte(text)); got.OK {
			t.Errorf("%q passed", text)
		}
	}
}

func TestHistoryModeReadsAFile(t *testing.T) {
	l := newTestLog(t)
	l.install(t)
	data, encodeErr := json.Marshal(activationChain(t, l, 2))
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	path := filepath.Join(t.TempDir(), "history.json")
	if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if code := runPolicyHistoryMode(path, true); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if code := runPolicyHistoryMode(path+"x", true); code != 2 {
		t.Fatalf("a missing file gave exit %d", code)
	}
}
