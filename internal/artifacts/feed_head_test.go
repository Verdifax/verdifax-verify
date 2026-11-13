package artifacts

import (
	"strings"
	"testing"
)

// Round 61, N23: a feed head states the account's highest event and that
// event's hash; its hash covers every stated value and its leaf binds them,
// so a head for another account, place or event cannot stand for this one.
func TestFeedHeadBindsItsPlace(t *testing.T) {
	h := &FeedHead{Format: FeedHeadFormat, Account: "account-7", Sequence: 12, HeadHash: strings.Repeat("a", 64), StatedAt: "2026-11-12T21:58:20Z"}
	h.HeadStatementHash = h.ComputeHash()
	if err := h.Validate(); err != nil {
		t.Fatalf("a head must be valid: %v", err)
	}
	want := lengthPrefixedHash([]string{FeedHeadFormat, "account-7", "12", strings.Repeat("a", 64), "2026-11-12T21:58:20Z"})
	if h.HeadStatementHash != want {
		t.Fatal("the head's recipe changed")
	}
	leaf := h.LeafHash()
	for name, mutate := range map[string]func(x *FeedHead){
		"account": func(x *FeedHead) { x.Account = "account-8" }, "sequence": func(x *FeedHead) { x.Sequence = 13 },
		"head": func(x *FeedHead) { x.HeadHash = strings.Repeat("b", 64) }, "time": func(x *FeedHead) { x.StatedAt = "2026-11-12T21:58:21Z" },
	} {
		x := *h
		mutate(&x)
		if x.ComputeHash() == h.HeadStatementHash {
			t.Errorf("the hash must cover the %s", name)
		}
		x.HeadStatementHash = x.ComputeHash()
		if x.LeafHash() == leaf {
			t.Errorf("the leaf must cover the %s", name)
		}
	}
	for name, mutate := range map[string]func(x *FeedHead){
		"format": func(x *FeedHead) { x.Format = SignOffHeadFormat }, "account": func(x *FeedHead) { x.Account = "acct-7" },
		"sequence": func(x *FeedHead) { x.Sequence = 0 }, "head": func(x *FeedHead) { x.HeadHash = "x" },
		"time": func(x *FeedHead) { x.StatedAt = "" }, "statement": func(x *FeedHead) { x.HeadStatementHash = "" },
	} {
		x := *h
		mutate(&x)
		if x.Validate() == nil {
			t.Errorf("a head with a bad %s must be refused", name)
		}
	}
	signOff := &SignOffHead{Format: SignOffHeadFormat, ChainID: "account-7", Sequence: 12, HeadHash: h.HeadHash, StatedAt: h.StatedAt}
	signOff.HeadStatementHash = h.HeadStatementHash
	if signOff.LeafHash() == leaf {
		t.Fatal("a sign-off head's leaf must never stand for a feed head's")
	}
}
