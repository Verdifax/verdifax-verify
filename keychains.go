package main

// Request-key chains (round 61, N22). Since the server release that came
// with v0.34.0, each customer key's request key is sealed in its account's
// feed when the key's holder registers it, replaces it or clears it, and when
// Verdifax clears it. --signals follows each key's chain: the first
// registration pins a key, each replacement must carry a valid approval by
// the key before it, and a clear by Verdifax breaks the chain. A change the
// owner decides must then be signed by the owner key's request key current at
// that event. A key registered before the feed shows (before the server
// sealed registrations, or before the point checked) cannot be followed; the
// report says so and names --owner-request-key, which confirms the keys from
// outside the feed.

import (
	"fmt"
	"sort"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// requestKeyChains follows every key's request-key chain through a feed.
type requestKeyChains struct {
	byKey map[int64]*RequestKeyChain
	// ownerKeyID is the account's owner key, by its creation in the feed,
	// or 0 when the feed given does not show it.
	ownerKeyID int64
	ownerKeys  map[int64]bool
	notes      []string
	noted      map[string]bool
	// freshStart is the latest event, after the account's start, that began
	// the owner's chain afresh (round 62, N28): Verdifax clearing the owner
	// key's request key, the owner clearing its own, or Verdifax replacing
	// the owner key. Nil while the feed shows none.
	freshStart *ownerFreshStart
	// unconfirmed marks an owner key whose current request key was
	// registered after a fresh start and is not named by --owner-request-key.
	unconfirmed map[int64]bool
}

// ownerFreshStart is one event that began the owner's chain afresh.
type ownerFreshStart struct {
	Sequence int64
	Route    string
}

// The three routes that begin the owner's chain afresh (round 62, N28),
// worded as the report prints them.
const (
	freshStartVerdifaxClear = "Verdifax cleared the owner key's request key"
	freshStartOwnerClear    = "the owner cleared the owner key's request key"
	freshStartReplaced      = "Verdifax replaced the owner key"
)

func newRequestKeyChains() *requestKeyChains {
	return &requestKeyChains{byKey: map[int64]*RequestKeyChain{}, ownerKeys: map[int64]bool{}, noted: map[string]bool{},
		unconfirmed: map[int64]bool{}}
}

// startOwnerAfresh records a fresh start of the owner's chain and, when no
// key is pinned, says how to confirm what follows.
func (r *requestKeyChains) startOwnerAfresh(sequence int64, route string, keyID int64, pinned map[string]bool) {
	r.freshStart = &ownerFreshStart{Sequence: sequence, Route: route}
	r.unconfirmed[keyID] = true
	if len(pinned) == 0 && route != freshStartVerdifaxClear {
		r.note(fmt.Sprintf("%s at event %d, so the owner's chain starts afresh there; pass --owner-request-key to confirm later owner changes.", route, sequence))
	}
}

// isOwnerKey reports whether the feed has shown keyID as an owner key.
func (r *requestKeyChains) isOwnerKey(keyID int64) bool { return r.ownerKeys[keyID] }

// unconfirmedOwnerSigner reports whether an owner change signed by signer is
// unconfirmed, and the fresh start that made it so. A signer the owner key's
// chain does not hold is left to checkOwnerSigner, which fails it.
func (r *requestKeyChains) unconfirmedOwnerSigner(signer string) (bool, *ownerFreshStart) {
	ch, known := r.byKey[r.ownerKeyID]
	if r.ownerKeyID == 0 || !known || ch.Current != signer || r.freshStart == nil {
		return false, nil
	}
	return r.unconfirmed[r.ownerKeyID], r.freshStart
}

func (r *requestKeyChains) note(text string) {
	if !r.noted[text] {
		r.noted[text] = true
		r.notes = append(r.notes, text)
	}
}

func (r *requestKeyChains) chain(keyID int64) *RequestKeyChain {
	c, ok := r.byKey[keyID]
	if !ok {
		c = &RequestKeyChain{KeyID: keyID}
		r.byKey[keyID] = c
	}
	return c
}

// apply reads one checked event into the chains and returns why the feed
// fails at it, or "".
func (r *requestKeyChains) apply(sequence int64, kind string, got *checkedEntry, pinned map[string]bool) string {
	if got.keyScope == artifacts.KeyScopeOwner {
		switch kind {
		case artifacts.SignalKeyCreated:
			// A second owner key is a replacement: its first request key
			// starts the owner's chain afresh (round 62, N28).
			if len(r.ownerKeys) > 0 {
				r.startOwnerAfresh(sequence, freshStartReplaced, got.keyID, pinned)
			}
			r.ownerKeyID, r.ownerKeys[got.keyID] = got.keyID, true
		case artifacts.SignalKeyRevoked:
			if r.ownerKeyID == got.keyID {
				r.ownerKeyID = 0
			}
		}
	}
	if c := got.change; c != nil && artifacts.IsRequestKeyAction(c.Action) {
		if failure := r.applyChange(sequence, c, pinned); failure != "" {
			return failure
		}
	}
	if got.ownerKey != "" {
		return r.checkOwnerSigner(sequence, got.ownerKey)
	}
	return ""
}

// applyChange follows one registration, replacement or clear.
func (r *requestKeyChains) applyChange(sequence int64, c *artifacts.AccountChange, pinned map[string]bool) string {
	ch := r.chain(c.KeyID)
	rooted := len(ch.Events) > 0
	ch.Events = append(ch.Events, RequestKeyEventAt{Sequence: sequence, Action: c.Action, Key: c.Value, DecidedBy: c.DecidedBy})
	owner := r.ownerKeys[c.KeyID]
	held := func() string {
		if ch.Current == "" {
			return "holds none"
		}
		return "is " + truncate(ch.Current, 12)
	}
	switch {
	case c.Action == artifacts.AccountRequestKeyRegistered:
		if ch.Current != "" {
			return fmt.Sprintf("it registers a request key for key %d, which holds one already; a held request key is replaced only with its own approval", c.KeyID)
		}
		// After a fresh start nothing approves the new key, so it is
		// unconfirmed unless --owner-request-key names it (round 62, N28).
		if owner {
			r.unconfirmed[c.KeyID] = r.freshStart != nil && !pinned[c.Value]
		}
	case c.Action == artifacts.AccountRequestKeyCleared && c.DecidedBy == artifacts.DecidedByVerdifax:
		ch.Current, ch.ClearedByVerdifax = "", sequence
		if owner {
			if len(pinned) == 0 {
				r.note(fmt.Sprintf("the owner's key chain was cleared by Verdifax at event %d; pass --owner-request-key to confirm later owner changes.", sequence))
			}
			r.startOwnerAfresh(sequence, freshStartVerdifaxClear, c.KeyID, pinned)
		}
		return ""
	default:
		// A replacement, or the holder's own clear: approved by the key
		// before it. The approval's signature was checked with the record;
		// here its key must be the chain's.
		approver := c.RequestKeyApproval.PublicKey
		if !rooted {
			ch.Unrooted = true
		} else if approver != ch.Current {
			return fmt.Sprintf("it changes key %d's request key with the approval of %s, and the key's request key at this event %s",
				c.KeyID, truncate(approver, 12), held())
		}
	}
	if c.Value != "" && owner && len(pinned) > 0 && !pinned[c.Value] {
		return fmt.Sprintf("the owner key's request key set here, %s, is not one given with --owner-request-key", truncate(c.Value, 12))
	}
	// The holder's own clear starts the owner's chain afresh; a replacement
	// approved by the key before it keeps that key's standing (round 62, N28).
	if owner && rooted {
		switch c.Action {
		case artifacts.AccountRequestKeyCleared:
			r.startOwnerAfresh(sequence, freshStartOwnerClear, c.KeyID, pinned)
		case artifacts.AccountRequestKeyRotated:
			r.unconfirmed[c.KeyID] = r.unconfirmed[c.KeyID] && !pinned[c.Value]
		}
	}
	ch.Current = c.Value
	return ""
}

// checkOwnerSigner checks the request key that signed an owner's change
// against the owner key's chain at that event.
func (r *requestKeyChains) checkOwnerSigner(sequence int64, signer string) string {
	ch, known := r.byKey[r.ownerKeyID]
	if r.ownerKeyID == 0 || !known || len(ch.Events) == 0 {
		r.note("the owner key's request key is not registered in this feed (it was registered before the server sealed registrations, or before the point checked), " +
			"so the owner's changes are checked against the key each names; pass --owner-request-key to confirm them.")
		return ""
	}
	switch {
	case ch.Current == "":
		return fmt.Sprintf("a change the owner decided is signed by request key %s, and the owner key holds no request key at this event", truncate(signer, 12))
	case ch.Current != signer:
		return fmt.Sprintf("a change the owner decided is signed by request key %s, and the owner key's request key at this event is %s",
			truncate(signer, 12), truncate(ch.Current, 12))
	}
	return ""
}

// report lists the chains by key, and the notes.
func (r *requestKeyChains) report() ([]RequestKeyChain, []string) {
	var out []RequestKeyChain
	for id, ch := range r.byKey {
		ch.OwnerKey = r.ownerKeys[id]
		out = append(out, *ch)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out, r.notes
}
