package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Round 62: a feed read from its start lists every webhook subscription in
// place at its end, by its sealed value, so a reader sees every place the
// account's events are sent; a part of a feed only counts its changes.
func TestTheFeedListsTheWebhooksInPlace(t *testing.T) {
	a := artifacts.WebhookValue("https://a.example/in", nil)
	b := artifacts.WebhookValue("https://b.example/in", []string{"run.refused"})
	add := func(seq int64, v string) SignalFeedEntry {
		return SignalFeedEntry{Sequence: seq, Change: artifacts.AccountWebhookSubscribed, Value: v}
	}
	remove := func(seq int64, v string) SignalFeedEntry {
		return SignalFeedEntry{Sequence: seq, Change: artifacts.AccountWebhookDeleted, Value: v}
	}
	other := SignalFeedEntry{Sequence: 9, Change: artifacts.AccountSettingVerdifaxDelete, Value: artifacts.SettingBlocked}
	for name, c := range map[string]struct {
		entries   []SignalFeedEntry
		fromStart bool
		changes   int
		want      []string
		note      string
	}{
		"no webhook ever":                     {[]SignalFeedEntry{other}, true, 0, nil, ""},
		"one added":                           {[]SignalFeedEntry{add(1, a), other}, true, 1, []string{a}, ""},
		"one added then removed":              {[]SignalFeedEntry{add(1, a), remove(2, a)}, true, 2, nil, ""},
		"the same address twice, one removed": {[]SignalFeedEntry{add(1, a), add(2, a), add(3, b), remove(4, a)}, true, 4, []string{a, b}, ""},
		"read from the middle":                {[]SignalFeedEntry{add(5, a)}, false, 1, nil, ""},
		"a removal never added":               {[]SignalFeedEntry{remove(3, b)}, true, 1, nil, "event 3 removes a webhook"},
	} {
		changes, got, notes := webhooksOf(c.entries, c.fromStart, nil)
		sort.Strings(c.want)
		if changes != c.changes || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %d change(s), in place %v; want %d, %v", name, changes, got, c.changes, c.want)
		}
		if (c.note == "") != (len(notes) == 0) || (c.note != "" && !strings.Contains(notes[0], c.note)) {
			t.Errorf("%s: notes %v, want %q", name, notes, c.note)
		}
	}
}
