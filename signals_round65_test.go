package main

import (
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Round 65, N44: a setting change prints with its name and new value, as
// --json already carries them, so a reader of the text report sees when, for
// example, the owner allowed owner reads.
func TestSettingChangesPrintTheirNameAndValue(t *testing.T) {
	c := &SignalFeedCheck{OK: true, Entries: []SignalFeedEntry{
		{Sequence: 11, Kind: "account.changed", Change: artifacts.AccountSettingOwnerReads, Value: artifacts.SettingAllowed},
		{Sequence: 12, Kind: "account.changed", Change: artifacts.AccountSettingVerdifaxDelete, Value: artifacts.SettingBlocked},
		{Sequence: 13, Kind: "account.changed", Change: artifacts.AccountWebhookSubscribed, Value: "sha256=ab kinds=run.sealed"},
	}}
	out := captureStdout(t, func() { printSignalFeed(c) })
	for _, want := range []string{"account.changed: setting.owner_reads = allowed", "account.changed: setting.verdifax_deletion = blocked",
		"account.changed: webhook.subscribed, sha256=ab kinds=run.sealed"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "webhook.subscribed = ") {
		t.Errorf("a webhook change is printed twice:\n%s", out)
	}
}
