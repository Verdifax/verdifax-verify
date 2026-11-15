package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Round 62: each machine names itself as its feed events' source, held to
// the key that logged each event; events already published keep the hosted
// service's name.

func readFeed(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// renameSources rewrites every event's source from one base to another.
func renameSources(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	// any: the feed file is rewritten field by field, keeping every other value.
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	events, _ := doc.([]any)
	if page, isPage := doc.(map[string]any); isPage {
		events, _ = page["events"].([]any)
	}
	if len(events) == 0 {
		t.Fatal("the feed holds no events")
	}
	for _, e := range events {
		ev := e.(map[string]any)
		ev["source"] = strings.Replace(ev["source"].(string), from, to, 1)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPublishedFeedsKeepVerifying(t *testing.T) {
	for _, f := range []string{"testdata/round63/attested-signals-2026-11-14.json", "testdata/round63/hosted-signals-2026-11-14.json"} {
		if c := checkSignalFeed(readFeed(t, f), nil); !c.OK {
			t.Errorf("%s no longer verifies: %s", f, c.Reason)
		}
	}
}

func TestHardwareMachineNamesItself(t *testing.T) {
	raw := renameSources(t, readFeed(t, "testdata/round63/attested-signals-2026-11-14.json"), signalSource, attestedSignalSource)
	if c := checkSignalFeed(raw, nil); !c.OK {
		t.Fatalf("key 4's events naming the hardware machine must verify: %s", c.Reason)
	}
}

func TestHostedEventsCannotNameTheHardwareMachine(t *testing.T) {
	raw := renameSources(t, readFeed(t, "testdata/round63/hosted-signals-2026-11-14.json"), signalSource, attestedSignalSource)
	if c := checkSignalFeed(raw, nil); c.OK || !strings.Contains(c.Reason, "names the hardware-attested machine") {
		t.Fatalf("an event logged by the hosted service's key naming the hardware machine must fail: %+v", c.Reason)
	}
}

func TestKey4EventsAfterTheSwitchMustNameTheMachine(t *testing.T) {
	saved := key4HostedSourceUntilUnix
	key4HostedSourceUntilUnix = 0
	defer func() { key4HostedSourceUntilUnix = saved }()
	if c := checkSignalFeed(readFeed(t, "testdata/round63/attested-signals-2026-11-14.json"), nil); c.OK || !strings.Contains(c.Reason, "does not name the hardware-attested machine") {
		t.Fatalf("key 4's events logged after the switch under the hosted name must fail: %+v", c.Reason)
	}
}
