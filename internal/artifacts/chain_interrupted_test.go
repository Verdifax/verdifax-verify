package artifacts

import (
	"strings"
	"testing"
)

func sampleInterrupted() ChainInterrupted {
	c := ChainInterrupted{Format: ChainInterruptedFormat, Chain: GapChainSignOffs, Place: 4, RecordKind: SignOffKind,
		PlannedRecordHash: strings.Repeat("a", 64), PlannedLeaf: strings.Repeat("b", 64), RecordedAt: "2026-11-10T12:00:00.000000000Z",
		Signal: SignalLink{Account: "account-7", Sequence: 9, PreviousSignalHash: strings.Repeat("c", 64)}}
	c.InterruptedHash = c.ComputeHash()
	return c
}

// Round 57, N2: an interrupted record names one place of a sign-off or policy
// chain, the record that was being logged there and the leaf its entry would
// carry; every one of those values is in its hash and its leaf.
func TestAnInterruptedRecordBindsThePlaceAndThePlannedEntry(t *testing.T) {
	c := sampleInterrupted()
	if err := c.Validate(); err != nil {
		t.Fatalf("a well-formed record must validate: %v", err)
	}
	if err := ValidateReceiptLeafFieldsV3(ChainInterruptedKind, c.Signal.Account, c.InterruptedHash, c.Signal.Sequence, c.Signal.PreviousSignalHash); err != nil {
		t.Fatalf("its entry must be loggable: %v", err)
	}
	for name, change := range map[string]func(*ChainInterrupted){
		"place":        func(x *ChainInterrupted) { x.Place = 5 },
		"planned leaf": func(x *ChainInterrupted) { x.PlannedLeaf = strings.Repeat("d", 64) },
		"record hash":  func(x *ChainInterrupted) { x.PlannedRecordHash = strings.Repeat("e", 64) },
		"chain":        func(x *ChainInterrupted) { x.Chain = GapChainAccountPolicy; x.RecordKind = PolicyActivationKind },
		"feed place":   func(x *ChainInterrupted) { x.Signal.Sequence = 10 },
	} {
		x := sampleInterrupted()
		change(&x)
		if x.ComputeHash() == c.InterruptedHash {
			t.Errorf("changing the %s must change the hash", name)
		}
	}
	for name, change := range map[string]func(*ChainInterrupted){
		"the feed chain":                 func(x *ChainInterrupted) { x.Chain = GapChainSignals },
		"a policy chain with no key":     func(x *ChainInterrupted) { x.Chain = GapChainPolicy; x.RecordKind = PolicyActivationKind },
		"a sign-off chain with a key":    func(x *ChainInterrupted) { x.KeyID = 3 },
		"a sign-off chain's policy kind": func(x *ChainInterrupted) { x.RecordKind = PolicyActivationKind },
		"place zero":                     func(x *ChainInterrupted) { x.Place = 0 },
		"a short planned leaf":           func(x *ChainInterrupted) { x.PlannedLeaf = "abc" },
	} {
		x := sampleInterrupted()
		change(&x)
		if x.Validate() == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}
