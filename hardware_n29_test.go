package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Round 62, N29: every hardware record states its debug setting and its
// firmware; --strict-hardware fails debug on or unpinned firmware; a sealed
// guest policy must equal the report's own.

const october2026Firmware = "7a89cceaaba0bbdddc4f775acca3ef15d1f9bf8abccdc6115cfad7fb8eae113df3ee0bb50efa34db9c53ae065b1dc766"

func TestHardwareStatementCases(t *testing.T) {
	cases := []struct {
		debug       bool
		measurement string
		want        string
		strict      bool
	}{
		{false, october2026Firmware, "debug off; firmware is ", false},
		{true, october2026Firmware, "debug ON, the host could read this machine's memory; firmware is ", true},
		{false, strings.Repeat("ab", 48), "debug off; firmware not one Verdifax pins", true},
		{true, strings.Repeat("ab", 48), "debug ON, the host could read this machine's memory; firmware not one Verdifax pins", true},
	}
	for _, c := range cases {
		got, strictFailure := hardwareStatement(c.debug, c.measurement)
		if !strings.HasPrefix(got, c.want) {
			t.Errorf("debug %v, measurement %.8s: statement %q, want it to start %q", c.debug, c.measurement, got, c.want)
		}
		if (strictFailure != "") != c.strict {
			t.Errorf("debug %v, measurement %.8s: strict failure %q, want failing %v", c.debug, c.measurement, strictFailure, c.strict)
		}
	}
}

func loadHardwareRecord(t *testing.T) *artifacts.AuditBundle {
	t.Helper()
	raw, err := os.ReadFile("testdata/round40/hardware-run-2026-10.json")
	if err != nil {
		t.Fatal(err)
	}
	var b artifacts.AuditBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

func TestHardwareRecordStatesDebugAndFirmware(t *testing.T) {
	b := loadHardwareRecord(t)
	c := verifySevSnpQuote(b)
	if !c.Match || c.Computed != "verified; debug off; firmware is "+pinnedFirmware[october2026Firmware] {
		t.Fatalf("the October 2026 record reads %+v, want verified with debug off and its firmware pinned", c)
	}
	strictHardware = true
	defer func() { strictHardware = false }()
	if c := verifySevSnpQuote(b); !c.Match {
		t.Fatalf("--strict-hardware failed the October 2026 record, whose debug is off and firmware pinned: %+v", c)
	}
}

func TestStrictHardwareFailsUnpinnedFirmware(t *testing.T) {
	saved := pinnedFirmware
	pinnedFirmware = map[string]string{}
	defer func() { pinnedFirmware = saved }()
	b := loadHardwareRecord(t)
	if c := verifySevSnpQuote(b); !c.Match || !strings.Contains(c.Computed, "firmware not one Verdifax pins") {
		t.Fatalf("without --strict-hardware an unpinned firmware must be stated, not failed: %+v", c)
	}
	strictHardware = true
	defer func() { strictHardware = false }()
	if c := verifySevSnpQuote(b); c.Match || !strings.Contains(c.Computed, "--strict-hardware: its firmware is not one Verdifax pins") {
		t.Fatalf("--strict-hardware must fail an unpinned firmware: %+v", c)
	}
}

func TestSealedGuestPolicyMustMatchTheReport(t *testing.T) {
	b := loadHardwareRecord(t)
	v := *b.HardwareAttestation.Verification
	v.PolicyHex = "0000000000030000"
	b.HardwareAttestation.Verification = &v
	if c := verifySevSnpQuote(b); c.Match || !strings.Contains(c.Computed, "verification.policy_hex") {
		t.Fatalf("a sealed guest policy that differs from the report must fail: %+v", c)
	}
	v.PolicyHex = "0000000002030000"
	vmpl := uint32(0)
	v.VMPL = &vmpl
	b.HardwareAttestation.Verification = &v
	if c := verifySevSnpQuote(b); c.Match || !strings.Contains(c.Computed, "verification.vmpl") {
		t.Fatalf("a sealed privilege level that differs from the report must fail: %+v", c)
	}
	vmpl = 1
	if c := verifySevSnpQuote(b); !c.Match {
		t.Fatalf("a sealed policy and privilege level equal to the report's must pass: %+v", c)
	}
}

// R300 (round 63): a pinned firmware statement says what the measurement
// identifies: the platform every guest of that generation shares, never a
// Verdifax machine of its own.
func TestPinnedFirmwareNamesThePlatformNotTheMachine(t *testing.T) {
	for m, words := range pinnedFirmware {
		statement, _ := hardwareStatement(false, m)
		for _, want := range []string{"shares", "identifies the platform", "not the Verdifax machine"} {
			if !strings.Contains(statement, want) {
				t.Errorf("firmware %s...: statement %q does not say %q", m[:8], statement, want)
			}
		}
		if strings.Contains(words, "firmware of Verdifax") || strings.Contains(statement, "firmware matches") {
			t.Errorf("firmware %s...: statement %q reads as identifying a Verdifax machine", m[:8], statement)
		}
	}
}
