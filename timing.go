package main

// Bundle-level verification of the measured runtime timings.
//
// The timings are real per-stage measurements; their digest is sealed
// in the bundle and recomputed here, so editing a duration after
// sealing is detected. Honest boundary, stated wherever the timing is
// reported: the digest is NOT in the anchored leaf, because per-run
// timings there would ride into the manifest hash and break replay
// determinism; an editor who rewrites the timings AND the digest
// together defeats this check, which is exactly as far as a
// bundle-level seal reaches.

import (
	"fmt"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// TimingCheck records the runtime-timing digest verdict.
type TimingCheck struct {
	Performed bool   `json:"performed"`
	Match     bool   `json:"match"`
	Stages    int    `json:"stages,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

func verifyRuntimeTiming(b *artifacts.AuditBundle) TimingCheck {
	if b.RuntimeTimingHash == "" && len(b.RuntimeTiming) == 0 {
		return TimingCheck{Performed: false,
			Reason: "no runtime timing recorded (bundle predates the instrumentation)"}
	}
	recomputed := artifacts.ComputeRuntimeTimingHash(b.RuntimeTiming)
	if recomputed != b.RuntimeTimingHash {
		return TimingCheck{Performed: true, Match: false, Stages: len(b.RuntimeTiming),
			Reason: "the recorded timing digest does not match the measured durations in this bundle"}
	}
	return TimingCheck{Performed: true, Match: true, Stages: len(b.RuntimeTiming)}
}

func printTimingCheck(c TimingCheck) {
	switch {
	case c.Performed && c.Match:
		fmt.Printf("  Runtime timing:   %d stages measured, digest matches (bundle-sealed, not anchored)\n", c.Stages)
	case c.Performed && !c.Match:
		fmt.Printf("  Runtime timing:   ✗ FAILED · %s\n", c.Reason)
	default:
		fmt.Printf("  Runtime timing:   not recorded (pre-instrumentation bundle)\n")
	}
}
