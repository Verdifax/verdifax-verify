package main

// Record values (v0.12.1). Round eight of the external review noted
// that the verdict never showed the values it had checked, so a reader
// comparing the record in another viewer could not see a discrepancy.
// Strict decoding now makes every reader see the same values; printing
// the decision-bearing ones lets a person confirm it by eye.

import (
	"fmt"
	"strings"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// RecordValues are the decision-bearing values of the record exactly
// as this tool decoded and checked them.
type RecordValues struct {
	Decision        string   `json:"decision"`
	AttestedKind    string   `json:"attested_decision_kind"`
	AttestedResult  string   `json:"attested_decision_result"`
	AttestedActor   string   `json:"attested_actor_id"`
	AivpOutcome     string   `json:"aivp_outcome"`
	AivpDecision    string   `json:"aivp_decision"`
	Approvers       []string `json:"approvers"`
	HumanInLoop     bool     `json:"human_in_loop_performed"`
	SLSALevel       int      `json:"slsa_level"`
	EffectsRecorded int      `json:"effects_recorded"`
	EnvelopeID      string   `json:"envelope_id"`
}

func recordValuesOf(b *artifacts.AuditBundle) RecordValues {
	v := RecordValues{
		Decision:        b.AER.Decision.Result,
		AttestedKind:    b.EPA.AttestedContext.DecisionKind,
		AttestedResult:  b.EPA.AttestedContext.DecisionResult,
		AttestedActor:   b.EPA.AttestedContext.ActorID,
		AivpOutcome:     b.AivpT4.Outcome,
		AivpDecision:    b.AivpT4.Decision,
		HumanInLoop:     b.AuthorizationChain.HumanInLoop.Performed,
		SLSALevel:       b.SystemProvenance.BuildProvenance.SLSALevel,
		EffectsRecorded: len(b.CausalGraph.EffectLog),
		EnvelopeID:      b.Envelope.EnvelopeID,
	}
	for _, a := range b.AuthorizationChain.Approvers {
		v.Approvers = append(v.Approvers, a.ActorID)
	}
	return v
}

func orNone(s string) string {
	if s == "" {
		return "(none recorded)"
	}
	return s
}

func printRecordValues(v RecordValues) {
	fmt.Println("  Record says (the values checked above; any viewer must show the same):")
	fmt.Printf("    decision:          %s\n", orNone(v.Decision))
	fmt.Printf("    attested decision: %s / %s, actor %s\n",
		orNone(v.AttestedKind), orNone(v.AttestedResult), orNone(v.AttestedActor))
	fmt.Printf("    AI governance:     outcome %s, decision %s\n", orNone(v.AivpOutcome), orNone(v.AivpDecision))
	fmt.Printf("    approvers:         %s (human in loop performed: %v)\n",
		orNone(strings.Join(v.Approvers, ", ")), v.HumanInLoop)
	fmt.Printf("    effects recorded:  %d; build SLSA level %d\n", v.EffectsRecorded, v.SLSALevel)
}
