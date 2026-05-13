package artifacts

import "testing"

// TestBuilderAndRecomputeAreInLockstep is the load-bearing test for the
// independent verifier. It builds a sample bundle through BuildAuditBundle
// (the one and only construction path) and then runs each Recompute*
// function over the resulting artifacts. Every recomputed hash must equal
// the value the builder filled in. If any one drifts, the verifier will
// reject every bundle in production — so this test guards the contract.
func TestBuilderAndRecomputeAreInLockstep(t *testing.T) {
	in := sampleInput()
	b := BuildAuditBundle(in)

	checks := []struct {
		name     string
		got      string
		want     string
	}{
		{"payload", RecomputePayloadHash(b.Payload), b.Payload.Hash},
		{"envelope", RecomputeEnvelopeHash(b.Envelope), b.Envelope.Hash},
		{"transport", RecomputeTransportHash(b.Transport), b.Transport.Hash},
		{"epa", RecomputeEPAHash(b.EPA), b.EPA.Hash},
		{"efa", RecomputeEFAHash(b.EFA), b.EFA.Hash},
		{"aer", RecomputeAERHash(b.AER), b.AER.Hash},
		{"transcript", RecomputeTranscriptHash(b.Transcript), b.Transcript.Hash},
		{"hardware_attestation", RecomputeHardwareAttestationHash(b.HardwareAttestation), b.HardwareAttestation.Hash},
		{"leakage_bundle", RecomputeLeakageBundleHash(b.LeakageBundle), b.LeakageBundle.Hash},
		{"zksp_binding", RecomputeZkspBindingHash(b.ZkspBinding), b.ZkspBinding.Hash},
		{"migration_token", RecomputeMigrationTokenHash(b.MigrationToken), b.MigrationToken.Hash},
		{"replay_fingerprint", RecomputeReplayFingerprintHash(b.ReplayFingerprint), b.ReplayFingerprint.Hash},
		{"pote_proof", RecomputePoteProofHash(b.PoteProof), b.PoteProof.Hash},
		{"final_vfa", RecomputeFinalVFAHash(b.FinalVFA), b.FinalVFA.Hash},
		{"request_substance", RecomputeRequestSubstanceHash(b.RequestSubstance), b.RequestSubstance.Hash},
		{"authorization_chain", RecomputeAuthorizationChainHash(b.AuthorizationChain), b.AuthorizationChain.Hash},
		{"regulatory_scaffolding", RecomputeRegulatoryScaffoldingHash(b.RegulatoryScaffolding), b.RegulatoryScaffolding.Hash},
		{"causal_graph", RecomputeCausalGraphHash(b.CausalGraph), b.CausalGraph.Hash},
		{"system_provenance", RecomputeSystemProvenanceHash(b.SystemProvenance), b.SystemProvenance.Hash},
		{"bundle", RecomputeBundleHash(b), b.BundleHash},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: builder produced %s, recompute produced %s — drift between builder.go and recompute.go",
				c.name, c.want, c.got)
		}
	}
}
