package main

// Copy consistency (v0.17.9), the answer to round 43 of the external
// review. A record stores some values more than once: the envelope
// identifier in three sections, each section's sealed hash in the final
// VFA, and the AER, transport, program and payload hashes again in the
// execution record and the proof sections. The public-log entry or AMD's
// report binds one copy of each. Before this check the other copies were
// read by nothing, so a rewrite could change a copy and keep the bound
// value: the record then told two stories, and a reader of the copy saw
// the one no entry binds. Every copy must now equal the others.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// boundCopyGroup is one value the record stores in several places, named
// by JSON path. The first path is the copy the public-log entry or AMD's
// report binds in at least one record generation.
type boundCopyGroup struct {
	paths []string
	value func(b *artifacts.AuditBundle) []*string
}

// boundCopyGroups lists every value the record stores more than once by
// design. Each group's values are read from the decoded record, in the
// order of its paths; a value the record does not carry (an absent
// execution record) is nil.
var boundCopyGroups = []boundCopyGroup{
	{[]string{"envelope.envelope_id", "transport.envelope_id", "aer.envelope_id"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.Envelope.EnvelopeID, &b.Transport.EnvelopeID, &b.AER.EnvelopeID}
		}},
	{[]string{"envelope.seal.sealed_hash", "transport.envelope_hash", "final_vfa.envelope_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.Envelope.Seal.SealedHash, &b.Transport.EnvelopeHash, &b.FinalVFA.EnvelopeHash}
		}},
	{[]string{"aer.seal.sealed_hash", "final_vfa.aer_hash", "pote_proof.execution_trace_hash", "execution_record.aer_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.AER.Seal.SealedHash, &b.FinalVFA.AerHash, &b.PoteProof.ExecutionTraceHash, execRecordField(b, "aer_hash")}
		}},
	{[]string{"execution_record.transport_hash", "transport.seal.sealed_hash", "final_vfa.transport_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{execRecordField(b, "transport_hash"), &b.Transport.Seal.SealedHash, &b.FinalVFA.TransportHash}
		}},
	{[]string{"execution_record.program_hash", "envelope.registry_record_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{execRecordField(b, "program_hash"), &b.Envelope.RegistryRecordHash}
		}},
	{[]string{"execution_record.input_hash", "payload.content_hash", "envelope.payload_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{execRecordField(b, "input_hash"), &b.Payload.ContentHash, &b.Envelope.PayloadHash}
		}},
	{[]string{"zksp_binding.seal.sealed_hash", "final_vfa.zksp_binding_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.ZkspBinding.Seal.SealedHash, &b.FinalVFA.ZkspBindingHash}
		}},
	{[]string{"epa.seal.sealed_hash", "final_vfa.epa_hash"},
		func(b *artifacts.AuditBundle) []*string { return []*string{&b.EPA.Seal.SealedHash, &b.FinalVFA.EpaHash} }},
	{[]string{"efa.seal.sealed_hash", "final_vfa.efa_hash"},
		func(b *artifacts.AuditBundle) []*string { return []*string{&b.EFA.Seal.SealedHash, &b.FinalVFA.EfaHash} }},
	{[]string{"transcript.seal.sealed_hash", "final_vfa.transcript_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.Transcript.Seal.SealedHash, &b.FinalVFA.TranscriptHash}
		}},
	{[]string{"hardware_attestation.seal.sealed_hash", "final_vfa.hardware_attestation_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.HardwareAttestation.Seal.SealedHash, &b.FinalVFA.HardwareAttestHash}
		}},
	{[]string{"leakage_bundle.seal.sealed_hash", "final_vfa.leakage_bundle_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.LeakageBundle.Seal.SealedHash, &b.FinalVFA.LeakageBundleHash}
		}},
	{[]string{"migration_token.seal.sealed_hash", "final_vfa.migration_token_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.MigrationToken.Seal.SealedHash, &b.FinalVFA.MigrationTokenHash}
		}},
	{[]string{"replay_fingerprint.seal.sealed_hash", "final_vfa.replay_fingerprint"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.ReplayFingerprint.Seal.SealedHash, &b.FinalVFA.ReplayFingerprint}
		}},
	{[]string{"pote_proof.seal.sealed_hash", "final_vfa.pote_proof_hash"},
		func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.PoteProof.Seal.SealedHash, &b.FinalVFA.PoteProofHash}
		}},
}

// execRecordField returns a pointer to one hash of the execution record,
// or nil when the record carries none.
func execRecordField(b *artifacts.AuditBundle, field string) *string {
	rec := b.ExecutionRecord
	if rec == nil {
		return nil
	}
	switch field {
	case "aer_hash":
		return &rec.AerHash
	case "transport_hash":
		return &rec.TransportHash
	case "program_hash":
		return &rec.ProgramHash
	case "input_hash":
		return &rec.InputHash
	}
	return nil
}

// boundListGroup is one list the record stores in several places. In
// each path "[]" marks the item: the AER's execution ids, the EFA's step
// ids and the execution record's kernel output ids are the same six ids.
type boundListGroup struct {
	paths []string
	value func(b *artifacts.AuditBundle) [][]string
}

var boundListGroups = []boundListGroup{
	{[]string{"execution_record.kernel_output_ids[]", "aer.execution_ids[]", "efa.steps[].execution_id"},
		func(b *artifacts.AuditBundle) [][]string {
			steps := make([]string, len(b.EFA.Steps))
			for i, s := range b.EFA.Steps {
				steps[i] = s.ExecutionID
			}
			var kernel []string
			if b.ExecutionRecord != nil {
				kernel = b.ExecutionRecord.KernelOutputIDs
			}
			return [][]string{kernel, b.AER.ExecutionIDs, steps}
		}},
}

// boundCopyGroupOf returns the group that holds path, if any.
func boundCopyGroupOf(path string) (boundCopyGroup, bool) {
	for _, g := range boundCopyGroups {
		for _, p := range g.paths {
			if p == path {
				return g, true
			}
		}
	}
	return boundCopyGroup{}, false
}

// verifyBoundCopies returns one failure for every group whose copies the
// record carries but which do not all hold the same value.
func verifyBoundCopies(b *artifacts.AuditBundle) []string {
	var failures []string
	for _, g := range boundCopyGroups {
		var differ []string
		var first *string
		firstPath := ""
		for i, v := range g.value(b) {
			if v == nil {
				continue
			}
			if first == nil {
				first, firstPath = v, g.paths[i]
				continue
			}
			if *v != *first {
				differ = append(differ, g.paths[i])
			}
		}
		if len(differ) > 0 {
			failures = append(failures, fmt.Sprintf(
				"%s does not equal %s: the record stores this value more than once and its copies disagree",
				strings.Join(differ, " and "), firstPath))
		}
	}
	for _, g := range boundListGroups {
		var differ []string
		var first []string
		firstPath := ""
		for i, v := range g.value(b) {
			if b.ExecutionRecord == nil && strings.HasPrefix(g.paths[i], "execution_record.") {
				continue
			}
			if firstPath == "" {
				first, firstPath = v, g.paths[i]
				continue
			}
			if !slices.Equal(v, first) {
				differ = append(differ, g.paths[i])
			}
		}
		if len(differ) > 0 {
			failures = append(failures, fmt.Sprintf(
				"%s does not equal %s: the record stores this list more than once and its copies disagree",
				strings.Join(differ, " and "), firstPath))
		}
	}
	return failures
}
