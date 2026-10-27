package main

// Copy consistency (v0.17.9, extended in v0.17.10), the answer to rounds
// 43 and 44 of the external review. A record stores some values more
// than once: the envelope identifier in three sections, each section's
// sealed hash in the final VFA, the AER, transport, program and payload
// hashes again in the execution record and the proof sections, the
// public-log entry's number, time and checkpoint in the
// proof-of-execution section, the AIVP kernel's output id as the PIA
// hash, and so on. The public-log entry or AMD's report binds one copy
// of each. Before this check the other copies were read by nothing, so a
// rewrite could change a copy and keep the bound value: the record then
// told two stories, and a reader of the copy saw the one no entry binds.
// Every copy in the groups below must equal the others.
//
// The groups are a hand-written list, so a test
// (TestEveryDuplicatedValueIsAccountedFor) enumerates every value the
// published records store more than once and fails unless each is one
// of these groups, is checked another way, or is a listed coincidence
// of independently declared values. Round 44 found twelve copies the
// first list missed.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// boundCopyGroup is one value the record stores in several places, named
// by JSON path. The first path is the copy the public-log entry or AMD's
// report binds in at least one record generation. With anyOf, the first
// copy is written from one of the other sources and must equal at least
// one of them (the transcript records the execution record's proof hash,
// or, in records built before that hash existed, the AER hash).
type boundCopyGroup struct {
	paths []string
	value func(b *artifacts.AuditBundle) []*string
	anyOf bool
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func whenCarried(carried bool, s string) *string {
	if !carried {
		return nil
	}
	return &s
}

func listItem(l []string, i int) *string {
	if i >= len(l) {
		return nil
	}
	return &l[i]
}

// boundCopyGroups lists every value the record stores more than once by
// design. Each group's values are read from the decoded record, in the
// order of its paths; a value the record does not carry (an absent
// execution record, a section the record generation lacks) is nil.
var boundCopyGroups = []boundCopyGroup{
	{paths: []string{"envelope.envelope_id", "transport.envelope_id", "aer.envelope_id"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.Envelope.EnvelopeID, &b.Transport.EnvelopeID, &b.AER.EnvelopeID}
		}},
	{paths: []string{"envelope.seal.sealed_hash", "transport.envelope_hash", "final_vfa.envelope_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.Envelope.Seal.SealedHash, &b.Transport.EnvelopeHash, &b.FinalVFA.EnvelopeHash}
		}},
	{paths: []string{"aer.seal.sealed_hash", "final_vfa.aer_hash", "pote_proof.execution_trace_hash", "execution_record.aer_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.AER.Seal.SealedHash, &b.FinalVFA.AerHash, &b.PoteProof.ExecutionTraceHash, execRecordField(b, "aer_hash")}
		}},
	{paths: []string{"execution_record.transport_hash", "transport.seal.sealed_hash", "final_vfa.transport_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{execRecordField(b, "transport_hash"), &b.Transport.Seal.SealedHash, &b.FinalVFA.TransportHash}
		}},
	{paths: []string{"execution_record.program_hash", "envelope.registry_record_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{execRecordField(b, "program_hash"), &b.Envelope.RegistryRecordHash}
		}},
	{paths: []string{"execution_record.input_hash", "payload.content_hash", "envelope.payload_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{execRecordField(b, "input_hash"), &b.Payload.ContentHash, &b.Envelope.PayloadHash}
		}},
	{paths: []string{"zksp_binding.seal.sealed_hash", "final_vfa.zksp_binding_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.ZkspBinding.Seal.SealedHash, &b.FinalVFA.ZkspBindingHash}
		}},
	{paths: []string{"epa.seal.sealed_hash", "final_vfa.epa_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.EPA.Seal.SealedHash, &b.FinalVFA.EpaHash}
		}},
	{paths: []string{"efa.seal.sealed_hash", "final_vfa.efa_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.EFA.Seal.SealedHash, &b.FinalVFA.EfaHash}
		}},
	{paths: []string{"transcript.seal.sealed_hash", "final_vfa.transcript_hash", "transcript.transcript_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.Transcript.Seal.SealedHash, &b.FinalVFA.TranscriptHash, &b.Transcript.TranscriptHash}
		}},
	{paths: []string{"hardware_attestation.seal.sealed_hash", "final_vfa.hardware_attestation_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.HardwareAttestation.Seal.SealedHash, &b.FinalVFA.HardwareAttestHash}
		}},
	{paths: []string{"leakage_bundle.seal.sealed_hash", "final_vfa.leakage_bundle_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.LeakageBundle.Seal.SealedHash, &b.FinalVFA.LeakageBundleHash}
		}},
	{paths: []string{"migration_token.seal.sealed_hash", "final_vfa.migration_token_hash", "migration_token.state_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.MigrationToken.Seal.SealedHash, &b.FinalVFA.MigrationTokenHash, &b.MigrationToken.StateHash}
		}},
	{paths: []string{"replay_fingerprint.seal.sealed_hash", "final_vfa.replay_fingerprint"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.ReplayFingerprint.Seal.SealedHash, &b.FinalVFA.ReplayFingerprint}
		}},
	{paths: []string{"pote_proof.seal.sealed_hash", "final_vfa.pote_proof_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.PoteProof.Seal.SealedHash, &b.FinalVFA.PoteProofHash}
		}},

	// Round 44: copies outside the groups above were rewritable on the
	// hardware run while their originals were bound by the public-log
	// entry or AMD's report.

	// The AIVP kernel's output id is the PIA hash the AI-review section
	// shows; the three lists of execution ids hold it at index 4.
	{paths: []string{"aivp_t4.pia_hash", "aer.execution_ids[4]", "efa.steps[4].execution_id", "execution_record.kernel_output_ids[4]"},
		value: func(b *artifacts.AuditBundle) []*string {
			var kernel []string
			if b.ExecutionRecord != nil {
				kernel = b.ExecutionRecord.KernelOutputIDs
			}
			var step *string
			if len(b.EFA.Steps) > 4 {
				step = &b.EFA.Steps[4].ExecutionID
			}
			return []*string{nonEmpty(b.AivpT4.PiaHash), listItem(b.AER.ExecutionIDs, 4), step, listItem(kernel, 4)}
		}},
	// The proof-of-execution section repeats the run entry's number,
	// Rekor time and checkpoint from the anchor the verifier checks.
	{paths: []string{"rekor_anchor.log_entry_id", "pote_proof.log_entry_id"},
		value: func(b *artifacts.AuditBundle) []*string {
			on := b.PoteProof.LedgerBackend == "rekor"
			return []*string{whenCarried(on, b.RekorAnchor.LogEntryID), whenCarried(on, b.PoteProof.LogEntryID)}
		}},
	{paths: []string{"rekor_anchor.integrated_time", "pote_proof.integrated_time"},
		value: func(b *artifacts.AuditBundle) []*string {
			on := b.PoteProof.LedgerBackend == "rekor"
			return []*string{whenCarried(on, strconv.FormatInt(b.RekorAnchor.IntegratedTime, 10)),
				whenCarried(on, strconv.FormatInt(b.PoteProof.IntegratedTime, 10))}
		}},
	{paths: []string{"rekor_anchor.checkpoint", "pote_proof.ledger_checkpoint"},
		value: func(b *artifacts.AuditBundle) []*string {
			on := b.PoteProof.LedgerBackend == "rekor"
			return []*string{whenCarried(on, b.RekorAnchor.Checkpoint), whenCarried(on, b.PoteProof.LedgerCheckpoint)}
		}},
	// The transcript records the hash the ZK stage ran over: the
	// execution record's proof hash, or, in records built before that
	// hash existed, the AER hash.
	{paths: []string{"transcript.proof_hash_input", "execution_record.proof_hash", "aer.seal.sealed_hash"}, anyOf: true,
		value: func(b *artifacts.AuditBundle) []*string {
			var proof *string
			if b.ExecutionRecord != nil {
				proof = nonEmpty(b.ExecutionRecord.ProofHash)
			}
			return []*string{&b.Transcript.ProofHashInput, proof, &b.AER.Seal.SealedHash}
		}},
	// A SEV-SNP record shows the guest's launch measurement, the platform
	// label and the report data twice: in the section and in its
	// verification block (which verifySevSnpQuote compares with the raw
	// report). A hosted record's measurement field holds the section's
	// sealed hash.
	{paths: []string{"hardware_attestation.verification.measurement_hex", "hardware_attestation.enclave_measurement"},
		value: func(b *artifacts.AuditBundle) []*string {
			v := b.HardwareAttestation.Verification
			if v == nil {
				return []*string{nil, nil}
			}
			return []*string{&v.MeasurementHex, &b.HardwareAttestation.EnclaveMeasurement}
		}},
	{paths: []string{"hardware_attestation.seal.sealed_hash", "hardware_attestation.enclave_measurement"},
		value: func(b *artifacts.AuditBundle) []*string {
			if b.HardwareAttestation.AttestationMode == "sev_snp" {
				return []*string{nil, nil}
			}
			return []*string{&b.HardwareAttestation.Seal.SealedHash, &b.HardwareAttestation.EnclaveMeasurement}
		}},
	{paths: []string{"hardware_attestation.verification.platform", "hardware_attestation.platform"},
		value: func(b *artifacts.AuditBundle) []*string {
			v := b.HardwareAttestation.Verification
			if v == nil {
				return []*string{nil, nil}
			}
			return []*string{&v.Platform, &b.HardwareAttestation.Platform}
		}},
	{paths: []string{"hardware_attestation.verification.report_data_hex", "hardware_attestation.report_data_hex"},
		value: func(b *artifacts.AuditBundle) []*string {
			v := b.HardwareAttestation.Verification
			if v == nil {
				return []*string{nil, nil}
			}
			return []*string{&v.ReportDataHex, &b.HardwareAttestation.ReportDataHex}
		}},
	// One sequence id, one clock and one manifest hash, written into
	// several sections.
	{paths: []string{"transport.sequence_id", "aer.sequence_id"},
		value: func(b *artifacts.AuditBundle) []*string { return []*string{&b.Transport.SequenceID, &b.AER.SequenceID} }},
	{paths: []string{"envelope.timestamp", "generated_at", "epa.environment_snapshot.time"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.Envelope.Timestamp, &b.GeneratedAt, &b.EPA.EnvironmentSnapshot.Time}
		}},
	{paths: []string{"manifest_hash", "replay_fingerprint.expected_output_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.ManifestHash, &b.ReplayFingerprint.ExpectedOutputHash}
		}},
	// The server's own commit, stated twice in the provenance section.
	{paths: []string{"system_provenance.orchestrator_git_sha", "system_provenance.build_provenance.source_commit_sha"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.SystemProvenance.OrchestratorGitSHA, nonEmpty(b.SystemProvenance.BuildProvenance.SourceCommitSHA)}
		}},
	// The caller's attested decision, copied from the EPA's attested
	// context into the AER's decision record.
	{paths: []string{"aer.decision.kind", "epa.attested_context.decision_kind"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.AER.Decision.Kind, &b.EPA.AttestedContext.DecisionKind}
		}},
	{paths: []string{"aer.decision.result", "epa.attested_context.decision_result"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.AER.Decision.Result, &b.EPA.AttestedContext.DecisionResult}
		}},
	{paths: []string{"aer.decision.note", "epa.attested_context.decision_note"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.AER.Decision.Note, &b.EPA.AttestedContext.DecisionNote}
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
// extras names scalar copies of single items (the PIA hash is item 4).
type boundListGroup struct {
	paths  []string
	value  func(b *artifacts.AuditBundle) [][]string
	extras map[int][]string
}

var boundListGroups = []boundListGroup{
	{paths: []string{"execution_record.kernel_output_ids[]", "aer.execution_ids[]", "efa.steps[].execution_id"},
		value: func(b *artifacts.AuditBundle) [][]string {
			steps := make([]string, len(b.EFA.Steps))
			for i, s := range b.EFA.Steps {
				steps[i] = s.ExecutionID
			}
			var kernel []string
			if b.ExecutionRecord != nil {
				kernel = b.ExecutionRecord.KernelOutputIDs
			}
			return [][]string{kernel, b.AER.ExecutionIDs, steps}
		},
		extras: map[int][]string{4: {"aivp_t4.pia_hash"}}},
}

// boundCopyGroupOf returns the first group that holds path, if any.
func boundCopyGroupOf(path string) (boundCopyGroup, bool) {
	for _, g := range boundCopyGroups {
		if slices.Contains(g.paths, path) {
			return g, true
		}
	}
	return boundCopyGroup{}, false
}

// boundCopyPeers returns every other path that shares a group with path.
func boundCopyPeers(path string) []string {
	var peers []string
	for _, g := range boundCopyGroups {
		if !slices.Contains(g.paths, path) {
			continue
		}
		for _, p := range g.paths {
			if p != path && !slices.Contains(peers, p) {
				peers = append(peers, p)
			}
		}
	}
	return peers
}

// verifyBoundCopies returns one failure for every group whose copies the
// record carries but which do not all hold the same value.
func verifyBoundCopies(b *artifacts.AuditBundle) []string {
	var failures []string
	for _, g := range boundCopyGroups {
		vals := g.value(b)
		if g.anyOf {
			if vals[0] == nil {
				continue
			}
			var others []string
			matched := false
			for i, v := range vals[1:] {
				if v == nil {
					continue
				}
				others = append(others, g.paths[i+1])
				matched = matched || *v == *vals[0]
			}
			if len(others) > 0 && !matched {
				failures = append(failures, fmt.Sprintf(
					"%s equals neither %s: the record copies this value from one of them and the copy disagrees",
					g.paths[0], strings.Join(others, " nor ")))
			}
			continue
		}
		var differ []string
		var first *string
		firstPath := ""
		for i, v := range vals {
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
