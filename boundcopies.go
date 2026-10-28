package main

// Copy consistency (v0.17.9, extended in v0.17.10 and v0.17.11), the
// answer to rounds 43, 44 and 45 of the external review. A record stores
// some values more than once: the envelope identifier in three sections,
// each section's sealed hash in the final VFA, the AER, transport,
// program and payload hashes again in the execution record and the proof
// sections, the public-log entry's number, time and checkpoint in the
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
//
// Round 45 found two groups that a field the record itself declares
// could switch off: the entry groups read the proof section's own
// ledger name, and the PIA-hash group skipped a deleted PIA hash. A
// group that compares nothing under some condition now names that
// condition as a gate (copyGate): the field a forger would have to
// change, and the value that switches the group off. A test switches
// every gate off on every record generation and requires the public log
// or AMD's report to catch it, unless the record already discloses the
// group's paths as uncovered (TestEveryGateIsBound), and another test
// fails any group that returns no value for a path the record carries
// without a declared gate (TestEveryGateIsDeclared).

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// boundCopyGroup is one value the record stores in several places, named
// by JSON path. The first path is the copy the public-log entry or AMD's
// report binds in at least one record generation.
type boundCopyGroup struct {
	paths []string
	value func(b *artifacts.AuditBundle) []*string
	// gates are the conditions under which the group compares nothing
	// although the record carries its paths; empty when it always
	// compares. Each names the field that decides it.
	gates []copyGate
}

// copyGate is one field whose value switches a copy group off. off is
// the value a forger would write there (or the key is deleted when
// deleted is true), active reports whether the group is on for a
// record, and why says what binds the field.
type copyGate struct {
	path    string
	off     string
	deleted bool
	active  func(b *artifacts.AuditBundle) bool
	why     string
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

// The conditions the gates read. Each reads a field the public log or
// AMD's report binds, or whose change fails the record on its own.

// rekorAnchored reports whether the record's anchor names the public
// log. The verifier dispatches on this field: a record whose anchor
// names any other ledger is unanchored and fails by default.
func rekorAnchored(b *artifacts.AuditBundle) bool { return b.RekorAnchor.Backend == "rekor" }

// aivpRan reports whether the AI review ran. The outcome is a row of
// the anchored pre-anchor table.
func aivpRan(b *artifacts.AuditBundle) bool {
	return b.AivpT4.Outcome != "" && b.AivpT4.Outcome != "skipped"
}

// Record generations, by the time the public log signed the record's
// first entry (rekor_anchor.integrated_time). The log's signed entry
// timestamp covers that time, so a rewrite cannot move a record across a
// boundary without failing the anchor check. Each boundary is the
// anchoring time of the first record that wrote the copies equal, found
// by running the verifier read-only over every record the server has
// stored (scripts/refresh-verdict-map.sh, round 46): every stored record
// anchored before it wrote them differently, every one after it equal.
const (
	// The proof section's ledger name and Rekor time equal the anchor's
	// from run 192 (anchored 2026-05-28T20:59:51Z); runs 177 to 191 left
	// them empty or held the sealing-time values.
	poteLedgerCopiesSince int64 = 1780001991
	// The proof section's checkpoint equals the anchor's from run 217
	// (anchored 2026-06-03T17:36:21Z); runs up to 216 kept the
	// checkpoint seen at sealing.
	poteCheckpointCopiesSince int64 = 1780508181
	// The PIA hash is the fifth execution id from the October 2026
	// hardware run (anchored 2026-10-03T15:00:47Z) on; the server began
	// writing it there in commit 8e0b434 that evening, after run 233.
	piaInExecutionIDsSince int64 = 1791039647
)

// anchoredSince reports whether the record's first entry names the
// public log and was logged at or after t.
func anchoredSince(t int64) func(b *artifacts.AuditBundle) bool {
	return func(b *artifacts.AuditBundle) bool {
		return rekorAnchored(b) && b.RekorAnchor.IntegratedTime >= t
	}
}

// piaInExecutionIDs reports whether the record is of the generation in
// which the server writes the AI review's PIA hash into the fifth
// execution id and the review ran. Round 46: the gate read the outcome
// alone and failed run 208 (and every record from May 6 to October 2,
// 2026) as a rewrite.
func piaInExecutionIDs(b *artifacts.AuditBundle) bool {
	return aivpRan(b) && anchoredSince(piaInExecutionIDsSince)(b)
}

// sevSnp reports whether the record claims a SEV-SNP report, which the
// verifier then checks against AMD's root; a record that claims one and
// carries no verification block fails that check.
func sevSnp(b *artifacts.AuditBundle) bool { return b.HardwareAttestation.AttestationMode == "sev_snp" }

func hasVerificationBlock(b *artifacts.AuditBundle) bool {
	return sevSnp(b) && b.HardwareAttestation.Verification != nil
}

func hasExecutionRecord(b *artifacts.AuditBundle) bool { return b.ExecutionRecord != nil }

// transcriptProofSourceSince is the anchored clock of run 248
// (2026-10-18), the first public record built by orchestrator 32d7122,
// from which the transcript records the execution record's proof hash
// as the hash the ZK stage ran over. Every record built before it
// recorded the AER hash there. The clock is read from the anchored
// pre-anchor table when the record has one, else from the envelope.
const transcriptProofSourceSince = "2026-10-18T14:13:04.127240866Z"

// recordClock is the record's run clock: the anchored table's
// clock_epoch row when the record carries a table, else the envelope's
// timestamp.
func recordClock(b *artifacts.AuditBundle) string {
	for _, row := range b.PreAnchor {
		if row.Name == "clock_epoch" {
			return row.Value
		}
	}
	return b.Envelope.Timestamp
}

// transcriptFromProof reports whether the transcript's input hash is
// the execution record's proof hash (records from run 248 on) rather
// than the AER hash. A record whose clock is missing or does not parse
// reads as the older generation; every record from run 248 on carries
// its clock in the anchored table, which the entry's leaf binds.
func transcriptFromProof(b *artifacts.AuditBundle) bool {
	clock, clockErr := time.Parse(time.RFC3339Nano, recordClock(b))
	if clockErr != nil {
		return false
	}
	since, _ := time.Parse(time.RFC3339Nano, transcriptProofSourceSince)
	return !clock.Before(since)
}

var (
	rekorGate = copyGate{path: "rekor_anchor.backend", off: "mock", active: rekorAnchored,
		why: "the verifier dispatches on the anchor's ledger name; any other value leaves the record unanchored, which fails by default"}
	aivpGate = copyGate{path: "aivp_t4.outcome", off: "skipped", active: piaInExecutionIDs,
		why: "the outcome is the aivp_outcome row of the anchored pre-anchor table; on the hardware run, which predates the table, the whole AI-review section is disclosed as uncovered"}
	sevGate = copyGate{path: "hardware_attestation.attestation_mode", off: "policy_scaffold", active: sevSnp,
		why: "the mode selects the AMD check; a record relabelled as hosted contradicts its execution record's hardware row, whose preimage the AER hash the entry binds commits to, so no rewrite verifies"}
	verificationGate = copyGate{path: "hardware_attestation.verification", deleted: true, active: hasVerificationBlock,
		why: "a SEV-SNP record without a verification block fails the AMD check"}
	hostedGate = copyGate{path: "hardware_attestation.attestation_mode", off: "sev_snp", active: func(b *artifacts.AuditBundle) bool { return !sevSnp(b) },
		why: "a hosted record relabelled as SEV-SNP carries no report and fails the AMD check"}
	ledgerGenerationGate = copyGate{path: "rekor_anchor.integrated_time", off: "1779000000", active: anchoredSince(poteLedgerCopiesSince),
		why: "the time the log signed the first entry; its signed entry timestamp covers it, so it cannot be moved before the boundary without failing the anchor check"}
	checkpointGenerationGate = copyGate{path: "rekor_anchor.integrated_time", off: "1779000000", active: anchoredSince(poteCheckpointCopiesSince),
		why: "the time the log signed the first entry; its signed entry timestamp covers it"}
	piaGenerationGate = copyGate{path: "rekor_anchor.integrated_time", off: "1779000000", active: anchoredSince(piaInExecutionIDsSince),
		why: "the time the log signed the first entry; its signed entry timestamp covers it"}
	executionRecordGate = copyGate{path: "execution_record", deleted: true, active: hasExecutionRecord,
		why: "the execution record's rows are bound by the public-log entry from leaf v5 on and by the report-data recipe on the hardware run"}
	clockGate = copyGate{path: "envelope.timestamp", off: "2026-10-17T00:00:00Z", active: transcriptFromProof,
		why: "the clock is read from the anchored table's clock_epoch row when the record has one (bound by the entry's leaf); the envelope timestamp is one copy of the record clock, whose copies the EPA hash in the table binds"}
)

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
	{paths: []string{"execution_record.program_hash", "envelope.registry_record_hash"}, gates: []copyGate{executionRecordGate},
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
	// shows; the three lists of execution ids hold it at index 4. When
	// the AI review ran, the PIA hash must be carried and equal (round
	// 45: a deleted PIA hash was skipped, so its deletion verified).
	{paths: []string{"aivp_t4.pia_hash", "aer.execution_ids[4]", "efa.steps[4].execution_id", "execution_record.kernel_output_ids[4]"},
		gates: []copyGate{aivpGate, piaGenerationGate},
		value: func(b *artifacts.AuditBundle) []*string {
			if !piaInExecutionIDs(b) {
				return []*string{nil, nil, nil, nil}
			}
			var kernel []string
			if b.ExecutionRecord != nil {
				kernel = b.ExecutionRecord.KernelOutputIDs
			}
			var step *string
			if len(b.EFA.Steps) > 4 {
				step = &b.EFA.Steps[4].ExecutionID
			}
			return []*string{&b.AivpT4.PiaHash, listItem(b.AER.ExecutionIDs, 4), step, listItem(kernel, 4)}
		}},
	// The proof-of-execution section repeats the run entry's number,
	// Rekor time and checkpoint from the anchor the verifier checks, and
	// names the same ledger. The anchor's own ledger name is the gate
	// (round 45: the section's name was, so a section renamed to another
	// ledger escaped the comparison).
	{paths: []string{"rekor_anchor.backend", "pote_proof.ledger_backend"}, gates: []copyGate{rekorGate, ledgerGenerationGate},
		value: func(b *artifacts.AuditBundle) []*string {
			on := anchoredSince(poteLedgerCopiesSince)(b)
			return []*string{whenCarried(on, b.RekorAnchor.Backend), whenCarried(on, b.PoteProof.LedgerBackend)}
		}},
	{paths: []string{"rekor_anchor.log_entry_id", "pote_proof.log_entry_id"}, gates: []copyGate{rekorGate},
		value: func(b *artifacts.AuditBundle) []*string {
			on := rekorAnchored(b)
			return []*string{whenCarried(on, b.RekorAnchor.LogEntryID), whenCarried(on, b.PoteProof.LogEntryID)}
		}},
	{paths: []string{"rekor_anchor.integrated_time", "pote_proof.integrated_time"}, gates: []copyGate{rekorGate, ledgerGenerationGate},
		value: func(b *artifacts.AuditBundle) []*string {
			on := anchoredSince(poteLedgerCopiesSince)(b)
			return []*string{whenCarried(on, strconv.FormatInt(b.RekorAnchor.IntegratedTime, 10)),
				whenCarried(on, strconv.FormatInt(b.PoteProof.IntegratedTime, 10))}
		}},
	{paths: []string{"rekor_anchor.checkpoint", "pote_proof.ledger_checkpoint"}, gates: []copyGate{rekorGate, checkpointGenerationGate},
		value: func(b *artifacts.AuditBundle) []*string {
			on := anchoredSince(poteCheckpointCopiesSince)(b)
			return []*string{whenCarried(on, b.RekorAnchor.Checkpoint), whenCarried(on, b.PoteProof.LedgerCheckpoint)}
		}},
	// The transcript records the hash the ZK stage ran over. From run
	// 248 on (transcriptProofSourceSince) that is the execution record's
	// proof hash; every record built before it recorded the AER hash.
	// The record's anchored clock decides which, so neither source can be
	// swapped for the other (round 45: a copy that could equal either
	// source let a forger switch it).
	{paths: []string{"transcript.proof_hash_input", "execution_record.proof_hash", "aer.seal.sealed_hash"},
		gates: []copyGate{clockGate, executionRecordGate},
		value: func(b *artifacts.AuditBundle) []*string {
			if !transcriptFromProof(b) {
				return []*string{&b.Transcript.ProofHashInput, nil, &b.AER.Seal.SealedHash}
			}
			var proof *string
			if b.ExecutionRecord != nil {
				proof = &b.ExecutionRecord.ProofHash
			}
			return []*string{&b.Transcript.ProofHashInput, proof, nil}
		}},
	// A SEV-SNP record shows the guest's launch measurement, the platform
	// label and the report data twice: in the section and in its
	// verification block (which verifySevSnpQuote compares with the raw
	// report). A hosted record's measurement field holds the section's
	// sealed hash.
	{paths: []string{"hardware_attestation.verification.measurement_hex", "hardware_attestation.enclave_measurement"},
		gates: []copyGate{sevGate, verificationGate},
		value: func(b *artifacts.AuditBundle) []*string {
			if !hasVerificationBlock(b) {
				return []*string{nil, nil}
			}
			return []*string{&b.HardwareAttestation.Verification.MeasurementHex, &b.HardwareAttestation.EnclaveMeasurement}
		}},
	{paths: []string{"hardware_attestation.seal.sealed_hash", "hardware_attestation.enclave_measurement"},
		gates: []copyGate{hostedGate},
		value: func(b *artifacts.AuditBundle) []*string {
			if sevSnp(b) {
				return []*string{nil, nil}
			}
			return []*string{&b.HardwareAttestation.Seal.SealedHash, &b.HardwareAttestation.EnclaveMeasurement}
		}},
	{paths: []string{"hardware_attestation.verification.platform", "hardware_attestation.platform"},
		gates: []copyGate{sevGate, verificationGate},
		value: func(b *artifacts.AuditBundle) []*string {
			if !hasVerificationBlock(b) {
				return []*string{nil, nil}
			}
			return []*string{&b.HardwareAttestation.Verification.Platform, &b.HardwareAttestation.Platform}
		}},
	{paths: []string{"hardware_attestation.verification.report_data_hex", "hardware_attestation.report_data_hex"},
		gates: []copyGate{sevGate, verificationGate},
		value: func(b *artifacts.AuditBundle) []*string {
			if !hasVerificationBlock(b) {
				return []*string{nil, nil}
			}
			return []*string{&b.HardwareAttestation.Verification.ReportDataHex, &b.HardwareAttestation.ReportDataHex}
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
	// The server's own commit, stated twice in the provenance section
	// since the section first shipped (round 45: a deleted second copy
	// was skipped).
	{paths: []string{"system_provenance.orchestrator_git_sha", "system_provenance.build_provenance.source_commit_sha"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.SystemProvenance.OrchestratorGitSHA, &b.SystemProvenance.BuildProvenance.SourceCommitSHA}
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
	// Round 45: each category section's own hash, which the verifier
	// recomputes, and the copy inside its seal, which nothing compared.
	// Every seal must name the record's manifest hash, so a record
	// without one fails before this check.
	{paths: []string{"request_substance.hash", "request_substance.seal.sealed_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.RequestSubstance.Hash, &b.RequestSubstance.Seal.SealedHash}
		}},
	{paths: []string{"authorization_chain.hash", "authorization_chain.seal.sealed_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.AuthorizationChain.Hash, &b.AuthorizationChain.Seal.SealedHash}
		}},
	{paths: []string{"regulatory_scaffolding.hash", "regulatory_scaffolding.seal.sealed_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.RegulatoryScaffolding.Hash, &b.RegulatoryScaffolding.Seal.SealedHash}
		}},
	{paths: []string{"causal_graph.hash", "causal_graph.seal.sealed_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.CausalGraph.Hash, &b.CausalGraph.Seal.SealedHash}
		}},
	{paths: []string{"system_provenance.hash", "system_provenance.seal.sealed_hash"},
		value: func(b *artifacts.AuditBundle) []*string {
			return []*string{&b.SystemProvenance.Hash, &b.SystemProvenance.Seal.SealedHash}
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
