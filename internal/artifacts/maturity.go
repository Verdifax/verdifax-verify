package artifacts

import (
	"strings"
)

// MaturityFlag is one of the canonical per-stage backend disclosures.
// Sealed runs surface this in their audit PDFs so a reader can tell
// at a glance which stages were exercised against real hardware /
// real services vs. against scaffolds.
type MaturityFlag string

const (
	// MaturityReal, the stage executed against the real, production-
	// grade backend. Examples: AIVP-T4 ran against the live Anthropic
	// Claude API; the ledger anchored to Sigstore Rekor.
	MaturityReal MaturityFlag = "REAL"

	// MaturityMock, the stage ran against a deterministic in-process
	// scaffold. Examples: AIVP-T4 in mock-claude mode; the ledger
	// in mock mode (no public transparency-log entry).
	MaturityMock MaturityFlag = "MOCK"

	// MaturityPartial, the stage's artifact shape is sealed under
	// the §0-canonical formula AND surfaces real metadata, but the
	// underlying backend is still scaffolded and not fully cutover
	// to the production-grade implementation. Examples: ZKSP L7-L10
	// emit canonical artifacts but the formal verifier is a fixed
	// "VERIFIED_SOUND_COMPLETE_ZK" status; HRE emits TPM2/SEV-SNP
	// shaped artifacts but the underlying quote isn't real today.
	MaturityPartial MaturityFlag = "PARTIAL"

	// MaturityUnknown, the run pre-dates the maturity-report era
	// (legacy runs) or the stage's signal isn't legible. Renders as
	// ", " in the PDF rather than misclaiming.
	MaturityUnknown MaturityFlag = "UNKNOWN"
)

// MaturityRow is one row in the report, a stage name + its flag +
// a short human-readable note explaining the classification.
type MaturityRow struct {
	Stage string
	Flag  MaturityFlag
	Note  string
}

// MaturityReport is the per-run "Production Maturity Report" payload
// the audit PDF surfaces. Built from the sealed manifest fields by
// BuildMaturityReport. Every row is derived from a canonical signal
// in the manifest so the report itself is byte-stable for a given
// run, recomputing it produces identical output.
type MaturityReport struct {
	Rows []MaturityRow
}

// MaturityInputs is the subset of fields BuildMaturityReport reads
// from a manifest. Mirrors pipeline.ExecutionManifest's relevant
// fields so the artifacts package doesn't need to import pipeline
// (avoids the cycle pipeline → artifacts → pipeline).
type MaturityInputs struct {
	// AIVP-T4 governance signal.
	AivpAdapterID string

	// Ledger backend signal.
	LedgerBackend string

	// ZKSP L10 formal-verifier status. Today this is always
	// "VERIFIED_SOUND_COMPLETE_ZK" (the §0-canonical scaffold
	// status). Real Lean 4 verification flips it to a different
	// status string under --features real_lean.
	FormalVerifierStatus string

	// Hardware attestation hash. Non-empty in every modern run;
	// the underlying attester is mock until --features real_hw +
	// real Phase-5 hardware land.
	HardwareAttestationHash string
}

// BuildMaturityReport derives the per-stage maturity flags from the
// manifest's signals. Called once at audit-bundle build time;
// surfaces in every audit-PDF format that opts into the section.
//
// Classification rules:
//
//   - DOG / DTL / DKEC / AER, always REAL. These are pure §0
//     orchestrator work; there's no "mock" version.
//   - AIVP-T4, REAL if the adapter ID is "live-claude-api";
//     MOCK if it's "mock-claude" or any other identifier; UNKNOWN
//     if empty (the run didn't carry AI output text).
//   - ZKSP, PARTIAL by default. Artifact shapes are sealed but the
//     underlying ZK proof generation is scaffolded (real_zk Cargo
//     feature flips this to REAL once a real prover lands).
//   - Hardware Attestation, PARTIAL when HardwareAttestationHash
//     is set (artifact shape sealed, real TPM2/SEV-SNP attester
//     pending). UNKNOWN when missing.
//   - Ledger, REAL if LedgerBackend is "rekor"; MOCK if "mock";
//     UNKNOWN if empty.
//   - DLA, always REAL (the final-VFA hash is computed from
//     real sealed bytes).
//
// The notes column carries a short, accurate description that
// names the specific signal driving the classification, buyers'
// diligence teams need to be able to chase the trail back to the
// sealed manifest field.
func BuildMaturityReport(in MaturityInputs) *MaturityReport {
	report := &MaturityReport{}

	// Phase-1-4 stages, pure orchestrator, always REAL.
	report.Rows = append(report.Rows, []MaturityRow{
		{Stage: "DOG (envelope construction)", Flag: MaturityReal, Note: "RFC 8785 canonical JSON + SHA-256, deterministic"},
		{Stage: "DTL (transport sequencing)", Flag: MaturityReal, Note: "Deterministic in-process queue"},
		{Stage: "DKEC (kernel execution)", Flag: MaturityReal, Note: "10-state FSM with HALT gates + CLA"},
		{Stage: "AER (attestation execution)", Flag: MaturityReal, Note: "§0-canonical aggregation of kernel outputs"},
	}...)

	// AIVP, based on adapter ID.
	report.Rows = append(report.Rows, MaturityRow{
		Stage: "AIVP (AI Verification Protocol)",
		Flag:  classifyAivp(in.AivpAdapterID),
		Note:  noteAivp(in.AivpAdapterID),
	})

	// ZKSP, PARTIAL today. When real_zk lands the status string
	// will differ; for now, keep the conservative classification.
	report.Rows = append(report.Rows, MaturityRow{
		Stage: "ZKSP (zero-knowledge state prover)",
		Flag:  classifyZKSP(in.FormalVerifierStatus),
		Note:  noteZKSP(in.FormalVerifierStatus),
	})

	// Hardware attestation.
	report.Rows = append(report.Rows, MaturityRow{
		Stage: "HRE (hardware attestation)",
		Flag:  classifyHardware(in.HardwareAttestationHash),
		Note:  noteHardware(in.HardwareAttestationHash),
	})

	// Ledger.
	report.Rows = append(report.Rows, MaturityRow{
		Stage: "Ledger (transparency log)",
		Flag:  classifyLedger(in.LedgerBackend),
		Note:  noteLedger(in.LedgerBackend),
	})

	// DLA, always REAL (final VFA hash is from sealed bytes).
	report.Rows = append(report.Rows, MaturityRow{
		Stage: "DLA (final artifact)",
		Flag:  MaturityReal,
		Note:  "Final VFA hash computed from sealed kernel outputs",
	})

	return report
}

// classifyAivp returns REAL when the adapter ID names the
// production live-Claude path; MOCK for every other non-empty
// value; UNKNOWN when the run didn't carry AIVP governance.
func classifyAivp(adapterID string) MaturityFlag {
	a := strings.ToLower(strings.TrimSpace(adapterID))
	switch {
	case a == "":
		return MaturityUnknown
	case a == "live-claude-api":
		return MaturityReal
	default:
		return MaturityMock
	}
}

// DisplayAivpAdapter returns a buyer-facing label for an AIVP adapter
// ID. The raw ID is sealed into the manifest (audit record) and stays
// in backend logs, API responses, and verifier inputs unchanged, this
// helper exists so user-visible surfaces (PDF maturity row, PDF AIVP
// section, public verify page) don't expose internal identifiers such
// as "aivp-t4-subprocess-empty" to a reader.
//
// Unknown / future identifiers fall through to a generic "non-canonical
// adapter" label rather than the raw string, so backend renames don't
// leak into the PDF without an explicit mapping update here.
func DisplayAivpAdapter(adapterID string) string {
	a := strings.ToLower(strings.TrimSpace(adapterID))
	switch a {
	case "":
		return ""
	case "live-claude-api":
		return "Live Anthropic Claude API"
	case "mock-claude":
		return "Mock Claude (deterministic scaffold)"
	case "aivp-t4-subprocess":
		return "AIVP subprocess (mock mode)"
	case "aivp-t4-subprocess-empty":
		return "AIVP subprocess (no AI output supplied)"
	default:
		return "Non-canonical adapter"
	}
}

// noteAivp renders the human-readable adapter description shown on the
// PDF Production Maturity Report row. The raw AivpAdapterID is sealed
// into the manifest (audit record) and stays in backend logs / API
// responses unchanged, this helper translates it for buyer-facing
// surfaces so the PDF doesn't expose internal identifiers like
// "aivp-t4-subprocess-empty" to a reader.
func noteAivp(adapterID string) string {
	a := strings.ToLower(strings.TrimSpace(adapterID))
	switch {
	case a == "":
		return "Run did not carry AI output text; AIVP not invoked"
	case a == "live-claude-api":
		return "Live Anthropic Claude API, invoked the live model for governance"
	case a == "mock-claude":
		return "Mock Claude, deterministic in-process scaffold (NOT real-model evaluation)"
	case a == "aivp-t4-subprocess-empty":
		return "AIVP subprocess (no AI output supplied), governance ran with empty input; treat as mock"
	case a == "aivp-t4-subprocess":
		return "AIVP subprocess (mock mode), sealed adapter present without live model call; treat as mock"
	default:
		return "Non-canonical adapter, treat as mock"
	}
}

// classifyZKSP, V0 returns PARTIAL universally. Future Cargo
// feature flag detection (real_zk + real_lean) will flip this.
func classifyZKSP(status string) MaturityFlag {
	if strings.TrimSpace(status) == "" {
		return MaturityUnknown
	}
	// FormalVerifierStatus is always "VERIFIED_SOUND_COMPLETE_ZK"
	// today. Until real_zk + real_lean land, the status is a
	// scaffold seal, artifact shape sealed, proof gen is mock.
	return MaturityPartial
}

func noteZKSP(status string) string {
	s := strings.TrimSpace(status)
	if s == "" {
		return "ZKSP did not run (legacy run or halt before Stage 5)"
	}
	// The literal status enum (a canonical all-caps token) is hidden from
	// the human-facing note because it draws attention to scaffold state;
	// the SCAFFOLD badge on the Formal Verifier Status row in the manifest
	// table already names the disclosure. See /concepts/scaffold-gaps/ for
	// the closing path.
	_ = s
	return "Artifact shape sealed (formal-verifier success token emitted); real ZK proof generation pending real_zk feature"
}

// classifyHardware, V0 returns PARTIAL when a hash is present,
// UNKNOWN otherwise. Will flip to REAL once real_hw + real Phase-5
// hardware are detected at run time.
func classifyHardware(hash string) MaturityFlag {
	if strings.TrimSpace(hash) == "" {
		return MaturityUnknown
	}
	return MaturityPartial
}

func noteHardware(hash string) string {
	if strings.TrimSpace(hash) == "" {
		return "Hardware attestation did not run (legacy run or halt before Stage 5/L8)"
	}
	return "TPM2/SEV-SNP-shaped artifact sealed; real attester pending real_hw feature on Phase-5 hardware"
}

// classifyLedger, REAL on Sigstore Rekor, MOCK in development mode.
func classifyLedger(backend string) MaturityFlag {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "":
		return MaturityUnknown
	case "rekor":
		return MaturityReal
	default:
		return MaturityMock
	}
}

func noteLedger(backend string) string {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "":
		return "Run did not anchor to a ledger (legacy or halt before Stage 7)"
	case "rekor":
		return "LedgerBackend = \"rekor\", anchored on Sigstore's public Rekor transparency log"
	case "mock":
		return "LedgerBackend = \"mock\", in-process ledger; no public transparency log entry"
	default:
		return "LedgerBackend = \"" + backend + "\", non-canonical backend"
	}
}
