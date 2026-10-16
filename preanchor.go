package main

// Pre-anchor table enforcement (leaf v5), the answer to round five of
// the external review, which demonstrated three content rewrites that
// passed as VERIFIED AND ANCHORED because the v3 leaf covered six
// values and the rest of the record was only self-consistent.
//
// A v5 bundle carries a named table of every deterministic pre-anchor
// value. Three properties get enforced here, and together they make
// the whole covered surface rewrite-proof:
//
//  1. SHAPE: the table's keys and order equal the frozen list, so a
//     table with renamed, dropped, or reordered rows cannot exist.
//  2. ANCHOR: the digest of the table is the one bound inside the
//     anchored leaf (leafbinding rebuilds the leaf with this digest,
//     so a table edit breaks the public-log entry itself).
//  3. CONSISTENCY: every table entry equals the value the bundle
//     displays for it, section by section, so the presentation
//     cannot tell a different story than the anchored table: the
//     actor section, the AIVP governance fields, the caller-attested
//     block (recomputed from epa.attested_context), the payload, the
//     scaffold flags, and every sealed section hash.
//
// Table v2 (leaf v6, verifier v0.11.0) is the frozen v1 list plus one
// row, complete_record_anchor = "required", digested under its own
// domain. The shape check selects the frozen list by the presence of
// that row, the row's value must be exactly "required", and the leaf
// check binds the v2 digest into the v6 leaf; bundleanchor.go then
// fails a record whose anchored table requires a complete-record
// anchor it does not carry.
//
// Cross-generation checks that apply to EVERY bundle, old or new:
// payload.content_hash must equal the execution record's disclosed
// input_hash (the reviewer's payload-swap died here), and the zksp
// section's status must equal the sealed formal-verifier status.

import (
	"fmt"
	"strings"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// PreAnchorCheck reports the table enforcement verdict.
type PreAnchorCheck struct {
	Performed bool `json:"performed"`
	Match     bool `json:"match"`
	// Form is the table form judged: verdifax.preanchor.v1 (leaf v5)
	// or verdifax.preanchor.v2 (leaf v6, which seals the requirement
	// for a complete-record anchor). Empty when no table is present.
	Form     string   `json:"table_form,omitempty"`
	Rows     int      `json:"rows,omitempty"`
	Failures []string `json:"failures,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// verifyPreAnchor enforces the three properties. The leaf-binding
// check separately proves the digest is the anchored one; here the
// digest is recomputed and compared to the bundle's stored copy so a
// reader of the JSON report sees the chain explicitly.
func verifyPreAnchor(b *artifacts.AuditBundle) PreAnchorCheck {
	if len(b.PreAnchor) == 0 && b.PreAnchorDigest == "" {
		return PreAnchorCheck{Performed: false,
			Reason: "no pre-anchor table (record predates leaf v5); anchor coverage is partial"}
	}

	var failures []string
	fail := func(format string, args ...any) {
		failures = append(failures, fmt.Sprintf(format, args...))
	}

	// 1. SHAPE, against the frozen list of the table's own form. A
	// table carrying the requirement row is judged as v2 wherever the
	// row sits, so a misplaced row fails here instead of passing as v1.
	form := artifacts.PreAnchorTableForm(b.PreAnchor)
	names := artifacts.PreAnchorNames
	if form == artifacts.PreAnchorFormV2 {
		names = artifacts.PreAnchorNamesV2
	}
	if len(b.PreAnchor) != len(names) {
		fail("table has %d rows, frozen order requires %d", len(b.PreAnchor), len(names))
	} else {
		for i, name := range names {
			if b.PreAnchor[i].Name != name {
				fail("row %d is %q, frozen order requires %q", i, b.PreAnchor[i].Name, name)
			}
		}
	}

	table := make(map[string]string, len(b.PreAnchor))
	for _, e := range b.PreAnchor {
		table[e.Name] = e.Value
	}

	// The requirement row has exactly one defined value. Any other
	// value is not a weaker requirement; it is a table this verifier
	// does not know, and it fails rather than being read as "optional".
	if v, ok := table[artifacts.CompleteRecordAnchorRow]; ok && v != artifacts.CompleteRecordAnchorRequired {
		fail("%s is %q, the only defined value is %q",
			artifacts.CompleteRecordAnchorRow, safePrefix(v), artifacts.CompleteRecordAnchorRequired)
	}

	// 2. ANCHOR (digest level; the leaf itself is leafbinding's job).
	if len(failures) == 0 {
		recomputed := artifacts.ComputePreAnchorDigestForTable(b.PreAnchor)
		if recomputed != b.PreAnchorDigest {
			fail("table digest %s does not match the stored pre_anchor_digest %s",
				recomputed[:16], safePrefix(b.PreAnchorDigest))
		}
	}

	// 3. CONSISTENCY, entry by entry against the displaying section.
	expect := func(name, displayed, where string) {
		if v, ok := table[name]; ok && v != displayed {
			fail("%s: anchored %q, but %s displays %q", name, safePrefix(v), where, safePrefix(displayed))
		}
	}
	expect("program_id", b.Envelope.ProgramID, "envelope.program_id")
	expect("route_id", b.Envelope.RouteID, "envelope.route_id")
	expect("registry_record_hash", b.Envelope.RegistryRecordHash, "envelope.registry_record_hash")
	expect("envelope_id", b.Envelope.EnvelopeID, "envelope.envelope_id")
	expect("input_hash", b.Payload.ContentHash, "payload.content_hash")
	expect("envelope_hash", b.Envelope.Seal.SealedHash, "envelope.seal")
	expect("transport_hash", b.Transport.Seal.SealedHash, "transport.seal")
	expect("epa_hash", b.EPA.Seal.SealedHash, "epa.seal")
	expect("efa_hash", b.EFA.Seal.SealedHash, "efa.seal")
	expect("aer_hash", b.AER.Seal.SealedHash, "aer.seal")
	expect("execution_ids", strings.Join(b.AER.ExecutionIDs, ","), "aer.execution_ids")
	expect("aivp_outcome", b.AivpT4.Outcome, "aivp_t4.outcome")
	expect("aivp_adapter_id", b.AivpT4.AdapterID, "aivp_t4.adapter_id")
	expect("aivp_pia_hash", b.AivpT4.PiaHash, "aivp_t4.pia_hash")
	expect("aivp_ai_output_hash", b.AivpT4.AiOutputHash, "aivp_t4.ai_output_hash")
	expect("aivp_halt_receipt_hash", b.AivpT4.HaltReceiptHash, "aivp_t4.halt_receipt_hash")
	expect("transcript_hash", b.Transcript.Seal.SealedHash, "transcript.seal")
	expect("hardware_attestation_hash", b.HardwareAttestation.Seal.SealedHash, "hardware_attestation.seal")
	expect("leakage_bundle_hash", b.LeakageBundle.Seal.SealedHash, "leakage_bundle.seal")
	expect("zksp_binding_hash", b.ZkspBinding.Seal.SealedHash, "zksp_binding.seal")
	expect("formal_verifier_status", b.ZkspBinding.VerificationStatus, "zksp_binding.verification_status")
	expect("migration_token_hash", b.MigrationToken.Seal.SealedHash, "migration_token.seal")
	expect("replay_fingerprint", b.ReplayFingerprint.Seal.SealedHash, "replay_fingerprint.seal")
	expect("nrep_actor_id", b.Nrep.ActorID, "nrep.actor_id")
	expect("nrep_public_key", b.Nrep.PublicKey, "nrep.public_key")
	expect("nrep_signature", b.Nrep.Signature, "nrep.signature")
	expect("nrep_signed_at", b.Nrep.SignedAt, "nrep.signed_at")
	expect("attested_digest",
		artifacts.ComputeAttestedContextDigest(b.EPA.AttestedContext),
		"epa.attested_context (recomputed digest)")
	expect("scaffold_flags_hash",
		artifacts.ComputeScaffoldFlagsHash(
			b.Transcript.Scaffold.IsScaffold,
			b.HardwareAttestation.Scaffold.IsScaffold,
			b.ZkspBinding.Scaffold.IsScaffold,
			b.LeakageBundle.Scaffold.IsScaffold),
		"the four scaffold flags (recomputed digest)")

	out := PreAnchorCheck{Performed: true, Form: form, Rows: len(b.PreAnchor), Failures: failures}
	out.Match = len(failures) == 0
	if !out.Match {
		out.Reason = "the record's contents disagree with its anchored pre-anchor table"
	}
	return out
}

// verifyCrossGeneration holds the checks every bundle generation must
// pass, because their inputs exist in every generation.
func verifyCrossGeneration(b *artifacts.AuditBundle) []string {
	var failures []string
	if b.ExecutionRecord != nil && b.Payload.ContentHash != "" &&
		b.ExecutionRecord.InputHash != b.Payload.ContentHash {
		failures = append(failures,
			"payload.content_hash does not equal the execution record's disclosed input_hash: "+
				"the payload shown is not the payload the anchored record executed on")
	}
	return failures
}

func safePrefix(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}

func printPreAnchor(c PreAnchorCheck) {
	switch {
	case c.Performed && c.Match && c.Form == artifacts.PreAnchorFormV2:
		fmt.Printf("  Pre-anchor table: %d values anchored and consistent with the record,\n", c.Rows)
		fmt.Println("                    including the requirement for a complete-record anchor (table v2)")
	case c.Performed && c.Match:
		fmt.Printf("  Pre-anchor table: %d values anchored and consistent with the record\n", c.Rows)
	case c.Performed && !c.Match:
		fmt.Printf("  Pre-anchor table: ✗ FAILED · %s\n", c.Reason)
		for _, f := range c.Failures {
			fmt.Printf("      · %s\n", f)
		}
	default:
		fmt.Printf("  Pre-anchor table: absent (pre-v5 record; anchor coverage is partial)\n")
	}
}
