package main

// Complete-record anchoring (bundle anchor v1), the answer to round six
// of the external review.
//
// Round six rewrote the descriptive sections of a live anchored record
// (aer.decision, request_substance, authorization_chain,
// causal_graph.effect_log, system_provenance), recomputed their section
// hashes and bundle_hash, and v0.9.0 still printed VERIFIED AND
// ANCHORED. The run's first public-log entry binds the run identity and
// the 33-value pre-anchor table; bundle_hash was never anchored, so
// every section it covers was only self-consistent.
//
// From v0.10.0 a run carries a second public-log entry, bundle_anchor,
// whose leaf binds the anchored record digest: a digest over
// bundle_hash and every section outside it, each value RECOMPUTED here
// from the bundle's own contents (internal/artifacts/bundle_anchor.go
// holds the frozen recipe, byte-identical to the producer's). A
// rewrite of any covered field changes the recomputed digest, the
// rebuilt leaf stops matching the logged entry, and the record FAILS.
// The entry itself is checked exactly as the main anchor is: the
// hashedrekord body must name the leaf, the Merkle proof must reach the
// signed root, and the checkpoint must verify under the embedded Rekor
// key.
//
// A v5 record without bundle_anchor (sealed before it shipped, or
// whose second submission failed) is reported honestly as partial
// coverage: its descriptive sections are bundle-sealed, not anchored.
//
// From v0.11.0 a record sealed with the v6 leaf states, inside the
// pre-anchor values its first entry anchors, that a complete-record
// anchor is required (verifyCompleteRecordRequirement below). For such
// a record a missing or failing bundle_anchor is a FAILURE, never the
// partial verdict, so deleting the second entry is detectable.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/rekorverify"
)

// rekorAnchorVerifier is the offline Rekor check both anchors use. It
// is a variable only so tests can run the complete path against a log
// key they control (rekorverify.VerifyAnchorWithKey); production
// always uses the embedded Rekor key.
var rekorAnchorVerifier = rekorverify.VerifyAnchor

// BundleAnchorCheck reports the complete-record anchor verdict.
type BundleAnchorCheck struct {
	// Present is true when the bundle carries a bundle_anchor.
	Present bool `json:"present"`
	// Performed is true when a public-log (rekor) proof was checked.
	Performed      bool   `json:"performed"`
	Match          bool   `json:"match"`
	Backend        string `json:"backend,omitempty"`
	LogEntryID     string `json:"log_entry_id,omitempty"`
	LogIndex       int64  `json:"log_index,omitempty"`
	RecordedDigest string `json:"recorded_anchored_digest,omitempty"`
	ComputedDigest string `json:"computed_anchored_digest,omitempty"`
	RecordedLeaf   string `json:"recorded_leaf_hash,omitempty"`
	ComputedLeaf   string `json:"computed_leaf_hash,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// verifyBundleAnchor recomputes the anchored record digest and the
// bundle leaf from the bundle's contents and checks the second entry.
func verifyBundleAnchor(b *artifacts.AuditBundle) BundleAnchorCheck {
	a := b.BundleAnchor
	if a == nil {
		return BundleAnchorCheck{Present: false,
			Reason: "no bundle_anchor: the descriptive sections are bundle-sealed, not anchored"}
	}
	out := BundleAnchorCheck{
		Present:        true,
		Backend:        a.Backend,
		LogEntryID:     a.LogEntryID,
		LogIndex:       a.LogIndex,
		RecordedDigest: a.AnchoredDigest,
		RecordedLeaf:   strings.ToLower(a.LeafHashHex),
	}
	fail := func(reason string) BundleAnchorCheck {
		out.Match = false
		out.Reason = reason
		return out
	}

	if a.Kind != artifacts.BundleAnchorKind || a.DigestForm != artifacts.BundleAnchorDigestForm {
		return fail(fmt.Sprintf("bundle_anchor is kind %q form %q; this verifier knows %q form %q",
			a.Kind, a.DigestForm, artifacts.BundleAnchorKind, artifacts.BundleAnchorDigestForm))
	}

	out.ComputedDigest = artifacts.ComputeAnchoredRecordDigest(b)
	if err := artifacts.ValidateBundleLeafFields(b.Envelope.EnvelopeID, out.ComputedDigest); err != nil {
		return fail(err.Error())
	}
	out.ComputedLeaf = artifacts.ComputeBundleLeafHash(b.Envelope.EnvelopeID, out.ComputedDigest)

	if out.ComputedDigest != a.AnchoredDigest {
		return fail("the record's contents do not produce the anchored record digest: " +
			"at least one section was changed after the record was anchored")
	}
	if out.ComputedLeaf != out.RecordedLeaf {
		return fail("the bundle leaf rebuilt from this record's envelope_id and anchored " +
			"record digest is not the leaf the bundle_anchor claims")
	}

	if a.Backend != "rekor" {
		// Consistent, but no public log holds it: never anchored.
		out.Match = true
		out.Reason = fmt.Sprintf("bundle_anchor backend is %q: the record digest is consistent, "+
			"but it is not on a public log", a.Backend)
		return out
	}

	out.Performed = true
	// Error model of this binary: a CLI whose failures are the report
	// itself, so the verification error becomes the printed reason;
	// there is no logger in this binary and nothing to log to.
	anchorErr := rekorAnchorVerifier(rekorverify.AnchorInput{
		LeafHashHex:   a.LeafHashHex,
		EntryBody:     a.EntryBody,
		LogIndex:      a.LogIndex,
		TreeSize:      a.TreeSize,
		RootHashHex:   a.RootHashHex,
		InclusionPath: a.InclusionPath,
		Checkpoint:    a.Checkpoint,
		LogID:         a.LogID,
	})
	if anchorErr != nil {
		return fail("the second public-log entry does not verify: " + anchorErr.Error())
	}
	out.Match = true
	return out
}

// CompleteRecordRequirementCheck reports the leaf v6 guarantee: whether
// the record's own anchored values require a complete-record anchor,
// and whether the record carries one that holds.
type CompleteRecordRequirementCheck struct {
	// Sealed is true when the pre-anchor table, which the first
	// public-log entry anchors, carries complete_record_anchor.
	Sealed bool `json:"sealed"`
	// Satisfied is true when Sealed and the bundle_anchor is present,
	// holds over this record, and (for a run anchored on the public
	// log) is itself a verified public-log entry.
	Satisfied bool   `json:"satisfied"`
	Reason    string `json:"reason,omitempty"`
}

// verifyCompleteRecordRequirement turns a deleted complete-record
// anchor from an undetectable downgrade into a failure, for records
// whose anchored table says one must exist.
//
// Why the table and not some other field: a forger who strips
// bundle_anchor can rewrite anything that is not anchored, including
// any flag claiming the record once had one. The requirement row sits
// inside the v2 table, whose digest is bound into the v6 leaf of the
// FIRST public-log entry, so removing or changing it breaks that entry
// (leafbinding.go), and keeping it makes the missing anchor fail here.
//
// Why a public-log run needs a public-log record anchor: otherwise the
// strip attack becomes a swap attack, replacing the genuine Rekor
// bundle_anchor with a self-consistent one claiming a mock backend,
// which recomputes from any rewritten record. A run whose own anchor
// is not on the public log is at most SELF-CONSISTENT anyway, so a
// present, consistent record anchor of any backend satisfies it.
func verifyCompleteRecordRequirement(b *artifacts.AuditBundle, ba BundleAnchorCheck) CompleteRecordRequirementCheck {
	if !artifacts.TableRequiresCompleteRecordAnchor(b.PreAnchor) {
		reason := "no pre-anchor table (pre-v5 record): no requirement is sealed"
		if len(b.PreAnchor) > 0 {
			reason = "the anchored table predates leaf v6 and states no requirement, " +
				"so a deleted complete-record anchor cannot be detected for this record"
		}
		return CompleteRecordRequirementCheck{Sealed: false, Reason: reason}
	}
	out := CompleteRecordRequirementCheck{Sealed: true}
	switch {
	case !ba.Present:
		out.Reason = "the record's own anchored values require a complete-record anchor, " +
			"and it is missing: bundle_anchor was deleted or never made, so the " +
			"descriptive sections may have been rewritten"
	case !ba.Match:
		out.Reason = "the record's own anchored values require a complete-record anchor, " +
			"and the one it carries does not hold: " + ba.Reason
	case b.RekorAnchor.Backend == "rekor" && !ba.Performed:
		out.Reason = fmt.Sprintf("the record's own anchored values require a complete-record "+
			"anchor on the public log that anchors this run, and its bundle_anchor is on "+
			"backend %q instead", ba.Backend)
	default:
		out.Satisfied = true
	}
	return out
}

func printCompleteRecordRequirement(c CompleteRecordRequirementCheck, tablePresent bool) {
	switch {
	case c.Sealed && c.Satisfied:
		fmt.Println("  Anchor required:  sealed in the anchored table (leaf v6) and satisfied")
	case c.Sealed:
		fmt.Printf("  Anchor required:  ✗ FAILED · %s\n", c.Reason)
	case tablePresent:
		fmt.Println("  Anchor required:  not sealed (pre-v6 record; a deleted record anchor is not detectable)")
	}
}

// completeRecordAnchored is the strongest claim this tool makes: the
// run identity and pre-anchor table are anchored by the first entry
// and the complete record by the second, both on the public log.
func completeRecordAnchored(r *Report) bool {
	return r.AllPassed && r.Anchored &&
		r.PreAnchor.Performed && r.PreAnchor.Match &&
		r.BundleAnchor.Present && r.BundleAnchor.Performed && r.BundleAnchor.Match
}

// recordCoverage names how much of the record the public log binds.
func recordCoverage(r *Report) string {
	switch {
	case !r.AllPassed:
		return "failed"
	case !r.Anchored:
		return "not_anchored"
	case completeRecordAnchored(r):
		return "complete_record_anchored"
	case r.PreAnchor.Performed:
		return "partial_descriptive_sections_bundle_sealed"
	default:
		return "partial_pre_v5_identity_only"
	}
}

// isNoEntryBody reports the anchor state where no entry body binds
// the claimed leaf to the Merkle proof.
func isNoEntryBody(err error) bool { return errors.Is(err, rekorverify.ErrNoEntryBody) }

func printBundleAnchor(c BundleAnchorCheck) {
	switch {
	case !c.Present:
		fmt.Println("  Record anchor:    absent; descriptive sections are bundle-sealed, not anchored")
	case !c.Match:
		fmt.Printf("  ✗  complete-record anchor FAILED\n")
		fmt.Printf("     Reason: %s\n", c.Reason)
		if c.ComputedDigest != "" && c.ComputedDigest != c.RecordedDigest {
			fmt.Printf("     This record's contents produce %s\n", truncate(c.ComputedDigest, 24))
			fmt.Printf("     The anchored record digest is %s\n", truncate(c.RecordedDigest, 24))
		}
	case !c.Performed:
		fmt.Printf("  ·  record anchor present but not on a public log (backend = %s)\n", c.Backend)
	default:
		fmt.Printf("  ✓  complete record anchored, second entry, log index %d\n", c.LogIndex)
		fmt.Println("     The anchored record digest recomputes from every section of this")
		fmt.Println("     record; the leaf, inclusion proof and signed checkpoint verify.")
		fmt.Printf("     View on https://search.sigstore.dev/?logIndex=%s\n", c.LogEntryID)
		if c.LogEntryID != "" && c.LogEntryID != strconv.FormatInt(c.LogIndex, 10) {
			fmt.Printf("     (%s is the global index across shards; %d is the shard position.)\n",
				c.LogEntryID, c.LogIndex)
		}
	}
}
