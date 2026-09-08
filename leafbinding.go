package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Binding the public-log entry to THIS run.
//
// # WHY THIS FILE EXISTS
//
// Before it, this verifier proved two things and never joined them:
//
//  1. the manifest recomputes and every artifact is sealed to it
//  2. some leaf hash is genuinely inside Rekor's Merkle tree
//
// Both true, and together they still do not say the leaf in the log is
// the one this run's inputs produce. The bundle simply asserted a
// leaf_hash and the anchor check took it at face value. A manifest
// sealed at run time naming an unrelated Rekor entry, one from another
// run, or one Verdifax anchored for any reason at all, passed cleanly.
// Since Verdifax is the party the reader is auditing, that is the gap
// that matters most.
//
// artifacts/types.go has stated the contract for a while:
//
//	External verifiers reproduce the leaf bytes from
//	join("verdifax.ledger.input.v2", envelope_id, aer_hash,
//	     zksp_binding_hash, input_nonce)
//	and confirm sha256(leaf_bytes) equals LeafHashHex above.
//
// Nothing executed it. Documenting a check is not performing one.
//
// # WHY THIS ARRIVED HERE LATE
//
// This check shipped in the orchestrator's internal copy of the verifier
// on 2026-09-04. It did not reach this repository, which is the public,
// independently buildable verifier the product's trust claim actually
// rests on, until 2026-09-08. For four days the private tool was
// stricter than the public one. The divergence is the more important
// defect: a fix that lands only where nobody outside can run it does not
// protect the reader it was written for.
//
// # WHY NO OLD BUNDLE IS INVALIDATED
//
// Every input is already in the bundle and input_nonce is sealed into
// ManifestHash, so this recovers a property that was always present and
// merely unchecked. Bundles issued before this shipped verify unchanged.
//
// # THE FIELD THAT IS EASY TO GET WRONG
//
// The manifest's aer_hash is NOT bundle.AER.Hash. AER.Hash is the
// canonical hash of the AER ARTIFACT, computed by the bundle builder;
// the manifest's aer_hash comes from the AER adapter and is carried in
// AER.Seal.SealedHash. Same trap for zksp_binding_hash. Reconstructing
// from .Hash compiles, reads correctly, and fails on every genuine
// bundle.

const (
	leafDomainV1 = "verdifax.ledger.input.v1"
	leafDomainV2 = "verdifax.ledger.input.v2"
)

// LeafBindingCheck records whether the anchored leaf is this run's.
type LeafBindingCheck struct {
	Performed bool   `json:"performed"`
	Match     bool   `json:"match"`
	Form      string `json:"preimage_form,omitempty"`
	Recorded  string `json:"recorded_leaf_hash,omitempty"`
	Computed  string `json:"computed_leaf_hash,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// joinLeafParts mirrors the producing side exactly: strings.Join(parts, ".").
//
// Kept as its own named function rather than inlined so the coupling is
// visible. If the separator ever changes on the producing side this must
// change with it, and a reader comparing the two should see that in one
// glance.
//
// The separator is also why this file RECONSTRUCTS the preimage instead
// of parsing one. "." appears inside the domain tag itself, and nothing
// length-prefixes the fields, so a preimage cannot be split back into
// its parts unambiguously. Rebuilding from known inputs and comparing
// hashes sidesteps that entirely.
//
// Reconstruction avoids the PARSING ambiguity but would not, on its own,
// avoid a COLLISION: if a joined field could itself contain a dot, two
// different input tuples would produce one preimage and therefore one
// leaf. They cannot, and that is a property worth stating because
// publishing this file publishes the formula. The domain is a constant.
// envelope_id is minted as "env-" plus sixteen hex characters and is
// never caller-supplied. aer_hash and zksp_binding_hash are hex digests.
// input_nonce is decimal digits. Empty values are rejected before the
// join rather than skipped. TestNoLeafFieldCanContainTheSeparator holds
// this property so it cannot decay into a comment.
func joinLeafParts(parts ...string) string {
	return strings.Join(parts, ".")
}

// verifyLeafBinding recomputes the anchored leaf from the bundle's own
// fields and compares it to the leaf hash the bundle claims.
func verifyLeafBinding(b *artifacts.AuditBundle) LeafBindingCheck {
	a := b.RekorAnchor

	// Only a public-log claim can be checked against a public log. A
	// mock-ledger bundle makes no such claim, and reporting a failure
	// for one would punish honesty about not being anchored.
	if a.Backend != "rekor" {
		return LeafBindingCheck{Performed: false}
	}

	envelopeID := b.Envelope.EnvelopeID
	aerHash := b.AER.Seal.SealedHash
	bindingHash := b.ZkspBinding.Seal.SealedHash

	// A bundle that claims a Rekor anchor but omits the inputs needed to
	// check it is a defect in the bundle, not an absence of evidence, so
	// it fails rather than skipping. Skipping here would let a producer
	// dodge this check by dropping a field.
	var missing []string
	if envelopeID == "" {
		missing = append(missing, "envelope.envelope_id")
	}
	if aerHash == "" {
		missing = append(missing, "aer.seal.sealed_hash")
	}
	if bindingHash == "" {
		missing = append(missing, "zksp_binding.seal.sealed_hash")
	}
	if a.LeafHashHex == "" {
		missing = append(missing, "rekor_anchor.leaf_hash")
	}
	if len(missing) > 0 {
		return LeafBindingCheck{
			Performed: true,
			Match:     false,
			Recorded:  a.LeafHashHex,
			Reason: fmt.Sprintf(
				"this bundle claims a Rekor anchor but does not carry the inputs "+
					"needed to confirm the anchored leaf is this run's: %s",
				strings.Join(missing, ", ")),
		}
	}

	// Version selection is driven by the data, not assumed. A bundle
	// sealed before the nonce arrived has none and used the v1 preimage.
	// Hardcoding v2 would report every legacy bundle as forged, which is
	// a worse error than the one being fixed.
	var (
		preimage string
		form     string
	)
	if a.InputNonce != 0 {
		form = leafDomainV2
		preimage = joinLeafParts(leafDomainV2, envelopeID, aerHash, bindingHash,
			strconv.FormatInt(a.InputNonce, 10))
	} else {
		form = leafDomainV1
		preimage = joinLeafParts(leafDomainV1, envelopeID, aerHash, bindingHash)
	}

	sum := sha256.Sum256([]byte(preimage))
	computed := hex.EncodeToString(sum[:])

	out := LeafBindingCheck{
		Performed: true,
		Form:      form,
		Recorded:  strings.ToLower(a.LeafHashHex),
		Computed:  computed,
	}
	out.Match = out.Computed == out.Recorded
	if !out.Match {
		out.Reason = "the leaf hash anchored in the public log is not the one this " +
			"run's envelope, AER and binding hashes produce. The log entry is real, " +
			"but it does not belong to this run"
	}
	return out
}
