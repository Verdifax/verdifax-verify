package main

// Offline verification of the Phase-15 NREP actor signature.
//
// The orchestrator binds an actor identity to a run by signing the
// canonical preimage
//
//	"verdifax.nrep.v1" || envelope_id || aer_hash || actor_id || run_clock
//
// (components joined with single 0x00 bytes) with the actor's Ed25519
// key, and seals the actor id, the public key, the signature, and the
// run_clock (signed_at) into the bundle's nrep section. This file
// rebuilds that exact preimage from the bundle's own fields and runs
// ed25519.Verify, so the actor-binding claim is checkable offline with
// no Verdifax cooperation.
//
// The preimage construction MUST stay byte-identical to the producing
// side (verdifax-orchestrator internal/nrep). Null-byte separation
// prevents a component containing another component's value from
// producing a colliding preimage.
//
// WHAT THIS CHECK CAN AND CANNOT PROVE, stated bluntly because an
// external review (2026-10-15) demonstrated the gap with a working
// forgery against v0.7.0: the public key is the one the bundle itself
// supplies, and in current bundles the nrep section is not covered by
// the bundle hash or the public-log leaf. An attacker can therefore
// replace the whole section, actor name, key, signature, clock, with
// a self-consistent one of their own making, and this check will
// validate it. For that reason a passing check is reported as
// CONSISTENT, never as verified: it proves the section is internally
// consistent and bound to this run's envelope_id and aer_hash by
// whoever held the embedded key, and nothing about who that was.
// Identity assurance requires pinning the key against a registry and
// sealing the section into the hashed record and the anchor, both of
// which are in progress; until then the one thing an INVALID
// signature still proves is sloppy tampering, so invalid flips the
// verdict while valid earns only the consistency wording.
//
// States, mirroring the Rekor and leaf-binding checks:
//
//   - Performed=false, empty section: the run claimed no actor
//     identity (anonymous or pre-Phase-15). Not a failure, and per the
//     section's own contract, NOT "skipped means valid" either: the
//     run's authority must be established by surrounding-system logs.
//   - Performed=false, signature present but signed_at empty: the
//     bundle predates the signed_at field, so the preimage cannot be
//     rebuilt offline. Reported distinctly from every other state.
//   - Performed=true, Match=true: the signature is CONSISTENT, see
//     above for exactly how little that means about identity.
//   - Performed=true, Match=false: the signature does not validate
//     even on its own terms. A failure; it flips the verdict.

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// nrepPreimageVersion is the canonical-preimage version tag. Must
// match the producing side's PreimageVersion exactly.
const nrepPreimageVersion = "verdifax.nrep.v1"

// NrepCheck records the verdict of the offline actor-signature
// verification. A Performed=true, Match=false check flips AllPassed.
type NrepCheck struct {
	Performed bool   `json:"performed"`
	Match     bool   `json:"match"`
	ActorID   string `json:"actor_id,omitempty"`
	Reason    string `json:"reason,omitempty"`

	// KeyPinned stays false until registry pinning lands. Sealed is
	// true when the anchored leaf covers this section (a version-3 leaf
	// embedding its digest, or a version 5 to 7 leaf binding the table
	// that carries its values) and that leaf is the one a published
	// Verdifax key logged: the section can then no longer be replaced
	// offline. Sealed consistency is still not identity;
	// that upgrade needs the key pinned.
	KeyPinned bool `json:"key_pinned"`
	Sealed    bool `json:"sealed"`
}

// verifyNrepSignature checks the bundle's nrep section against the
// bundle's own envelope_id and aer_hash. See the file comment for the
// four states.
// verifyNrepSignature takes the leaf-binding verdict so it can report
// the sealed state honestly: here Sealed is set only when a version-3
// leaf, whose preimage embeds the actor-section digest recomputed
// from this very section, matched the leaf hash the bundle records.
// Records with a version 5 to 7 leaf are sealed through the pre-anchor
// table, which sealedByPreAnchor applies once that table has been
// checked. Either way sealedOnlyWhenLogged then clears Sealed unless
// the public-log entry itself matches and is signed by a published
// Verdifax key.
func verifyNrepSignature(b *artifacts.AuditBundle, leaf LeafBindingCheck) NrepCheck {
	sec := b.Nrep

	if sec.ActorID == "" && sec.PublicKey == "" && sec.Signature == "" {
		return NrepCheck{
			Performed: false,
			Reason:    "no actor signature claimed (anonymous or pre-Phase-15 run)",
		}
	}
	if sec.ActorID == "" || sec.PublicKey == "" || sec.Signature == "" {
		return NrepCheck{
			Performed: true,
			Match:     false,
			ActorID:   sec.ActorID,
			Reason:    "nrep section partially populated; a claimed actor binding must carry actor_id, public_key, and signature together",
		}
	}
	if sec.SignedAt == "" {
		return NrepCheck{
			Performed: false,
			ActorID:   sec.ActorID,
			Reason:    "signature present but bundle predates the signed_at field; the signed preimage cannot be rebuilt offline",
		}
	}

	// Error model of this file: this is a CLI whose failures are the
	// report itself, so every decode error is surfaced verbatim in
	// the check's reason field, which the user reads directly; there
	// is no logger in this binary and nothing to log to.
	pubBytes, decodeErr := base64.StdEncoding.DecodeString(sec.PublicKey)
	if decodeErr != nil {
		return NrepCheck{Performed: true, Match: false, ActorID: sec.ActorID,
			Reason: fmt.Sprintf("decode public key: %v", decodeErr)}
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return NrepCheck{Performed: true, Match: false, ActorID: sec.ActorID,
			Reason: fmt.Sprintf("invalid public key length %d (want %d)", len(pubBytes), ed25519.PublicKeySize)}
	}
	sigBytes, decodeErr := base64.StdEncoding.DecodeString(sec.Signature)
	if decodeErr != nil {
		return NrepCheck{Performed: true, Match: false, ActorID: sec.ActorID,
			Reason: fmt.Sprintf("decode signature: %v", decodeErr)}
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return NrepCheck{Performed: true, Match: false, ActorID: sec.ActorID,
			Reason: fmt.Sprintf("invalid signature length %d (want %d)", len(sigBytes), ed25519.SignatureSize)}
	}

	preimage := nrepPreimage(b.Envelope.EnvelopeID, b.FinalVFA.AerHash, sec.ActorID, sec.SignedAt)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), preimage, sigBytes) {
		return NrepCheck{Performed: true, Match: false, ActorID: sec.ActorID,
			Reason: "signature does not verify over this run's envelope_id and aer_hash"}
	}
	sealed := leaf.Performed && leaf.Match && leaf.Form == leafDomainV3
	return NrepCheck{Performed: true, Match: true, ActorID: sec.ActorID, Sealed: sealed}
}

// nrepPreimage is a byte-identical port of the producing side's
// buildPreimage: components joined with single 0x00 separators.
func nrepPreimage(envelopeID, aerHash, actorID, runClock string) []byte {
	parts := []string{nrepPreimageVersion, envelopeID, aerHash, actorID, runClock}
	total := len(parts) - 1
	for _, p := range parts {
		total += len(p)
	}
	buf := make([]byte, 0, total)
	for i, p := range parts {
		if i > 0 {
			buf = append(buf, 0x00)
		}
		buf = append(buf, p...)
	}
	return buf
}

// printNrepCheck renders the actor-signature verdict in the
// human-readable report, one line per state.
func printNrepCheck(c NrepCheck) {
	switch {
	case c.Performed && c.Match && c.Sealed:
		fmt.Printf("  Actor signature:  consistent and SEALED to the anchor · %s (key not pinned; identity still not established)\n", c.ActorID)
	case c.Performed && c.Match:
		fmt.Printf("  Actor signature:  consistent · %s (key not pinned; section not sealed, identity NOT established)\n", c.ActorID)
	case c.Performed && !c.Match:
		fmt.Printf("  Actor signature:  ✗ FAILED · %s\n", c.Reason)
	case c.ActorID != "":
		fmt.Printf("  Actor signature:  present, not offline-verifiable (%s)\n", c.Reason)
	default:
		fmt.Printf("  Actor signature:  none claimed\n")
	}
}

// sealedOnlyWhenLogged keeps Sealed only when the leaf that seals the
// section is the one on the public log: the inclusion proof and signed
// checkpoint verify, the logged entry names this record's leaf, and a
// published Verdifax log-signing key signed the entry. The earlier steps
// compare the leaf rebuilt from the bundle with the leaf hash the bundle
// itself records, which an editor can rewrite together with the section,
// its table and that recorded hash; only the log entry cannot be.
func sealedOnlyWhenLogged(c NrepCheck, anchor RekorAnchorCheck, auth EntryAuthCheck) NrepCheck {
	if c.Sealed && !(anchor.Performed && anchor.Match && auth.Performed && auth.Match) {
		c.Sealed = false
	}
	return c
}

// sealedByPreAnchor reports the actor section as sealed on records whose
// anchored leaf is version 5, 6 or 7. Those leaves bind the pre-anchor
// table, and the table carries the actor section's four values
// (nrep_actor_id, nrep_public_key, nrep_signature, nrep_signed_at),
// which verifyPreAnchor checks against this record. So when the
// signature verifies, the leaf is this run's and the table is
// consistent, the section is sealed as surely as under a version-3
// leaf's embedded section digest. Anything less leaves the result as
// verifyNrepSignature reported it.
func sealedByPreAnchor(c NrepCheck, leaf LeafBindingCheck, pre PreAnchorCheck) NrepCheck {
	if c.Sealed || !c.Performed || !c.Match {
		return c
	}
	if !leaf.Performed || !leaf.Match {
		return c
	}
	switch leaf.Form {
	case leafDomainV5, leafDomainV6, leafDomainV7:
	default:
		return c
	}
	if !pre.Performed || !pre.Match {
		return c
	}
	c.Sealed = true
	return c
}
