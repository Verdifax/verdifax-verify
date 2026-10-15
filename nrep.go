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

	// KeyPinned and Sealed are both false in every bundle this
	// version can see; they exist so the JSON shape is stable when
	// registry pinning and section sealing land, and so no consumer
	// can misread Match=true as identity assurance in the meantime.
	KeyPinned bool `json:"key_pinned"`
	Sealed    bool `json:"sealed"`
}

// verifyNrepSignature checks the bundle's nrep section against the
// bundle's own envelope_id and aer_hash. See the file comment for the
// four states.
func verifyNrepSignature(b *artifacts.AuditBundle) NrepCheck {
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
	return NrepCheck{Performed: true, Match: true, ActorID: sec.ActorID}
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
