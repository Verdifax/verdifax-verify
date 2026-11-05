package main

// Offline verification of the customer's request signature.
//
// A customer can register a public key and sign each request on its own
// machine, so Verdifax never holds the private key. The record seals the
// signature in nrep.request_signature. This file rebuilds the signed bytes
// from the envelope's own values and runs ed25519.Verify.
//
// The key comes from the record, so a passing check alone is consistency.
// --signer-key is what names the signer: it fails unless the record carries
// a valid signature from the key the reader supplies. The signature covers
// the request, so it shows who requested the run and nothing about whether
// the key holder accepted the outcome.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// RequestSignatureCheck records the verdict. Performed=true, Match=false
// fails the record. KeyPinned is true only after --signer-key matched.
type RequestSignatureCheck struct {
	Performed bool   `json:"performed"`
	Match     bool   `json:"match"`
	PublicKey string `json:"public_key,omitempty"`
	KeyPinned bool   `json:"key_pinned"`
	Reason    string `json:"reason,omitempty"`
}

func requestSignatureFailure(key, reason string) RequestSignatureCheck {
	return RequestSignatureCheck{Performed: true, PublicKey: key, Reason: reason}
}

func verifyRequestSignature(b *artifacts.AuditBundle) RequestSignatureCheck {
	sig := b.Nrep.RequestSignature
	if sig == nil {
		return RequestSignatureCheck{Reason: "the run carries no request signature"}
	}
	pub, keyErr := base64.StdEncoding.DecodeString(sig.PublicKey)
	if keyErr != nil || len(pub) != ed25519.PublicKeySize {
		return requestSignatureFailure(sig.PublicKey, "the public key is not a base64 Ed25519 key")
	}
	raw, sigErr := base64.StdEncoding.DecodeString(sig.Signature)
	if sigErr != nil || len(raw) != ed25519.SignatureSize {
		return requestSignatureFailure(sig.PublicKey, "the signature is not a base64 Ed25519 signature")
	}
	if _, timeErr := time.Parse(time.RFC3339, sig.SignedAt); timeErr != nil {
		return requestSignatureFailure(sig.PublicKey, "signed_at is not an RFC 3339 time")
	}
	if nonce, nonceErr := hex.DecodeString(sig.Nonce); nonceErr != nil || len(nonce) != 16 {
		return requestSignatureFailure(sig.PublicKey, "the nonce is not 32 hex characters")
	}
	e := b.Envelope
	preimage := artifacts.RequestSignaturePreimage(e.PayloadHash, e.ProgramID, e.RouteID, e.RegistryRecordHash, sig.SignedAt, sig.Nonce)
	if !ed25519.Verify(pub, preimage, raw) {
		return requestSignatureFailure(sig.PublicKey, "the signature does not match this run's request")
	}
	return RequestSignatureCheck{Performed: true, Match: true, PublicKey: sig.PublicKey}
}

// applySignerKey pins the reader's key. A record with no request signature
// fails, so --signer-key can never pass as checked when nothing was checked.
func applySignerKey(r *Report, want string) {
	c := &r.RequestSignature
	switch {
	case !c.Performed:
		*c = requestSignatureFailure("", "--signer-key was given but the run carries no request signature")
		r.AllPassed = false
	case c.Match && c.PublicKey == want:
		c.KeyPinned = true
	case c.Match:
		c.Match = false
		c.Reason = "the request was signed by a different key than --signer-key"
		r.AllPassed = false
	}
}

func printRequestSignature(c RequestSignatureCheck) {
	switch {
	case !c.Performed:
		fmt.Println("  Request signature: none on this run")
	case !c.Match:
		fmt.Println("  Request signature: FAILED:", c.Reason)
	case c.KeyPinned:
		fmt.Println("  Request signature: matches the key you supplied, so the holder of that key requested this run")
		fmt.Println("                     (it does not show the key holder accepted the outcome)")
	default:
		fmt.Println("  Request signature: CONSISTENT with the key in the record; use --signer-key to name the signer")
	}
}
