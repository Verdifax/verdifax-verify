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
	"crypto/sha256"
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

	// BodyHash is the hash of the whole signed request (version 2).
	// RequestMatched is true only after --request matched it.
	BodyHash       string `json:"body_hash,omitempty"`
	RequestMatched bool   `json:"request_matched,omitempty"`
}

func requestSignatureFailure(key, reason string) RequestSignatureCheck {
	return RequestSignatureCheck{Performed: true, PublicKey: key, Reason: reason}
}

func verifyRequestSignature(b *artifacts.AuditBundle) RequestSignatureCheck {
	sig := b.Nrep.RequestSignature
	if sig == nil {
		return RequestSignatureCheck{Reason: "the run carries no request signature"}
	}
	e := b.Envelope
	fields := artifacts.SealedRequestFields{PayloadHash: e.PayloadHash, ProgramID: e.ProgramID, RouteID: e.RouteID,
		RegistryRecordHash: e.RegistryRecordHash, AiOutputHash: b.AivpT4.AiOutputHash}
	return checkRequestSignature(sig, fields, b.Nrep.Job)
}

// checkRequestSignature rebuilds the signed bytes from values the record
// holds, so a signature can only pass over this run's own request.
func checkRequestSignature(sig *artifacts.RequestSignature, fields artifacts.SealedRequestFields, job *artifacts.JobLink) RequestSignatureCheck {
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
	var preimage []byte
	switch sig.Version {
	case "":
		preimage = artifacts.RequestSignaturePreimage(fields.PayloadHash, fields.ProgramID, fields.RouteID,
			fields.RegistryRecordHash, sig.SignedAt, sig.Nonce)
	case artifacts.RequestSignatureVersion2:
		if len(sig.BodyHash) != 64 {
			return requestSignatureFailure(sig.PublicKey, "a version 2 signature needs a 64 character body_hash")
		}
		if sig.AiOutputHash != fields.AiOutputHash {
			return requestSignatureFailure(sig.PublicKey, "the signature names a different AI output than this record")
		}
		preimage = artifacts.RequestSignaturePreimageV2(sig.BodyHash, fields, job, sig.SignedAt, sig.Nonce)
	default:
		return requestSignatureFailure(sig.PublicKey, "this verifier does not know request signature version "+sig.Version)
	}
	if !ed25519.Verify(pub, preimage, raw) {
		return requestSignatureFailure(sig.PublicKey, "the signature does not match this run's request")
	}
	return RequestSignatureCheck{Performed: true, Match: true, PublicKey: sig.PublicKey, BodyHash: sig.BodyHash}
}

// applyRequestFile compares the reader's copy of the signed request with the
// hash the signature covers. This is the one way to reach fields the record
// holds only as hashes, such as metadata.
func applyRequestFile(c *RequestSignatureCheck, signed []byte) {
	if !c.Performed || !c.Match {
		c.Match = false
		c.Performed = true
		c.Reason = "--request needs a record with a valid request signature"
		return
	}
	if c.BodyHash == "" {
		c.Match = false
		c.Reason = "--request needs a version 2 signature; a version 1 signature does not cover the whole request"
		return
	}
	sum := sha256.Sum256(signed)
	if hex.EncodeToString(sum[:]) != c.BodyHash {
		c.Match = false
		c.Reason = "the request file is not the request this signature covers"
		return
	}
	c.RequestMatched = true
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

// applyReceiptSignerKey pins the reader's key against a receipt's signature.
func applyReceiptSignerKey(r *ReceiptReport, want string) {
	shadow := Report{AllPassed: true, RequestSignature: r.RequestSignature}
	applySignerKey(&shadow, want)
	r.RequestSignature = shadow.RequestSignature
	if !shadow.AllPassed {
		r.AllPassed, r.VerdictTier, r.Reason = false, "FAILED", shadow.RequestSignature.Reason
	}
}

func printRequestSignature(c RequestSignatureCheck) {
	switch {
	case !c.Performed:
		fmt.Println("  Request signature: none on this run")
	case !c.Match:
		fmt.Println("  Request signature: FAILED:", c.Reason)
	case c.RequestMatched:
		fmt.Println("  Request signature: covers the exact request file you supplied")
		fmt.Println("                     (it does not show the key holder accepted the outcome)")
	case c.KeyPinned:
		fmt.Println("  Request signature: matches the key you supplied, so the holder of that key requested this run")
		fmt.Println("                     (it does not show the key holder accepted the outcome)")
	default:
		fmt.Println("  Request signature: CONSISTENT with the key in the record; use --signer-key to name the signer")
	}
}
