// Package pslbuiltin holds the exact text of every policy Verdifax has run
// for a key with no policy of its own.
//
// The server runs the current one, and the public verifier carries a
// byte-identical copy of this directory, so a record decided by Verdifax's
// own rules can be checked as a customer's can: the verifier finds the text
// by the hash the record seals and runs the rules itself. Nothing here
// imports another package of either project, which is what lets the copy be
// exact.
//
// A version is never edited or removed once a record names it. A change to
// the built-in policy is a new file and a new entry, with the old one kept.
package pslbuiltin

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
)

//go:embed documents/*.json
var documents embed.FS

// Policy is one version of Verdifax's built-in policy.
type Policy struct {
	// File is the document's name in this package.
	File string
	// DocumentHash is the SHA-256 of the exact text, which a record from
	// verifier v0.20.0 on seals.
	DocumentHash string
	// PolicyHash is the hash earlier records seal. Each project's own
	// policy hash code must reach it from the text; a test in each holds
	// that.
	PolicyHash string
	// Current is true for the version the server runs today.
	Current bool
	// Document is the exact text.
	Document []byte
}

// versions lists every built-in policy, oldest first. The two hashes are
// written out so that a changed file fails a test instead of quietly
// becoming a different policy.
var versions = []Policy{
	{
		File:         "verdifax-default-allow-all-1.0.0.json",
		DocumentHash: "51e935fb0f6169273f980ba25a59fe7878759da2fa2b09c86b50c2bb59d79f7a",
		PolicyHash:   "0f7c55ca7884039111adc67c9c19f1572c8b48cbdfa50601585eb9acd9f5f042",
	},
	{
		File:         "verdifax-default-baseline-permit-1.0.0.json",
		DocumentHash: "c2395f30f608228a0442c00682326a040e030b895af59b22a41747740a9e4e28",
		PolicyHash:   "1a090975c0515a14296a0e68bb6840c5de4d76465369c50022e390b3da1e25d0",
		Current:      true,
	},
}

// All returns every version with its text, oldest first. It fails when a
// file is missing or its text no longer has the hash listed for it.
func All() ([]Policy, error) {
	out := make([]Policy, 0, len(versions))
	for _, v := range versions {
		text, readErr := documents.ReadFile("documents/" + v.File)
		if readErr != nil {
			return nil, fmt.Errorf("pslbuiltin: %s: %w", v.File, readErr)
		}
		sum := sha256.Sum256(text)
		if got := hex.EncodeToString(sum[:]); got != v.DocumentHash {
			return nil, fmt.Errorf("pslbuiltin: %s hashes to %s, listed as %s", v.File, got, v.DocumentHash)
		}
		v.Document = text
		out = append(out, v)
	}
	return out, nil
}

// Current returns the version the server runs today.
func Current() (Policy, error) {
	all, readErr := All()
	if readErr != nil {
		return Policy{}, readErr
	}
	for _, v := range all {
		if v.Current {
			return v, nil
		}
	}
	return Policy{}, fmt.Errorf("pslbuiltin: no version is marked current")
}

// ByDocumentHash finds a version by the hash of its exact text.
func ByDocumentHash(documentHash string) (Policy, bool) {
	all, readErr := All()
	if readErr != nil {
		return Policy{}, false
	}
	for _, v := range all {
		if v.DocumentHash == documentHash {
			return v, true
		}
	}
	return Policy{}, false
}

// ByPolicyHash finds a version by the policy hash a record seals, for
// records sealed before they named the policy's author.
func ByPolicyHash(policyHash string) (Policy, bool) {
	all, readErr := All()
	if readErr != nil {
		return Policy{}, false
	}
	for _, v := range all {
		if v.PolicyHash == policyHash {
			return v, true
		}
	}
	return Policy{}, false
}
