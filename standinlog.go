//go:build standinlog

// This file is compiled only into the stand-in test build:
//
//	go build -tags standinlog -o verdifax-verify-standinlog .
//
// That build also trusts the stand-in public log of the orchestrator's
// internal/standinlog package, so a free rehearsal can run every public-log
// check against a local server (round 62, decided by Robert on November 14,
// 2026). Both stand-in keys come from public seeds, so anyone can sign as
// them: no release build may carry this tag (R284), the build names itself
// in every version line and report, and it warns on every run. A release
// build is unchanged: it never compiles this file.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"

	"github.com/Verdifax/verdifax-verify/internal/rekorverify"
)

// The seeds the orchestrator's internal/standinlog derives its keys from;
// R284 holds the two files' seeds equal.
const (
	standinLogSeed           = "verdifax stand-in public log key, test use only"
	standinSignerSeed        = "verdifax stand-in log entry signer, test use only"
	standinCopyStatementSeed = "verdifax stand-in hosted-copy statement key, test use only"
)

func standinKey(seed string) *ecdsa.PrivateKey {
	sum := sha256.Sum256([]byte(seed))
	k, deriveErr := ecdsa.ParseRawPrivateKey(elliptic.P256(), sum[:])
	// Error model of this binary: a CLI with no logger; a stand-in key that
	// cannot be derived is a build defect of the test build, so it stops it.
	if deriveErr != nil {
		panic("verdifax-verify: derive stand-in key: " + deriveErr.Error())
	}
	return k
}

func standinPEM(pub *ecdsa.PublicKey) (string, string) {
	der, marshalErr := x509.MarshalPKIXPublicKey(pub)
	// Error model of this binary: as above, a defect of the test build stops it.
	if marshalErr != nil {
		panic("verdifax-verify: marshal stand-in key: " + marshalErr.Error())
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), hex.EncodeToString(sum[:])
}

func init() {
	buildFlavor = "standinlog"
	logKey := standinKey(standinLogSeed)
	_, logID := standinPEM(&logKey.PublicKey)
	release := rekorAnchorVerifier
	rekorAnchorVerifier = func(in rekorverify.AnchorInput) error {
		if strings.EqualFold(in.LogID, logID) {
			return rekorverify.VerifyAnchorWithKey(in, &logKey.PublicKey)
		}
		return release(in)
	}
	signerPEM, signerFP := standinPEM(&standinKey(standinSignerSeed).PublicKey)
	pinned := make(map[string]pinnedSigner, len(pinnedEntrySigners)+1)
	for fp, k := range pinnedEntrySigners {
		pinned[fp] = k
	}
	pinned[signerFP] = pinnedSigner{Name: "stand-in log entry signer (test build only)", PEM: signerPEM, TestOnly: true}
	pinnedEntrySigners = pinned
	// Round 65, N40: the rehearsal's hosted-copy statement key, so a
	// rehearsal checks --copy-statement on the copy its server keeps.
	statementPEM, statementFP := standinPEM(&standinKey(standinCopyStatementSeed).PublicKey)
	statements := make(map[string]copyStatementKey, len(copyStatementKeys)+1)
	for fp, k := range copyStatementKeys {
		statements[fp] = k
	}
	statements[statementFP] = copyStatementKey{Name: "Verdifax stand-in copy-statement key (test build only)",
		Label: "the stand-in copy-statement key (test build only)", PEM: statementPEM,
		Custody: "a key file of the stand-in test build; no release build pins it", Purpose: "signs the hosted-copy statements of a free rehearsal only",
		FirstUse: "free rehearsals of round 65 on", NotBefore: copyStatementKeyCreatedUnix}
	copyStatementKeys = statements
}
