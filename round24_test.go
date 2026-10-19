package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// What POST /attest logs: sha256 of the v2 leaf preimage built from
// "attest:<key>:<subject>", the caller's digest, sha256(alg\nsubject) and a nonce.
func attestLeaf(envelopeID, digest, binding string, nonce int64) string {
	sum := sha256.Sum256([]byte(joinLeafParts(leafDomainV2, envelopeID, digest, binding, strconv.FormatInt(nonce, 10))))
	return hex.EncodeToString(sum[:])
}

// attestShapedForgery rewrites run 238's story and anchors it with a
// leaf exactly as POST /attest builds one, logged by a stand-in for the
// production key.
func attestShapedForgery(t *testing.T, envelopeID string, loggedAt int64) *Report {
	t.Helper()
	l := newTestLog(t)
	l.install(t)
	b := loadRound7(t, "run-238-intact.json")
	subject := "anything"
	env := envelopeID
	b.Envelope.EnvelopeID = env
	b.Transport.EnvelopeID = env
	b.AER.EnvelopeID = env
	b.PreAnchor, b.PreAnchorDigest = nil, ""
	b.BundleAnchor = nil
	b.Nrep = artifacts.NrepSection{}
	b.NrepSectionHash, b.ScaffoldFlagsHash = "", ""
	storyRewrite(b)
	b.ZkspBinding.Seal.SealedHash = hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("sha256\n" + subject)); return s[:] }())
	b.Envelope.Hash = artifacts.RecomputeEnvelopeHash(b.Envelope)
	b.Transport.Hash = artifacts.RecomputeTransportHash(b.Transport)
	b.AER.Hash = artifacts.RecomputeAERHash(b.AER)
	b.BundleHash = artifacts.RecomputeBundleHash(b)
	nonce := int64(b.RekorAnchor.InputNonce)
	b.RekorAnchor.LeafHashHex = attestLeaf(env, b.AER.Seal.SealedHash, b.ZkspBinding.Seal.SealedHash, nonce)
	if loggedAt != 0 {
		l.integratedTime = loggedAt
	}
	anchorRun(t, l, b)
	r := verify(b)
	return r
}

// A record anchored by an /attest-shaped entry is refused: its envelope
// identifier is not a run identifier. Before v0.15.2 the same record read
// VERIFIED AND ANCHORED with partial coverage.
func TestR24AttestEntryCannotStandAsARecordLeaf(t *testing.T) {
	r := attestShapedForgery(t, "attest:2:anything", 0)
	if !r.LeafBinding.Match || !r.RekorAnchor.Match || !r.EntryAuth.Match {
		t.Fatalf("the forgery must pass the leaf, anchor and signer checks for this test to mean anything: %+v %+v %+v",
			r.LeafBinding, r.RekorAnchor, r.EntryAuth)
	}
	if r.RecordIdentity.Match || r.AllPassed || r.VerdictTier != "FAILED" {
		t.Fatalf("an /attest-shaped record must fail: tier=%s identity=%+v", r.VerdictTier, r.RecordIdentity)
	}
}

// A pre-table leaf logged after run 236's first entry cannot be genuine,
// even with a run-shaped identifier.
func TestR24PreTableLeafLoggedAfterTheCutoverFails(t *testing.T) {
	late := preTableLeafCutover.Add(time.Hour).Unix()
	r := attestShapedForgery(t, "env-0123456789abcdef", late)
	if r.RecordIdentity.Match || r.AllPassed {
		t.Fatalf("a v2 leaf logged after the cutover must fail: %+v", r.RecordIdentity)
	}
}
