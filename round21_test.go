package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// substitutedActor249 replaces run 249's actor with a fresh key, signs
// the actor preimage with it, rewrites the pre-anchor table's actor rows,
// and recomputes the table digest and the leaf the bundle records. The
// result is internally consistent, but its leaf is no longer the one on
// the public log.
func substitutedActor249(t *testing.T) *artifacts.AuditBundle {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "round18", "run-249-production.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := artifacts.DecodeBundleStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b.Nrep.ActorID = "actor_substituted"
	b.Nrep.PublicKey = base64.StdEncoding.EncodeToString(pub)
	b.Nrep.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv,
		nrepPreimage(b.Envelope.EnvelopeID, b.FinalVFA.AerHash, b.Nrep.ActorID, b.Nrep.SignedAt)))
	for i := range b.PreAnchor {
		switch b.PreAnchor[i].Name {
		case "nrep_actor_id":
			b.PreAnchor[i].Value = b.Nrep.ActorID
		case "nrep_public_key":
			b.PreAnchor[i].Value = b.Nrep.PublicKey
		case "nrep_signature":
			b.PreAnchor[i].Value = b.Nrep.Signature
		}
	}
	b.PreAnchorDigest = artifacts.ComputePreAnchorDigestForTable(b.PreAnchor)
	b.RekorAnchor.LeafHashHex = verifyLeafBinding(b).Computed
	return b
}

// A substituted actor section is not sealed: the leaf it rebuilds is
// not the one the public log holds, so nothing anchored covers it.
func TestR21SubstitutedActorIsNotReportedSealed(t *testing.T) {
	r := verify(substitutedActor249(t))
	if !r.NrepSignature.Match || !r.LeafBinding.Match || !r.PreAnchor.Match {
		t.Fatalf("the forgery must be internally consistent for this test to mean anything: nrep=%+v leaf=%+v pre=%+v",
			r.NrepSignature, r.LeafBinding, r.PreAnchor)
	}
	if r.RekorAnchor.Match {
		t.Fatalf("the public-log entry must not match the substituted leaf: %+v", r.RekorAnchor)
	}
	if r.NrepSignature.Sealed {
		t.Fatalf("a substituted actor section must not report sealed: %+v", r.NrepSignature)
	}
	if r.VerdictTier != "FAILED" {
		t.Fatalf("verdict = %s, want FAILED", r.VerdictTier)
	}
}

// Sealed survives only when the public-log entry matches and a
// published Verdifax key signed it.
func TestR21SealedOnlyWhenLoggedNeedsTheEntryAndItsSigner(t *testing.T) {
	sealed := NrepCheck{Performed: true, Match: true, ActorID: "a", Sealed: true}
	anchor := RekorAnchorCheck{Performed: true, Match: true}
	auth := EntryAuthCheck{Performed: true, Match: true}
	if !sealedOnlyWhenLogged(sealed, anchor, auth).Sealed {
		t.Fatal("entry matches and is signed: want sealed")
	}
	for name, tc := range map[string]struct {
		anchor RekorAnchorCheck
		auth   EntryAuthCheck
	}{
		"entry does not match": {RekorAnchorCheck{Performed: true, Match: false}, auth},
		"no anchor":            {RekorAnchorCheck{}, auth},
		"signer not accepted":  {anchor, EntryAuthCheck{Performed: true, Match: false}},
		"signer not checked":   {anchor, EntryAuthCheck{}},
	} {
		if sealedOnlyWhenLogged(sealed, tc.anchor, tc.auth).Sealed {
			t.Errorf("%s: must not report sealed", name)
		}
	}
}
