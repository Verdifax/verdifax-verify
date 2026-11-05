package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

const requestNonce = "00112233445566778899aabbccddeeff"

func requestSignedBundle(t *testing.T) (*artifacts.AuditBundle, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := &artifacts.AuditBundle{}
	b.Envelope.PayloadHash, b.Envelope.ProgramID = "aa", "bb"
	b.Envelope.RouteID, b.Envelope.RegistryRecordHash = "route", "cc"
	at := "2026-11-04T20:00:00Z"
	sig := ed25519.Sign(priv, artifacts.RequestSignaturePreimage("aa", "bb", "route", "cc", at, requestNonce))
	key := base64.StdEncoding.EncodeToString(pub)
	b.Nrep.RequestSignature = &artifacts.RequestSignature{PublicKey: key,
		Signature: base64.StdEncoding.EncodeToString(sig), SignedAt: at, Nonce: requestNonce}
	return b, key
}

func TestRequestSignatureVerifies(t *testing.T) {
	b, key := requestSignedBundle(t)
	c := verifyRequestSignature(b)
	if !c.Performed || !c.Match || c.KeyPinned || c.PublicKey != key {
		t.Fatalf("%+v", c)
	}
}

func TestRequestSignatureCoversEveryRequestValue(t *testing.T) {
	for name, change := range map[string]func(*artifacts.AuditBundle){
		"payload":  func(b *artifacts.AuditBundle) { b.Envelope.PayloadHash = "xx" },
		"program":  func(b *artifacts.AuditBundle) { b.Envelope.ProgramID = "xx" },
		"route":    func(b *artifacts.AuditBundle) { b.Envelope.RouteID = "xx" },
		"registry": func(b *artifacts.AuditBundle) { b.Envelope.RegistryRecordHash = "xx" },
		"time":     func(b *artifacts.AuditBundle) { b.Nrep.RequestSignature.SignedAt = "2026-11-04T20:00:01Z" },
		"nonce":    func(b *artifacts.AuditBundle) { b.Nrep.RequestSignature.Nonce = "ffffffffffffffffffffffffffffffff" },
	} {
		b, _ := requestSignedBundle(t)
		change(b)
		if c := verifyRequestSignature(b); !c.Performed || c.Match {
			t.Errorf("%s changed and the signature still matched: %+v", name, c)
		}
	}
}

func TestRequestSignatureRefusesMalformedFields(t *testing.T) {
	for name, change := range map[string]func(*artifacts.RequestSignature){
		"key":       func(s *artifacts.RequestSignature) { s.PublicKey = "not base64" },
		"short key": func(s *artifacts.RequestSignature) { s.PublicKey = "AAAA" },
		"signature": func(s *artifacts.RequestSignature) { s.Signature = "AAAA" },
		"time":      func(s *artifacts.RequestSignature) { s.SignedAt = "yesterday" },
		"nonce":     func(s *artifacts.RequestSignature) { s.Nonce = "abc" },
	} {
		b, _ := requestSignedBundle(t)
		change(b.Nrep.RequestSignature)
		if c := verifyRequestSignature(b); !c.Performed || c.Match {
			t.Errorf("%s: %+v", name, c)
		}
	}
}

func TestSignerKeyNamesTheSigner(t *testing.T) {
	b, key := requestSignedBundle(t)
	r := &Report{AllPassed: true, RequestSignature: verifyRequestSignature(b)}
	applySignerKey(r, key)
	if !r.AllPassed || !r.RequestSignature.KeyPinned {
		t.Fatalf("%+v", r.RequestSignature)
	}
}

func TestSignerKeyRefusesAnotherKey(t *testing.T) {
	b, _ := requestSignedBundle(t)
	other, _, _ := ed25519.GenerateKey(nil)
	r := &Report{AllPassed: true, RequestSignature: verifyRequestSignature(b)}
	applySignerKey(r, base64.StdEncoding.EncodeToString(other))
	if r.AllPassed || r.RequestSignature.Match || r.RequestSignature.KeyPinned {
		t.Fatalf("%+v", r.RequestSignature)
	}
}

func TestSignerKeyFailsOnUnsignedRun(t *testing.T) {
	r := &Report{AllPassed: true, RequestSignature: verifyRequestSignature(&artifacts.AuditBundle{})}
	applySignerKey(r, "anything")
	if r.AllPassed || r.RequestSignature.Match {
		t.Fatalf("%+v", r.RequestSignature)
	}
}

// Deleting the signature changes the section hash the record's anchor
// covers, and a record without it hashes exactly as before.
func TestSectionHashBindsRequestSignature(t *testing.T) {
	b, _ := requestSignedBundle(t)
	signed := b.Nrep.SectionHash()
	b.Nrep.RequestSignature = nil
	plain := b.Nrep.SectionHash()
	if signed == plain {
		t.Fatal("the section hash does not cover the request signature")
	}
	if plain != artifacts.ComputeNrepSectionHash("", "", "", "") {
		t.Fatal("an unsigned record no longer hashes as before")
	}
}
