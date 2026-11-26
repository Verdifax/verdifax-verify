package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

// Round 65, N40: a hosted copy's served statement checks only with a pinned
// copy-statement key, only for its own token, bytes and run, and only when
// it keeps the copy.
func TestACopyStatementBindsTheTokenToTheRecord(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	fpSum := sha256.Sum256(der)
	keys := map[string]copyStatementKey{hex.EncodeToString(fpSum[:]): {Label: "test copy-statement key",
		PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}
	record := []byte(`{"run_id":282,"kind":"bundle"}`)
	sum := sha256.Sum256(record)
	token := strings.Repeat("a", 32)
	header := func(k *ecdsa.PrivateKey, s copyStatement) string {
		raw, _ := json.Marshal(s)
		d := sha256.Sum256(raw)
		sig, _ := ecdsa.SignASN1(rand.Reader, k, d[:])
		return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	good := copyStatement{Format: copyStatementFormat, Action: "keep", Token: token, Origin: "attested.verdifax.com", Kind: "bundle",
		OriginRunID: 282, RecordSHA256: hex.EncodeToString(sum[:]), Sequence: 9, StatedAt: "2026-11-26T15:00:00.5Z"}
	if c := checkCopyStatement(header(key, good), token, record, keys); !c.OK || c.RunID != 282 || c.Sequence != 9 {
		t.Fatalf("a good statement: %+v", c)
	}
	cases := map[string]func() (string, string, []byte){
		"another key":    func() (string, string, []byte) { return header(other, good), token, record },
		"another token":  func() (string, string, []byte) { return header(key, good), strings.Repeat("b", 32), record },
		"other bytes":    func() (string, string, []byte) { return header(key, good), token, []byte(`{"run_id":282,"kind":"x"}`) },
		"a withdrawal":   func() (string, string, []byte) { d := good; d.Action = "drop"; return header(key, d), token, record },
		"another run":    func() (string, string, []byte) { d := good; d.OriginRunID = 283; return header(key, d), token, record },
		"another format": func() (string, string, []byte) { d := good; d.Format = "v0"; return header(key, d), token, record },
		"not two parts":  func() (string, string, []byte) { return "abc", token, record },
		"a changed byte": func() (string, string, []byte) { h := header(key, good); return "x" + h[1:], token, record },
	}
	for name, mk := range cases {
		h, tok, rec := mk()
		if c := checkCopyStatement(h, tok, rec, keys); c.OK || c.Reason == "" {
			t.Errorf("%s: %+v, want a failure with its reason", name, c)
		}
	}
	if c := checkCopyStatement(header(key, good), token, record, nil); c.OK {
		t.Errorf("a verifier that pins no copy-statement key passed a statement")
	}
}

// Round 65, N40: every pinned copy-statement key is a P-256 public key whose
// fingerprint, the hex SHA-256 of its DER SubjectPublicKeyInfo, is the one it
// is pinned under, and the machine's key made on November 26, 2026 is pinned.
func TestEveryPinnedCopyStatementKeyMatchesItsFingerprint(t *testing.T) {
	const machine = "93a6eb8db2b50f62c462cc92e588e9f3bd98668c81e8cffad4f7dd4f4c2afe7e"
	if _, ok := copyStatementKeys[machine]; !ok {
		t.Fatalf("the hardware machine's copy-statement key %s is not pinned", machine)
	}
	for fp, k := range copyStatementKeys {
		block, _ := pem.Decode([]byte(k.PEM))
		if block == nil {
			t.Fatalf("%s: the pinned PEM does not decode", fp)
		}
		sum := sha256.Sum256(block.Bytes)
		if got := hex.EncodeToString(sum[:]); got != fp {
			t.Fatalf("%s: the pinned key's fingerprint is %s", fp, got)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		pub, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok || pub.Curve != elliptic.P256() {
			t.Fatalf("%s: the pinned key is not an ECDSA P-256 key", fp)
		}
		if k.Label == "" {
			t.Fatalf("%s: the pinned key has no label", fp)
		}
	}
}
