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
	"time"
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
	if c := checkCopyStatement(header(key, good), token, record, copySignOff{}, keys); !c.OK || c.RunID != 282 || c.Sequence != 9 {
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
		if c := checkCopyStatement(h, tok, rec, copySignOff{}, keys); c.OK || c.Reason == "" {
			t.Errorf("%s: %+v, want a failure with its reason", name, c)
		}
	}
	if c := checkCopyStatement(header(key, good), token, record, copySignOff{}, nil); c.OK {
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

// testCopyKey makes a pinned test copy-statement key accepted from notBefore.
func testCopyKey(t *testing.T, notBefore int64) (*ecdsa.PrivateKey, map[string]copyStatementKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	fp := sha256.Sum256(der)
	return key, map[string]copyStatementKey{hex.EncodeToString(fp[:]): {Name: "test", Label: "test copy-statement key", NotBefore: notBefore,
		PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}
}

func signCopyStatement(k *ecdsa.PrivateKey, s copyStatement) string {
	raw, _ := json.Marshal(s)
	d := sha256.Sum256(raw)
	sig, _ := ecdsa.SignASN1(rand.Reader, k, d[:])
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Round 66, N48: the sign-off file served at the same link is checked by the
// tool, not by eye, and the record's kind is read from the record.
func TestACopyStatementChecksTheSignOffFileAndTheKind(t *testing.T) {
	key, keys := testCopyKey(t, 0)
	record := []byte(`{"run_id":282,"manifest_hash":"x"}`)
	receipt := []byte(`{"run_id":282,"deny_receipt":{}}`)
	signoff := []byte(`[{"decision":"approve"}]`)
	rs, ss := sha256.Sum256(record), sha256.Sum256(signoff)
	token := strings.Repeat("a", 32)
	good := copyStatement{Format: copyStatementFormat, Action: "keep", Token: token, Origin: "attested.verdifax.com", Kind: "bundle",
		OriginRunID: 282, RecordSHA256: hex.EncodeToString(rs[:]), SignOffSHA256: hex.EncodeToString(ss[:]), Sequence: 9, StatedAt: "2026-11-27T15:00:00Z"}
	h := signCopyStatement(key, good)
	if c := checkCopyStatement(h, token, record, copySignOff{Given: true, Bytes: signoff}, keys); !c.OK || !c.SignOffChecked {
		t.Fatalf("the served sign-off file with its stated SHA-256: %+v", c)
	}
	if c := checkCopyStatement(h, token, record, copySignOff{Given: true, Bytes: append([]byte(" "), signoff...)}, keys); c.OK || !strings.Contains(c.Reason, "sign-off file") {
		t.Errorf("a sign-off file one byte off passed: %+v", c)
	}
	if c := checkCopyStatement(h, token, record, copySignOff{Strict: true}, keys); c.OK || !strings.Contains(c.Reason, "--strict-signoff") {
		t.Errorf("--strict-signoff with no sign-off file passed: %+v", c)
	}
	if c := checkCopyStatement(h, token, record, copySignOff{}, keys); !c.OK || c.SignOffChecked {
		t.Errorf("without --strict-signoff a missing file must pass and read not checked: %+v", c)
	}
	none := good
	none.SignOffSHA256 = ""
	if c := checkCopyStatement(signCopyStatement(key, none), token, record, copySignOff{Given: true, Bytes: signoff}, keys); c.OK {
		t.Errorf("a sign-off file given for a statement that names none passed: %+v", c)
	}
	if c := checkCopyStatement(signCopyStatement(key, none), token, record, copySignOff{Strict: true}, keys); !c.OK {
		t.Errorf("a statement that names no sign-off file needs none, even under --strict-signoff: %+v", c)
	}
	asReceipt := good
	asReceipt.Kind = "receipt"
	if c := checkCopyStatement(signCopyStatement(key, asReceipt), token, record, copySignOff{}, keys); c.OK || !strings.Contains(c.Reason, "is a bundle") {
		t.Errorf("a bundle stated as a receipt passed: %+v", c)
	}
	rr := sha256.Sum256(receipt)
	asBundle := good
	asBundle.RecordSHA256 = hex.EncodeToString(rr[:])
	if c := checkCopyStatement(signCopyStatement(key, asBundle), token, receipt, copySignOff{}, keys); c.OK || !strings.Contains(c.Reason, "is a receipt") {
		t.Errorf("a receipt stated as a bundle passed: %+v", c)
	}
	asBundle.Kind = "receipt"
	if c := checkCopyStatement(signCopyStatement(key, asBundle), token, receipt, copySignOff{}, keys); !c.OK {
		t.Errorf("a receipt stated as a receipt: %+v", c)
	}
}

// Round 66, N49: a copy-statement key vouches only for statements stated
// within its period, and the machine's key from the moment KMS created it.
func TestACopyStatementKeyIsAcceptedOnlyWithinItsPeriod(t *testing.T) {
	key, keys := testCopyKey(t, copyStatementKeyCreatedUnix)
	record := []byte(`{"run_id":5}`)
	sum := sha256.Sum256(record)
	token := strings.Repeat("c", 32)
	s := copyStatement{Format: copyStatementFormat, Action: "keep", Token: token, Origin: "o", Kind: "bundle", OriginRunID: 5,
		RecordSHA256: hex.EncodeToString(sum[:]), Sequence: 1}
	s.StatedAt = time.Unix(copyStatementKeyCreatedUnix-1, 0).UTC().Format(time.RFC3339Nano)
	if c := checkCopyStatement(signCopyStatement(key, s), token, record, copySignOff{}, keys); c.OK || !strings.Contains(c.Reason, "outside the period") {
		t.Errorf("a statement dated before the key existed passed: %+v", c)
	}
	s.StatedAt = time.Unix(copyStatementKeyCreatedUnix, 0).UTC().Format(time.RFC3339Nano)
	if c := checkCopyStatement(signCopyStatement(key, s), token, record, copySignOff{}, keys); !c.OK {
		t.Errorf("a statement dated at the key's creation: %+v", c)
	}
	for fp, k := range copyStatementKeys {
		if k.NotBefore == 0 || k.Name == "" || k.Custody == "" || k.Purpose == "" || k.FirstUse == "" {
			t.Errorf("%s: a pinned copy-statement key needs a period start, a name, custody, purpose and first use for --keys", fp)
		}
	}
	if k := copyStatementKeys["93a6eb8db2b50f62c462cc92e588e9f3bd98668c81e8cffad4f7dd4f4c2afe7e"]; k.NotBefore != 1795725762 || k.NotAfter != 0 {
		t.Errorf("the machine's key must be accepted from 2026-11-26T20:42:42Z, its KMS creation, with no end: %+v", k)
	}
}
