package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

// Hosted copies (round 65, N40). The hardware-attested machine is offline
// between evaluations, so the hosted service keeps an exact copy of every
// record it publishes. With each copy the hosted service serves the
// machine's signed statement in the header X-Verdifax-Hosted-Copy-Statement:
// the statement's bytes and its ECDSA P-256 signature, each base64url, joined
// by a dot. The statement binds the link's token to the record's kind, run
// and SHA-256, the sign-off file's SHA-256 and a sequence number the machine
// never repeats. It is signed with the machine's copy-statement key, a KMS
// key used for nothing else (decided by Robert, November 26, 2026: one key
// per purpose); this verifier trusts it only by the fingerprint pinned here.
//
//	verdifax-verify --copy-statement "$HEADER" --copy-token TOKEN record.json
//
// checks the signature with the pinned key, that the statement keeps (not
// withdraws) a copy under TOKEN, that the record file's SHA-256 is the one
// stated, that its run is the statement's and that the record is of the kind
// the statement names (round 66, N48: read from the record itself, a receipt
// or a bundle). With --copy-signoff FILE it also checks that the sign-off file
// served at the same link has the SHA-256 the statement names; when the
// statement names one and no file is given, --strict-signoff fails the check
// and without it the report says the file was not checked (round 66, N48).
//
// The key is accepted only for statements stated within its period, as a
// log-signing key is for entries (round 66, N49), and it is listed with the
// log-signing keys by --keys (and --log-keys).

const copyStatementFormat = "verdifax.hosted-copy-statement.v1"

// copyStatementKey is one pinned copy-statement key and the period, in the
// statement's own signed time, in which its statements are accepted: from
// NotBefore inclusive to NotAfter exclusive (0 means open-ended), the form a
// log-signing key's period takes (round 66, N49). The time checked is the
// statement's stated_at, which the key itself signs, so the period stops a
// key from vouching for statements dated outside it; a statement carries no
// third party's time.
type copyStatementKey struct {
	Name      string // the name --keys lists it under
	Label     string
	PEM       string
	Custody   string
	Purpose   string
	FirstUse  string
	NotBefore int64
	NotAfter  int64
}

// copyStatementKeyCreatedUnix is 2026-11-26T20:42:42Z, when AWS KMS created
// the hardware machine's copy-statement key (aws kms describe-key, read on
// November 28, 2026): the first moment its statements are accepted.
const copyStatementKeyCreatedUnix = 1795725762

// copyStatementKeyAcceptsAt reports whether k may vouch for a statement
// stated at unix time t: NotBefore <= t < NotAfter.
func copyStatementKeyAcceptsAt(k copyStatementKey, t int64) bool {
	return (k.NotBefore == 0 || t >= k.NotBefore) && (k.NotAfter == 0 || t < k.NotAfter)
}

// copyStatementKeys are the copy-statement keys this verifier trusts, by the
// hex SHA-256 of their DER SubjectPublicKeyInfo, the form log keys are
// pinned by (entryauth.go).
var copyStatementKeys = map[string]copyStatementKey{
	// The hardware-attested machine's copy-statement key: KMS key
	// 53aba6de-0b88-4f6b-b1de-3e74b25cc2b5, alias verdifax-copy-statements-prod,
	// us-east-2, made November 26, 2026; ECC_NIST_P256, used for nothing else.
	"93a6eb8db2b50f62c462cc92e588e9f3bd98668c81e8cffad4f7dd4f4c2afe7e": {
		Name:      "Verdifax copy-statement key (hardware-attested machine, AWS KMS)",
		Label:     "the hardware machine's copy-statement key",
		Custody:   "AWS KMS us-east-2, ECC_NIST_P256; its private half never leaves KMS, and the hardware-attested machine signs with it through its own role",
		Purpose:   "signs only the statements that bind a hosted copy to its link; it signs no public-log entry and no record",
		FirstUse:  "in use by 2026-11-27, when the paid readiness run checked the statements of all 131 hosted copies",
		NotBefore: copyStatementKeyCreatedUnix,
		PEM: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtPFbzLooRiVB51wcsxrm926D8QUX
2Yc/aiI1haThIIp4fTfAApEVmN3QjJmXJd4RdyYozPr++CY7oZZy8XmDug==
-----END PUBLIC KEY-----
`,
	},
}

// CopyStatementCheck is the --copy-statement result.
type CopyStatementCheck struct {
	Performed     bool   `json:"performed"`
	OK            bool   `json:"ok"`
	Token         string `json:"token,omitempty"`
	Origin        string `json:"origin,omitempty"`
	Kind          string `json:"kind,omitempty"`
	RunID         int64  `json:"run_id,omitempty"`
	RecordSHA256  string `json:"record_sha256,omitempty"`
	SignOffSHA256 string `json:"signoff_sha256,omitempty"`
	// SignOffChecked is true when --copy-signoff gave the sign-off file and
	// its SHA-256 is the one the statement names (round 66, N48).
	SignOffChecked bool   `json:"signoff_checked"`
	Sequence       int64  `json:"sequence,omitempty"`
	StatedAt       string `json:"stated_at,omitempty"`
	Key            string `json:"key,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// copySignOff is the --copy-signoff input: the sign-off file's bytes, whether
// one was given, and whether --strict-signoff requires it.
type copySignOff struct {
	Given  bool
	Bytes  []byte
	Strict bool
}

type copyStatement struct {
	Format        string `json:"format"`
	Action        string `json:"action"`
	Token         string `json:"token"`
	Origin        string `json:"origin"`
	Kind          string `json:"kind,omitempty"`
	OriginRunID   int64  `json:"origin_run_id,omitempty"`
	RecordSHA256  string `json:"record_sha256,omitempty"`
	SignOffSHA256 string `json:"signoff_sha256,omitempty"`
	Sequence      int64  `json:"sequence"`
	StatedAt      string `json:"stated_at"`
}

// checkCopyStatement checks a served statement header against the record's
// bytes, the token of the link it was served at and the pinned keys.
func checkCopyStatement(header, token string, record []byte, signoff copySignOff, keys map[string]copyStatementKey) *CopyStatementCheck {
	c := &CopyStatementCheck{Performed: true, Token: token}
	fail := func(reason string) *CopyStatementCheck {
		c.Reason = reason
		return c
	}
	parts := strings.Split(strings.TrimSpace(header), ".")
	if len(parts) != 2 {
		return fail("the statement is not two base64url parts joined by a dot, as the X-Verdifax-Hosted-Copy-Statement header carries it")
	}
	raw, rawErr := base64.RawURLEncoding.DecodeString(parts[0])
	sig, sigErr := base64.RawURLEncoding.DecodeString(parts[1])
	if rawErr != nil || sigErr != nil || len(raw) == 0 || len(sig) == 0 {
		return fail("the statement or its signature is not base64url")
	}
	if len(keys) == 0 {
		return fail("this verifier pins no copy-statement key")
	}
	digest := sha256.Sum256(raw)
	var signer copyStatementKey
	for fp, k := range keys {
		block, _ := pem.Decode([]byte(k.PEM))
		if block == nil {
			continue
		}
		parsed, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
		pub, isECDSA := parsed.(*ecdsa.PublicKey)
		if parseErr != nil || !isECDSA {
			continue
		}
		if ecdsa.VerifyASN1(pub, digest[:], sig) {
			c.Key, signer = k.Label+" ("+fp[:16]+"...)", k
			break
		}
	}
	if c.Key == "" {
		return fail("the statement's signature does not verify with any pinned copy-statement key")
	}
	var s copyStatement
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return fail("the signed bytes are not a copy statement")
	}
	c.Origin, c.Kind, c.RunID, c.RecordSHA256, c.SignOffSHA256, c.Sequence, c.StatedAt =
		s.Origin, s.Kind, s.OriginRunID, s.RecordSHA256, s.SignOffSHA256, s.Sequence, s.StatedAt
	if s.Format != copyStatementFormat {
		return fail(fmt.Sprintf("the format of the statement is %q, not %s", s.Format, copyStatementFormat))
	}
	if s.Action != "keep" {
		return fail(fmt.Sprintf("the statement is a %q, not one that keeps a copy", s.Action))
	}
	if s.Token != token {
		return fail(fmt.Sprintf("the statement is for token %s, not %s", s.Token, token))
	}
	stated, timeErr := time.Parse(time.RFC3339Nano, s.StatedAt)
	if timeErr != nil || s.Sequence <= 0 || s.Origin == "" {
		return fail("the statement names no origin, sequence or time")
	}
	if !copyStatementKeyAcceptsAt(signer, stated.Unix()) {
		return fail(fmt.Sprintf("the statement is stated %s, outside the period in which %s is accepted (%s)", s.StatedAt, signer.Label, copyKeyPeriod(signer)))
	}
	sum := sha256.Sum256(record)
	if got := hex.EncodeToString(sum[:]); got != s.RecordSHA256 {
		return fail(fmt.Sprintf("the SHA-256 of the record is %s, and the statement names %s", got, s.RecordSHA256))
	}
	var head struct {
		RunID int64 `json:"run_id"`
	}
	if err := json.Unmarshal(record, &head); err != nil || head.RunID != s.OriginRunID {
		return fail(fmt.Sprintf("the record is run %d, and the statement names run %d", head.RunID, s.OriginRunID))
	}
	// Round 66, N48: the kind is read from the record, never taken from the
	// statement alone.
	if kind := copyRecordKind(record); kind != s.Kind {
		return fail(fmt.Sprintf("the record is a %s, and the statement names a %q", kind, s.Kind))
	}
	switch {
	case signoff.Given && s.SignOffSHA256 == "":
		return fail("a sign-off file was given with --copy-signoff, and the statement names none for this link")
	case signoff.Given:
		sum := sha256.Sum256(signoff.Bytes)
		if got := hex.EncodeToString(sum[:]); got != s.SignOffSHA256 {
			return fail(fmt.Sprintf("the SHA-256 of the sign-off file is %s, and the statement names %s", got, s.SignOffSHA256))
		}
		c.SignOffChecked = true
	case s.SignOffSHA256 != "" && signoff.Strict:
		return fail("the statement names a sign-off file (SHA-256 " + s.SignOffSHA256 + ") and none was given; --strict-signoff requires the file served at the same link with --copy-signoff")
	}
	c.OK = true
	return c
}

// readCopySignOff reads the --copy-signoff file; a file that cannot be read
// stops the run with exit 2, as every other input file does.
func readCopySignOff(path string, strict bool) copySignOff {
	if path == "" {
		return copySignOff{Strict: strict}
	}
	b, readErr := os.ReadFile(path)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify: read --copy-signoff:", readErr)
		os.Exit(2)
	}
	return copySignOff{Given: true, Bytes: b, Strict: strict}
}

// copyRecordKind is the kind a hosted copy's record is, read from the record
// as the verifier reads its input: "receipt" for a receipt document, "bundle"
// otherwise.
func copyRecordKind(record []byte) string {
	if isReceiptDocument(record) {
		return "receipt"
	}
	return "bundle"
}

// copyKeyPeriod prints a copy-statement key's acceptance period.
func copyKeyPeriod(k copyStatementKey) string {
	from, until := "always", "always"
	if k.NotBefore != 0 {
		from = time.Unix(k.NotBefore, 0).UTC().Format(time.RFC3339)
	}
	if k.NotAfter != 0 {
		until = time.Unix(k.NotAfter, 0).UTC().Format(time.RFC3339)
	}
	return "accepted from " + from + " until " + until
}

// printCopyStatement prints the --copy-statement result as one report line.
func printCopyStatement(c *CopyStatementCheck) {
	if c == nil || !c.Performed {
		return
	}
	if !c.OK {
		fmt.Printf("  %-18s✗ FAILED · %s\n", "Hosted copy:", c.Reason)
		return
	}
	signoff := "no sign-off file"
	switch {
	case c.SignOffChecked:
		signoff = "sign-off file checked, SHA-256 " + c.SignOffSHA256 + " as stated"
	case c.SignOffSHA256 != "":
		signoff = "sign-off file NOT CHECKED: the statement names SHA-256 " + c.SignOffSHA256 + "; pass the file served at the same link with --copy-signoff"
	}
	fmt.Printf("  %-18s✓ the statement signed by %s binds token %s to this record (run %d, %s), served for %s, sequence %d, stated %s; %s\n",
		"Hosted copy:", c.Key, c.Token, c.RunID, c.Kind, c.Origin, c.Sequence, c.StatedAt, signoff)
}
