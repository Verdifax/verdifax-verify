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
// stated and that its run is the statement's, and prints the stated
// sign-off file SHA-256 so it can be compared with what was served.

const copyStatementFormat = "verdifax.hosted-copy-statement.v1"

// copyStatementKey is one pinned copy-statement key.
type copyStatementKey struct {
	Label string
	PEM   string
}

// copyStatementKeys are the copy-statement keys this verifier trusts, by the
// hex SHA-256 of their DER SubjectPublicKeyInfo, the form log keys are
// pinned by (entryauth.go).
var copyStatementKeys = map[string]copyStatementKey{
	// The hardware-attested machine's copy-statement key: KMS key
	// 53aba6de-0b88-4f6b-b1de-3e74b25cc2b5, alias verdifax-copy-statements-prod,
	// us-east-2, made November 26, 2026; ECC_NIST_P256, used for nothing else.
	"93a6eb8db2b50f62c462cc92e588e9f3bd98668c81e8cffad4f7dd4f4c2afe7e": {
		Label: "the hardware machine's copy-statement key",
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
	Sequence      int64  `json:"sequence,omitempty"`
	StatedAt      string `json:"stated_at,omitempty"`
	Key           string `json:"key,omitempty"`
	Reason        string `json:"reason,omitempty"`
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
func checkCopyStatement(header, token string, record []byte, keys map[string]copyStatementKey) *CopyStatementCheck {
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
			c.Key = k.Label + " (" + fp[:16] + "...)"
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
	if _, err := time.Parse(time.RFC3339Nano, s.StatedAt); err != nil || s.Sequence <= 0 || s.Origin == "" {
		return fail("the statement names no origin, sequence or time")
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
	c.OK = true
	return c
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
	if c.SignOffSHA256 != "" {
		signoff = "sign-off file SHA-256 " + c.SignOffSHA256
	}
	fmt.Printf("  %-18s✓ the statement signed by %s binds token %s to this record (run %d, %s), served for %s, sequence %d, stated %s; %s\n",
		"Hosted copy:", c.Key, c.Token, c.RunID, c.Kind, c.Origin, c.Sequence, c.StatedAt, signoff)
}
