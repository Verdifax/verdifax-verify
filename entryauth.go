package main

// Entry authentication (v0.12.0), the answer to round seven of the
// external review.
//
// Round seven showed that a verified public-log entry proves only that
// its leaf is in the log. Rekor accepts a hashedrekord entry from
// anyone with any key, and earlier releases read nothing from an entry
// but its kind and hash. A forger could rewrite a record, recompute
// every digest, log the new leaves under a key of their own, and the
// record verified as COMPLETE RECORD ANCHORED. The anchoring time and
// entry number were display values anyone could edit.
//
// This file closes the "who": every public-log entry must be signed by
// a pinned Verdifax log-signing key, the signature must verify over
// the logged digest, and a run's two entries must share one signer.
// rekorverify closes the "when": each entry's signed entry timestamp
// is verified under Rekor's key, which authenticates its integrated
// time and global index. With both in hand:
//
//   - The record entry may not predate the run entry.
//   - On a record whose anchored table seals an anchoring window (table
//     v3, leaf v7), both entries must fall within that window of the
//     run's sealed clock_epoch. That is what makes a later re-log by
//     the key holder, Verdifax included, fail: the re-log carries a
//     later Rekor time, and moving clock_epoch to match changes the
//     record's own sealed date. Older records show their authenticated
//     anchoring time and its gap from the clock, and cannot fail on it.
//
// What this does not do: it cannot tell a genuine record from one
// Verdifax sealed with false inputs in the first place. Pinning shows
// Verdifax's key logged the record; the window shows when.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/rekorverify"
)

// pinnedSigner is one published Verdifax log-signing key and the
// period, in Rekor-authenticated Unix time, in which its entries are
// accepted (0 means open-ended). The period is checked against the
// signed entry timestamp, so an entry logged outside it fails even if
// the key's private half were ever copied.
type pinnedSigner struct {
	Name      string
	PEM       string
	NotBefore int64
	NotAfter  int64
}

// Key 1 is the production orchestrator's key. It signed every public
// Verdifax entry on api.verdifax.com from the first (2026-05-13) on
// and has not been rotated. Custody: the private key is a file on the
// production API server's volume, not in a hardware module.
//
// Key 2 was generated on the AWS SEV-SNP instance that produced the
// October 2026 hardware evidence run, signed that run's single entry
// (2026-10-03T15:00:47Z), and existed only on that instance, which was
// destroyed after the run. It is accepted only within an hour of that
// entry, so it can never vouch for anything logged later.
const (
	verdifaxLogSigningKey1Fingerprint = "0822255b6c085f394088d1ce4142dc927941789be75faf084d163059551000b7"
	verdifaxLogSigningKey2Fingerprint = "16349c23103f9bd5fd59f0be45e199540e430ab02587e497f96856817d47fe0a"
)

// pinnedEntrySigners maps each trusted signer fingerprint (hex SHA-256
// of the DER SubjectPublicKeyInfo) to its key. A variable only so tests
// can pin the key of a test log they control; production always uses
// the published Verdifax keys.
var pinnedEntrySigners = map[string]pinnedSigner{
	verdifaxLogSigningKey1Fingerprint: {
		Name: "Verdifax log-signing key 1",
		PEM: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsgyMROAY9glbF1VAFeKzSG7xN2Vg
pIA8djKUggfjIOOLQ25gtyrQNUk2JLbDvOM015SmWZyoB8cPG0LdO/0SSA==
-----END PUBLIC KEY-----
`,
	},
	verdifaxLogSigningKey2Fingerprint: {
		Name: "Verdifax log-signing key 2 (October 2026 hardware evidence run)",
		PEM: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtn//E+NR9JsyD5ssGshpIceKCMBo
SjGPIXP3UGH1hTsdwx+uYHNJ5a0b6nsdiIf+Z0a4L5LWvfEQF1p8kev6Sw==
-----END PUBLIC KEY-----
`,
		NotBefore: 1791039647 - 3600,
		NotAfter:  1791039647 + 3600,
	},
}

// anchoringClockSkew is how far before the run's sealed clock a Rekor
// time may fall. Rekor's clock and the server's are separate; a small
// negative gap is skew, never an attack, since nobody can make Rekor
// record an earlier time.
const anchoringClockSkew = 5 * time.Minute

// maxAnchoringWindowSeconds bounds the window a v3 table may seal, so
// a record cannot claim a window too wide to mean anything.
const maxAnchoringWindowSeconds = 3600

// EntryAuthCheck reports who logged a run's public-log entries and
// when, as authenticated by the entry signatures and Rekor's signed
// entry timestamps.
type EntryAuthCheck struct {
	Performed         bool   `json:"performed"`
	Match             bool   `json:"match"`
	SignerFingerprint string `json:"signer_fingerprint,omitempty"`
	SignerName        string `json:"signer_name,omitempty"`
	// RunAnchoredAt and RecordAnchoredAt are the Rekor-authenticated
	// times of the first and second entries (RFC 3339, UTC).
	RunAnchoredAt    string `json:"run_anchored_at,omitempty"`
	RecordAnchoredAt string `json:"record_anchored_at,omitempty"`
	ClockEpoch       string `json:"clock_epoch,omitempty"`
	// GapSeconds is the first entry's authenticated time minus the
	// sealed clock_epoch, when the record carries a clock.
	GapSeconds    *int64 `json:"anchor_gap_seconds,omitempty"`
	WindowSealed  bool   `json:"window_sealed"`
	WindowSeconds int64  `json:"anchoring_window_seconds,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

func init() {
	for fp, k := range pinnedEntrySigners {
		block, _ := pem.Decode([]byte(k.PEM))
		if block == nil {
			panic("verdifax-verify: pinned log-signing key is not PEM: " + k.Name)
		}
		// Error model of this binary: a CLI with no logger; a pinned key
		// that does not parse is a build defect, so it stops the binary.
		if _, parseErr := x509.ParsePKIXPublicKey(block.Bytes); parseErr != nil {
			panic("verdifax-verify: pinned log-signing key does not parse: " + k.Name + ": " + parseErr.Error())
		}
		sum := sha256.Sum256(block.Bytes)
		if hex.EncodeToString(sum[:]) != fp {
			panic("verdifax-verify: pinned log-signing key fingerprint mismatch: " + k.Name)
		}
	}
}

// signerAcceptsAt reports whether key k may vouch for an entry the log
// recorded at unix time t.
func signerAcceptsAt(k pinnedSigner, t int64) bool {
	return (k.NotBefore == 0 || t >= k.NotBefore) && (k.NotAfter == 0 || t <= k.NotAfter)
}

// parseAnchoringWindow reads a sealed window row: whole seconds,
// positive, and no wider than maxAnchoringWindowSeconds.
func parseAnchoringWindow(v string) (int64, error) {
	// Error model: the parse error is folded into the reported reason;
	// this binary has no logger.
	n, convErr := strconv.ParseInt(v, 10, 64)
	if convErr != nil || strconv.FormatInt(n, 10) != v {
		return 0, errors.New("not a whole number of seconds")
	}
	if n <= 0 || n > maxAnchoringWindowSeconds {
		return 0, fmt.Errorf("outside 1 to %d seconds", maxAnchoringWindowSeconds)
	}
	return n, nil
}

// entrySignerOf returns the verified signer fingerprint of an entry.
func entrySignerOf(entryBodyB64 string) (string, error) {
	body, decodeErr := base64.StdEncoding.DecodeString(entryBodyB64)
	if decodeErr != nil {
		return "", fmt.Errorf("entry_body base64 decode: %w", decodeErr)
	}
	return rekorverify.EntrySigner(body)
}

func preAnchorValue(table []artifacts.PreAnchorEntry, name string) (string, bool) {
	for _, e := range table {
		if e.Name == name {
			return e.Value, true
		}
	}
	return "", false
}

func utc(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.RFC3339) }

// verifyEntryAuthentication runs after both anchors have verified as
// log entries (inclusion proof, checkpoint, entry body, signed entry
// timestamp). It is performed only for a run anchored on the public
// log whose first entry verified; a failed entry has already failed.
func verifyEntryAuthentication(b *artifacts.AuditBundle, r *Report) EntryAuthCheck {
	ra := b.RekorAnchor
	if ra.Backend != "rekor" || !r.RekorAnchor.Performed || !r.RekorAnchor.Match {
		return EntryAuthCheck{Performed: false}
	}
	out := EntryAuthCheck{Performed: true, RunAnchoredAt: utc(ra.IntegratedTime)}
	fail := func(format string, args ...any) EntryAuthCheck {
		out.Match = false
		out.Reason = fmt.Sprintf(format, args...)
		return out
	}

	// WHO: the run entry.
	runSigner, runErr := entrySignerOf(ra.EntryBody)
	if runErr != nil {
		return fail("the run's public-log entry has no valid signer: %v", runErr)
	}
	out.SignerFingerprint = runSigner
	key, pinned := pinnedEntrySigners[runSigner]
	if !pinned {
		return fail("the run's public-log entry was logged by key %s, which is not a published "+
			"Verdifax log-signing key: anyone can add entries to the public log", truncate(runSigner, 16))
	}
	out.SignerName = key.Name
	if !signerAcceptsAt(key, ra.IntegratedTime) {
		return fail("the run's public-log entry was logged at %s, outside the period in which %s "+
			"is accepted", out.RunAnchoredAt, key.Name)
	}

	// WHO and WHEN: the record entry, when it is on the public log.
	// (Its absence, or a non-public backend, is judged by the
	// complete-record requirement, not here.)
	ba := b.BundleAnchor
	recordOnLog := ba != nil && ba.Backend == "rekor" && r.BundleAnchor.Performed && r.BundleAnchor.Match
	if recordOnLog {
		out.RecordAnchoredAt = utc(ba.IntegratedTime)
		recordSigner, recordErr := entrySignerOf(ba.EntryBody)
		if recordErr != nil {
			return fail("the record's public-log entry has no valid signer: %v", recordErr)
		}
		if recordSigner != runSigner {
			return fail("the record's public-log entry was logged by key %s, not by %s, the key "+
				"that logged the run's entry", truncate(recordSigner, 16), truncate(runSigner, 16))
		}
		if !signerAcceptsAt(key, ba.IntegratedTime) {
			return fail("the record's public-log entry was logged at %s, outside the period in which "+
				"%s is accepted", out.RecordAnchoredAt, key.Name)
		}
		if ba.IntegratedTime < ra.IntegratedTime {
			return fail("the record's public-log entry (%s) predates the run's entry (%s)",
				out.RecordAnchoredAt, out.RunAnchoredAt)
		}
	}

	// WHEN, against the run's own sealed clock.
	clock, hasClock := preAnchorValue(b.PreAnchor, "clock_epoch")
	var clockUnix float64
	if hasClock {
		out.ClockEpoch = clock
		t, parseErr := time.Parse(time.RFC3339Nano, clock)
		if parseErr != nil {
			return fail("the sealed clock_epoch %q is not an RFC 3339 time", safePrefix(clock))
		}
		clockUnix = float64(t.UnixNano()) / 1e9
		gap := int64(float64(ra.IntegratedTime) - clockUnix)
		out.GapSeconds = &gap
	}
	if raw, sealed := preAnchorValue(b.PreAnchor, artifacts.AnchoringWindowRow); sealed {
		window, windowErr := parseAnchoringWindow(raw)
		if windowErr != nil {
			return fail("%s is %q: %v", artifacts.AnchoringWindowRow, safePrefix(raw), windowErr)
		}
		out.WindowSealed, out.WindowSeconds = true, window
		if !hasClock {
			return fail("the table seals an anchoring window but no clock_epoch")
		}
		within := func(it int64) bool {
			d := float64(it) - clockUnix
			return d >= -anchoringClockSkew.Seconds() && d <= float64(window)
		}
		if !within(ra.IntegratedTime) {
			return fail("the run's public-log entry was logged at %s, outside the sealed %d-second "+
				"window after the run's clock (%s): the entry was made later than the record claims",
				out.RunAnchoredAt, window, clock)
		}
		if recordOnLog && !within(ba.IntegratedTime) {
			return fail("the record's public-log entry was logged at %s, outside the sealed %d-second "+
				"window after the run's clock (%s): the entry was made later than the record claims",
				out.RecordAnchoredAt, window, clock)
		}
	}
	out.Match = true
	return out
}

func printEntryAuth(c EntryAuthCheck) {
	if !c.Performed {
		return
	}
	if !c.Match {
		fmt.Printf("  Logged by:        ✗ FAILED · %s\n", c.Reason)
		return
	}
	fmt.Printf("  Logged by:        %s (%s)\n", c.SignerName, truncate(c.SignerFingerprint, 16))
	at := c.RunAnchoredAt
	if c.RecordAnchoredAt != "" && c.RecordAnchoredAt != c.RunAnchoredAt {
		at += ", record entry " + c.RecordAnchoredAt
	}
	switch {
	case c.GapSeconds == nil:
		fmt.Printf("  Logged at:        %s (time authenticated by the log)\n", at)
	default:
		fmt.Printf("  Logged at:        %s, %ds after the run's sealed clock\n", at, *c.GapSeconds)
	}
	switch {
	case c.WindowSealed:
		fmt.Printf("  Anchoring window: sealed at %ds and met; a later re-log would fail\n", c.WindowSeconds)
	case c.GapSeconds != nil:
		fmt.Println("  Anchoring window: not sealed in this record; a later re-log by the key")
		fmt.Println("                    holder would show only as a larger gap")
	}
}
