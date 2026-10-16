// Package rekorverify implements offline verification of Sigstore Rekor
// inclusion proofs against a pinned Rekor public key.
//
// This is the cryptographic core of Day 4 of the Verdifax Rekor
// integration: given a leaf hash, an inclusion proof (sibling path +
// claimed root + tree size), and a signed checkpoint over the tree
// head, this package answers two independent questions:
//
//  1. Is the leaf actually committed at the claimed log_index in the
//     claimed Merkle root? (Merkle inclusion proof verification per
//     RFC 6962 §2.1.1.)
//
//  2. Did Rekor itself sign the (root_hash, tree_size) tuple? (Signed
//     checkpoint verification per c2sp.org/tlog-checkpoint, ECDSA
//     P-256 over the c2sp note format.)
//
// Both checks must pass for an anchor to be considered verified. The
// verifier never contacts Rekor, the inclusion proof + signed
// checkpoint travel with the audit bundle, and the Rekor public key is
// embedded at build time. This is the operationalization of Verdifax's
// "no network access required to verify a sealed run" claim, extended
// to the public transparency log.
//
// USAGE
//
//	import "github.com/Verdifax/verdifax-verify/internal/rekorverify"
//
//	err := rekorverify.VerifyAnchor(rekorverify.AnchorInput{
//	    LeafHashHex:    "abc123...",
//	    LogIndex:       42,
//	    TreeSize:       1000,
//	    RootHashHex:    "def456...",
//	    InclusionPath:  []string{"hash1", "hash2", ...},
//	    Checkpoint:     "rekor.sigstore.dev\n1000\ndef456...\n\n,  signature\n",
//	    LogID:          "...",
//	})
//	if err != nil {
//	    // verification failed; the err describes which check failed
//	}
//
// # SECURITY MODEL
//
// The verification is sound if and only if:
//
//   - The embedded Rekor public key in rekor_pubkey.go matches the
//     real Rekor instance's signing key. Operators must update this
//     key when Rekor rotates (Sigstore rotates its keys infrequently
//     and announces in advance via the TUF root).
//
//   - The hash used by Rekor is SHA-256, which is the published
//     Rekor v1 algorithm.
//
//   - The c2sp tlog-checkpoint format is followed strictly. This
//     package implements the format as documented at:
//     https://c2sp.org/tlog-checkpoint
package rekorverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

// AnchorInput carries every field needed to verify a single Rekor
// transparency-log anchor. All hex strings are lowercase. All hash
// values are 32-byte SHA-256 digests in hex form.
type AnchorInput struct {
	// LeafHashHex is the hex SHA-256 of the canonical leaf bytes that
	// were submitted to Rekor (the data.hash.value of the hashedrekord
	// entry). NOT the RFC 6962 Merkle tree leaf hash, which is
	// computed inside VerifyAnchor from EntryBody.
	LeafHashHex string

	// EntryBody is the base64-encoded canonical JSON of the Rekor
	// hashedrekord entry. The RFC 6962 Merkle leaf hash used to walk
	// the inclusion proof is SHA-256(0x00 || base64decode(EntryBody)),
	// per c2sp.org/static-ct §3.1 and RFC 6962 §2.1.
	//
	// REQUIRED since v0.10.0, and the body must name LeafHashHex. The
	// Merkle proof covers the BODY, not LeafHashHex, so the body is
	// the only thing that ties the claimed leaf hash to the log.
	// Through v0.9.0 nothing compared the two: a bundle could keep a
	// genuine body, proof and checkpoint while claiming any leaf hash
	// it liked, and every check that recomputes the leaf from the
	// bundle's own contents then compared against a value the log
	// never saw. An empty body now returns ErrNoEntryBody (the caller
	// reports the anchor as not verifiable, never as anchored), and a
	// body that is not a sha256 hashedrekord over LeafHashHex fails.
	EntryBody string

	// LogIndex is the 0-based position of the leaf in the Rekor tree.
	LogIndex int64

	// TreeSize is the total number of leaves in the Rekor tree at the
	// time this proof was issued. Required for the RFC 6962 inclusion
	// proof algorithm.
	TreeSize int64

	// RootHashHex is the claimed Merkle root for the tree at TreeSize.
	// The verifier recomputes the root from LeafHashHex + InclusionPath
	// and compares against this value.
	RootHashHex string

	// InclusionPath is the ordered list of hex sibling hashes used to
	// recompute the Merkle root. Order matches Rekor's response. The
	// path length is roughly log2(TreeSize) hashes.
	InclusionPath []string

	// Checkpoint is the full signed checkpoint (c2sp.org/tlog-checkpoint
	// format) produced by Rekor for (RootHashHex, TreeSize). The
	// verifier checks the ECDSA signature in this checkpoint against
	// the embedded Rekor public key.
	Checkpoint string

	// LogID is the Rekor log identifier, the hex SHA-256 of the public
	// key. Used as a sanity check: the verifier confirms the embedded
	// public key's hash matches this LogID.
	LogID string

	// LogEntryID is the entry's GLOBAL index across Rekor shards (the
	// number search.sigstore.dev shows), IntegratedTime the Unix time
	// Rekor recorded the entry, and SignedEntryTimestamp Rekor's
	// signature over (body, integratedTime, logID, global index). The
	// SET is what authenticates the time and the global index: without
	// it both are display values anyone can edit (round seven of the
	// external review). It is required.
	LogEntryID           string
	IntegratedTime       int64
	SignedEntryTimestamp string
}

// ErrSignedEntryTimestampMismatch reports a signed entry timestamp
// that does not verify over the anchor's body, time, log id and global
// entry number.
var ErrSignedEntryTimestampMismatch = errors.New("rekorverify: signed entry timestamp does not verify " +
	"under the log key: the anchoring time, entry number or entry body is not what the log recorded")

// ErrNoSignedEntryTimestamp reports an anchor without Rekor's signed
// entry timestamp, so its anchoring time and global index are not
// authenticated.
var ErrNoSignedEntryTimestamp = errors.New("rekorverify: anchor carries no signed_entry_timestamp, " +
	"so its anchoring time and entry number are not authenticated")

// VerifyAnchor performs full offline verification of a Rekor anchor:
// the inclusion proof shape, the recomputed Merkle root, and the
// signed checkpoint over that root. Returns nil iff all checks pass.
//
// Errors are returned with descriptive messages so audit reports can
// surface exactly which check failed (most common diagnostic
// scenarios are stale public key, tampered proof, or wrong log_id).
func VerifyAnchor(in AnchorInput) error {
	// Library error model: every failure is returned to the caller,
	// which reports it verbatim; this package has no logger.
	rekorPubKey, keyErr := loadRekorPublicKey()
	if keyErr != nil {
		// Input problems still report first, so a malformed anchor
		// reads as malformed rather than as a key problem.
		if verr := validateInput(in); verr != nil {
			return fmt.Errorf("rekorverify: invalid input: %w", verr)
		}
		return fmt.Errorf("rekorverify: load embedded rekor pubkey: %w", keyErr)
	}
	return VerifyAnchorWithKey(in, rekorPubKey)
}

// ErrNoEntryBody reports an anchor that carries no hashedrekord entry
// body. Without the body nothing binds the claimed leaf hash to the
// Merkle leaf the proof walks, so the anchor cannot be verified
// offline; callers must report it as not anchored, never as verified.
var ErrNoEntryBody = errors.New("rekorverify: anchor carries no entry_body, so the claimed " +
	"leaf hash cannot be bound to the Merkle leaf the inclusion proof covers")

// VerifyAnchorWithKey is VerifyAnchor against an explicit log key.
// Production code calls VerifyAnchor, which always uses the embedded
// Rekor key; this form exists so tests can exercise the complete
// path (body binding, Merkle walk, signed checkpoint, log id) against
// a log they control, without any way to swap the embedded key.
func VerifyAnchorWithKey(in AnchorInput, rekorPubKey *ecdsa.PublicKey) error {
	// 1. Sanity-check the input structure before doing any crypto.
	if err := validateInput(in); err != nil {
		return fmt.Errorf("rekorverify: invalid input: %w", err)
	}
	if rekorPubKey == nil {
		return errors.New("rekorverify: nil log public key")
	}

	// 2. Compute the RFC 6962 Merkle leaf hash. Rekor's tree-leaf hash
	// is SHA-256(0x00 || canonical_body), NOT the data.hash.value the
	// hashedrekord entry references. EntryBody is the canonical-body
	// bytes Rekor returned at submit time, base64-encoded.
	//
	// The body is also what binds LeafHashHex to the log: it must be a
	// sha256 hashedrekord whose data.hash.value IS LeafHashHex. There
	// is no fallback for a missing body. The pre-v0.10.0 fallback used
	// LeafHashHex itself as the Merkle leaf, which no genuine Rekor
	// entry ever satisfies (Rekor's tree leaf is the hash of the body)
	// and which drops RFC 6962's 0x00 leaf domain separation.
	if in.EntryBody == "" {
		return ErrNoEntryBody
	}
	bodyBytes, decodeErr := base64.StdEncoding.DecodeString(in.EntryBody)
	if decodeErr != nil {
		return fmt.Errorf("rekorverify: entry_body base64 decode: %w", decodeErr)
	}
	if err := EntryBodyNamesLeaf(bodyBytes, in.LeafHashHex); err != nil {
		return err
	}
	// RFC 6962 §2.1 leaf hash: SHA-256(0x00 || body).
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(bodyBytes)
	leafHash := h.Sum(nil)

	claimedRoot, err := hex.DecodeString(in.RootHashHex)
	if err != nil || len(claimedRoot) != sha256.Size {
		return fmt.Errorf("rekorverify: root hash must be 64-char hex SHA-256")
	}

	siblings := make([][]byte, 0, len(in.InclusionPath))
	for i, h := range in.InclusionPath {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != sha256.Size {
			return fmt.Errorf("rekorverify: inclusion path[%d] is not a 64-char hex SHA-256", i)
		}
		siblings = append(siblings, raw)
	}

	// 3. Recompute the Merkle root from leaf + sibling path per RFC 6962.
	computedRoot, err := recomputeRootRFC6962(leafHash, in.LogIndex, in.TreeSize, siblings)
	if err != nil {
		return fmt.Errorf("rekorverify: merkle root recompute: %w", err)
	}
	if !bytesEqual(computedRoot, claimedRoot) {
		return fmt.Errorf("rekorverify: merkle root mismatch, recomputed %x, claimed %s",
			computedRoot, in.RootHashHex)
	}

	// 4. Verify the signed checkpoint binds (RootHashHex, TreeSize)
	// under Rekor's public key. This is what stops an attacker who
	// crafted a fake leaf+path+root from convincing a verifier that
	// Rekor agreed with the (root, tree_size), only Rekor can sign.
	if err := verifySignedCheckpoint(in.Checkpoint, in.RootHashHex, in.TreeSize, rekorPubKey); err != nil {
		return fmt.Errorf("rekorverify: signed checkpoint: %w", err)
	}

	// 5. Sanity-check the LogID against the public key. Rekor uses the
	// hex SHA-256 of the DER-encoded public key as the log identifier.
	// A mismatch here means the proof was issued by a different log
	// than the one our embedded key trusts.
	expectedLogID, err := computeRekorLogID(rekorPubKey)
	if err != nil {
		return fmt.Errorf("rekorverify: compute expected log id: %w", err)
	}
	if !strings.EqualFold(in.LogID, expectedLogID) {
		return fmt.Errorf("rekorverify: log_id mismatch, proof claims %s, embedded key produces %s",
			in.LogID, expectedLogID)
	}

	// 6. Verify the signed entry timestamp, which authenticates the
	// anchoring time and the global entry index under the same log key.
	if setErr := verifySignedEntryTimestamp(in, expectedLogID, rekorPubKey); setErr != nil {
		return setErr
	}

	return nil
}

// setPayload is the object Rekor signs to produce a signed entry
// timestamp. Field order is the canonical (sorted) key order Rekor
// signs, and every value is plain ASCII (base64, hex, integers), so
// encoding/json reproduces the canonical bytes exactly.
type setPayload struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
}

// verifySignedEntryTimestamp checks Rekor's ECDSA signature over the
// entry body, integrated time, log id and GLOBAL index. A pass means
// all four are exactly what Rekor recorded; an edit to any of them,
// or a SET lifted from another entry, fails.
func verifySignedEntryTimestamp(in AnchorInput, logIDHex string, rekorPubKey *ecdsa.PublicKey) error {
	if in.SignedEntryTimestamp == "" {
		return ErrNoSignedEntryTimestamp
	}
	globalIndex, parseErr := strconv.ParseInt(strings.TrimSpace(in.LogEntryID), 10, 64)
	if parseErr != nil || globalIndex < 0 {
		return fmt.Errorf("rekorverify: log_entry_id %q is not a global entry index", in.LogEntryID)
	}
	payload, marshalErr := json.Marshal(setPayload{
		Body:           in.EntryBody,
		IntegratedTime: in.IntegratedTime,
		LogID:          strings.ToLower(logIDHex),
		LogIndex:       globalIndex,
	})
	if marshalErr != nil {
		return fmt.Errorf("rekorverify: encode signed entry timestamp payload: %w", marshalErr)
	}
	sig, decodeErr := base64.StdEncoding.DecodeString(in.SignedEntryTimestamp)
	if decodeErr != nil {
		return fmt.Errorf("rekorverify: signed_entry_timestamp base64 decode: %w", decodeErr)
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(rekorPubKey, digest[:], sig) {
		return ErrSignedEntryTimestampMismatch
	}
	return nil
}

// EntrySigner identifies who submitted a hashedrekord entry. It decodes
// the entry's public key, requires ECDSA P-256 (the only key type the
// Verdifax producer uses), verifies the entry's signature over the
// logged sha256 digest, and returns the hex SHA-256 of the key's DER
// SubjectPublicKeyInfo. Rekor accepts entries from anyone with any
// key; the caller decides which fingerprints it trusts.
func EntrySigner(body []byte) (string, error) {
	// Library error model: every failure is returned to the caller,
	// which reports it verbatim; this package has no logger.
	var e hashedRekordBody
	if unmarshalErr := json.Unmarshal(body, &e); unmarshalErr != nil {
		return "", fmt.Errorf("rekorverify: entry_body is not a JSON Rekor entry: %w", unmarshalErr)
	}
	pemBytes, pemErr := base64.StdEncoding.DecodeString(e.Spec.Signature.PublicKey.Content)
	if pemErr != nil {
		return "", fmt.Errorf("rekorverify: entry public key base64 decode: %w", pemErr)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", errors.New("rekorverify: entry public key is not a PEM PUBLIC KEY")
	}
	parsed, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
	if parseErr != nil {
		return "", fmt.Errorf("rekorverify: entry public key: %w", parseErr)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return "", errors.New("rekorverify: entry public key is not ECDSA P-256")
	}
	digest, hexErr := hex.DecodeString(e.Spec.Data.Hash.Value)
	if hexErr != nil || len(digest) != sha256.Size {
		return "", errors.New("rekorverify: entry hash is not a 64-char hex SHA-256")
	}
	sig, sigErr := base64.StdEncoding.DecodeString(e.Spec.Signature.Content)
	if sigErr != nil {
		return "", fmt.Errorf("rekorverify: entry signature base64 decode: %w", sigErr)
	}
	if !ecdsa.VerifyASN1(pub, digest, sig) {
		return "", errors.New("rekorverify: entry signature does not verify under the entry's own public key")
	}
	fp := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(fp[:]), nil
}

// hashedRekordBody is the subset of a hashedrekord v0.0.1 entry body
// the binding check reads. Typed on purpose: the body is canonical
// JSON produced by Rekor, and nothing here round-trips it.
type hashedRekordBody struct {
	Kind string `json:"kind"`
	Spec struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

// EntryBodyNamesLeaf confirms a decoded Rekor entry body is a sha256
// hashedrekord whose data.hash.value equals leafHashHex (hex compared
// case-insensitively). This is the check that ties the bundle's
// claimed leaf hash to the entry the Merkle proof actually covers.
func EntryBodyNamesLeaf(body []byte, leafHashHex string) error {
	var e hashedRekordBody
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("rekorverify: entry_body is not a JSON Rekor entry: %w", err)
	}
	if e.Kind != "hashedrekord" {
		return fmt.Errorf("rekorverify: entry_body kind is %q, expected hashedrekord", e.Kind)
	}
	if e.Spec.Data.Hash.Algorithm != "sha256" {
		return fmt.Errorf("rekorverify: entry_body hash algorithm is %q, expected sha256",
			e.Spec.Data.Hash.Algorithm)
	}
	if e.Spec.Data.Hash.Value == "" || !strings.EqualFold(e.Spec.Data.Hash.Value, leafHashHex) {
		return fmt.Errorf("rekorverify: entry_body records leaf %s, but the bundle claims leaf %s; "+
			"the logged entry is not this leaf", e.Spec.Data.Hash.Value, leafHashHex)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// RFC 6962 Merkle inclusion proof
// ─────────────────────────────────────────────────────────────────────────────

// recomputeRootRFC6962 implements the RFC 6962 §2.1.1 inclusion proof
// algorithm. Given a leaf hash, its index, the tree size at proof
// time, and the ordered sibling path, returns the Merkle root.
//
// RFC 6962 hash semantics:
//
//	leaf hash:   hash[i]   = SHA256(0x00 || data[i])
//	internal:    hash[a,b] = SHA256(0x01 || hash[a] || hash[b])
//
// The leaf hash is provided ALREADY DOMAIN-PREFIXED by Rekor (the
// "data.hash.value" in a hashedrekord entry IS the leaf hash for
// inclusion-proof purposes, Rekor handles the 0x00 prefix at submit
// time). So this function only applies the 0x01 internal-node prefix
// when combining siblings.
func recomputeRootRFC6962(leafHash []byte, logIndex, treeSize int64, siblings [][]byte) ([]byte, error) {
	if logIndex < 0 || logIndex >= treeSize {
		return nil, fmt.Errorf("log_index %d out of range for tree_size %d", logIndex, treeSize)
	}
	if treeSize == 0 {
		return nil, fmt.Errorf("tree_size must be > 0")
	}

	// Standard RFC 6962 inclusion-proof verification loop.
	// Reference: github.com/transparency-dev/merkle (path verification)
	// and RFC 6962 §2.1.1.
	hash := make([]byte, len(leafHash))
	copy(hash, leafHash)

	fn := logIndex
	sn := treeSize - 1
	pathPos := 0
	for sn > 0 {
		if pathPos >= len(siblings) {
			return nil, fmt.Errorf("inclusion path too short: need at least %d more sibling(s) at sn=%d", 1, sn)
		}
		sibling := siblings[pathPos]
		pathPos++

		if fn%2 == 1 || fn == sn {
			// Right child: combine sibling || hash.
			hash = hashChildren(sibling, hash)
			// Advance fn until we hit a position where fn != sn.
			for fn%2 == 0 && fn != 0 {
				fn /= 2
				sn /= 2
			}
		} else {
			// Left child: combine hash || sibling.
			hash = hashChildren(hash, sibling)
		}

		fn /= 2
		sn /= 2
	}

	if pathPos != len(siblings) {
		return nil, fmt.Errorf("inclusion path too long: %d siblings consumed, %d provided",
			pathPos, len(siblings))
	}

	return hash, nil
}

// hashChildren computes SHA256(0x01 || left || right) per RFC 6962.
func hashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// ─────────────────────────────────────────────────────────────────────────────
// c2sp.org/tlog-checkpoint signature verification
// ─────────────────────────────────────────────────────────────────────────────

// verifySignedCheckpoint parses a c2sp tlog-checkpoint, confirms it
// commits to the expected (rootHashHex, treeSize), and verifies the
// embedded ECDSA P-256 signature against pubKey.
//
// The c2sp format (https://c2sp.org/tlog-checkpoint) is:
//
//	<origin>\n
//	<tree_size>\n
//	<base64 root hash>\n
//	[optional extension lines...]\n
//	\n
//	,  <key_name> <base64-signature>\n
//
// The signature is over everything before the blank separator line.
// Multiple signature lines may follow; we accept the first one whose
// key hint matches Rekor's public-key short identifier.
func verifySignedCheckpoint(checkpoint, expectedRootHashHex string, expectedTreeSize int64, pubKey *ecdsa.PublicKey) error {
	body, signatures, err := splitCheckpoint(checkpoint)
	if err != nil {
		return fmt.Errorf("split: %w", err)
	}
	if err := validateCheckpointBody(body, expectedRootHashHex, expectedTreeSize); err != nil {
		return fmt.Errorf("body: %w", err)
	}

	// Compute the Rekor short key hint, the first 4 bytes of
	// SHA-256(public-key-SubjectPublicKeyInfo-DER), base64-encoded.
	keyHint, err := rekorKeyHint(pubKey)
	if err != nil {
		return fmt.Errorf("compute key hint: %w", err)
	}

	// Walk the signature lines looking for one that matches the
	// embedded Rekor key. Verify it against the body.
	hash := sha256.Sum256([]byte(body))
	for _, sigLine := range signatures {
		sigBytes, err := decodeCheckpointSignatureLine(sigLine, keyHint)
		if err != nil {
			continue // wrong key hint, skip
		}
		if ecdsa.VerifyASN1(pubKey, hash[:], sigBytes) {
			return nil
		}
		return fmt.Errorf("ecdsa signature verify failed for matching key hint")
	}
	return fmt.Errorf("no signature line matches the embedded Rekor public key (key hint %s)",
		base64.StdEncoding.EncodeToString(keyHint))
}

// splitCheckpoint divides a c2sp note into its body (everything before
// the blank separator line) and its signature lines (each starting
// with U+2014 EM DASH).
func splitCheckpoint(checkpoint string) (body string, signatures []string, err error) {
	// Normalize line endings for parsing.
	checkpoint = strings.ReplaceAll(checkpoint, "\r\n", "\n")

	const sep = "\n\n"
	idx := strings.Index(checkpoint, sep)
	if idx == -1 {
		return "", nil, errors.New("missing blank-line separator between body and signatures")
	}
	// The body in c2sp note format INCLUDES the trailing newline before
	// the separator (so body.endsWith("\n")). Signing covers exactly
	// these bytes.
	body = checkpoint[:idx+1]
	tail := checkpoint[idx+2:]

	// Each signature line starts with U+2014 EM DASH then a space, per
	// c2sp.org/signed-note. Use the explicit unicode escape so the
	// em-dash sanitizer we run on user-facing surfaces cannot ever
	// "scrub" this load-bearing character (an earlier pass did exactly
	// that and replaced "— " with ",  ", which broke every Rekor
	// checkpoint verification until corrected).
	const sigLinePrefix = "— "
	for _, line := range strings.Split(strings.TrimRight(tail, "\n"), "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, sigLinePrefix) {
			return "", nil, fmt.Errorf("unexpected signature line: %q", line)
		}
		signatures = append(signatures, line)
	}
	if len(signatures) == 0 {
		return "", nil, errors.New("no signature lines after body")
	}
	return body, signatures, nil
}

// validateCheckpointBody confirms a c2sp body commits to the expected
// (root, tree_size). The body format is:
//
//	<origin>\n
//	<tree_size>\n
//	<base64-std-encoding root>\n
//	[optional extension lines]
func validateCheckpointBody(body, expectedRootHashHex string, expectedTreeSize int64) error {
	lines := strings.Split(body, "\n")
	if len(lines) < 3 {
		return fmt.Errorf("body has fewer than 3 lines (origin/size/root)")
	}
	// lines[0] = origin (we don't pin origin here, the LogID check
	// already binds the proof to a specific Rekor instance via the key)

	gotSize, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil {
		return fmt.Errorf("parse tree_size on line 2: %w", err)
	}
	if gotSize != expectedTreeSize {
		return fmt.Errorf("tree_size mismatch, checkpoint says %d, expected %d", gotSize, expectedTreeSize)
	}

	rootB64 := strings.TrimSpace(lines[2])
	rootBytes, err := base64.StdEncoding.DecodeString(rootB64)
	if err != nil {
		return fmt.Errorf("decode root base64 on line 3: %w", err)
	}
	gotRootHex := hex.EncodeToString(rootBytes)
	if !strings.EqualFold(gotRootHex, expectedRootHashHex) {
		return fmt.Errorf("root hash mismatch, checkpoint says %s, expected %s", gotRootHex, expectedRootHashHex)
	}
	return nil
}

// decodeCheckpointSignatureLine parses one c2sp note signature line.
// Line format: ",  <key_name> <base64-signature-with-key-hint-prefix>\n"
//
// The signature blob is 4 bytes of key-hint prefix followed by the raw
// signature. This function returns the raw signature ONLY when the
// key hint matches keyHint (returns nil error and signature bytes), or
// returns an error when the line doesn't match the expected key.
func decodeCheckpointSignatureLine(line string, keyHint []byte) ([]byte, error) {
	// Strip the U+2014 EM DASH + space prefix. The em-dash literal
	// here is load-bearing for c2sp.org/signed-note parsing and must
	// NOT be replaced by any em-dash sanitizer pass.
	const prefix = "— "
	if !strings.HasPrefix(line, prefix) {
		return nil, errors.New("missing em-dash prefix")
	}
	rest := line[len(prefix):]

	// Split off key name (up to first space) and base64 blob.
	spaceIdx := strings.IndexByte(rest, ' ')
	if spaceIdx == -1 {
		return nil, errors.New("missing space between key name and signature")
	}
	sigBlob := strings.TrimSpace(rest[spaceIdx+1:])
	raw, err := base64.StdEncoding.DecodeString(sigBlob)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	if len(raw) < 4 {
		return nil, errors.New("signature blob too short for key-hint prefix")
	}
	if !bytesEqual(raw[:4], keyHint) {
		return nil, errors.New("key hint mismatch")
	}
	return raw[4:], nil
}

// rekorKeyHint computes the 4-byte short identifier Rekor places in
// front of every checkpoint signature: the first 4 bytes of
// SHA-256(SubjectPublicKeyInfo DER bytes).
func rekorKeyHint(pubKey *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("marshal pkix: %w", err)
	}
	sum := sha256.Sum256(der)
	return sum[:4], nil
}

// computeRekorLogID returns the hex SHA-256 of the SubjectPublicKeyInfo
// DER form of the Rekor public key, the canonical Rekor LogID.
func computeRekorLogID(pubKey *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("marshal pkix: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// EmbeddedLogID returns the Rekor LogID computed from the embedded
// production Rekor public key. Used by the orchestrator's bundle
// builder to populate the bundle's LogID field so the verifier can
// confirm the bundle was anchored under the same log the verifier
// trusts.
func EmbeddedLogID() (string, error) {
	pubKey, err := loadRekorPublicKey()
	if err != nil {
		return "", err
	}
	return computeRekorLogID(pubKey)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public-key loading
// ─────────────────────────────────────────────────────────────────────────────

// loadRekorPublicKey decodes the embedded Rekor production public key
// (see rekor_pubkey.go) into an *ecdsa.PublicKey ready for signature
// verification. Returns an error if the embedded key is empty or
// cannot be parsed, both of which indicate the operator forgot to
// populate rekor_pubkey.go before building.
func loadRekorPublicKey() (*ecdsa.PublicKey, error) {
	if strings.TrimSpace(RekorPublicKeyPEM) == "" {
		return nil, errors.New("RekorPublicKeyPEM is empty, populate cmd/.../rekor_pubkey.go with the current Rekor production key (see comment in that file)")
	}
	block, _ := pem.Decode([]byte(RekorPublicKeyPEM))
	if block == nil {
		return nil, errors.New("RekorPublicKeyPEM does not contain a PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("RekorPublicKeyPEM is not an ECDSA public key (got %T)", parsed)
	}
	return pub, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func validateInput(in AnchorInput) error {
	if in.LeafHashHex == "" {
		return errors.New("LeafHashHex is empty")
	}
	if in.RootHashHex == "" {
		return errors.New("RootHashHex is empty")
	}
	if in.TreeSize <= 0 {
		return fmt.Errorf("TreeSize must be > 0 (got %d)", in.TreeSize)
	}
	if in.LogIndex < 0 {
		return fmt.Errorf("LogIndex must be >= 0 (got %d)", in.LogIndex)
	}
	if in.LogIndex >= in.TreeSize {
		return fmt.Errorf("LogIndex %d >= TreeSize %d", in.LogIndex, in.TreeSize)
	}
	if in.Checkpoint == "" {
		return errors.New("Checkpoint is empty")
	}
	if in.LogID == "" {
		return errors.New("LogID is empty")
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
