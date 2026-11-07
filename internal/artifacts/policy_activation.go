package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// Policy activations. Every change of the policy in force is one record that
// names the policy, links to the change before it, may be signed by the
// customer's request key, and is anchored on the public log. Each links to the
// last, so a removed change breaks the chain: loosening a policy, doing a run
// and restoring it leaves two records anyone can read.
const (
	// PolicyActivationFormat is the format field of an activation record.
	PolicyActivationFormat = "verdifax.policy.activation.v1"
	// PolicyActivationKind is the leaf kind of its public-log entry.
	PolicyActivationKind = "policy_activation"
	// PolicyActivationSignatureForm opens what the request key signs.
	PolicyActivationSignatureForm = "verdifax.policy-activation.v1"
	// NoPreviousActivation is the previous hash of the first record in a chain.
	NoPreviousActivation = "0000000000000000000000000000000000000000000000000000000000000000"
)

// PolicyActivationSignature is the request key's approval of a change.
type PolicyActivationSignature struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	SignedAt  string `json:"signed_at"`
	Nonce     string `json:"nonce"`
}

// PolicyActivation is one change of the policy in force under one API key.
type PolicyActivation struct {
	Format                 string                     `json:"format"`
	ChainID                string                     `json:"chain_id"`
	Sequence               int64                      `json:"sequence"`
	PreviousActivationHash string                     `json:"previous_activation_hash"`
	PolicyID               string                     `json:"policy_id"`
	PolicyVersion          string                     `json:"policy_version"`
	PolicyHash             string                     `json:"policy_hash"`
	DocumentHash           string                     `json:"document_hash"`
	ActivatedAt            string                     `json:"activated_at"`
	Signature              *PolicyActivationSignature `json:"signature,omitempty"`
	ActivationHash         string                     `json:"activation_hash"`
	Anchor                 *ReceiptAnchor             `json:"anchor,omitempty"`
}

// PolicyActivationPreimage is what the request key signs: the chain, the exact
// policy text and the change it follows, so a signature cannot be replayed on
// another key, another policy or another point in the chain.
func PolicyActivationPreimage(chainID, documentHash, previousHash, signedAt, nonce string) []byte {
	return []byte(strings.Join([]string{PolicyActivationSignatureForm, chainID, documentHash, previousHash, signedAt, nonce}, "\x00"))
}

// ComputeHash returns the record's hash. Every field but the hash itself and
// the anchor goes in, each length-prefixed so that free text cannot run into
// the next field. The anchor is made from this hash, so it cannot be inside it.
func (a *PolicyActivation) ComputeHash() string {
	fields := []string{a.Format, a.ChainID, strconv.FormatInt(a.Sequence, 10), a.PreviousActivationHash,
		a.PolicyID, a.PolicyVersion, a.PolicyHash, a.DocumentHash, a.ActivatedAt}
	if s := a.Signature; s != nil {
		fields = append(fields, s.PublicKey, s.Signature, s.SignedAt, s.Nonce)
	}
	digest := sha256.New()
	for _, f := range fields {
		digest.Write([]byte(strconv.Itoa(len(f)) + ":" + f))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// Validate checks the record's shape, the values its leaf is built from.
func (a *PolicyActivation) Validate() error {
	switch {
	case a.Format != PolicyActivationFormat:
		return errors.New("policy activation: unknown format")
	case a.ChainID == "" || strings.Contains(a.ChainID, "."):
		return errors.New("policy activation: chain_id is empty or contains a dot")
	case a.Sequence <= 0:
		return errors.New("policy activation: sequence must be positive")
	case !jobHashPattern.MatchString(a.PreviousActivationHash):
		return errors.New("policy activation: previous hash must be 64 lowercase hex characters")
	case !jobHashPattern.MatchString(a.PolicyHash) || !jobHashPattern.MatchString(a.DocumentHash):
		return errors.New("policy activation: policy and document hashes must be 64 lowercase hex characters")
	case !jobHashPattern.MatchString(a.ActivationHash):
		return errors.New("policy activation: activation hash must be 64 lowercase hex characters")
	}
	return nil
}

// LeafHash is the public-log leaf that binds this record: its hash, its place
// in the chain and the change before it.
func (a *PolicyActivation) LeafHash() string {
	return ComputeReceiptLeafHashV3(PolicyActivationKind, a.ChainID, a.ActivationHash, a.Sequence, a.PreviousActivationHash)
}
