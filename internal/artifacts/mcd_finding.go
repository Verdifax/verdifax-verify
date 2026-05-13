package artifacts

// MCDFinding is the sealed artifact recording a Malicious Code Defense
// detection event. Produced by the MCD inspector inside PEPG when a
// signature, static-pattern, or provenance check fires.
//
// MCDFindings are referenced by hash from the corresponding DenyReceipt
// (via DenyReceipt.MCDFindingHash). This separation keeps the DenyReceipt
// schema stable across MCD library versions: the receipt only references
// the finding by hash, while the finding itself can grow richer over time
// without invalidating any existing deny_receipt_hash values.
//
// See BUILDING DOCS/MCD_SIGNATURE_LIBRARY_V0.yaml for the v0 signature set.
type MCDFinding struct {
	// Category is one of: prompt_injection, dangerous_api,
	// supply_chain, filesystem_escape.
	Category string `json:"category"`

	// EnvelopeID identifies the envelope whose payload triggered the finding.
	EnvelopeID string `json:"envelope_id"`

	// FindingClock is the HLC-derived RFC 3339 UTC timestamp at which the
	// finding was sealed.
	FindingClock string `json:"finding_clock"`

	// LibraryHash is the SHA-256 hex of the MCD signature library that
	// detected this finding. Lets audits prove which library version
	// made which detection.
	LibraryHash string `json:"library_hash"`

	// MatchedSignatureID is the stable ID from the signature library
	// (e.g., "mcd-llm-001" for the direct-prompt-injection signature).
	MatchedSignatureID string `json:"matched_signature_id"`

	// PayloadFingerprint is the SHA-256 of the offending payload subset.
	// Captures WHAT triggered the finding without storing the raw payload
	// (which may contain sensitive content).
	PayloadFingerprint string `json:"payload_fingerprint"`

	// Severity mirrors the signature library entry: critical | high | medium | low.
	Severity string `json:"severity"`

	// Version is always "vfa.mcd_finding.v1" for this artifact version.
	Version string `json:"version"`

	// Hash is the canonical SHA-256 hex of the eight preimage fields above.
	// Filled by BuildMCDFindingHash. Not part of the preimage itself.
	Hash string `json:"hash,omitempty"`
}

// BuildMCDFindingHash computes the canonical hash of the finding's
// preimage and populates Hash. Mutates the finding in place; returns
// the resulting Hash.
//
// Stub: returns through CanonicalHash() over the preimage subset.
func BuildMCDFindingHash(finding *MCDFinding) (string, error) {
	preimage := struct {
		Category           string `json:"category"`
		EnvelopeID         string `json:"envelope_id"`
		FindingClock       string `json:"finding_clock"`
		LibraryHash        string `json:"library_hash"`
		MatchedSignatureID string `json:"matched_signature_id"`
		PayloadFingerprint string `json:"payload_fingerprint"`
		Severity           string `json:"severity"`
		Version            string `json:"version"`
	}{
		Category:           finding.Category,
		EnvelopeID:         finding.EnvelopeID,
		FindingClock:       finding.FindingClock,
		LibraryHash:        finding.LibraryHash,
		MatchedSignatureID: finding.MatchedSignatureID,
		PayloadFingerprint: finding.PayloadFingerprint,
		Severity:           finding.Severity,
		Version:            finding.Version,
	}
	hash, err := CanonicalHash(preimage)
	if err != nil {
		return "", err
	}
	finding.Hash = hash
	return hash, nil
}

// VerifyMCDFindingHash recomputes the finding's canonical hash and
// compares to the stored Hash field. Returns nil on match.
func VerifyMCDFindingHash(finding *MCDFinding) error {
	expected := finding.Hash
	finding.Hash = ""
	defer func() { finding.Hash = expected }()
	actual, err := BuildMCDFindingHash(finding)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrMCDFindingHashMismatch
	}
	return nil
}
