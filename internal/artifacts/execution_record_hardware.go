package artifacts

// Kept byte-identical in verdifax-orchestrator and the public
// verdifax-verify, like execution_record.go beside it.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// ExecutionRecordHardwareHash returns SHA-256 over the bundle's raw
// SEV-SNP quote: the value a hardware-attested record's hardware slot
// must equal. The quote's own signature and report_data binding are
// checked separately, against the pinned AMD root.
func ExecutionRecordHardwareHash(b *AuditBundle) (string, error) {
	h := b.HardwareAttestation
	if h.AttestationMode != "sev_snp" || h.QuoteB64 == "" {
		return "", errors.New("record claims hardware but the bundle carries no sev_snp quote")
	}
	raw, err := base64.StdEncoding.DecodeString(h.QuoteB64)
	if err != nil {
		return "", fmt.Errorf("quote_b64 undecodable: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
