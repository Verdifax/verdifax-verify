package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// A job is a map of sealed steps. Each step names the records it directly
// follows, so a missing, swapped or duplicated step is visible and work can
// split into branches and join again. The recipe is byte-identical in the
// producing orchestrator and the public verifier.

const (
	// JobFormat tags the job fields wherever they are hashed or signed.
	JobFormat = "verdifax.job.v1"
	// MaxJobPrevious bounds how many records one step can follow.
	MaxJobPrevious = 64
	// MaxJobExternal bounds links to records from another account.
	MaxJobExternal = 16
)

var (
	jobNamePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	jobHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// JobLink places one record in a job. A record hash is the manifest hash of a
// completed run, or the receipt hash of a refused or halted run.
type JobLink struct {
	JobID                string   `json:"job_id"`
	StepID               string   `json:"step_id"`
	PreviousRecordHashes []string `json:"previous_record_hashes,omitempty"`
	ExternalPrevious     []string `json:"external_previous,omitempty"`
	Final                bool     `json:"final,omitempty"`
}

func validateHashList(name string, hashes []string, limit int) error {
	if len(hashes) > limit {
		return fmt.Errorf("job: %s holds %d hashes, the limit is %d", name, len(hashes), limit)
	}
	for i, hash := range hashes {
		if !jobHashPattern.MatchString(hash) {
			return fmt.Errorf("job: %s[%d] is not a 64 character lowercase hex hash", name, i)
		}
		if i > 0 && hashes[i-1] >= hash {
			return fmt.Errorf("job: %s must be sorted with no repeats", name)
		}
	}
	return nil
}

// Validate checks the shape of a job block. Lists must be sorted, so one job
// block has exactly one signed and hashed form.
func (j *JobLink) Validate() error {
	if j == nil {
		return errors.New("job: empty")
	}
	if !jobNamePattern.MatchString(j.JobID) {
		return errors.New("job: job_id must be 1 to 128 letters, digits, dots, dashes, underscores or colons")
	}
	if !jobNamePattern.MatchString(j.StepID) {
		return errors.New("job: step_id must be 1 to 128 letters, digits, dots, dashes, underscores or colons")
	}
	if err := validateHashList("previous_record_hashes", j.PreviousRecordHashes, MaxJobPrevious); err != nil {
		return err
	}
	return validateHashList("external_previous", j.ExternalPrevious, MaxJobExternal)
}

// SortJobHashes returns a sorted copy, for a client building a job block.
func SortJobHashes(hashes []string) []string {
	sorted := append([]string(nil), hashes...)
	sort.Strings(sorted)
	return sorted
}

// fields is the job block's fixed form. A nil job has all fields empty, and
// the empty job_id cannot occur in a real one.
func (j *JobLink) fields() []string {
	if j == nil {
		return []string{JobFormat, "", "", "", "", "false"}
	}
	final := "false"
	if j.Final {
		final = "true"
	}
	return []string{JobFormat, j.JobID, j.StepID, strings.Join(j.PreviousRecordHashes, ","),
		strings.Join(j.ExternalPrevious, ","), final}
}

// SealedRequestFields are the request values a signature names directly, so
// the verifier can compare them with the record with nothing else in hand.
type SealedRequestFields struct {
	PayloadHash        string `json:"payload_hash"`
	ProgramID          string `json:"program_id"`
	RouteID            string `json:"route_id"`
	RegistryRecordHash string `json:"registry_record_hash"`
	AiOutputHash       string `json:"ai_output_hash,omitempty"`
}

// RequestSignatureVersion2 marks a signature over the exact signed bytes.
const RequestSignatureVersion2 = "2"

// RequestSignaturePreimageV2 is what a version 2 request signature signs.
// bodyHash is the SHA-256 of the exact signed_request bytes, which covers the
// whole request. The other values repeat fields the record can show.
func RequestSignaturePreimageV2(bodyHash string, f SealedRequestFields, job *JobLink, signedAt, nonce string) []byte {
	parts := []string{"verdifax.request.v2", bodyHash, f.PayloadHash, f.ProgramID, f.RouteID,
		f.RegistryRecordHash, f.AiOutputHash}
	parts = append(parts, job.fields()...)
	parts = append(parts, signedAt, nonce)
	return []byte(strings.Join(parts, "\x00"))
}

// RequestKeyChangePreimage is what the current key signs to replace or clear
// itself. newKey is empty when clearing.
func RequestKeyChangePreimage(newKey, signedAt, nonce string) []byte {
	return []byte(strings.Join([]string{"verdifax.request-key-change.v1", newKey, signedAt, nonce}, "\x00"))
}

// ReceiptContext is what a refused or halted run seals beside its receipt. A
// receipt's own fields are fixed by its kind, so the job and the signature
// live here and bind to the receipt through its public-log entry.
type ReceiptContext struct {
	Request          SealedRequestFields `json:"request"`
	RequestSignature *RequestSignature   `json:"request_signature,omitempty"`
	Job              *JobLink            `json:"job,omitempty"`
}

// Hash digests the context for the receipt leaf.
func (c ReceiptContext) Hash() string {
	parts := []string{"verdifax.receipt-context.v1", c.Request.PayloadHash, c.Request.ProgramID, c.Request.RouteID,
		c.Request.RegistryRecordHash, c.Request.AiOutputHash}
	if s := c.RequestSignature; s != nil {
		parts = append(parts, "request_signature")
		parts = append(parts, s.fields()...)
	}
	if c.Job != nil {
		parts = append(parts, c.Job.fields()...)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

const (
	// ReceiptAnchorKindV3 is receipt_anchor.kind for a receipt with a context.
	ReceiptAnchorKindV3 = "verdifax.receipt_anchor.v3"
	// ReceiptLeafDomainV3 is the domain tag of that leaf.
	ReceiptLeafDomainV3 = "verdifax.ledger.receipt.v3"
)

// ReceiptLeafPreimageV3 binds the v2 values and the context hash.
func ReceiptLeafPreimageV3(kind, envelopeID, receiptHash string, runID int64, contextHash string) string {
	return strings.Join([]string{ReceiptLeafDomainV3, kind, envelopeID, receiptHash, fmt.Sprint(runID), contextHash}, ".")
}

// ComputeReceiptLeafHashV3 returns hex(sha256(ReceiptLeafPreimageV3(...))).
func ComputeReceiptLeafHashV3(kind, envelopeID, receiptHash string, runID int64, contextHash string) string {
	sum := sha256.Sum256([]byte(ReceiptLeafPreimageV3(kind, envelopeID, receiptHash, runID, contextHash)))
	return hex.EncodeToString(sum[:])
}

// ValidateReceiptLeafFieldsV3 adds the context hash to the v2 checks.
func ValidateReceiptLeafFieldsV3(kind, envelopeID, receiptHash string, runID int64, contextHash string) error {
	if err := ValidateReceiptLeafFieldsV2(kind, envelopeID, receiptHash, runID); err != nil {
		return err
	}
	if !jobHashPattern.MatchString(contextHash) {
		return errors.New("receipt leaf: context hash must be 64 lowercase hex characters")
	}
	return nil
}
