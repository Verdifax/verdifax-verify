package artifacts

// The attestation execution record (AER) and its proof, computed with
// the formulas of Verdifax's allowed US patent application
// (specification sections 7 and 8):
//
//	aer_hash   = SHA256("aer.v1." || input_hash || transport_hash ||
//	                    execution_control_hash || program_hash ||
//	                    kernel_1_id || ... || kernel_n_id ||
//	                    hardware_attestation_hash)
//	proof_hash = SHA256("proof.v1." || aer_hash || hardware_attestation_hash)
//
// "||" is plain concatenation of the fields' 64-character lowercase hex
// encodings. Every field is required to be exactly that shape, which is
// what gives each one a fixed byte position: no content in one field
// can shift into another, so the preimage needs no separators.
//
// This file is kept byte-identical in verdifax-orchestrator and the
// public verdifax-verify. The orchestrator builds records with it and
// the verifier recomputes them with it; a change here that is not made
// in both places breaks verification of every record sealed after it.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	// AerFormulaV1 names the record formula above. A record carrying any
	// other formula name is not one this code can recompute.
	AerFormulaV1 = "aer.v1"

	// ExecutionRecordKind is the audit-bundle section kind.
	ExecutionRecordKind = "verdifax.execution_record.v1"

	aerV1Prefix   = "aer.v1."
	proofV1Prefix = "proof.v1."
)

// NoHardwareAttestationHash fills the hardware slot of a record built
// when no hardware measurement existed before the record was computed.
// It is a published constant, SHA256("hw.none.v1"), so a verifier can
// tell from the record alone that no hardware measurement is bound.
var NoHardwareAttestationHash = func() string {
	sum := sha256.Sum256([]byte("hw.none.v1"))
	return hex.EncodeToString(sum[:])
}()

// ExecutionRecord is the audit-bundle section disclosing every preimage
// field of the record and its proof, so anyone can recompute both
// offline. Absent from bundles sealed before the section shipped.
type ExecutionRecord struct {
	Kind                    string   `json:"kind"`
	Formula                 string   `json:"formula"`
	InputHash               string   `json:"input_hash"`
	TransportHash           string   `json:"transport_hash"`
	ExecutionControlHash    string   `json:"execution_control_hash"`
	ProgramHash             string   `json:"program_hash"`
	KernelOutputIDs         []string `json:"kernel_output_ids"`
	HardwareAttestationHash string   `json:"hardware_attestation_hash"`
	HardwareAttested        bool     `json:"hardware_attested"`
	AerHash                 string   `json:"aer_hash"`
	ProofHash               string   `json:"proof_hash"`
}

// ComputeAerV1 returns the aer.v1 record hash, or an error naming the
// first field that is not 64 lowercase hex characters.
func ComputeAerV1(inputHash, transportHash, executionControlHash, programHash string, kernelOutputIDs []string, hardwareAttestationHash string) (string, error) {
	if len(kernelOutputIDs) == 0 {
		return "", fmt.Errorf("aer.v1: at least one kernel output id is required")
	}
	fields := []struct{ name, value string }{
		{"input_hash", inputHash},
		{"transport_hash", transportHash},
		{"execution_control_hash", executionControlHash},
		{"program_hash", programHash},
	}
	for i, id := range kernelOutputIDs {
		fields = append(fields, struct{ name, value string }{fmt.Sprintf("kernel_output_ids[%d]", i), id})
	}
	fields = append(fields, struct{ name, value string }{"hardware_attestation_hash", hardwareAttestationHash})

	h := sha256.New()
	h.Write([]byte(aerV1Prefix))
	for _, f := range fields {
		if !isHex64(f.value) {
			return "", fmt.Errorf("aer.v1: %s must be 64 lowercase hex characters", f.name)
		}
		h.Write([]byte(f.value))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeProofV1 returns the proof.v1 hash binding a record to its
// hardware attestation hash.
func ComputeProofV1(aerHash, hardwareAttestationHash string) (string, error) {
	if !isHex64(aerHash) {
		return "", fmt.Errorf("proof.v1: aer_hash must be 64 lowercase hex characters")
	}
	if !isHex64(hardwareAttestationHash) {
		return "", fmt.Errorf("proof.v1: hardware_attestation_hash must be 64 lowercase hex characters")
	}
	sum := sha256.Sum256([]byte(proofV1Prefix + aerHash + hardwareAttestationHash))
	return hex.EncodeToString(sum[:]), nil
}

// RecomputeExecutionRecord recomputes the record and proof hashes from
// the section's disclosed fields. It returns an error when the section
// names a formula this code does not implement or a field is malformed.
func RecomputeExecutionRecord(r ExecutionRecord) (aerHash, proofHash string, err error) {
	if r.Kind != ExecutionRecordKind {
		return "", "", fmt.Errorf("execution record: unknown kind %q", r.Kind)
	}
	if r.Formula != AerFormulaV1 {
		return "", "", fmt.Errorf("execution record: unknown formula %q", r.Formula)
	}
	aerHash, err = ComputeAerV1(r.InputHash, r.TransportHash, r.ExecutionControlHash,
		r.ProgramHash, r.KernelOutputIDs, r.HardwareAttestationHash)
	if err != nil {
		return "", "", err
	}
	proofHash, err = ComputeProofV1(aerHash, r.HardwareAttestationHash)
	if err != nil {
		return "", "", err
	}
	return aerHash, proofHash, nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
