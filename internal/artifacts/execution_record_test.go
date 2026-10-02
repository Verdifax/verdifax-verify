package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func h(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func knownRecord() ExecutionRecord {
	ids := make([]string, 6)
	for i := range ids {
		ids[i] = h("kernel-" + string(rune('1'+i)))
	}
	return ExecutionRecord{
		Kind:                    ExecutionRecordKind,
		Formula:                 AerFormulaV1,
		InputHash:               h("input"),
		TransportHash:           h("transport"),
		ExecutionControlHash:    h("control"),
		ProgramHash:             h("program"),
		KernelOutputIDs:         ids,
		HardwareAttestationHash: h("hardware"),
	}
}

// The expected values were computed outside Go, in Python's hashlib,
// directly from the patent specification's formulas (sections 7 and 8),
// so this test pins the code to the published text rather than to
// itself.
func TestComputeAerV1MatchesSpecificationFormula(t *testing.T) {
	r := knownRecord()
	aer, proof, err := RecomputeExecutionRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := "bf96ea2c182a728ee58b6eb35679d568c696dad4a129e9ca1ad51fbf6b5c08dd"; aer != want {
		t.Errorf("aer = %s, want %s", aer, want)
	}
	if want := "6992037d4dc8f4f11e294df2885333ff56c7ef26b8e80f136b764a2255979228"; proof != want {
		t.Errorf("proof = %s, want %s", proof, want)
	}
}

func TestNoHardwareAttestationHashIsPublishedConstant(t *testing.T) {
	if want := "24bb55af849ee40add8ef25953f68099983f032cd5678ed5fee411dc0ab2eae5"; NoHardwareAttestationHash != want {
		t.Errorf("NoHardwareAttestationHash = %s, want %s", NoHardwareAttestationHash, want)
	}
}

func TestComputeAerV1ChangesWhenAnyFieldChanges(t *testing.T) {
	base, _, err := RecomputeExecutionRecord(knownRecord())
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*ExecutionRecord){
		"input":     func(r *ExecutionRecord) { r.InputHash = h("other") },
		"transport": func(r *ExecutionRecord) { r.TransportHash = h("other") },
		"control":   func(r *ExecutionRecord) { r.ExecutionControlHash = h("other") },
		"program":   func(r *ExecutionRecord) { r.ProgramHash = h("other") },
		"kernel":    func(r *ExecutionRecord) { r.KernelOutputIDs[5] = h("other") },
		"hardware":  func(r *ExecutionRecord) { r.HardwareAttestationHash = h("other") },
		"swap kernels": func(r *ExecutionRecord) {
			r.KernelOutputIDs[0], r.KernelOutputIDs[1] = r.KernelOutputIDs[1], r.KernelOutputIDs[0]
		},
	}
	for name, mutate := range mutations {
		r := knownRecord()
		mutate(&r)
		got, _, err := RecomputeExecutionRecord(r)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == base {
			t.Errorf("%s: record hash did not change", name)
		}
	}
}

func TestComputeAerV1RejectsMalformedFields(t *testing.T) {
	cases := map[string]func(*ExecutionRecord){
		"uppercase":     func(r *ExecutionRecord) { r.InputHash = strings.ToUpper(r.InputHash) },
		"short":         func(r *ExecutionRecord) { r.TransportHash = r.TransportHash[:63] },
		"empty":         func(r *ExecutionRecord) { r.ProgramHash = "" },
		"non hex":       func(r *ExecutionRecord) { r.ExecutionControlHash = strings.Repeat("g", 64) },
		"no kernels":    func(r *ExecutionRecord) { r.KernelOutputIDs = nil },
		"bad kernel":    func(r *ExecutionRecord) { r.KernelOutputIDs[2] = "x" },
		"bad hardware":  func(r *ExecutionRecord) { r.HardwareAttestationHash = "" },
		"wrong formula": func(r *ExecutionRecord) { r.Formula = "aer.v2" },
		"wrong kind":    func(r *ExecutionRecord) { r.Kind = "verdifax.other.v1" },
	}
	for name, mutate := range cases {
		r := knownRecord()
		mutate(&r)
		if _, _, err := RecomputeExecutionRecord(r); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestComputeProofV1RejectsMalformedInputs(t *testing.T) {
	if _, err := ComputeProofV1("", h("hardware")); err == nil {
		t.Error("empty aer: expected an error")
	}
	if _, err := ComputeProofV1(h("aer"), "nope"); err == nil {
		t.Error("bad hardware: expected an error")
	}
}
