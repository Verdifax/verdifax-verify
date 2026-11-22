package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// independentHash recomputes a length-prefixed SHA-256 apart from the
// package's helper, from the recipe the records' documentation states.
func independentHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(strconv.Itoa(len(p)) + ":" + p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func targetPassedVector() *SignOffTargetPassed {
	r := &SignOffTargetPassed{Format: SignOffTargetPassedFormat, ResultKind: TargetResultReceipt, RunID: 11, ResultSequence: 5,
		ResultHash: strings.Repeat("a", 64), Source: TargetSourceRefusals, Within: 300, Compare: TargetCompareFirstApproval,
		Notice: TargetNoticeEvent, StartBasis: TargetStartPublicLog, Start: "2026-11-01T00:10:05Z", Deadline: "2026-11-01T00:15:05Z",
		Statement: SignOffTargetStatement, StatedAt: "2026-11-01T00:20:06Z",
		Signal: SignalLink{Account: "account-7", Sequence: 24, PreviousSignalHash: strings.Repeat("c", 64)}}
	r.TargetPassedHash = r.ComputeHash()
	return r
}

// R332: the target-passed record's hash follows its stated recipe, its leaf
// is the v3 receipt leaf of kind signoff_target, and the vector is valid.
func TestTheTargetPassedRecordFollowsItsRecipe(t *testing.T) {
	r := targetPassedVector()
	want := independentHash(r.Format, "receipt", "11", "5", r.ResultHash, "response_targets.refusals", "300", "first_approval", "event",
		"public_log", "2026-11-01T00:10:05Z", "2026-11-01T00:15:05Z", SignOffTargetStatement, "2026-11-01T00:20:06Z",
		"signal", "account-7", "24", strings.Repeat("c", 64))
	if r.TargetPassedHash != want {
		t.Fatalf("hash %s, want %s", r.TargetPassedHash, want)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("the vector must be valid: %v", err)
	}
	if r.LeafHash() != ComputeReceiptLeafHashV3(SignOffTargetKind, "account-7", r.TargetPassedHash, 24, strings.Repeat("c", 64)) {
		t.Fatal("the leaf is not the v3 receipt leaf of kind signoff_target")
	}
	if err := ValidateReceiptLeafFieldsV3(SignOffTargetKind, "account-7", r.TargetPassedHash, 24, strings.Repeat("c", 64)); err != nil {
		t.Fatalf("a target-passed record must be loggable: %v", err)
	}
}

// R332: a target-passed record that could state something untrue is refused.
func TestATargetPassedRecordCannotBeBuiltWrong(t *testing.T) {
	for name, mutate := range map[string]func(r *SignOffTargetPassed){
		"stated before the deadline": func(r *SignOffTargetPassed) { r.StatedAt = "2026-11-01T00:15:04Z" },
		"deadline not recomputed":    func(r *SignOffTargetPassed) { r.Deadline = "2026-11-01T00:15:06Z" },
		"head-only notice":           func(r *SignOffTargetPassed) { r.Notice = TargetNoticeHead },
		"another sentence":           func(r *SignOffTargetPassed) { r.Statement = "the sign-off was late" },
		"result after the record":    func(r *SignOffTargetPassed) { r.ResultSequence = 24 },
		"record from refusals":       func(r *SignOffTargetPassed) { r.ResultKind = TargetResultRecord },
		"unknown compare":            func(r *SignOffTargetPassed) { r.Compare = "any" },
		"zero target":                func(r *SignOffTargetPassed) { r.Within = 0 },
		"unknown start":              func(r *SignOffTargetPassed) { r.StartBasis = "server" },
		"bad hash":                   func(r *SignOffTargetPassed) { r.TargetPassedHash = "x" },
	} {
		r := targetPassedVector()
		mutate(r)
		if r.Validate() == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// R332: a sealed target joins a run.sealed record's hash and a receipt
// context's hash only when present, so every record without one hashes as
// it did, and a record with one names it.
func TestASealedTargetJoinsTheHashOnlyWhenPresent(t *testing.T) {
	rs := &RunSealed{Format: RunSealedFormat, RunID: 9, RecordHash: strings.Repeat("a", 64), SealedAt: "2026-11-01T00:00:00Z",
		SignOffRequired: true, Signal: SignalLink{Account: "account-7", Sequence: 2, PreviousSignalHash: strings.Repeat("b", 64)}}
	before := rs.ComputeHash()
	if before != independentHash(rs.Format, "9", rs.RecordHash, "", "", rs.SealedAt, "signal", "account-7", "2", strings.Repeat("b", 64), "signoff_required=true") {
		t.Fatal("a run-sealed record without a target no longer hashes as before")
	}
	rs.SignOffTarget = &SealedTarget{Within: 600, Compare: TargetCompareFirstSignOff, Notice: TargetNoticeBoth}
	if got := rs.ComputeHash(); got == before || got != independentHash(rs.Format, "9", rs.RecordHash, "", "", rs.SealedAt, "signal", "account-7",
		"2", strings.Repeat("b", 64), "signoff_required=true", "signoff_target", "600", "first_signoff", "both") {
		t.Fatal("a run-sealed record's target does not join its hash as stated")
	}
	rs.RunSealedHash = rs.ComputeHash()
	if err := rs.Validate(); err != nil {
		t.Fatal(err)
	}
	rs.SignOffRequired = false
	if rs.Validate() == nil {
		t.Fatal("a target sealed on a result that requires no sign-off must be refused")
	}
	ctx := ReceiptContext{AccountID: "account-7"}
	plain := ctx.Hash()
	ctx.ResponseTarget = &SealedTarget{Within: 60, Compare: TargetCompareFirstSignOff, Notice: TargetNoticeHead}
	if ctx.Hash() == plain {
		t.Fatal("a receipt context's response target does not join its hash")
	}
}
