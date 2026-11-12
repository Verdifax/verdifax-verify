package artifacts

import "testing"

// Round 59, N15 and N19: one definition of the sign-offs that name a result,
// and of the decision in force on it.
func TestTheSignOffsThatNameAResult(t *testing.T) {
	record := SignOffResult{Kind: SignOffTargetRecord, RunID: 7, Digest: "d"}
	receipt := SignOffResult{Kind: SignOffTargetReceipt, RunID: 7, Digest: "d"}
	cases := []struct {
		target SignOffTarget
		result SignOffResult
		names  bool
	}{
		{SignOffTarget{Kind: SignOffTargetRecord, RunID: 7, Digest: "d"}, record, true},
		{SignOffTarget{Kind: SignOffTargetJob, RunID: 7, Digest: "d", JobID: "j"}, record, true},
		{SignOffTarget{Kind: SignOffTargetReceipt, RunID: 7, Digest: "d"}, record, false},
		{SignOffTarget{Kind: SignOffTargetReceipt, RunID: 7, Digest: "d"}, receipt, true},
		{SignOffTarget{Kind: SignOffTargetJob, RunID: 7, Digest: "d", JobID: "j"}, receipt, false},
		{SignOffTarget{Kind: SignOffTargetRecord, RunID: 8, Digest: "d"}, record, false},
		{SignOffTarget{Kind: SignOffTargetRecord, RunID: 7, Digest: "e"}, record, false},
	}
	for i, c := range cases {
		if got := c.target.NamesResult(c.result); got != c.names {
			t.Errorf("case %d: %+v names %+v = %v, want %v", i, c.target, c.result, got, c.names)
		}
	}
	so := func(seq int64, kind, decision string) SignOff {
		t := SignOffTarget{Kind: kind, RunID: 7, Digest: "d"}
		if kind == SignOffTargetJob {
			t.JobID = "j"
		}
		return SignOff{Sequence: seq, Target: t, Decision: decision, SignOffHash: string(rune('a' + seq))}
	}
	inForce, own := DecisionInForce([]SignOff{so(1, SignOffTargetRecord, SignOffApprove), so(2, SignOffTargetRecord, SignOffReject)}, record)
	if inForce == nil || inForce.Decision != SignOffReject || own != nil {
		t.Fatalf("the later record sign-off is in force: %+v %+v", inForce, own)
	}
	inForce, own = DecisionInForce([]SignOff{so(1, SignOffTargetJob, SignOffApprove), so(2, SignOffTargetRecord, SignOffReject)}, record)
	if inForce == nil || inForce.Decision != SignOffApprove || inForce.Target.Kind != SignOffTargetJob || own == nil || own.Decision != SignOffReject {
		t.Fatalf("the job's decision governs, and the record's own is shown under it: %+v %+v", inForce, own)
	}
	if inForce, own = DecisionInForce(nil, record); inForce != nil || own != nil {
		t.Fatal("no sign-off names the result")
	}
}
