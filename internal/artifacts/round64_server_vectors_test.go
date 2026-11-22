package artifacts

import (
	"strings"
	"testing"
)

// Round 64 (v0.38.0): each hash below was computed by the server's own
// artifacts package (verdifax-orchestrator, round 64 build of 2026-11-17) for
// the values written here, so a verifier that hashes a new sealed fact
// differently from the server fails: the declared client in the attested
// digest, the data-use digest, a receipt context with data use and a setup
// fingerprint, and an EPA section with data use and sealed setup facts.
func TestRound64HashesAreTheServers(t *testing.T) {
	temp := 0.2
	ac := AttestedContext{Attested: true, ActorID: "u-1", ModelProvider: "anthropic", ModelName: "claude-opus-5-5",
		ModelTemperature: &temp, ClientName: "Claude Code", ClientVersion: "2.1.0"}
	plain := ac
	plain.ClientName, plain.ClientVersion = "", ""
	use := &DataUse{Purpose: "claims.review", Basis: "contract", Categories: []string{"claims", "contact"},
		Reference: "hmac-sha256:" + strings.Repeat("0a", 32)}
	ctx := ReceiptContext{Request: SealedRequestFields{PayloadHash: strings.Repeat("1", 64), ProgramID: strings.Repeat("2", 64),
		RouteID: "route-a", RegistryRecordHash: strings.Repeat("3", 64)}, AccountID: "account-7"}
	withUse, withSetup, both := ctx, ctx, ctx
	withUse.DataUse = use
	withSetup.SetupHash = strings.Repeat("e", 64)
	both.DataUse, both.SetupHash = use, strings.Repeat("e", 64)
	epa := EPA{Kind: "epa", KernelID: "k", KernelVersion: "1", PolicyHash: strings.Repeat("4", 64), AttestedContext: ac, DataUse: use,
		PolicyGate: &PolicyGate{PolicyID: "p", PolicyHash: strings.Repeat("4", 64), Outcome: "allow", FiredRuleID: "r",
			Inputs: &PolicyInputs{SubjectID: "u-1", DataUse: use, Setup: &SetupFacts{DeclaredByCaller: &DeclaredSetup{ModelName: "claude-opus-5-5"}}}}}
	for name, c := range map[string]struct{ got, want string }{
		"attested digest with client":    {ComputeAttestedContextDigest(ac), "d0ec3c7cd39830fa0c6171d138e9814f1ca6fa16f13e0238a75a3b4673424674"},
		"attested digest without client": {ComputeAttestedContextDigest(plain), "6c45927c0193c53f54d852adb5959855f0ebf52a7950e450f06a1085d70da446"},
		"data use digest":                {DataUseDigest(use), "0cd72160eb713e80917ffcabb3a26fca500ce3fa1deaf4413e8c3767d9df2221"},
		"receipt context plain":          {ctx.Hash(), "38605bfc5950eacb66d9605c43c0e3f6b4c0a11e88b91716f1aed5c3cf3502b7"},
		"receipt context data use":       {withUse.Hash(), "3c220d070d4231058a378a71631ee5fe61a4bbaffbb83414a764babfbca030a8"},
		"receipt context setup hash":     {withSetup.Hash(), "5479e60a16f01204a313f46f2ddf461dfa5e580cb5a150c50107e239e41712db"},
		"receipt context both":           {both.Hash(), "2d0f472d161bea8bc22566c3b24ca027e28c8221b839b308da10f9e5bb317a22"},
		"EPA with data use and setup":    {RecomputeEPAHash(epa), "33e06e9a5a692881f0a26f1537bda63c6157decec272aa943a9ae9d916360615"},
	} {
		if c.got != c.want {
			t.Errorf("%s: %s, the server's %s", name, c.got, c.want)
		}
	}
}

// A review date record whose due_at is not the time its declaration gives
// is refused, even when it was stated after both times.
func TestAReviewDateRecomputesItsDueTime(t *testing.T) {
	r := reviewDueVectorRecord()
	r.DueAt = "2026-10-29T00:00:00.5Z"
	r.ReviewDueHash = r.ComputeHash()
	if r.Validate() == nil {
		t.Fatal("a due time that does not recompute from the declaration was accepted")
	}
}
