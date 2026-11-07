package artifacts

import "testing"

// The account fields join every hash they belong to, only when present, so
// earlier records hash as before and a changed account number fails.
func TestAccountFieldsJoinTheirHashes(t *testing.T) {
	n := NrepSection{ActorID: "api-key-7", PublicKey: "pk", Signature: "sig", SignedAt: "2026-11-07T00:00:00Z"}
	before := n.SectionHash()
	if before != ComputeNrepSectionHash(n.ActorID, n.PublicKey, n.Signature, n.SignedAt) {
		t.Fatal("a section with no account no longer hashes as before")
	}
	n.AccountID = "account-3"
	withAccount := n.SectionHash()
	n.AccountID = "account-4"
	if withAccount == before || withAccount == n.SectionHash() {
		t.Fatal("the account number does not change the section hash")
	}

	binding := &PolicyBinding{Source: PolicySourceCustomer, PolicyHash: "p", DocumentHash: "d", Outcome: "allow", FiredRuleID: "r"}
	keyOnly := ReceiptContext{Policy: binding}
	accountOnly := ReceiptContext{AccountPolicy: binding}
	if keyOnly.Hash() == accountOnly.Hash() {
		t.Fatal("the account's policy and the key's hash the same: one could stand for the other")
	}
	plain := ReceiptContext{}
	withID := ReceiptContext{AccountID: "account-3"}
	if plain.Hash() == withID.Hash() {
		t.Fatal("the account number does not change the receipt context hash")
	}
	if got := binding.fields(); got[0] != "policy" {
		t.Fatalf("the key's policy lost its label: %v", got[:1])
	}
}
