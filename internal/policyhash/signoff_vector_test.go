package policyhash

import (
	"strings"
	"testing"
)

// Round 58, B7: a rule's sign-off requirement is in the policy hash exactly
// as the server puts it there. The policy and its hash are the server's
// vector (verdifax-orchestrator internal/pepg/psl/signoff_vector_test.go).
const signOffVectorPolicy = `{"schema":"psl.v1","policy_id":"signoff-vector","policy_name":"Sign-off vector","policy_version":"1","effective_at":"2026-11-11T00:00:00Z","default_effect":"deny","rules":[{"rule_id":"high-risk","effect":"allow","subject":{"type":"any","id_match":{"operator":"any"}},"verb":{"match":{"operator":"any"}},"object":{"type":"any","id_match":{"operator":"any"}},"signoff":{"required":true}}]}`

const signOffVectorHash = "c67006f7287a6c964e760566f785478791fb46dc3e92ee2b805c7127e33dc343"

func TestTheSignOffVectorHashesAsTheServerDoes(t *testing.T) {
	got, hashErr := FromDocument([]byte(signOffVectorPolicy))
	if hashErr != nil || got.PolicyHash != signOffVectorHash {
		t.Fatalf("policy hash = %+v (%v), want %s", got, hashErr, signOffVectorHash)
	}
}

// The server refuses a signoff that requires nothing and one on a deny rule,
// so the verifier does too: a record never names a policy the server would
// refuse.
func TestASignOffThatCannotApplyIsRefused(t *testing.T) {
	for name, policy := range map[string]string{
		"required false": strings.Replace(signOffVectorPolicy, `"signoff":{"required":true}`, `"signoff":{"required":false}`, 1),
		"empty":          strings.Replace(signOffVectorPolicy, `"signoff":{"required":true}`, `"signoff":{}`, 1),
		"deny rule":      strings.Replace(signOffVectorPolicy, `"effect":"allow"`, `"effect":"deny"`, 1),
	} {
		if policy == signOffVectorPolicy {
			t.Fatalf("%s: the vector policy no longer has the text this test changes", name)
		}
		if _, hashErr := FromDocument([]byte(policy)); hashErr == nil || !strings.Contains(hashErr.Error(), "invalid signoff") {
			t.Fatalf("%s: want an invalid signoff error, got %v", name, hashErr)
		}
	}
}

// Round 58, B9: a data_quality condition is in the policy hash exactly as the
// server puts it there (the server's vector, same policy and hash).
const dataQualityVectorPolicy = `{"schema":"psl.v1","policy_id":"data-vector","policy_name":"Data quality vector","policy_version":"1","effective_at":"2026-11-11T00:00:00Z","default_effect":"deny","rules":[{"rule_id":"fresh-data","effect":"allow","subject":{"type":"any","id_match":{"operator":"any"}},"verb":{"match":{"operator":"any"}},"object":{"type":"any","id_match":{"operator":"any"}},"conditions":[{"type":"data_quality","max_age_seconds":3600,"checks":["complete","schema"]}]}]}`

const dataQualityVectorHash = "f4ffe3edaade1e273cdd508080a0200371b27358cf42f80284a44af5cbd87d75"

func TestTheDataQualityVectorHashesAsTheServerDoes(t *testing.T) {
	got, hashErr := FromDocument([]byte(dataQualityVectorPolicy))
	if hashErr != nil || got.PolicyHash != dataQualityVectorHash {
		t.Fatalf("policy hash = %+v (%v), want %s", got, hashErr, dataQualityVectorHash)
	}
}
