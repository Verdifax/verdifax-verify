package main

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/policyhash"
)

// Round 62. A refusal for missing fields seals no policy gate: it names the
// policy that required the fields by its hash, id and name, and lists the
// fields required and the fields missing. A policy document given with
// --policy or --account-policy is checked against it: the document must be
// the policy the refusal names, and require exactly the fields the refusal
// says were required, and every field said missing must be one of them.
// Before round 62 a document given with a refusal failed it, as a record with
// no gate to compare. Since round 62 an account policy can refuse a request
// this way, as a key's always could, so a reader holding either document can
// confirm the refusal is that policy's.
func checkGapPolicyDocument(gap *artifacts.AttestationGapReceipt, doc []byte, flag string) PolicyGateCheck {
	c := PolicyGateCheck{Present: true, PolicyID: gap.PolicyID, PolicyName: gap.PolicyName, PolicyHash: gap.PolicyHash,
		DecisionReasonCode: gap.DecisionReasonCode, Outcome: "refused", DocumentChecked: true}
	got, docErr := policyhash.FromDocument(doc)
	if docErr != nil {
		c.Reason = fmt.Sprintf("the %s document could not be read as a policy: %v", flag, docErr)
		return c
	}
	docRequired, requiredErr := policyhash.RequiredAttestedFields(doc)
	if requiredErr != nil {
		c.Reason = fmt.Sprintf("the %s document's required fields could not be read: %v", flag, requiredErr)
		return c
	}
	required := append([]string(nil), gap.RequiredFields...)
	sort.Strings(required)
	switch {
	case got.PolicyHash != gap.PolicyHash:
		c.Reason = fmt.Sprintf("the %s document's policy hash %s is not %s, the policy this refusal for missing fields names", flag, got.PolicyHash, gap.PolicyHash)
	case got.PolicyID != gap.PolicyID || got.PolicyName != gap.PolicyName:
		c.Reason = fmt.Sprintf("the %s document is %q %q, the refusal names %q %q", flag, got.PolicyID, got.PolicyName, gap.PolicyID, gap.PolicyName)
	case len(docRequired) == 0:
		c.Reason = fmt.Sprintf("the %s document requires no attested fields, so it refuses no request for missing ones", flag)
	case !reflect.DeepEqual(docRequired, required):
		c.Reason = fmt.Sprintf("the %s document requires %s, the refusal says %s were required", flag,
			strings.Join(docRequired, ", "), strings.Join(required, ", "))
	case len(gap.MissingFields) == 0:
		c.Reason = "the refusal names no missing field"
	default:
		listed := map[string]bool{}
		for _, f := range required {
			listed[f] = true
		}
		for _, f := range gap.MissingFields {
			if !listed[f] {
				c.Reason = fmt.Sprintf("the refusal says %s was missing, which the policy does not require", f)
				return c
			}
		}
		c.DocumentMatch = true
	}
	return c
}
