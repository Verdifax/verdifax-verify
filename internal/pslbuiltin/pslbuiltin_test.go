package pslbuiltin

import (
	"encoding/json"
	"testing"
)

// TestAllReadsEveryVersion holds the listed hashes to the files, and the
// files to the rule format.
func TestAllReadsEveryVersion(t *testing.T) {
	all, readErr := All()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(all) != len(versions) {
		t.Fatalf("read %d versions, %d listed", len(all), len(versions))
	}
	current := 0
	for _, v := range all {
		var doc struct {
			PolicyID string `json:"policy_id"`
			Rules    []struct {
				RuleID string `json:"rule_id"`
			} `json:"rules"`
		}
		if parseErr := json.Unmarshal(v.Document, &doc); parseErr != nil || doc.PolicyID == "" || len(doc.Rules) == 0 {
			t.Fatalf("%s is not a readable policy: %v", v.File, parseErr)
		}
		if v.Current {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("%d versions marked current, want exactly 1", current)
	}
}

func TestCurrent(t *testing.T) {
	v, currentErr := Current()
	if currentErr != nil || !v.Current || len(v.Document) == 0 {
		t.Fatalf("Current() = %+v, %v", v, currentErr)
	}
}

// TestLookups finds each version both ways and nothing for an unknown hash.
func TestLookups(t *testing.T) {
	for _, listed := range versions {
		byDoc, found := ByDocumentHash(listed.DocumentHash)
		if !found || byDoc.File != listed.File {
			t.Fatalf("ByDocumentHash(%s) = %q, %v", listed.DocumentHash, byDoc.File, found)
		}
		byPolicy, found := ByPolicyHash(listed.PolicyHash)
		if !found || byPolicy.File != listed.File {
			t.Fatalf("ByPolicyHash(%s) = %q, %v", listed.PolicyHash, byPolicy.File, found)
		}
	}
	unknown := "0000000000000000000000000000000000000000000000000000000000000000"
	if _, found := ByDocumentHash(unknown); found {
		t.Fatal("an unknown document hash was found")
	}
	if _, found := ByPolicyHash(unknown); found {
		t.Fatal("an unknown policy hash was found")
	}
}
