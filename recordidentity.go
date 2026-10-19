package main

import (
	"fmt"
	"regexp"
	"time"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// RecordIdentityCheck reports whether an anchored record's identity can
// belong to a pipeline run at all (v0.15.2).
//
// The orchestrator's POST /attest endpoint signs, with the same log key
// as run entries, a leaf in the legacy v2 form whose envelope field is
// "attest:<key id>:<subject>" and whose digest field is chosen by the
// caller. Without this check such an entry could stand as the first
// entry of a forged pre-v5 record, which then read as verified and
// anchored with partial coverage. A run's envelope identifier is "env-"
// followed by the first sixteen hex characters of the payload's admission
// hash: derived from what the caller sends, repeated when the same
// payload is sent again, and not a unique run number. What matters is
// that it always begins "env-" while every /attest preimage carries
// "attest:" in that position, so an anchored record whose identifier has
// any other form is not a run's record.
//
// A second rule covers the leaf forms themselves: records have been
// sealed with a pre-anchor table (leaf v5 and later) since run 236,
// whose first entry the public log integrated at 2026-10-15T19:51:06Z.
// A record anchored with an older leaf form in an entry the log
// integrated at or after that instant cannot be genuine.
type RecordIdentityCheck struct {
	Performed bool   `json:"performed"`
	Match     bool   `json:"match"`
	Reason    string `json:"reason,omitempty"`
}

var runEnvelopeID = regexp.MustCompile(`^env-[0-9a-f]{16}$`)

// preTableLeafCutover is when the log integrated run 236's first entry,
// the first record sealed with a pre-anchor table.
var preTableLeafCutover = time.Date(2026, 10, 15, 19, 51, 6, 0, time.UTC)

func verifyRecordIdentity(b *artifacts.AuditBundle, leaf LeafBindingCheck) RecordIdentityCheck {
	if b.RekorAnchor.Backend != "rekor" {
		return RecordIdentityCheck{}
	}
	if !runEnvelopeID.MatchString(b.Envelope.EnvelopeID) {
		return RecordIdentityCheck{Performed: true, Reason: fmt.Sprintf(
			"envelope identifier %q is not a run envelope identifier (env- and the first sixteen hex characters of the payload's admission hash); "+
				"public-log entries the /attest endpoint signs carry attest: identifiers and are never a record's entries",
			safePrefix(b.Envelope.EnvelopeID))}
	}
	switch leaf.Form {
	case leafDomainV1, leafDomainV2, leafDomainV3:
		logged := time.Unix(b.RekorAnchor.IntegratedTime, 0).UTC()
		if b.RekorAnchor.IntegratedTime != 0 && !logged.Before(preTableLeafCutover) {
			return RecordIdentityCheck{Performed: true, Reason: fmt.Sprintf(
				"the record uses the pre-table leaf form %s, but its entry was logged at %s, "+
					"after every record began carrying a pre-anchor table (run 236, %s)",
				leaf.Form, logged.Format(time.RFC3339), preTableLeafCutover.Format(time.RFC3339))}
		}
	}
	return RecordIdentityCheck{Performed: true, Match: true}
}

func printRecordIdentity(c RecordIdentityCheck) {
	if !c.Performed {
		return
	}
	if c.Match {
		fmt.Printf("  Record identity:  an env- envelope identifier (from the payload hash; not unique per run), in a leaf form current when it was logged\n")
		return
	}
	fmt.Printf("  Record identity:  ✗ FAILED · %s\n", c.Reason)
}
