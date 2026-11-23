package feedcount

import "strings"

// The plain words for every figure, shared by the server's PDF and the
// verifier's printout, so a reader sees one name for each figure wherever
// it appears (round 64, N38, R377).

// FigureWords says a figure's name in plain words. A sign-off figure says a
// registered approver key signed, never that a person approved.
func FigureWords(name string) string {
	base, qualifier, _ := strings.Cut(name, ":")
	by := func(v string) string {
		switch v {
		case "owner":
			return "the owner"
		case "owner.signed":
			return "the owner, with the owner's request-key signature"
		case "owner.unsigned":
			return "the owner on the server's word, with no request-key signature"
		case "verdifax_admin":
			return "Verdifax"
		case "unstated":
			return "a decider the record does not state"
		}
		return v
	}
	words := map[string]string{
		"runs.sealed":                            "runs sealed, each a successful run with its record",
		"runs.sealed.job_steps":                  "runs sealed as steps of a job",
		"runs.sealed.signoff_required":           "runs sealed whose rule requires a sign-off",
		"runs.sealed.target_sealed":              "runs sealed with a response target sealed in the result",
		"runs.refused":                           "runs refused",
		"runs.refused.receipt":                   "runs refused with a " + qualifier,
		"runs.refused.code":                      "runs refused with code " + qualifier,
		"runs.refused.account_stopped":           "runs refused because the account was stopped",
		"runs.refused.data_use_declared":         "runs refused that sealed a declared data use",
		"runs.refused.target_sealed":             "runs refused with a response target sealed in the receipt",
		"runs.halted":                            "runs halted",
		"runs.halted.receipt":                    "runs halted with a " + qualifier,
		"runs.halted.code":                       "runs halted with code " + qualifier,
		"runs.halted.target_sealed":              "runs halted with a response target sealed in the receipt",
		"runs.failed":                            "runs that failed with a server error",
		"runs.failed.class":                      "runs that failed with error class " + qualifier,
		"runs.failed.stage":                      "runs that failed at stage " + qualifier,
		"signoffs.made":                          "sign-offs a registered approver key signed",
		"signoffs.made.target":                   "sign-offs a registered approver key signed on a " + qualifier,
		"signoffs.refused":                       "sign-offs refused because the account was stopped",
		"results.signoff_required.none_in_force": "results whose rule requires a sign-off, with no sign-off in force at the period's end",
		"policy.changed":                         "policy changes",
		"policy.changed.signed":                  "policy changes signed by the owner's request key",
		"policy.changed.chain":                   "policy changes to " + qualifier + " policies",
		"keys.created":                           "keys created",
		"keys.created.by":                        "keys created by " + by(qualifier),
		"keys.revoked":                           "keys revoked",
		"keys.revoked.by":                        "keys revoked by " + by(qualifier),
		"approvers.registered":                   "approver keys registered",
		"approvers.registered.by":                "approver keys registered by " + by(qualifier),
		"approvers.revoked":                      "approver keys revoked",
		"approvers.revoked.by":                   "approver keys revoked by " + by(qualifier),
		"account.changed":                        "account changes",
		"account.changed.by":                     "account changes by " + by(qualifier),
		"runs.deleted":                           "records deleted",
		"runs.deleted.by":                        "records deleted by " + by(qualifier),
		"runs.published":                         "records made public",
		"runs.published.by":                      "records made public by " + by(qualifier),
		"runs.unpublished":                       "records withdrawn from public view",
		"runs.unpublished.by":                    "records withdrawn from public view by " + by(qualifier),
		"chain.gaps":                             "declared restore gaps",
		"chain.interrupted":                      "entries the public log never confirmed, each closed by its own record",
		"setup.changed":                          "setup changes the policy's watch saw",
		"review.due":                             "declared policy review dates that passed",
		"account.stops":                          "stops placed on the account",
		"account.stops.by":                       "stops placed on the account by " + by(qualifier),
		"account.resumes":                        "stops lifted",
		"account.resumes.by":                     "stops lifted by " + by(qualifier),
		"account.stopped_seconds":                "seconds the account was stopped inside the period, any stop standing",
		"account.stopped_seconds.by":             "seconds the account was stopped inside the period by " + by(qualifier),
		"signoff.target_passed":                  "response targets that passed with no sign-off of the compared kind on the public log",
		"signoff.target_passed.result":           "response targets that passed on a " + qualifier,
		"events.record_deleted.unplaced":         "events whose record was deleted, inside the period's span of events, whose sealed time can no longer be read",
	}
	if w, ok := words[base]; ok {
		return w
	}
	switch {
	case strings.HasPrefix(name, "signoffs.made."):
		return "sign-offs in which a registered approver key signed " + strings.TrimPrefix(name, "signoffs.made.")
	case strings.HasPrefix(name, "results.decision_in_force."):
		return "results whose decision in force at the period's end is " + strings.TrimPrefix(name, "results.decision_in_force.") + ", as a registered approver key signed it"
	case strings.HasPrefix(name, "response_times."):
		return responseTimeFigureWords(strings.TrimPrefix(name, "response_times."))
	}
	return name
}

// responseTimeFigureWords says a response-time figure in plain words.
func responseTimeFigureWords(rest string) string {
	lists := map[string]string{
		"results":                                "results measured for a response time",
		"results_deleted":                        "results measured whose run was deleted",
		"with_target":                            "results with a response target",
		"unsigned_as_of_head":                    "results with no sign-off of the compared kind as of the head",
		"longer_than_target.signed_after":        "results whose wait was longer than the target, signed after it",
		"longer_than_target.unsigned_as_of_head": "results unsigned as of the head and longer than the target",
	}
	if w, ok := lists[rest]; ok {
		return w
	}
	ends := map[string]string{"first_signoff": "the first sign-off", "first_approval": "the first approval", "decision_in_force": "the decision in force"}
	parts := strings.Split(rest, ".")
	end, known := ends[parts[0]]
	if !known {
		return "response_times." + rest
	}
	if len(parts) == 2 && parts[1] == "reached" {
		return "results that reached " + end
	}
	if len(parts) == 3 {
		clock := map[string]string{"log": "on the public log", "record": "on the sealed record times"}[parts[1]]
		stat := map[string]string{"median_seconds": "median (lower middle) wait in seconds", "p90_seconds": "90th percentile wait in seconds",
			"longest_seconds": "longest wait in seconds"}[parts[2]]
		if clock != "" && stat != "" {
			return stat + " to " + end + ", " + clock + ", as measured"
		}
	}
	return "response_times." + rest
}
