package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Round 44: the README said every value the record stores more than once
// is checked, while the copy groups were a hand-written list, and twelve
// copies outside it were rewritable on the hardware run. This test
// enumerates every value the published records store more than once and
// fails unless each duplicate is one of the copy groups, is checked
// another way, or is a listed coincidence of independently declared
// values. A new record generation that repeats a value somewhere new
// fails here until the verifier accounts for it.

// duplicateRecords are the genuine records the enumeration runs over:
// every public record, the hardware run and the fixtures of each record
// generation the verifier accepts.
var duplicateRecords = []string{
	"testdata/round18/run-249-production.json",
	"testdata/round22/run-253-production.json",
	"testdata/round40/hardware-run-2026-10.json",
	"testdata/round6/run-237-intact.json",
	"testdata/round7/run-238-intact.json",
	"testdata/round8/run-239-intact.json",
	"testdata/round7/v6-intact-test-log.json",
	"testdata/policy-gate/orchestrator-mock-allowed-run.json",
	"testdata/round45/run-248-production.json",
}

// checkedOtherwise explains a duplicate without a copy group. Each entry
// is a predicate over the normalized path (list indices read as []).
var checkedOtherwise = []struct {
	why   string
	match func(path string) bool
}{
	{"the complete-record anchor, which the verifier checks against the log entry it names",
		func(p string) bool { return strings.HasPrefix(p, "bundle_anchor.") }},
	{"the inclusion proof and log identity of each anchor, which the verifier checks against the log",
		func(p string) bool {
			return strings.HasSuffix(p, ".inclusion_path[]") || p == "rekor_anchor.log_id" || p == "bundle_anchor.log_id"
		}},
	{"the manifest hash every seal carries, which the verifier checks is one value",
		func(p string) bool {
			return p == "manifest_hash" || strings.HasSuffix(p, ".seal.manifest_hash") || p == "formal_verification.manifest_hash"
		}},
}

// comparedPreAnchorRows names the rows of a record's pre-anchor table the
// verifier compares with a displayed value or checks for its one defined
// value (round 45, R82). Any other row that repeats a record value is a
// duplicate to explain like any other.
func comparedPreAnchorRows(t *testing.T, file string) map[string]bool {
	t.Helper()
	b := mustDecode(t, file)
	table := map[string]string{}
	for _, row := range b.PreAnchor {
		table[row.Name] = row.Value
	}
	out := map[string]bool{}
	for _, row := range preAnchorDisplayedRows(b, table) {
		out[row.name] = true
	}
	for name, kind := range preAnchorRowKinds {
		if strings.HasPrefix(kind, "value:") {
			out[name] = true
		}
	}
	return out
}

// coincidences are values that are equal on a record without one being
// derived from the other: independent declarations the caller made with
// the same text, or two notes with the same wording. Each is keyed by
// the sorted, normalized paths it joins.
var coincidences = map[string]string{
	"authorization_chain.approvers[].approved_request_hash|causal_graph.affected_entities[].id_hash|envelope.program_id": "the October 2026 hardware run's caller declared the program id as the approved request hash and the affected entity id; three independent declarations",
	"authorization_chain.approvers[].actor_id|epa.attested_context.actor_id":                                             "the same person declared as approver and as the attested actor; two independent declarations",
	"epa.attested_context.model_name|epa.attested_context.model_version":                                                 "the caller declared the model version equal to its name; two independent declarations",
	"epa.attested_context.prompt_hash|request_substance.prompt.hash|request_substance.prompt.user_hash":                  "caller-declared hashes of the same prompt; none derives from another, and from run 239 on the complete-record entry binds all three",
	"aivp_t4.ai_output_hash|request_substance.output.hash":                                                               "the caller's declared output hash and the AI review's input hash, equal when the same text is declared in both places; from run 239 on the complete-record entry binds both",
	"transcript.scaffold.activated_by|zksp_binding.scaffold.activated_by":                                                "two scaffold notes with the same wording",
	"system_provenance.environment.hostname|system_provenance.environment.instance_id":                                   "Fly names the machine by its instance id; both are the server's own observation",
	"reproducibility_context.git_commit_sha|system_provenance.orchestrator_git_sha":                                      "the caller declared the server's commit as its own; the server's two copies are a group, the caller's is independent",
}

var listIndex = regexp.MustCompile(`\[\d+\]`)

func walkLeaves(node any, path string, visit func(path string, value any)) {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walkLeaves(child, p, visit)
		}
	case []any:
		for i, child := range v {
			walkLeaves(child, fmt.Sprintf("%s[%d]", path, i), visit)
		}
	default:
		visit(path, v)
	}
}

func keyNames(node any, out map[string]bool) {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			out[k] = true
			keyNames(child, out)
		}
	case []any:
		for _, child := range v {
			keyNames(child, out)
		}
	}
}

// groupedPaths is every normalized path a copy group or list group covers.
func groupedPaths() map[string]bool {
	out := map[string]bool{}
	for _, g := range boundCopyGroups {
		for _, p := range g.paths {
			out[listIndex.ReplaceAllString(p, "[]")] = true
		}
	}
	for _, g := range boundListGroups {
		for _, p := range g.paths {
			out[p] = true
		}
		for _, extras := range g.extras {
			for _, p := range extras {
				out[p] = true
			}
		}
	}
	return out
}

func TestEveryDuplicatedValueIsAccountedFor(t *testing.T) {
	grouped := groupedPaths()
	for _, file := range duplicateRecords {
		raw, readErr := os.ReadFile(file)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var root any
		if err := json.Unmarshal(raw, &root); err != nil {
			t.Fatal(err)
		}
		// The pre-anchor table is read by row name, so each row is
		// excused only if the verifier compares that row.
		compared := comparedPreAnchorRows(t, file)
		if m, isMap := root.(map[string]any); isMap {
			if rows, isList := m["pre_anchor"].([]any); isList {
				byName := map[string]any{}
				for _, r := range rows {
					if row, ok := r.(map[string]any); ok {
						byName[fmt.Sprint(row["name"])] = row["value"]
					}
				}
				m["pre_anchor"] = byName
			}
		}
		keys := map[string]bool{}
		keyNames(root, keys)
		byValue := map[string][]string{}
		walkLeaves(root, "", func(path string, value any) {
			var key string
			switch v := value.(type) {
			case string:
				if len(v) < 10 || keys[v] || strings.HasSuffix(path, ".signed_entry_timestamp") {
					return
				}
				key = "s:" + v
			case float64:
				if v < 1e6 {
					return
				}
				key = "n:" + fmt.Sprint(v)
			default:
				return
			}
			byValue[key] = append(byValue[key], listIndex.ReplaceAllString(path, "[]"))
		})
		for value, paths := range byValue {
			sort.Strings(paths)
			paths = uniqueStrings(paths)
			// A path a check covers on its own explains nothing about
			// the others, so it leaves the group first: the pre-anchor
			// table and the anchors are compared with the record and
			// the log, whatever else repeats their values.
			var rest []string
			for _, p := range paths {
				covered := strings.HasPrefix(p, "pre_anchor.") && compared[strings.TrimPrefix(p, "pre_anchor.")]
				for _, rule := range checkedOtherwise {
					covered = covered || rule.match(p)
				}
				if !covered {
					rest = append(rest, p)
				}
			}
			if len(rest) < 2 {
				continue
			}
			var open []string
			for _, p := range rest {
				if !grouped[p] {
					open = append(open, p)
				}
			}
			if len(open) == 0 {
				continue
			}
			if _, listed := coincidences[strings.Join(rest, "|")]; listed {
				continue
			}
			// A group plus one independent declaration listed as a
			// coincidence with the group's canonical path.
			if len(open) == 1 && allGrouped(rest, open[0], grouped) {
				continue
			}
			t.Errorf("%s: the value %s… is stored at %s; %s is checked by nothing: add a copy group, a check or a listed coincidence",
				file, value[2:min(14, len(value))], strings.Join(paths, ", "), strings.Join(open, ", "))
		}
	}
}

func uniqueStrings(in []string) []string {
	var out []string
	for _, s := range in {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

// allGrouped reports whether every path but one is in a copy group,
// which leaves the odd one as an independent declaration listed in
// coincidences together with the group's canonical path.
func allGrouped(paths []string, odd string, grouped map[string]bool) bool {
	for _, p := range paths {
		if p != odd && !grouped[p] {
			return false
		}
	}
	for key := range coincidences {
		parts := strings.Split(key, "|")
		if len(parts) == 2 && (parts[0] == odd || parts[1] == odd) {
			other := parts[0]
			if other == odd {
				other = parts[1]
			}
			for _, p := range paths {
				if p == other {
					return true
				}
			}
		}
	}
	return false
}

// Every listed coincidence names paths that exist on some record, so the
// list cannot silently excuse a path that no longer exists.
func TestListedCoincidencesStillOccur(t *testing.T) {
	seen := map[string]bool{}
	for _, file := range duplicateRecords {
		raw, _ := os.ReadFile(file)
		var root any
		if err := json.Unmarshal(raw, &root); err != nil {
			t.Fatal(err)
		}
		walkLeaves(root, "", func(path string, _ any) { seen[listIndex.ReplaceAllString(path, "[]")] = true })
	}
	for key := range coincidences {
		for _, p := range strings.Split(key, "|") {
			if !seen[p] {
				t.Errorf("coincidence names %s, which no listed record carries", p)
			}
		}
	}
}
