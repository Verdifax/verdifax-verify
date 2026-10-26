package main

// --tamper-test runs the check both Verdifax offers ask a customer to
// make before any fee is due: change a sealed record and see it fail.
// It changes every non-empty scalar value of the record one at a time
// (and, separately, deletes each), runs the full verification on each
// changed copy, and reports any copy that does not fail. It is the same
// method the Verdifax review replay uses on the public records.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var tamperHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// verifyForTamper reports whether a candidate record would be accepted:
// it decodes as strictly as the normal path does and passes every check
// (a partially covered record counts as accepted, since it does not read
// FAILED).
func verifyForTamper(data []byte) bool {
	// Error model: this binary has no logger; a candidate that cannot
	// be decoded is simply not accepted.
	b, decodeErr := decodeBundle(data)
	if decodeErr != nil {
		return false
	}
	return !exitShouldFail(verify(b), false, false)
}

// The record is decoded generically (any) because the test must reach
// every value whatever its type or section, including fields this
// verifier's own types do not name.
type tamperLeaf struct {
	path   string
	parent any
	key    any
}

func tamperLeaves(node any, path string, out *[]tamperLeaf) {
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := path + "." + k
			switch c := v[k].(type) {
			case map[string]any, []any:
				tamperLeaves(c, p, out)
			default:
				if !tamperEmpty(c) {
					*out = append(*out, tamperLeaf{p, v, k})
				}
			}
		}
	case []any:
		for i, c := range v {
			p := fmt.Sprintf("%s[%d]", path, i)
			switch c.(type) {
			case map[string]any, []any:
				tamperLeaves(c, p, out)
			default:
				if !tamperEmpty(c) {
					*out = append(*out, tamperLeaf{p, v, i})
				}
			}
		}
	}
}

func tamperEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case bool:
		return !x
	case json.Number:
		f, floatErr := x.Float64()
		return floatErr == nil && f == 0
	}
	return false
}

func tamperAltered(v any) any {
	switch x := v.(type) {
	case bool:
		return !x
	case json.Number:
		if i, intErr := x.Int64(); intErr == nil {
			return json.Number(strconv.FormatInt(i+1, 10))
		}
		if f, floatErr := x.Float64(); floatErr == nil {
			return json.Number(strconv.FormatFloat(f+1, 'g', -1, 64))
		}
	case string:
		if tamperHex64.MatchString(x) {
			if x[0] == 'f' {
				return "0" + x[1:]
			}
			return "f" + x[1:]
		}
		return x + "x"
	}
	return v
}

func tamperDecode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var root any
	if decodeErr := dec.Decode(&root); decodeErr != nil {
		return nil, decodeErr
	}
	return root, nil
}

func tamperSet(l tamperLeaf, v any, del bool) {
	switch p := l.parent.(type) {
	case map[string]any:
		if del {
			delete(p, l.key.(string))
		} else {
			p[l.key.(string)] = v
		}
	case []any:
		p[l.key.(int)] = v
	}
}

// runTamperTest returns the process exit code: 0 when every change fails
// verification, 1 when any change is accepted or the record itself does
// not verify, 2 when the record cannot be read.
func runTamperTest(w io.Writer, data []byte, accepts func([]byte) bool) int {
	if !accepts(data) {
		fmt.Fprintln(w, "TAMPER TEST: the record itself does not verify, so there is nothing to test.")
		return 1
	}
	root, readErr := tamperDecode(data)
	if readErr != nil {
		fmt.Fprintln(w, "verdifax-verify: tamper test:", readErr)
		return 2
	}
	// The test re-encodes the record after each change; the unchanged
	// re-encoding must still verify, or results would mean nothing.
	same, encodeErr := json.Marshal(root)
	if encodeErr != nil || !accepts(same) {
		fmt.Fprintln(w, "verdifax-verify: tamper test: the re-encoded record does not verify; no result")
		return 2
	}
	var leaves []tamperLeaf
	tamperLeaves(root, "$", &leaves)
	tried, accepted := 0, []string{}
	for _, l := range leaves {
		var original any
		switch p := l.parent.(type) {
		case map[string]any:
			original = p[l.key.(string)]
		case []any:
			original = p[l.key.(int)]
		}
		for _, del := range []bool{false, true} {
			if del {
				if _, isList := l.parent.([]any); isList {
					continue // list elements are changed, not deleted
				}
			}
			tamperSet(l, tamperAltered(original), del)
			changed, mErr := json.Marshal(root)
			tamperSet(l, original, false)
			if mErr != nil {
				continue
			}
			tried++
			if accepts(changed) {
				kind := "changed"
				if del {
					kind = "deleted"
				}
				accepted = append(accepted, kind+" "+l.path)
			}
		}
	}
	fmt.Fprintf(w, "TAMPER TEST: %d changes to %d sealed values tried; %d rejected, %d accepted.\n",
		tried, len(leaves), tried-len(accepted), len(accepted))
	if len(accepted) == 0 {
		fmt.Fprintln(w, "Every change made the record fail verification.")
		return 0
	}
	for _, a := range accepted {
		fmt.Fprintln(w, "  ACCEPTED:", a)
	}
	return 1
}

// uncoveredFields returns, for a record that verifies without a
// complete-record anchor, every field a single change or deletion leaves
// verifying, found by the same method as --tamper-test. A record with a
// complete-record anchor, or one that fails, returns none: on the former
// every change fails, and the latter is already FAILED.
func uncoveredFields(data []byte, r *Report) []string {
	if r == nil || r.RecordCoverage == "complete_record_anchored" || exitShouldFail(r, false, false) {
		return nil
	}
	root, readErr := tamperDecode(data)
	if readErr != nil {
		return nil
	}
	if same, mErr := json.Marshal(root); mErr != nil || !verifyForTamper(same) {
		return nil
	}
	var leaves []tamperLeaf
	tamperLeaves(root, "$", &leaves)
	seen := map[string]bool{}
	var out []string
	for _, l := range leaves {
		var original any
		switch p := l.parent.(type) {
		case map[string]any:
			original = p[l.key.(string)]
		case []any:
			original = p[l.key.(int)]
		}
		for _, del := range []bool{false, true} {
			if _, isList := l.parent.([]any); del && isList {
				continue
			}
			tamperSet(l, tamperAltered(original), del)
			changed, mErr := json.Marshal(root)
			tamperSet(l, original, false)
			if mErr == nil && verifyForTamper(changed) {
				p := tamperIndex.ReplaceAllString(strings.TrimPrefix(l.path, "$."), "[]")
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

var tamperIndex = regexp.MustCompile(`\[\d+\]`)

// printUncoveredFields prints the uncovered fields grouped by section.
func printUncoveredFields(fields []string) {
	if len(fields) == 0 {
		return
	}
	groups := map[string][]string{}
	var order []string
	for _, f := range fields {
		section, rest, found := strings.Cut(f, ".")
		if !found {
			section, rest = "(record)", f
		}
		if _, ok := groups[section]; !ok {
			order = append(order, section)
		}
		groups[section] = append(groups[section], rest)
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i] == "(record)" && order[j] != "(record)" })
	fmt.Printf("  Not hash-covered: %d fields no hash in this record covers; a change to\n", len(fields))
	fmt.Println("                    one of them still verifies (see --tamper-test):")
	for _, s := range order {
		fmt.Printf("                    %s: %s\n", s, strings.Join(groups[s], ", "))
	}
}
