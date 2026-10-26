package main

// --tamper-test runs the check both Verdifax offers ask a customer to
// make before any fee is due: change a sealed record and see it fail.
// It changes every value of the record one at a time (empty, false, zero
// and null included), deletes every key (whole sections and lists
// included), removes every list item, appends a copy of each list's last
// item and adds an unknown key to every object, runs the full
// verification on each changed copy, and reports any copy that does not
// fail.

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

// tamperStep is one step of a path into the decoded record: an object
// key or a list index.
type tamperStep struct {
	key   string
	index int
	list  bool
}

// tamperChange is one change the test makes to a fresh copy of the
// record: changing a value (empty, false, zero and null included),
// deleting a key (whole sections and lists included), removing a list
// item, adding a copy of a list's last item, or adding an unknown key to
// an object.
type tamperChange struct {
	kind string // changed, deleted, removed, appended, added
	path []tamperStep
}

func tamperPathString(path []tamperStep) string {
	var b strings.Builder
	b.WriteString("$")
	for _, s := range path {
		if s.list {
			fmt.Fprintf(&b, "[%d]", s.index)
		} else {
			b.WriteString("." + s.key)
		}
	}
	return b.String()
}

// tamperChanges lists every change for the record rooted at node.
func tamperChanges(node any, path []tamperStep, out *[]tamperChange) {
	at := func(s tamperStep) []tamperStep {
		p := make([]tamperStep, len(path)+1)
		copy(p, path)
		p[len(path)] = s
		return p
	}
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := at(tamperStep{key: k})
			switch v[k].(type) {
			case map[string]any, []any:
				tamperChanges(v[k], child, out)
			default:
				*out = append(*out, tamperChange{"changed", child})
			}
			// Deleting a key whose value is empty, false, zero or null,
			// or a section made only of such values, leaves the record's
			// meaning unchanged: a missing value reads as that value. It
			// is not a change, so it is not tried.
			if !tamperZero(v[k]) {
				*out = append(*out, tamperChange{"deleted", child})
			}
		}
		*out = append(*out, tamperChange{"added", path})
	case []any:
		for i, c := range v {
			child := at(tamperStep{index: i, list: true})
			switch c.(type) {
			case map[string]any, []any:
				tamperChanges(c, child, out)
			default:
				*out = append(*out, tamperChange{"changed", child})
			}
			*out = append(*out, tamperChange{"removed", child})
		}
		if len(v) > 0 {
			*out = append(*out, tamperChange{"appended", path})
		}
	}
}

// tamperZero reports whether v is empty, false, zero or null, or an
// object or list made only of such values.
func tamperZero(v any) bool {
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
	case map[string]any:
		for _, c := range x {
			if !tamperZero(c) {
				return false
			}
		}
		return true
	case []any:
		for _, c := range x {
			if !tamperZero(c) {
				return false
			}
		}
		return true
	}
	return false
}

// tamperAltered returns a different value of the same kind: a string
// gains a character (an empty one becomes "x"), a 64-digit hash changes
// its first digit, a number gains one, a boolean flips, and null becomes
// a string.
func tamperAltered(v any) any {
	switch x := v.(type) {
	case nil:
		return "x"
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

// tamperApply makes change c to a fresh copy of the record and returns
// the copy's JSON.
func tamperApply(data []byte, c tamperChange) ([]byte, bool) {
	root, readErr := tamperDecode(data)
	if readErr != nil {
		return nil, false
	}
	target := c.path
	if c.kind != "added" && c.kind != "appended" {
		target = c.path[:len(c.path)-1]
	}
	parent := root
	var grand any
	var last tamperStep
	for _, s := range target {
		grand, last = parent, s
		if s.list {
			parent = parent.([]any)[s.index]
		} else {
			parent = parent.(map[string]any)[s.key]
		}
	}
	switch c.kind {
	case "added":
		parent.(map[string]any)["tamper_test_unknown_key"] = "x"
	case "appended":
		l := parent.([]any)
		l = append(l, l[len(l)-1])
		tamperReplace(&root, grand, last, l, len(target) == 0)
	default:
		s := c.path[len(c.path)-1]
		if s.list {
			l := parent.([]any)
			if c.kind == "removed" {
				l = append(append([]any{}, l[:s.index]...), l[s.index+1:]...)
				tamperReplace(&root, grand, last, l, len(target) == 0)
			} else {
				l[s.index] = tamperAltered(l[s.index])
			}
		} else {
			m := parent.(map[string]any)
			if c.kind == "deleted" {
				delete(m, s.key)
			} else {
				m[s.key] = tamperAltered(m[s.key])
			}
		}
	}
	out, encodeErr := json.Marshal(root)
	return out, encodeErr == nil
}

// tamperReplace stores a rebuilt list back in its parent.
func tamperReplace(root *any, grand any, last tamperStep, l []any, atRoot bool) {
	if atRoot {
		*root = l
		return
	}
	if last.list {
		grand.([]any)[last.index] = l
	} else {
		grand.(map[string]any)[last.key] = l
	}
}

// tamperAccepted runs every change and returns the ones a verifier
// accepts, plus how many were tried.
func tamperAccepted(data []byte, accepts func([]byte) bool) (accepted []tamperChange, tried int, ok bool) {
	root, readErr := tamperDecode(data)
	if readErr != nil {
		return nil, 0, false
	}
	// The test re-encodes the record after each change; the unchanged
	// re-encoding must still verify, or results would mean nothing.
	same, encodeErr := json.Marshal(root)
	if encodeErr != nil || !accepts(same) {
		return nil, 0, false
	}
	var changes []tamperChange
	tamperChanges(root, nil, &changes)
	for _, c := range changes {
		changed, built := tamperApply(data, c)
		if !built {
			continue
		}
		tried++
		if accepts(changed) {
			accepted = append(accepted, c)
		}
	}
	return accepted, tried, true
}

// runTamperTest returns the process exit code: 0 when every change fails
// verification, 1 when any change is accepted or the record itself does
// not verify, 2 when the record cannot be read.
func runTamperTest(w io.Writer, data []byte, accepts func([]byte) bool) int {
	if !accepts(data) {
		fmt.Fprintln(w, "TAMPER TEST: the record itself does not verify, so there is nothing to test.")
		return 1
	}
	accepted, tried, ok := tamperAccepted(data, accepts)
	if !ok {
		fmt.Fprintln(w, "verdifax-verify: tamper test: the record could not be decoded and re-encoded unchanged; no result")
		return 2
	}
	fmt.Fprintf(w, "TAMPER TEST: %d changes tried (every value changed, every key holding a value deleted, every list item removed, a list item appended, an unknown key added to every object); %d rejected, %d accepted.\n",
		tried, tried-len(accepted), len(accepted))
	if len(accepted) == 0 {
		fmt.Fprintln(w, "Every change made the record fail verification.")
		return 0
	}
	for _, c := range accepted {
		fmt.Fprintln(w, "  ACCEPTED:", c.kind, tamperPathString(c.path))
	}
	return 1
}

var tamperIndex = regexp.MustCompile(`\[\d+\]`)

// uncoveredFields returns, for a record that verifies without a
// complete-record anchor, every path where some change leaves the record
// verifying, found by the same changes as --tamper-test. A record with a
// complete-record anchor, or one that fails, returns none.
func uncoveredFields(data []byte, r *Report) []string {
	if r == nil || r.RecordCoverage == "complete_record_anchored" || exitShouldFail(r, false, false) {
		return nil
	}
	accepted, _, ok := tamperAccepted(data, verifyForTamper)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range accepted {
		p := strings.TrimPrefix(tamperIndex.ReplaceAllString(tamperPathString(c.path), "[]"), "$")
		p = strings.TrimPrefix(p, ".")
		switch c.kind {
		case "added":
			p = strings.TrimSuffix(p+".(added key)", ".")
		case "appended":
			p += "[] (appended item)"
		}
		if p == "" || p == ".(added key)" {
			p = "(added key)"
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

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
