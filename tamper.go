package main

// --tamper-test runs the check both Verdifax offers ask a customer to
// make before any fee is due: change a sealed record and see it fail.
// It changes every value of the record one at a time (empty, false, zero
// and null included), deletes every key (whole sections and lists
// included), removes every list item, appends a copy of each list's last
// item and adds an unknown key to every object, runs the full
// verification on each changed copy, and reports any copy that does not
// fail, and for every copy that fails, which checks caught it.
//
// With --recompute-hashes it plays a forger who rewrites the whole
// record: after each change, every hash the record itself determines is
// recomputed and stored wherever its old value appeared, so only checks
// no rewrite can satisfy are left to catch it: a change counts as stopped
// only when the public-log entries or their timestamps, AMD's report or
// strict reading catch it; one the actor signature alone stops is
// reported, since Verdifax holds those keys.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
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
	return runTamperTestJudged(w, data, acceptsJudge(accepts), false)
}

// tamperVerdict is what one changed copy of the record earned: accepted,
// or rejected by the named check groups.
type tamperVerdict struct {
	accepted bool
	caughtBy []string
}

type tamperJudge func([]byte) tamperVerdict

// The check groups a rejection is attributed to. tamperTier ranks them:
// the public-log entries and their timestamps, then AMD's report, then
// strict reading, then the actor signature, whose keys Verdifax holds.
const (
	catchFirstEntry    = "the first public-log entry"
	catchCompleteEntry = "the complete-record entry"
	catchEntrySigner   = "the entries' signer or timestamps"
	catchActor         = "the actor signature"
	catchAMD           = "AMD's report signature"
	catchDecode        = "the record no longer decodes"
	catchInternal      = "an internal hash"
	catchConsistency   = "a consistency check"
)

var tamperCatchOrder = []string{catchCompleteEntry, catchFirstEntry, catchEntrySigner, catchActor, catchAMD,
	catchDecode, catchInternal, catchConsistency}

// acceptsJudge wraps a plain accept/reject function, for callers that do
// not need to know which check caught a change.
func acceptsJudge(accepts func([]byte) bool) tamperJudge {
	return func(data []byte) tamperVerdict {
		if accepts(data) {
			return tamperVerdict{accepted: true}
		}
		return tamperVerdict{caughtBy: []string{catchInternal}}
	}
}

// judgeForTamper verifies a candidate the way verifyForTamper does and,
// when it fails, names every check group that failed.
func judgeForTamper(data []byte) tamperVerdict {
	// Error model: this binary has no logger; a candidate that cannot be
	// decoded is a rejection by decoding.
	b, decodeErr := decodeBundle(data)
	if decodeErr != nil {
		return tamperVerdict{caughtBy: []string{catchDecode}}
	}
	r := verify(b)
	if !exitShouldFail(r, false, false) {
		return tamperVerdict{accepted: true}
	}
	return tamperVerdict{caughtBy: tamperCatchers(r)}
}

// tamperCatchers names the check groups that failed in a report.
func tamperCatchers(r *Report) []string {
	hit := map[string]bool{}
	for _, c := range append(append([]HashCheck{}, r.Artifacts...), r.Categories...) {
		if c.Match {
			continue
		}
		if c.Name == "hardware_attestation_sevsnp_quote" {
			hit[catchAMD] = true
		} else {
			hit[catchInternal] = true
		}
	}
	if !r.BundleHashOK {
		hit[catchInternal] = true
	}
	for _, s := range r.Seals {
		if !s.Match {
			hit[catchInternal] = true
		}
	}
	if (r.RekorAnchor.Performed && !r.RekorAnchor.Match) || (r.LeafBinding.Performed && !r.LeafBinding.Match) ||
		(r.RecordIdentity.Performed && !r.RecordIdentity.Match) || !r.Anchored {
		hit[catchFirstEntry] = true
	}
	if (r.BundleAnchor.Present && !r.BundleAnchor.Match) ||
		(r.CompleteRecordRequirement.Sealed && !r.CompleteRecordRequirement.Satisfied) {
		hit[catchCompleteEntry] = true
	}
	if r.EntryAuth.Performed && !r.EntryAuth.Match {
		hit[catchEntrySigner] = true
	}
	if r.NrepSignature.Performed && !r.NrepSignature.Match {
		hit[catchActor] = true
	}
	if (r.RuntimeTiming.Performed && !r.RuntimeTiming.Match) || (r.PreAnchor.Performed && !r.PreAnchor.Match) ||
		len(r.CrossChecks) > 0 {
		hit[catchConsistency] = true
	}
	var out []string
	for _, g := range tamperCatchOrder {
		if hit[g] {
			out = append(out, g)
		}
	}
	return out
}

// tamperRecompute rewrites the record the way a forger would: every
// stored hash that no longer recomputes is replaced, wherever its old
// value appears, by the recomputed value, until every internal hash
// agrees or nothing more changes. Signed public-log entry bodies, the
// actor signature and AMD's report cannot be recomputed and are left as
// they are.
func tamperRecompute(data []byte) []byte {
	for round := 0; round < 12; round++ {
		b, decodeErr := decodeBundle(data)
		if decodeErr != nil {
			return data
		}
		r := verify(b)
		stale := map[string]string{}
		note := func(recorded, computed string) {
			if recorded != computed && tamperHex64.MatchString(recorded) && tamperHex64.MatchString(computed) {
				stale[recorded] = computed
			}
		}
		for _, c := range append(append([]HashCheck{r.BundleHash}, r.Artifacts...), r.Categories...) {
			note(c.Recorded, c.Computed)
		}
		for _, s := range r.Seals {
			note(s.SealManifest, s.ExpectedManifest)
		}
		if len(stale) == 0 {
			return data
		}
		root, readErr := tamperDecode(data)
		if readErr != nil {
			return data
		}
		root = tamperReplaceValues(root, stale)
		next, encodeErr := json.Marshal(root)
		if encodeErr != nil || bytes.Equal(next, data) {
			return data
		}
		data = next
	}
	return data
}

// tamperDerivedHashes returns every hash value the record stores that
// verification recomputes from the record's own content.
func tamperDerivedHashes(data []byte) map[string]bool {
	out := map[string]bool{}
	b, decodeErr := decodeBundle(data)
	if decodeErr != nil {
		return out
	}
	r := verify(b)
	for _, c := range append(append([]HashCheck{r.BundleHash}, r.Artifacts...), r.Categories...) {
		if tamperHex64.MatchString(c.Recorded) {
			out[c.Recorded] = true
		}
	}
	for _, s := range r.Seals {
		if tamperHex64.MatchString(s.SealManifest) {
			out[s.SealManifest] = true
		}
	}
	return out
}

// tamperValueAt returns the value at path in the decoded record.
func tamperValueAt(node any, path []tamperStep) any {
	for _, s := range path {
		switch v := node.(type) {
		case map[string]any:
			node = v[s.key]
		case []any:
			if s.index >= len(v) {
				return nil
			}
			node = v[s.index]
		default:
			return nil
		}
	}
	return node
}

// tamperReplaceValues replaces every string value found in stale.
func tamperReplaceValues(node any, stale map[string]string) any {
	switch v := node.(type) {
	case map[string]any:
		for k, c := range v {
			v[k] = tamperReplaceValues(c, stale)
		}
	case []any:
		for i, c := range v {
			v[i] = tamperReplaceValues(c, stale)
		}
	case string:
		if n, found := stale[v]; found {
			return n
		}
	}
	return node
}

// The tiers a change can land in. With --recompute-hashes only the first
// three hold against a forger who rewrites the whole record without
// keys Verdifax or AMD hold; the actor signature's keys are Verdifax's.
const (
	tierLog       = "stopped by the public log"
	tierAMD       = "stopped by AMD's signed report"
	tierStrict    = "refused by strict reading"
	tierActorOnly = "stopped only by the actor signature, whose keys Verdifax holds"
	tierRejected  = "rejected"
	tierNot       = "not stopped"
)

var tamperTierOrder = []string{tierLog, tierAMD, tierStrict, tierActorOnly, tierRejected, tierNot}

// tamperTier places a verdict: in recompute mode by the strongest check
// that caught it, otherwise rejected or not.
func tamperTier(v tamperVerdict, recompute bool) string {
	if v.accepted {
		return tierNot
	}
	if !recompute {
		return tierRejected
	}
	has := map[string]bool{}
	for _, g := range v.caughtBy {
		has[g] = true
	}
	switch {
	case has[catchFirstEntry] || has[catchCompleteEntry] || has[catchEntrySigner]:
		return tierLog
	case has[catchAMD]:
		return tierAMD
	case has[catchDecode]:
		return tierStrict
	case has[catchActor]:
		return tierActorOnly
	}
	return tierNot
}

// tamperWellFormed returns a different value of the same form as s, for
// retrying a change whose first edit no longer decoded: a forger writes
// a value the record can hold, not a malformed one.
func tamperWellFormed(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	if ts, timeErr := time.Parse(time.RFC3339Nano, s); timeErr == nil {
		layout := time.RFC3339
		if strings.Contains(s, ".") {
			layout = time.RFC3339Nano
		}
		return ts.Add(time.Second).Format(layout), true
	}
	if n, ok := new(big.Int).SetString(s, 10); ok {
		return n.Add(n, big.NewInt(1)).String(), true
	}
	swap := func(c byte, alphabet string) string {
		i := strings.IndexByte(alphabet, c)
		return string(alphabet[(i+1)%len(alphabet)])
	}
	const hexDigits = "0123456789abcdef"
	if len(s)%2 == 0 && strings.Trim(s, hexDigits) == "" {
		return swap(s[0], hexDigits) + s[1:], true
	}
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if _, b64Err := base64.StdEncoding.DecodeString(s); b64Err == nil && len(s) >= 4 {
		return swap(s[0], b64) + s[1:], true
	}
	last := s[len(s)-1]
	switch {
	case last >= 'a' && last <= 'z':
		return s[:len(s)-1] + swap(last, "abcdefghijklmnopqrstuvwxyz"), true
	case last >= 'A' && last <= 'Z':
		return s[:len(s)-1] + swap(last, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"), true
	case last >= '0' && last <= '9':
		return s[:len(s)-1] + swap(last, "0123456789"), true
	}
	return "", false
}

// tamperSetAt returns the record's JSON with the value at path replaced.
func tamperSetAt(data []byte, path []tamperStep, value any) ([]byte, bool) {
	root, readErr := tamperDecode(data)
	if readErr != nil || len(path) == 0 {
		return nil, false
	}
	parent := tamperValueAt(root, path[:len(path)-1])
	s := path[len(path)-1]
	switch p := parent.(type) {
	case map[string]any:
		p[s.key] = value
	case []any:
		p[s.index] = value
	default:
		return nil, false
	}
	out, encodeErr := json.Marshal(root)
	return out, encodeErr == nil
}

// tamperResult is one change and what it earned.
type tamperResult struct {
	Kind     string   `json:"kind"`
	Path     string   `json:"path"`
	Accepted bool     `json:"accepted"`
	CaughtBy []string `json:"caught_by,omitempty"`
	Tier     string   `json:"tier"`
	Retried  bool     `json:"retried_well_formed,omitempty"`
	change   tamperChange
}

// tamperOutcome is the result of one run of the test.
type tamperOutcome struct {
	tried, unchanged int
	results          []tamperResult
	caughtCount      map[string]int // per check group, how many rejected changes it caught
	tierCount        map[string]int
}

// notStopped returns the results that count against the record: accepted
// changes, and in recompute mode changes no rewrite-proof check stopped
// or only the actor signature did.
func (o tamperOutcome) notStopped() []tamperResult {
	var out []tamperResult
	for _, r := range o.results {
		if r.Tier == tierNot || r.Tier == tierActorOnly {
			out = append(out, r)
		}
	}
	return out
}

// tamperRun runs every change; with recompute, each changed copy is first
// rewritten by tamperRecompute. A change whose edit no longer decodes is
// retried once with a well-formed value of the same form.
func tamperRun(data []byte, judge tamperJudge, recompute bool) (tamperOutcome, bool) {
	out := tamperOutcome{caughtCount: map[string]int{}, tierCount: map[string]int{}}
	root, readErr := tamperDecode(data)
	if readErr != nil {
		return out, false
	}
	// The test re-encodes the record after each change; the unchanged
	// re-encoding must still verify, or results would mean nothing.
	same, encodeErr := json.Marshal(root)
	if encodeErr != nil || !judge(same).accepted {
		return out, false
	}
	var changes []tamperChange
	tamperChanges(root, nil, &changes)
	var derived map[string]bool
	if recompute {
		derived = tamperDerivedHashes(same)
	}
	prepare := func(changed []byte) ([]byte, bool) {
		if !recompute {
			return changed, true
		}
		changed = tamperRecompute(changed)
		// A change the recomputation undoes entirely (a stored hash
		// edited to another value) leaves the forger's record identical
		// to the original: it is not a change.
		return changed, !bytes.Equal(changed, same)
	}
	for _, c := range changes {
		// A forger recomputes a stored hash rather than deleting it, so
		// deleting one is no more a change than editing it is.
		if recompute && c.kind == "deleted" {
			if s, isString := tamperValueAt(root, c.path).(string); isString && derived[s] {
				out.unchanged++
				continue
			}
		}
		changed, built := tamperApply(data, c)
		if !built {
			continue
		}
		changed, real := prepare(changed)
		if !real {
			out.unchanged++
			continue
		}
		out.tried++
		v := judge(changed)
		retried := false
		if c.kind == "changed" && len(v.caughtBy) == 1 && v.caughtBy[0] == catchDecode {
			if s, isString := tamperValueAt(root, c.path).(string); isString {
				if alt, formed := tamperWellFormed(s); formed {
					if again, rebuilt := tamperSetAt(data, c.path, alt); rebuilt {
						if again, real = prepare(again); real {
							v, retried = judge(again), true
						}
					}
				}
			}
		}
		for _, g := range v.caughtBy {
			out.caughtCount[g]++
		}
		tier := tamperTier(v, recompute)
		out.tierCount[tier]++
		out.results = append(out.results, tamperResult{Kind: c.kind, Path: tamperPathString(c.path), Accepted: v.accepted,
			CaughtBy: v.caughtBy, Tier: tier, Retried: retried, change: c})
	}
	return out, true
}

// tamperReport is the --json form of the test.
type tamperReport struct {
	Mode      string         `json:"mode"`
	Tried     int            `json:"changes_tried"`
	Unchanged int            `json:"changes_undone_by_recomputing,omitempty"`
	Tiers     map[string]int `json:"tiers"`
	CaughtBy  map[string]int `json:"caught_by"`
	Passed    bool           `json:"passed"`
	Changes   []tamperResult `json:"changes"`
}

// runTamperTestJudged prints the test's result and returns its exit code:
// 0 when every change fails (in recompute mode: when every change is
// stopped by the public log, AMD's report or strict reading), 1 otherwise
// or when the record itself does not verify, 2 when it cannot be read.
func runTamperTestJudged(w io.Writer, data []byte, judge tamperJudge, recompute bool) int {
	return runTamperTestOutput(w, data, judge, recompute, false)
}

func runTamperTestOutput(w io.Writer, data []byte, judge tamperJudge, recompute, asJSON bool) int {
	if !judge(data).accepted {
		fmt.Fprintln(w, "TAMPER TEST: the record itself does not verify, so there is nothing to test.")
		return 1
	}
	o, ok := tamperRun(data, judge, recompute)
	if !ok {
		fmt.Fprintln(w, "verdifax-verify: tamper test: the record could not be decoded and re-encoded unchanged; no result")
		return 2
	}
	failing := o.notStopped()
	code := 0
	if len(failing) > 0 {
		code = 1
	}
	if asJSON {
		mode := "tamper-test"
		if recompute {
			mode = "tamper-test --recompute-hashes"
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if encodeErr := enc.Encode(tamperReport{Mode: mode, Tried: o.tried, Unchanged: o.unchanged, Tiers: o.tierCount,
			CaughtBy: o.caughtCount, Passed: code == 0, Changes: o.results}); encodeErr != nil {
			return 2
		}
		return code
	}
	const kinds = "every value changed, every key holding a value deleted, every list item removed, a list item appended, an unknown key added to every object"
	if recompute {
		fmt.Fprintf(w, "TAMPER TEST WITH HASHES RECOMPUTED: %d changes tried (%s), each followed by recomputing every hash the record itself determines.\n", o.tried, kinds)
		var parts []string
		for _, tier := range tamperTierOrder {
			if n := o.tierCount[tier]; n > 0 || tier == tierLog || tier == tierNot {
				parts = append(parts, fmt.Sprintf("%s %d", tier, n))
			}
		}
		fmt.Fprintf(w, "Tiers: %s. %d changes left the record unchanged once its hashes were recomputed and are not counted.\n",
			strings.Join(parts, ", "), o.unchanged)
		fmt.Fprintf(w, "Stopped by the public log means %s, %s or %s caught it; strict reading refuses an unknown key or a record that no longer reads as a bundle, before any check.\n",
			catchFirstEntry, catchCompleteEntry, catchEntrySigner)
	} else {
		fmt.Fprintf(w, "TAMPER TEST: %d changes tried (%s); %d rejected, %d accepted.\n",
			o.tried, kinds, o.tried-len(failing), len(failing))
	}
	var parts []string
	for _, g := range tamperCatchOrder {
		if n := o.caughtCount[g]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", g, n))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "Caught by (a change can be caught by more than one check; --json lists them per change): %s.\n", strings.Join(parts, ", "))
	}
	if len(failing) == 0 {
		if recompute {
			fmt.Fprintln(w, "Every change was stopped by the public log, AMD's signed report or strict reading; none relied on the actor signature alone.")
		} else {
			fmt.Fprintln(w, "Every change made the record fail verification.")
		}
		return 0
	}
	for _, r := range failing {
		label := "ACCEPTED:"
		if recompute {
			label = "NOT STOPPED:"
		}
		line := fmt.Sprintf("  %s %s %s", label, r.Kind, r.Path)
		if !r.Accepted {
			line += " (caught only by " + strings.Join(r.CaughtBy, " and ") + ")"
		}
		fmt.Fprintln(w, line)
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
