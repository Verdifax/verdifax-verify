package main

// Job map verification. A job is a set of sealed records that name each other
// by hash, so work can split into branches and join again. --job takes a
// folder, checks every record in full, then checks the map: every link lands
// on a record in the folder, no step is repeated, nothing is left hanging, and
// the job is closed by one final step that leads back to every record.
//
// A map shows the links and completeness of what was sent. It cannot show a
// step that was never sent, and a closed job shows the customer said it was
// finished, not that nothing else happened.
//
// Round 61: a step whose record was deleted is given as its tombstone, the
// sealed run deletion that names the job, the step, the record's hash and
// the step's own job links. It stands for that hash, so later steps' links
// still land, and its sealed links are checked as a present step's are, so a
// dropped branch is still caught. A tombstone written before links were
// sealed cannot vouch for them: a job that would need it to fails. A job with
// a deleted step is never COMPLETE: it reads COMPLETE_EXCEPT_DELETED, exit 3
// unless --allow-partial.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// jobRecord is one file of the folder, reduced to what the map needs.
type jobRecord struct {
	File   string
	Hash   string
	Job    *artifacts.JobLink
	Signer string
	Reason string // why the record itself failed, if it did
	// Tombstone, for a file that is a deleted step's tombstone (round 61),
	// is the sealed deletion that stands for the step's record.
	Tombstone *artifacts.RunDeletion
}

// DeletedStep is a step of the job whose record was deleted, shown by its
// sealed tombstone (round 61).
type DeletedStep struct {
	Step       string `json:"step"`
	RunID      int64  `json:"run_id"`
	RecordHash string `json:"record_hash"`
	DeletedBy  string `json:"deleted_by"`
	// TombstoneSequence is the tombstone's event in the account's feed.
	TombstoneSequence int64  `json:"tombstone_sequence"`
	Account           string `json:"account"`
	File              string `json:"file"`
	// LinksSealed says the tombstone seals the step's own job links, so the
	// job is checked through it as through the record; a tombstone written
	// before the server release that came with v0.34.0 carries none.
	LinksSealed bool `json:"links_sealed"`
}

// ExternalLink reports a link to a record from another account.
type ExternalLink struct {
	Step     string `json:"step"`
	Record   string `json:"record"`
	Supplied bool   `json:"supplied"`
}

// JobReport is the --job verdict.
type JobReport struct {
	Tool        string         `json:"tool"`
	ToolVersion string         `json:"tool_version"`
	JobID       string         `json:"job_id"`
	Records     int            `json:"records"`
	Verdict     string         `json:"verdict"` // COMPLETE, COMPLETE_EXCEPT_DELETED, OPEN or FAILED
	Problems    []string       `json:"problems,omitempty"`
	Signers     []string       `json:"signers,omitempty"`
	External    []ExternalLink `json:"external,omitempty"`
	// Deleted lists the job's steps whose records were deleted, each shown
	// by its tombstone (round 61). A job with one is never COMPLETE.
	Deleted []DeletedStep `json:"deleted_steps,omitempty"`
}

// jobOptions carries the record-level choices into each record's check.
type jobOptions struct {
	allowUnanchored bool
	selfHosted      bool
	signerKey       string
	// traceDir, from --aivp-traces, holds the trace of every step whose AI
	// review ran, as <step>.txt beside the step's <step>.json.
	traceDir string
}

// jobStepTrace re-checks a step's AI review against its trace file when
// --aivp-traces is given: a step that seals a review must have its trace,
// and the trace must re-check. It returns "" when the step passes.
func jobStepTrace(file string, c *AIReviewCheck, opts jobOptions) string {
	if opts.traceDir == "" || c == nil {
		return ""
	}
	path := filepath.Join(opts.traceDir, strings.TrimSuffix(file, ".json")+".txt")
	if _, statErr := os.Stat(path); statErr != nil {
		return "the step's AI review sealed a trace, and --aivp-traces holds no " + filepath.Base(path)
	}
	if checked := applyAIReviewTrace(c, path); !checked.TraceMatch {
		return checked.Reason
	}
	return ""
}

func recordFromBundle(file string, data []byte, opts jobOptions) jobRecord {
	rec := jobRecord{File: file}
	bundle, decodeErr := decodeBundle(data)
	if decodeErr != nil {
		rec.Reason = decodeErr.Error()
		return rec
	}
	report := verify(bundle)
	if opts.signerKey != "" {
		applySignerKey(report, opts.signerKey)
	}
	rec.Hash, rec.Job, rec.Signer = bundle.ManifestHash, bundle.Nrep.Job, report.RequestSignature.PublicKey
	if exitShouldFail(report, false, opts.allowUnanchored) {
		rec.Reason = "the record fails verification"
		if c := report.RequestSignature; c.Performed && !c.Match {
			rec.Reason = c.Reason
		}
		if c := report.AIReview; aiReviewFailed(c) {
			rec.Reason = c.Reason
		}
	}
	if rec.Reason == "" {
		rec.Reason = jobStepTrace(file, report.AIReview, opts)
	}
	return rec
}

func recordFromReceipt(file string, data []byte, opts jobOptions) jobRecord {
	rec := jobRecord{File: file}
	doc, decodeErr := artifacts.DecodeReceiptStrict(data)
	if decodeErr != nil {
		rec.Reason = decodeErr.Error()
		return rec
	}
	report := verifyReceiptDocumentWith(doc, receiptOptions{selfHosted: opts.selfHosted})
	if opts.signerKey != "" {
		applyReceiptSignerKey(report, opts.signerKey)
	}
	if facts, factsErr := factsOf(doc); factsErr == nil && len(facts) == 1 {
		rec.Hash = facts[0].hash
	}
	if doc.ReceiptContext != nil {
		rec.Job = doc.ReceiptContext.Job
	}
	rec.Signer = report.RequestSignature.PublicKey
	if receiptExitShouldFail(report, opts.allowUnanchored) {
		rec.Reason = "the receipt fails verification"
		if report.Reason != "" {
			rec.Reason = report.Reason
		}
	}
	if rec.Reason == "" {
		rec.Reason = jobStepTrace(file, report.AIReview, opts)
	}
	return rec
}

var reflectRunDeletion = reflect.TypeOf(artifacts.RunDeletion{})

// isRunDeletion reports a file whose format names a run deletion: a deleted
// step's tombstone, as the account feed's run.deleted event carries it or as
// an export writes it beside the job's records.
func isRunDeletion(data []byte) bool {
	var head struct {
		Format string `json:"format"`
	}
	return json.Unmarshal(data, &head) == nil && head.Format == artifacts.RunDeletionFormat
}

// recordFromTombstone reads a deleted step's tombstone: it must verify on its
// own (its shape, hash, owner signature and public-log entry) and name its
// job and step, and it stands for the record hash it seals.
func recordFromTombstone(file string, data []byte) jobRecord {
	rec := jobRecord{File: file}
	if strictErr := artifacts.CheckStrict(data, reflectRunDeletion); strictErr != nil {
		rec.Reason = "the tombstone is not plain JSON: " + strictErr.Error()
		return rec
	}
	var d artifacts.RunDeletion
	if err := json.Unmarshal(data, &d); err != nil {
		rec.Reason = "the tombstone could not be read: " + err.Error()
		return rec
	}
	if err := checkSealedEntry(d.Validate(), d.ComputeHash(), d.DeletionHash, d.ChangedAt, "changed_at",
		d.Anchor, artifacts.RunDeletionKind, d.LeafHash()); err != nil {
		rec.Reason = "the tombstone does not verify: " + err.Error()
		if errors.Is(err, errNoLogEntry) {
			rec.Reason += "; check it in the account's feed, where a later event's entry commits it"
		}
		return rec
	}
	if d.JobID == "" {
		rec.Reason = "the tombstone names no job step, so it stands for no step of this job"
		return rec
	}
	rec.Hash, rec.Tombstone = d.RecordHash, &d
	return rec
}

// loadJobRecords reads every .json file of the folder, sorted by name.
func loadJobRecords(dir string, opts jobOptions) ([]jobRecord, error) {
	paths, globErr := filepath.Glob(filepath.Join(dir, "*.json"))
	if globErr != nil {
		return nil, globErr
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no .json records in %s", dir)
	}
	sort.Strings(paths)
	records := make([]jobRecord, 0, len(paths))
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		if isRunDeletion(data) {
			records = append(records, recordFromTombstone(filepath.Base(path), data))
		} else if isReceiptDocument(data) {
			records = append(records, recordFromReceipt(filepath.Base(path), data, opts))
		} else {
			records = append(records, recordFromBundle(filepath.Base(path), data, opts))
		}
	}
	return records, nil
}

// mainJobID picks the job being checked. Records from other jobs are allowed
// only as the targets of an external link.
func mainJobID(records []jobRecord) string {
	external := map[string]bool{}
	for _, r := range records {
		if r.Job != nil {
			for _, hash := range r.Job.ExternalPrevious {
				external[hash] = true
			}
		}
	}
	for _, r := range records {
		if r.Job != nil && !external[r.Hash] {
			return r.Job.JobID
		}
	}
	return ""
}

type jobIndex struct {
	byHash   map[string]jobRecord
	byStep   map[string]string
	followed map[string]bool
	final    []string
	// deleted holds the tombstones of the job's deleted steps, by the
	// record hash each stands for.
	deleted map[string]jobRecord
}

// indexJob checks each record's own place in the job.
func indexJob(records []jobRecord, jobID string, external map[string]bool, add func(string, ...any)) jobIndex {
	idx := jobIndex{byHash: map[string]jobRecord{}, byStep: map[string]string{}, followed: map[string]bool{}, deleted: map[string]jobRecord{}}
	for _, r := range records {
		if r.Tombstone != nil {
			d := r.Tombstone
			switch {
			case d.JobID != jobID:
				add("%s: the tombstone is of job %q, not %q", r.File, d.JobID, jobID)
			case idx.byStep[d.StepID] != "":
				add("step %q appears twice: %s and %s", d.StepID, idx.byStep[d.StepID], r.File)
			case idx.byHash[r.Hash].File != "":
				add("step %q is both here (%s) and deleted (%s)", idx.byHash[r.Hash].Job.StepID, idx.byHash[r.Hash].File, r.File)
			default:
				idx.byStep[d.StepID], idx.deleted[r.Hash] = r.File, r
				if d.JobLinks != nil && d.JobLinks.Final {
					idx.final = append(idx.final, r.File)
				}
			}
			continue
		}
		switch {
		case r.Reason != "":
			add("%s: %s", r.File, r.Reason)
		case r.Job == nil:
			add("%s: the record carries no job", r.File)
		case r.Job.JobID != jobID:
			if !external[r.Hash] {
				add("%s: the record belongs to job %q, not %q", r.File, r.Job.JobID, jobID)
			}
			continue
		}
		if r.Job == nil || r.Job.JobID != jobID {
			continue
		}
		if validErr := r.Job.Validate(); validErr != nil {
			add("%s: %v", r.File, validErr)
		}
		if other, seen := idx.byStep[r.Job.StepID]; seen {
			add("step %q appears twice: %s and %s", r.Job.StepID, other, r.File)
		}
		if other, seen := idx.byHash[r.Hash]; seen {
			add("one record appears twice: %s and %s", other.File, r.File)
		}
		if tomb, deleted := idx.deleted[r.Hash]; deleted {
			add("step %q is both here (%s) and deleted (%s)", r.Job.StepID, r.File, tomb.File)
		}
		idx.byStep[r.Job.StepID] = r.File
		idx.byHash[r.Hash] = r
		if r.Job.Final {
			idx.final = append(idx.final, r.File)
		}
	}
	return idx
}

// checkJobMap applies the map rules to verified records.
func checkJobMap(records []jobRecord) JobReport {
	report := JobReport{Tool: "verdifax-verify", ToolVersion: Version, Records: len(records), JobID: mainJobID(records)}
	add := func(format string, args ...any) {
		report.Problems = append(report.Problems, fmt.Sprintf(format, args...))
	}
	supplied, external := map[string]bool{}, map[string]bool{}
	for _, r := range records {
		supplied[r.Hash] = r.Reason == "" && r.Tombstone == nil
		if r.Job != nil {
			for _, hash := range r.Job.ExternalPrevious {
				external[hash] = true
			}
		}
		if r.Tombstone != nil && r.Tombstone.JobLinks != nil {
			for _, hash := range r.Tombstone.JobLinks.ExternalPrevious {
				external[hash] = true
			}
		}
	}
	idx := indexJob(records, report.JobID, external, add)
	signers := map[string]bool{}
	for _, r := range idx.byHash {
		if r.Signer != "" {
			signers[r.Signer] = true
		}
		for _, hash := range r.Job.PreviousRecordHashes {
			idx.followed[hash] = true
			_, found := idx.byHash[hash]
			_, deleted := idx.deleted[hash]
			if !found && !deleted {
				add("step %q follows a record that is not here (%s): a step is missing or was swapped", r.Job.StepID, truncate(hash, 16))
			}
		}
		for _, hash := range r.Job.ExternalPrevious {
			report.External = append(report.External, ExternalLink{Step: r.Job.StepID, Record: hash, Supplied: supplied[hash]})
		}
	}
	// Round 61: a deleted step's tombstone seals the step's own links, so
	// they are checked as a present step's are: each must land on a record
	// or a tombstone here, or be an external link.
	var unlinked []string
	for _, r := range idx.deleted {
		d := r.Tombstone
		if d.JobLinks == nil {
			unlinked = append(unlinked, d.StepID)
			continue
		}
		for _, hash := range d.JobLinks.PreviousRecordHashes {
			idx.followed[hash] = true
			_, found := idx.byHash[hash]
			_, deleted := idx.deleted[hash]
			if !found && !deleted {
				add("deleted step %q follows a record that is not here (%s), by its tombstone's sealed links: a step is missing or was swapped", d.StepID, truncate(hash, 16))
			}
		}
		for _, hash := range d.JobLinks.ExternalPrevious {
			report.External = append(report.External, ExternalLink{Step: d.StepID, Record: hash, Supplied: supplied[hash]})
		}
	}
	sort.Strings(unlinked)
	if len(idx.final) > 1 {
		add("more than one step closes this job: %s", strings.Join(idx.final, ", "))
	}
	if len(idx.final) == 1 {
		for hash, r := range idx.byHash {
			if r.Job.Final || idx.followed[hash] {
				continue
			}
			if len(unlinked) > 0 {
				// The step after this one may be a deleted step whose
				// tombstone carries no links: it cannot vouch for this one.
				add("step %q has no step after it, unless deleted step %s followed it; that tombstone predates sealed job links (written before the server release that came with v0.34.0), so it cannot show the link, and a branch may have been dropped",
					r.Job.StepID, strings.Join(quoteAll(unlinked), " or "))
				continue
			}
			add("step %q has no step after it, so a branch was dropped", r.Job.StepID)
		}
		for hash, r := range idx.deleted {
			if (r.Tombstone.JobLinks == nil || !r.Tombstone.JobLinks.Final) && !idx.followed[hash] {
				add("deleted step %q has no step after it, so a branch was dropped", r.Tombstone.StepID)
			}
		}
	}
	for _, r := range idx.deleted {
		d := r.Tombstone
		report.Deleted = append(report.Deleted, DeletedStep{Step: d.StepID, RunID: d.RunID, RecordHash: d.RecordHash, DeletedBy: d.DecidedBy,
			TombstoneSequence: d.Signal.Sequence, Account: d.Signal.Account, File: r.File, LinksSealed: d.JobLinks != nil})
	}
	sort.Slice(report.Deleted, func(i, j int) bool { return report.Deleted[i].Step < report.Deleted[j].Step })
	for signer := range signers {
		report.Signers = append(report.Signers, signer)
	}
	sort.Strings(report.Signers)
	sort.Strings(report.Problems)
	sort.Slice(report.External, func(i, j int) bool { return report.External[i].Step < report.External[j].Step })
	switch {
	case len(report.Problems) > 0:
		report.Verdict = "FAILED"
	case len(idx.final) == 1 && len(report.Deleted) > 0:
		// Round 61: a deleted step is shown by its tombstone, not its
		// record, so the job is complete except for it, never complete.
		report.Verdict = "COMPLETE_EXCEPT_DELETED"
	case len(idx.final) == 1:
		report.Verdict = "COMPLETE"
	default:
		report.Verdict = "OPEN"
	}
	return report
}

func printJobReport(r JobReport) {
	fmt.Printf("verdifax-verify %s: job %q, %d records\n", r.ToolVersion, r.JobID, r.Records)
	for _, problem := range r.Problems {
		fmt.Println("  ✗", problem)
	}
	for _, link := range r.External {
		state := "NOT SUPPLIED: this link is the customer's statement"
		if link.Supplied {
			state = "supplied and verified"
		}
		fmt.Printf("  External link from step %q to %s: %s\n", link.Step, truncate(link.Record, 16), state)
	}
	for _, signer := range r.Signers {
		fmt.Println("  Signed by:", signer)
	}
	var deleted []string
	for _, d := range r.Deleted {
		links := "its links checked through the tombstone"
		if !d.LinksSealed {
			links = "its tombstone predates sealed job links"
		}
		fmt.Printf("  Deleted step %q: run %d, record %s, deleted by %s, tombstone at event %d of %s, %s\n", d.Step, d.RunID, truncate(d.RecordHash, 16),
			deciderName(d.DeletedBy), d.TombstoneSequence, d.Account, links)
		deleted = append(deleted, strconv.Quote(d.Step))
	}
	switch r.Verdict {
	case "COMPLETE":
		fmt.Println("VERDICT: ✓ COMPLETE, every record verifies, every link lands on a record here, and one final step leads back to every branch.")
	case "COMPLETE_EXCEPT_DELETED":
		fmt.Printf("VERDICT: ◐ COMPLETE EXCEPT THE DELETED STEPS %s: every record here verifies, every link lands on a record here or on a deleted step's tombstone, and one final step leads back to every branch. A deleted step is shown by its sealed tombstone, not its record.\n",
			strings.Join(deleted, ", "))
	case "OPEN":
		fmt.Println("VERDICT: OPEN, every record and link verifies, but no final step closes this job, so nothing shows whether more steps were cut off.")
	default:
		fmt.Println("VERDICT: ✗ FAILED, this set of records is not a sound job.")
	}
	fmt.Println("         A job map covers what was sent. It cannot show a step that was never sent.")
}

// runJobCheck is the --job mode. It returns the process exit code: 0 complete,
// 1 failed, 2 unreadable, 3 open or complete except deleted steps unless
// --allow-partial was passed.
func runJobCheck(dir string, opts jobOptions, asJSON, allowOpen bool) int {
	records, loadErr := loadJobRecords(dir, opts)
	if loadErr != nil {
		fmt.Fprintln(os.Stderr, "verdifax-verify:", loadErr)
		return 2
	}
	report := checkJobMap(records)
	if asJSON {
		if encodeErr := json.NewEncoder(os.Stdout).Encode(report); encodeErr != nil {
			fmt.Fprintln(os.Stderr, "verdifax-verify:", encodeErr)
			return 2
		}
	} else {
		printJobReport(report)
	}
	switch report.Verdict {
	case "COMPLETE":
		return 0
	case "OPEN", "COMPLETE_EXCEPT_DELETED":
		if allowOpen {
			return 0
		}
		return exitPartialCoverage
	}
	return 1
}

// quoteAll quotes each name for a message.
func quoteAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strconv.Quote(n)
	}
	return out
}

var errJobFlags = errors.New("--job takes only --json, --allow-partial, --allow-unanchored, --self-hosted-receipt, --signer-key and --aivp-traces")
