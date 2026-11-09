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

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	Verdict     string         `json:"verdict"` // COMPLETE, OPEN or FAILED
	Problems    []string       `json:"problems,omitempty"`
	Signers     []string       `json:"signers,omitempty"`
	External    []ExternalLink `json:"external,omitempty"`
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
		if isReceiptDocument(data) {
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
}

// indexJob checks each record's own place in the job.
func indexJob(records []jobRecord, jobID string, external map[string]bool, add func(string, ...any)) jobIndex {
	idx := jobIndex{byHash: map[string]jobRecord{}, byStep: map[string]string{}, followed: map[string]bool{}}
	for _, r := range records {
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
		supplied[r.Hash] = r.Reason == ""
		if r.Job != nil {
			for _, hash := range r.Job.ExternalPrevious {
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
			if _, found := idx.byHash[hash]; !found {
				add("step %q follows a record that is not here (%s): a step is missing or was swapped", r.Job.StepID, truncate(hash, 16))
			}
		}
		for _, hash := range r.Job.ExternalPrevious {
			report.External = append(report.External, ExternalLink{Step: r.Job.StepID, Record: hash, Supplied: supplied[hash]})
		}
	}
	if len(idx.final) > 1 {
		add("more than one step closes this job: %s", strings.Join(idx.final, ", "))
	}
	if len(idx.final) == 1 {
		for hash, r := range idx.byHash {
			if !r.Job.Final && !idx.followed[hash] {
				add("step %q has no step after it, so a branch was dropped", r.Job.StepID)
			}
		}
	}
	for signer := range signers {
		report.Signers = append(report.Signers, signer)
	}
	sort.Strings(report.Signers)
	sort.Strings(report.Problems)
	sort.Slice(report.External, func(i, j int) bool { return report.External[i].Step < report.External[j].Step })
	switch {
	case len(report.Problems) > 0:
		report.Verdict = "FAILED"
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
	switch r.Verdict {
	case "COMPLETE":
		fmt.Println("VERDICT: ✓ COMPLETE, every record verifies, every link lands on a record here, and one final step leads back to every branch.")
	case "OPEN":
		fmt.Println("VERDICT: OPEN, every record and link verifies, but no final step closes this job, so nothing shows whether more steps were cut off.")
	default:
		fmt.Println("VERDICT: ✗ FAILED, this set of records is not a sound job.")
	}
	fmt.Println("         A job map covers what was sent. It cannot show a step that was never sent.")
}

// runJobCheck is the --job mode. It returns the process exit code: 0 complete,
// 1 failed, 2 unreadable, 3 open unless --allow-partial was passed.
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
	case "OPEN":
		if allowOpen {
			return 0
		}
		return exitPartialCoverage
	}
	return 1
}

var errJobFlags = errors.New("--job takes only --json, --allow-partial, --allow-unanchored, --self-hosted-receipt, --signer-key and --aivp-traces")
