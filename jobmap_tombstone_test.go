package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// tombstoneFor is the sealed, logged tombstone of one job step's record,
// written as a server before round 61 wrote it: with no job links.
func tombstoneFor(t *testing.T, f *feedBuilder, jobID, stepID, recordHash string) *artifacts.RunDeletion {
	t.Helper()
	return linkedTombstone(t, f, jobID, stepID, recordHash, nil)
}

// linkedTombstone is a job step's tombstone sealing the step's own links.
func linkedTombstone(t *testing.T, f *feedBuilder, jobID, stepID, recordHash string, links *artifacts.DeletedJobLinks) *artifacts.RunDeletion {
	t.Helper()
	link, at := f.next()
	d := &artifacts.RunDeletion{Format: artifacts.RunDeletionFormat, DecidedBy: artifacts.DecidedByVerdifax, RunID: 950, RecordHash: recordHash,
		JobID: jobID, StepID: stepID, JobLinks: links, ChangedAt: at.Format("2006-01-02T15:04:05Z07:00"), Signal: link}
	d.DeletionHash = d.ComputeHash()
	d.Anchor = f.anchor(artifacts.RunDeletionKind, d.DeletionHash, d.LeafHash(), at)
	f.add(artifacts.SignalRunDeleted, link, d.DeletionHash, d.RunID, *d)
	return d
}

func tombstoneRecord(t *testing.T, f *feedBuilder, stepID, recordHash string) jobRecord {
	t.Helper()
	return linkedTombstoneRecord(t, f, stepID, recordHash, nil)
}

func linkedTombstoneRecord(t *testing.T, f *feedBuilder, stepID, recordHash string, links *artifacts.DeletedJobLinks) jobRecord {
	t.Helper()
	raw, err := json.Marshal(linkedTombstone(t, f, "job", stepID, recordHash, links))
	if err != nil {
		t.Fatal(err)
	}
	if !isRunDeletion(raw) {
		t.Fatal("a tombstone is read as one")
	}
	return recordFromTombstone(stepID+".deleted.json", raw)
}

// Round 61: a job step whose record was deleted is verified through its
// sealed tombstone. The step reads as deleted by its decider, later steps'
// links land on the record hash the tombstone seals, and the job reads
// complete except the deleted steps, never complete. A tombstone of another
// job, one for a step also present, one whose seal was changed, and a
// deleted step nothing follows all fail.
func TestADeletedJobStepIsVerifiedThroughItsTombstone(t *testing.T) {
	f := newFeedBuilder(t)
	records := branching()
	credit := tombstoneRecord(t, f, "credit", hashOf("b"))
	if credit.Reason != "" || credit.Hash != hashOf("b") {
		t.Fatalf("a sealed tombstone stands for its record: %+v", credit)
	}
	withDeleted := []jobRecord{records[0], credit, records[2], records[3]}
	report := checkJobMap(withDeleted)
	if report.Verdict != "COMPLETE_EXCEPT_DELETED" || len(report.Problems) != 0 || len(report.Deleted) != 1 ||
		report.Deleted[0].Step != "credit" || report.Deleted[0].DeletedBy != artifacts.DecidedByVerdifax || report.Deleted[0].TombstoneSequence != 1 {
		t.Fatalf("the job is complete except its deleted step: %+v", report)
	}
	out := captureStdout(t, func() { printJobReport(report) })
	if !strings.Contains(out, `Deleted step "credit": run 950`) || !strings.Contains(out, "deleted by Verdifax") ||
		!strings.Contains(out, `COMPLETE EXCEPT THE DELETED STEPS "credit"`) {
		t.Fatalf("the report names the deleted step and its decider:\n%s", out)
	}
	if missing := checkJobMap([]jobRecord{records[0], records[2], records[3]}); missing.Verdict != "FAILED" {
		t.Fatalf("without its tombstone the step is missing: %+v", missing)
	}
	cases := map[string][]jobRecord{
		"a step both here and deleted":   append(branching(), tombstoneRecord(t, f, "credit-again", hashOf("b"))),
		"a deleted step nothing follows": {records[0], records[1], records[2], records[3], tombstoneRecord(t, f, "audit", hashOf("e"))},
	}
	other := tombstoneFor(t, f, "another-job", "credit", hashOf("b"))
	raw, _ := json.Marshal(other)
	cases["a tombstone of another job"] = []jobRecord{records[0], recordFromTombstone("other.json", raw), records[2], records[3]}
	for name, set := range cases {
		if r := checkJobMap(set); r.Verdict != "FAILED" {
			t.Errorf("%s must fail: %+v", name, r)
		}
	}
	forged := tombstoneFor(t, f, "job", "credit", hashOf("b"))
	forged.RecordHash = hashOf("f")
	raw, _ = json.Marshal(forged)
	if r := recordFromTombstone("forged.json", raw); r.Reason == "" || r.Tombstone != nil {
		t.Fatalf("a tombstone whose sealed record hash was changed must fail: %+v", r)
	}
	unlogged := tombstoneFor(t, f, "job", "credit", hashOf("b"))
	unlogged.Anchor = nil
	raw, _ = json.Marshal(unlogged)
	if r := recordFromTombstone("unlogged.json", raw); !strings.Contains(r.Reason, "check it in the account's feed") {
		t.Fatalf("a tombstone with no log entry of its own says where to check it: %+v", r)
	}
	// The folder reader picks a tombstone file out from the step records.
	dir := t.TempDir()
	good, _ := json.Marshal(tombstoneFor(t, f, "job", "credit", hashOf("b")))
	if err := os.WriteFile(filepath.Join(dir, "credit.json"), good, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadJobRecords(dir, jobOptions{})
	if err != nil || len(loaded) != 1 || loaded[0].Tombstone == nil {
		t.Fatalf("the folder's tombstone is read as one: %+v %v", loaded, err)
	}
}

// Round 61 (R253): a job whose deleted step was a refused, halted or failed
// run reads through that receipt's tombstone, given in the folder beside the
// steps: it stands for the receipt's hash, which the next step links to, and
// the job reads COMPLETE_EXCEPT_DELETED. A tombstone that names no job, as
// the server wrote for a receipt before this release, stands for no step.
func TestAJobWhoseDeletedStepWasAReceiptReadsThroughItsTombstone(t *testing.T) {
	f := newFeedBuilder(t)
	f.failedRun()
	var doc artifacts.ReceiptDocument
	if err := json.Unmarshal(f.events[0].Data.Entry, &doc); err != nil {
		t.Fatal(err)
	}
	receiptHash := doc.FailureReceipt.Hash
	link, at := f.next()
	d := artifacts.RunDeletion{Format: artifacts.RunDeletionFormat, DecidedBy: artifacts.DecidedByOwner, RunID: f.runID, RecordHash: receiptHash,
		JobID: "job", StepID: "screen", JobLinks: &artifacts.DeletedJobLinks{PreviousRecordHashes: []string{hashOf("a")}},
		LogEntries: []string{doc.ReceiptAnchor.LogEntryID}, ChangedAt: at.Format("2006-01-02T15:04:05Z07:00"), Signal: link}
	d.OwnerSignature = ownerSignature(artifacts.SignalRunDeleted, d.DeletionSubject())
	d.DeletionHash = d.ComputeHash()
	d.Anchor = f.anchor(artifacts.RunDeletionKind, d.DeletionHash, d.LeafHash(), at)
	dir := t.TempDir()
	raw, _ := json.Marshal(d)
	if err := os.WriteFile(filepath.Join(dir, "screen.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadJobRecords(dir, jobOptions{})
	if err != nil || len(loaded) != 1 || loaded[0].Reason != "" || loaded[0].Hash != receiptHash {
		t.Fatalf("the receipt step's tombstone is read from the folder: %+v %v", loaded, err)
	}
	steps := []jobRecord{step(hashOf("a"), "read", false), loaded[0], step(hashOf("d"), "decide", true, receiptHash)}
	report := checkJobMap(steps)
	if report.Verdict != "COMPLETE_EXCEPT_DELETED" || len(report.Deleted) != 1 || report.Deleted[0].Step != "screen" ||
		report.Deleted[0].RunID != f.runID || report.Deleted[0].DeletedBy != artifacts.DecidedByOwner || !report.Deleted[0].LinksSealed {
		t.Fatalf("a job whose deleted middle step was a receipt reads complete except it, through its sealed links: %+v", report)
	}
	// A link changed in the tombstone fails its hash.
	tampered := strings.Replace(string(raw), hashOf("a"), hashOf("f"), 1)
	if r := recordFromTombstone("screen.json", []byte(tampered)); !strings.Contains(r.Reason, "does not verify") || r.Tombstone != nil {
		t.Fatalf("a tombstone whose sealed link was changed must fail: %+v", r)
	}
	// The same tombstone written before links were sealed cannot vouch for
	// the link from "read": the job fails and says why.
	noLinks := d
	noLinks.JobLinks = nil
	noLinks.DeletionHash = noLinks.ComputeHash()
	noLinks.Anchor = f.anchor(artifacts.RunDeletionKind, noLinks.DeletionHash, noLinks.LeafHash(), at)
	raw, _ = json.Marshal(noLinks)
	old := recordFromTombstone("screen.json", raw)
	if old.Reason != "" {
		t.Fatalf("a tombstone with no links still verifies alone: %+v", old)
	}
	r := checkJobMap([]jobRecord{steps[0], old, steps[2]})
	if r.Verdict != "FAILED" || !strings.Contains(strings.Join(r.Problems, " "), "predates sealed job links") {
		t.Fatalf("a job that needs an old tombstone's links fails and names why: %+v", r)
	}
	// When every link it would need is otherwise accounted for, the old
	// tombstone is enough.
	r = checkJobMap([]jobRecord{steps[0], old, step(hashOf("c"), "income", false, hashOf("a")),
		step(hashOf("d"), "decide", true, receiptHash, hashOf("c"))})
	if r.Verdict != "COMPLETE_EXCEPT_DELETED" || r.Deleted[0].LinksSealed {
		t.Fatalf("an old tombstone the job does not rely on is enough: %+v", r)
	}
	noJob := d
	noJob.JobID, noJob.StepID, noJob.JobLinks = "", "", nil
	noJob.OwnerSignature = ownerSignature(artifacts.SignalRunDeleted, noJob.DeletionSubject())
	noJob.DeletionHash = noJob.ComputeHash()
	noJob.Anchor = f.anchor(artifacts.RunDeletionKind, noJob.DeletionHash, noJob.LeafHash(), at)
	raw, _ = json.Marshal(noJob)
	unnamed := recordFromTombstone("screen.json", raw)
	if !strings.Contains(unnamed.Reason, "names no job step") {
		t.Fatalf("a tombstone that names no job stands for no step: %+v", unnamed)
	}
	if r := checkJobMap([]jobRecord{steps[0], unnamed, steps[2]}); r.Verdict != "FAILED" {
		t.Fatalf("without a tombstone naming the step, the job fails: %+v", r)
	}
}

// Round 61: a deleted step's sealed links are checked as a present step's
// are. With the middle step "credit" deleted and its links sealed, the job
// reads complete except it; with another branch's record dropped, the
// dropped branch is still caught; a deleted step's link to a record not here
// fails; and a deleted final step counts as the one step that closes the job.
func TestADeletedStepsSealedLinksKeepTheJobCheckable(t *testing.T) {
	f := newFeedBuilder(t)
	credit := linkedTombstoneRecord(t, f, "credit", hashOf("b"), &artifacts.DeletedJobLinks{PreviousRecordHashes: []string{hashOf("a")}})
	read := step(hashOf("a"), "read", false)
	income := step(hashOf("c"), "income", false, hashOf("a"))
	whole := checkJobMap([]jobRecord{read, credit, income, step(hashOf("d"), "decide", true, hashOf("b"), hashOf("c"))})
	if whole.Verdict != "COMPLETE_EXCEPT_DELETED" || len(whole.Problems) != 0 {
		t.Fatalf("a job with a deleted middle step whose links are sealed: %+v", whole)
	}
	dropped := checkJobMap([]jobRecord{read, credit, income, step(hashOf("d"), "decide", true, hashOf("b"))})
	if dropped.Verdict != "FAILED" || !strings.Contains(strings.Join(dropped.Problems, " "), `step "income" has no step after it, so a branch was dropped`) {
		t.Fatalf("a dropped branch is caught in a job with a deletion: %+v", dropped)
	}
	stray := linkedTombstoneRecord(t, f, "credit", hashOf("b"), &artifacts.DeletedJobLinks{PreviousRecordHashes: []string{hashOf("e")}})
	if r := checkJobMap([]jobRecord{read, stray, income, step(hashOf("d"), "decide", true, hashOf("b"), hashOf("c"))}); r.Verdict != "FAILED" ||
		!strings.Contains(strings.Join(r.Problems, " "), "by its tombstone's sealed links") {
		t.Fatalf("a deleted step following a record not here fails: %+v", r)
	}
	finalDeleted := linkedTombstoneRecord(t, f, "decide", hashOf("d"), &artifacts.DeletedJobLinks{PreviousRecordHashes: []string{hashOf("b"), hashOf("c")}, Final: true})
	closed := checkJobMap([]jobRecord{read, step(hashOf("b"), "credit", false, hashOf("a")), income, finalDeleted})
	if closed.Verdict != "COMPLETE_EXCEPT_DELETED" || len(closed.Problems) != 0 {
		t.Fatalf("a deleted final step closes the job through its tombstone: %+v", closed)
	}
	twoFinals := checkJobMap([]jobRecord{read, step(hashOf("b"), "credit", false, hashOf("a")), income, finalDeleted,
		step(hashOf("f"), "close", true, hashOf("d"))})
	if twoFinals.Verdict != "FAILED" || !strings.Contains(strings.Join(twoFinals.Problems, " "), "more than one step closes this job") {
		t.Fatalf("a deleted final step counts toward one closing step: %+v", twoFinals)
	}
}
