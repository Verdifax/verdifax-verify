package main

import (
	"strings"
	"testing"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

func hashOf(c string) string { return strings.Repeat(c, 64) }

func step(hash, id string, final bool, previous ...string) jobRecord {
	return jobRecord{File: id + ".json", Hash: hash, Job: &artifacts.JobLink{JobID: "job", StepID: id,
		PreviousRecordHashes: artifacts.SortJobHashes(previous), Final: final}}
}

func branching() []jobRecord {
	return []jobRecord{
		step(hashOf("a"), "read", false),
		step(hashOf("b"), "credit", false, hashOf("a")),
		step(hashOf("c"), "income", false, hashOf("a")),
		step(hashOf("d"), "decide", true, hashOf("b"), hashOf("c")),
	}
}

func TestJobMapCompleteWithBranches(t *testing.T) {
	report := checkJobMap(branching())
	if report.Verdict != "COMPLETE" || len(report.Problems) != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestJobMapOpenWithoutAFinalStep(t *testing.T) {
	records := branching()[:3]
	if report := checkJobMap(records); report.Verdict != "OPEN" {
		t.Fatalf("report = %+v", report)
	}
}

func TestJobMapFindsAMissingStep(t *testing.T) {
	records := branching()
	records = append(records[:1], records[2:]...)
	report := checkJobMap(records)
	if report.Verdict != "FAILED" || !strings.Contains(strings.Join(report.Problems, " "), "a step is missing") {
		t.Fatalf("report = %+v", report)
	}
}

func TestJobMapFindsADroppedBranch(t *testing.T) {
	records := branching()
	records[3] = step(hashOf("d"), "decide", true, hashOf("b"))
	report := checkJobMap(records)
	if report.Verdict != "FAILED" || !strings.Contains(strings.Join(report.Problems, " "), "a branch was dropped") {
		t.Fatalf("report = %+v", report)
	}
}

func TestJobMapFindsARepeatedStep(t *testing.T) {
	records := append(branching(), step(hashOf("e"), "credit", false, hashOf("a")))
	if report := checkJobMap(records); report.Verdict != "FAILED" {
		t.Fatalf("report = %+v", report)
	}
}

func TestJobMapFindsTwoClosingSteps(t *testing.T) {
	records := append(branching(), step(hashOf("e"), "again", true, hashOf("d")))
	if report := checkJobMap(records); report.Verdict != "FAILED" {
		t.Fatalf("report = %+v", report)
	}
}

func TestJobMapFailsOnARecordThatFailsItself(t *testing.T) {
	records := branching()
	records[1].Reason = "the record fails verification"
	if report := checkJobMap(records); report.Verdict != "FAILED" {
		t.Fatalf("report = %+v", report)
	}
}

func TestJobMapFailsOnARecordOutsideAnyJob(t *testing.T) {
	records := append(branching(), jobRecord{File: "stray.json", Hash: hashOf("e")})
	if report := checkJobMap(records); report.Verdict != "FAILED" {
		t.Fatalf("report = %+v", report)
	}
}

func TestJobMapFailsOnARecordFromAnotherJob(t *testing.T) {
	other := step(hashOf("e"), "other", false)
	other.Job.JobID = "different"
	if report := checkJobMap(append(branching(), other)); report.Verdict != "FAILED" {
		t.Fatalf("report = %+v", report)
	}
}

func TestExternalLinkIsReportedAsNotSuppliedOrVerified(t *testing.T) {
	records := branching()
	records[0].Job.ExternalPrevious = []string{hashOf("9")}
	report := checkJobMap(records)
	if report.Verdict != "COMPLETE" || len(report.External) != 1 || report.External[0].Supplied {
		t.Fatalf("report = %+v", report)
	}
	partner := step(hashOf("9"), "their-step", false)
	partner.Job.JobID = "partner"
	report = checkJobMap(append(records, partner))
	if report.Verdict != "COMPLETE" || !report.External[0].Supplied {
		t.Fatalf("with the record supplied: %+v", report)
	}
}

func TestExternalRecordThatFailsIsNotCountedAsSupplied(t *testing.T) {
	records := branching()
	records[0].Job.ExternalPrevious = []string{hashOf("9")}
	partner := step(hashOf("9"), "their-step", false)
	partner.Job.JobID = "partner"
	partner.Reason = "the record fails verification"
	report := checkJobMap(append(records, partner))
	if report.Verdict != "FAILED" || report.External[0].Supplied {
		t.Fatalf("report = %+v", report)
	}
}

func TestSignatureOverVersion2CoversTheJob(t *testing.T) {
	fields := artifacts.SealedRequestFields{PayloadHash: hashOf("a"), ProgramID: hashOf("b"), RouteID: "r", RegistryRecordHash: hashOf("c")}
	job := &artifacts.JobLink{JobID: "j", StepID: "s"}
	base := string(artifacts.RequestSignaturePreimageV2(hashOf("d"), fields, job, "t", "n"))
	if base == string(artifacts.RequestSignaturePreimageV2(hashOf("d"), fields, &artifacts.JobLink{JobID: "j", StepID: "other"}, "t", "n")) {
		t.Fatal("the signed bytes do not cover the step")
	}
	if base == string(artifacts.RequestSignaturePreimageV2(hashOf("d"), fields, nil, "t", "n")) {
		t.Fatal("the signed bytes do not cover the job")
	}
}

func TestSectionHashCoversTheJobAndLeavesOldRecordsAlone(t *testing.T) {
	plain := artifacts.NrepSection{ActorID: "a", PublicKey: "k", Signature: "s", SignedAt: "t"}
	if plain.SectionHash() != artifacts.ComputeNrepSectionHash("a", "k", "s", "t") {
		t.Fatal("a record with no job hashes differently now")
	}
	withJob := plain
	withJob.Job = &artifacts.JobLink{JobID: "j", StepID: "s"}
	other := plain
	other.Job = &artifacts.JobLink{JobID: "j", StepID: "s", Final: true}
	if withJob.SectionHash() == plain.SectionHash() || withJob.SectionHash() == other.SectionHash() {
		t.Fatal("the section hash does not cover the job")
	}
}

func TestJobValidateRefusesUnsortedAndBadNames(t *testing.T) {
	good := artifacts.JobLink{JobID: "j", StepID: "s", PreviousRecordHashes: []string{hashOf("a"), hashOf("b")}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []artifacts.JobLink{
		{JobID: "bad id", StepID: "s"},
		{JobID: "j", StepID: ""},
		{JobID: "j", StepID: "s", PreviousRecordHashes: []string{hashOf("b"), hashOf("a")}},
		{JobID: "j", StepID: "s", PreviousRecordHashes: []string{hashOf("a"), hashOf("a")}},
		{JobID: "j", StepID: "s", ExternalPrevious: []string{"short"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
