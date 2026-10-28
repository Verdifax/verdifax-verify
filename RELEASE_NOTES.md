# verdifax-verify release notes

Newest first. The [README](./README.md) describes the current release.

### v0.17.11: gates named and tested, receipts under every flag, and the forger's best variant

Round 45 of the external review found two copy groups that a field
the record itself declares could switch off: the proof-of-execution
section's entry number, time and checkpoint were compared with the
anchor only while the section's own ledger name said rekor, and the
PIA hash was compared with the execution ids only while it was present,
so a deleted PIA hash verified in plain mode while the forger mode
reported the same deletion as stopped by AMD's report. The entry
groups now read the anchor's ledger name, which the verifier dispatches
on, and the section's name is a copy of it; the PIA hash must be
carried and equal whenever the AI review's outcome says it ran. Every
condition under which a group compares nothing is now a named gate in
boundcopies.go, with the field a forger would change and the value that
switches the group off; a test switches every gate off on every record
generation and requires the public log or AMD's report to catch it
unless the record already publishes that field as rewritable, and
another fails any group that returns no value for a path the record
carries without a declared gate.

The transcript's input hash no longer has two acceptable sources: from
run 248 (2026-10-18, the first public record built by orchestrator
32d7122) it must equal the execution record's proof hash, and before it
the AER hash, decided by the record's anchored clock. Each category
section's own hash and the copy in its seal are a group (the previous
excuse, that the verifier recomputed both, was false for the seal
copy), and the anchor's ledger name is stated again in the proof
section. The pre-anchor table's rows are compared from one list the
check and the enumeration test share: the policy gate's outcome (when
the EPA carries its block), the run clock (the clock the actor
signature covers) and the deny-receipt row (empty in a sealed run) are
compared now, the two value-checked rows are named as such, and the
allow token's hash is named table-only, since the record displays the
token nowhere.

The flags that apply only to audit bundles (--strict, --allow-partial,
--policy, --show-evidence-summary) were silently ignored on a receipt
document, as --self-hosted-receipt was on a bundle, and --tamper-test
did nothing on a receipt. Every flag now names the inputs it applies to
and is refused with exit 2 on the others, and the tamper test runs on a
receipt document, plain and as a forger who recomputes the receipt's
hash, judging each change by the receipt's hash, its public-log entry
and the entry's signer and timestamps. A receipt document whose ok flag
is false is refused as not one the API serves.

The forger mode tries each change in every copy that held the value,
in one copy alone, and in one copy with each gate of its group switched
off, and reports the variant the forger got furthest with (--json names
it); an edit that only checks a rewrite might satisfy reject is retried
once with a well-formed value, as one that no longer decodes already
was. On the October 2026 hardware run the uncovered paths fall from 55
to 48 and the rewritable paths from 297 to 291: the five category seal
copies, the proof section's ledger name and the provenance block are no
longer rewritable, and the PIA hash is, through the AI-review outcome,
which that record never bound. Run 249 takes 1,134 forger changes; the
public log stops 1,006 and strict reading refuses 128. Every public
record and every readiness record passes unchanged; the round-6 and
round-7 category rewrites in testdata, which left a seal's copy of the
section hash stale, now fail on that copy, and the fuller rewrite that
updates the copy keeps the partial verdict those records earned.

### v0.17.10: every duplicated value accounted for, and the attestation summary compared with the report

Round 44 of the external review found twelve values the record stores
twice that the v0.17.9 copy check did not cover, each rewritable on the
October 2026 hardware run while its original was bound: the AIVP
kernel's output id stated again as the PIA hash, the run entry's
number, time and checkpoint stated again in the proof-of-execution
section, the transcript's input hash (a copy of the AER hash), and the
guest measurement, report id, TCB values, report version and report
data stated in the attestation's verification block. The copy groups
now cover the first three kinds and more (the sequence id, the record
clock, the manifest hash, the server commit, the migration token's
state hash, the transcript hash and the caller's attested decision, each
stored twice), and a SEV-SNP record's verification block, measurement
and report-data fields are compared with the raw AMD report instead of
being trusted. A test enumerates every value the published records store
more than once and fails unless each is a copy group, is checked
another way, or is a listed coincidence of independently declared
values. Every public record and every readiness record passes
unchanged; the round-6 and round-27 rewrites that flipped the AER's
decision alone now fail outright, because the EPA's attested context
still carries the original.

The forger mode writes a change into every copy that held the same
value (not into every path of a group), handles list items and numbers
as copies, and places a change caught by several checks in the first
tier of the stated order. On the hardware run the rewritable paths fall
from 320 to 297, the uncovered paths from 72 to 55, and the AMD tier
grows from 23 to 53 changes; run 249 takes 1,130 changes, the public log
stops 1,002 and strict reading refuses 128. Internal: the synthetic
round-7 fixtures carry their test log's entry in the proof-of-execution
section, as a real record would.

### v0.17.9: every copy of a bound value must agree, and the rewritable paths listed

A record stores some values more than once: the envelope identifier in
three sections, each section's sealed hash again in the final VFA, the
AER hash in the final VFA, the proof-of-execution section and the
execution record, the transport, program and payload hashes in the
execution record, the envelope and the payload, and the six execution
ids in three lists. The public-log entry or AMD's report binds one copy;
the others were read by nothing, so a rewrite could change a copy and
keep the bound value. Verification now fails when any copies disagree.
This is a new check in normal verification; every public record and
every readiness record passes it unchanged.

`--tamper-test --recompute-hashes` writes a change to such a value into
every copy, as a forger would, and lists the rewritable paths (paths
where a change verifies after the rewrite) with their number, in the
report and in `--json` as `rewritable_paths`. A change that only an
internal hash or a consistency check rejects, but whose rewrite still
fails, now has its own tier instead of counting as not stopped. On the
October 2026 hardware run the rewritable paths fall from 372 to 320 and
its uncovered paths from 82 to 72; run 249 takes 1,131 changes (the
public log stops 1,003, strict reading refuses 128). The release
workflow now runs the full test suite on the tagged commit and builds
nothing unless it passes.

### v0.17.8: strict tiers for `--recompute-hashes`

v0.17.7 counted a change as stopped when a decode failure or the actor
signature caught it. A decode failure can come from the test's own
malformed edit, and Verdifax holds the actor keys, so neither shows that
the public log catches a forger. Each change now lands in one tier:
stopped by the public log, stopped by AMD's signed report, refused by
strict reading, stopped only by the actor signature, or not stopped. An
edit that no longer decodes is retried with a well-formed value, and
`--json` lists every change with its checks and tier. The test exits 0
only when no change is left not stopped or stopped only by the actor
signature. On every complete public record the public log stops every
change except unknown keys and a removed record kind, which strict
reading refuses (run 249: 1,005 and 128 of 1,133). Normal verification
is unchanged.

### v0.17.7: which check caught each change, and `--recompute-hashes`

`--tamper-test` now names, for every change that fails, the checks that
caught it. The new `--recompute-hashes` flag makes the test play a
forger who recomputes every hash the record stores after each change,
so only the public-log entries, their signer and timestamps, the actor
signature and AMD's report signature can stop it. It reported every
change stopped on every complete public record (run 249: 1,133), a count
v0.17.8 corrected, and 372 rewritable paths on the October 2026 hardware
run, a count v0.17.9 replaced with 320 under a published counting rule.
No check, verdict or exit code of normal verification changes.

### v0.17.6: `--tamper-test` covers empty values, sections and additions

v0.17.5's tamper test changed only non-empty values and deleted only
keys that held one. It now also changes empty, false, zero and null
values, deletes whole sections and lists, removes and appends list items,
and adds an unknown key to every object; deleting a key that holds an
empty value is not tried, since the record reads the same without it. On
every complete public record each change still fails (run 249: 1,232
changes). On the October 2026 hardware run the uncovered list grows from
74 to 82 paths: the AI review summary, actor and formal-verification
sections can be deleted whole, an empty halt-receipt hash can be filled
in, and two scaffold flags can be flipped. No check, verdict or exit
code changes.

### v0.17.5: `--tamper-test`, and uncovered fields named

`--tamper-test` runs the check both Verdifax offers ask a customer to
make: change a sealed record and see it fail (see above). For a record
without a complete-record anchor, the report now names every field no
hash covers on a `Not hash-covered` line, and `--json` adds
`uncovered_fields`. No check, verdict or exit code changes. The October
2026 hardware run is added to `testdata/round40` with tests for both.

### v0.17.4: README corrections

Documentation and the version string only; the verification code is the same as
v0.17.3. The v0.10.0 notes
now say to re-verify with v0.17.2 or later instead of naming v0.14.5,
which is retracted. Supported versions now says
exactly which Go commands warn about a retracted release and which ways
of pinning a version Go does not check.

### v0.17.3: releases before v0.17.2 are retracted

`go.mod` retracts every release from v0.1.0 to v0.17.1 (see Supported
versions). No check, verdict or exit code changes from v0.17.2. A new
test, `TestKeyPeriodsOverlapOnlyInKey2sDocumentedWindow`, fails if any
second is accepted by no key, or by two keys anywhere except key 2's
documented one-hour window around the hardware run's entry, which lies
inside key 1's period by design.

### v0.17.2: built with Go 1.27.3

The same verification code as v0.17.1 (only the version string changes),
built with Go 1.27.3, which fixes a Go
standard-library advisory (GO-2026-6809: crypto/x509 now refuses known
compromised intermediate certificates). The verifier reaches that code
only through the standard library; no check, verdict or exit code
changes. Every workflow (tests, fuzzing, CodeQL and release) now uses
Go 1.27.3, and `govulncheck` reports no vulnerabilities.

### v0.17.1: no second at which two keys are both accepted

In v0.17.0 a key's period included its end second, so at exactly
2026-10-24T15:59:19Z both key 1 and key 3 were accepted. No entry was
logged at that second, and Rekor's signed entry timestamp means none can
be now, but the overlap had no purpose. From this release every period
runs from its start up to, but not including, its end: key 1 is
accepted only for entries logged before the switch, and key 3 from the
switch on. Key 2's one-hour window around the hardware run's entry is
unchanged in effect. Every public record and test vector keeps its
verdict and exit code. `TestExactlyOneKeyIsAcceptedAroundTheSwitch`
checks the second before, at and after the switch.

### v0.17.0: log-signing key 3, held in AWS KMS

The production orchestrator now signs public-log entries with key 3,
an ECC_NIST_P256 key in AWS Key Management Service whose private key
never leaves KMS (orchestrator aef1b3e and 04d06fd). The switch took
effect at 2026-10-24T15:59:19Z. This release pins key 3 for entries
logged from that moment on and limits key 1, whose private key was a
file on the server volume, to entries logged up to it, so a copy of
key 1 can never vouch for a later entry. Every record logged before the
switch verifies exactly as before.

Key 3 signed three entries before this release was published, all from
private test runs on the day of the switch. Entry 3441033974 is the
run entry of private test run 254. The server then signed the run's
complete-record entry with the old key path, which is empty once KMS
signing is configured, so run 254 stopped before that entry: it has no
complete record and nothing a verifier can check, and its stored run
row still reads as successful. Orchestrator 04d06fd fixed it, and run
255 then logged both of its entries (3441086489 and 3441086501). Tests in `key3_test.go` check that
key 1 is refused after the switch and key 3 before it.

### v0.16.0: a partially covered record is not reported as verified, and exits 3

A record the public log covers only in part, either sealed before leaf
v5 (the October 2026 hardware run is one) or a v5 record without a
verified complete-record anchor, printed `VERIFIED AND ANCHORED, PARTIAL
COVERAGE` and exited 0. Its descriptive sections, including the
decision, the approval chain and the real-world effects, are sealed only
by hashes inside the bundle. An external review on 2026-10-19 took the
published hardware run, flipped its decision to deny, changed the
approver, added a confirmed wire transfer and raised its SLSA level,
recomputed those hashes and kept the real public-log entry; v0.15.3
reported it as verified with exit code 0, so a script gating on exit
status accepted it. The limit was disclosed, but the verdict and exit
code vouched for it.

From v0.16.0 such a record reads `ANCHORED, PARTIAL COVERAGE`, with a
line saying not to rely on the unanchored sections. The JSON
`verdict_tier` is `ANCHORED_PARTIAL_COVERAGE` instead of
`VERIFIED_ANCHORED`, and the exit code is 3. `--allow-partial` restores
exit 0 for anyone who accepts partial coverage knowingly. No check
changed: every record passes or fails exactly as before, and
complete-record anchored records, receipts and failures keep their
verdicts and exit codes. Tests in `round27_test.go` replay the
reviewer's rewrite of the hardware run and the six round-six rewrites.

### v0.15.3: the record identity line says what the identifier is

Report wording only; no verdict changes. The envelope identifier v0.15.2
checks is derived from the payload the caller sends (`env-` followed by
the first sixteen hex characters of its admission hash): it repeats when
the same payload is sent again (runs 237, 238 and 239 share one) and is
not a unique run number. v0.15.2's report and this README called it a
run identifier minted by the server; v0.15.3 says what it is. The check
itself is unchanged and its reason is unchanged: every `/attest`
preimage carries `attest:` where a record carries this identifier, and
`/attest` has used that prefix since its first version (orchestrator
27da552, 2026-09-03T01:47Z).

### v0.15.2: a record must carry a run envelope identifier

The orchestrator's `POST /attest` endpoint signs, with log-signing key 1,
a leaf in the same legacy form as records sealed before run 236, carrying
`attest:<key id>:<subject>` where a record carries its envelope
identifier and the caller's digest where a record carries its execution
record hash. v0.15.1 and earlier would accept a record built around such
an entry and report it as VERIFIED AND ANCHORED with partial coverage
(the pre-v5 tier; never complete-record coverage, which needs a second
entry of a form `/attest` never produces). v0.15.2 fails any anchored
record whose envelope identifier is not a run envelope identifier
(`env-` followed by the first sixteen hex characters of the payload's
admission hash), and any record in a pre-table leaf form (v1, v2 or v3) whose
entry the log integrated at or after run 236's first entry
(2026-10-15T19:51:06Z). Every genuine record keeps its verdict; a test
builds the forgery and checks it fails.

### v0.15.1: --policy refuses documents other readers would read differently

From an October 2026 external review. `--policy FILE` now reads the
policy document under the strict rules bundles are read with
(`internal/artifacts/strictjson.go`) and refuses, before any hash is
computed: a key that is not byte-for-byte a field of the policy
document (an unknown key such as an extra `override_rules` array, which
Go ignored while jq or Python kept it; or a case variant such as `Rules`
for `rules`, which Go matched while other readers saw no rules); two
keys in one object equal under case folding, including exact
duplicates; a number not written in its canonical spelling (`1.0`,
`1e2`); invalid UTF-8, an unpaired surrogate escape or NUL in a string;
and any rule that sets a non-zero `priority`, a reserved field that no
evaluation code reads and the policy hash excludes, so two documents
differing only in it hashed the same. Such a document is now refused
with the path named, instead of hashing as if the extra content were
not there. Verdicts of every record are unchanged, and the production
default policy keeps its hash. The orchestrator's own policy reader
(`psl.Parse`) applies the same rules from the same date, so a policy
document is read the same way, or refused, by both.

### v0.15.0: the policy gate's decision is read, and a policy document can be checked

Records sealed from orchestrator 564f1d4 (October 19, 2026 UTC) on
carry `epa.policy_gate`; this release reads it, prints it, and adds
`--policy FILE` (see above). Verdicts of every existing record are
unchanged: the section is covered by the existing EPA section hash,
whose recipe appends it last and omits it when absent, so a record
sealed before the field existed hashes exactly as before. The
policy-hash port is checked byte for byte against the orchestrator's
own hashes. One deliberate difference from the orchestrator's policy
reader: a document that names the same key twice in one object (exact
or case-variant) is refused, because other readers would keep different
values.


### v0.14.7: SEALED requires the public-log entry and its signer

Report wording only; no verdict changes. v0.14.6 and earlier set the
actor line's SEALED label once the leaf rebuilt from the record matched
the leaf hash the record itself states. An editor who substitutes the
actor section, re-signs it with their own key, rebuilds the pre-anchor
table and recomputes that stated leaf hash got the label, although the
public-log entry no longer matched and the verdict was FAILED with exit
code 1 under every flag. v0.14.7 sets SEALED only when the public-log
entry also matches (inclusion proof, signed checkpoint, and the entry
naming this leaf) and a published Verdifax log-signing key signed it.
This applies to version-3 leaves as well as versions 5 to 7. Genuine
records keep the label; a test substitutes run 249's actor section.

### v0.14.6: the actor section on leaf v5 to v7 records reads as sealed

Report wording only; no verdict changes. On records anchored with a
version 5, 6 or 7 leaf, the anchored pre-anchor table carries the actor
section's four values (actor id, public key, signature and signing
time), and the verifier already checked each against the record, so a
changed actor section already failed. The report now says so: when the
signature verifies, the leaf is this run's and the table is consistent,
the actor line reads "consistent and SEALED to the anchor", as it
already did for version 3 leaves. The key is still the one the record
supplies, so the line still says identity is not established. Production
run 249 is carried as a test.

### v0.14.5: strings every reader reads the same way

From an October 2026 review by Google Gemini. Strict reading now also
refuses invalid UTF-8, an unpaired UTF-16 surrogate escape, and the NUL
character in any string. Go replaces the first two with U+FFFD while
other readers keep or reject them, so a reader and this verifier could
show different text; NUL is the separator several sealed digests join
on. The Verdifax API refuses NUL in requests, and no genuine record
carries any of the three, so every real record keeps its verdict. Tests
also pin that `-0` is refused and that small and large numbers follow
the canonical spelling (`0.00005`, `5e-7`, `1e+21`).

### v0.14.4: every receipt failure names every cause

Wording only, from round fourteen of the external review; no verdict
changes. The run 242 cutover failure and the off-log anchor failure now
name every cause (rewritten, invented, an altered anchor, or a
deployment that does not anchor receipts), and a receipt clock written
with an offset is printed with its UTC instant, so it no longer reads as
contradicting the UTC cutover.

### v0.14.3: the receipt cutover message names every cause

Wording only, from round thirteen of the external review; no verdict
changes. The run 241 cutover's failure now names every way a receipt
can lack an anchor (stripped, invented, anchoring failed at issue time,
or a deployment that does not anchor receipts) instead of stating that
every receipt since then carries one, and the README states that the
remaining limit covers invented receipts too, not only stripped ones.

### v0.14.2: receipts dated from run 241 on must be anchored

Answers round twelve of the external review, which found no break and
suggested this. A receipt dated at or after run 241's clock, the first
receipt the Verdifax API anchored on the public log, fails if it carries
no public-log anchor, even with `--allow-unanchored`, unless
`--self-hosted-receipt` is passed. A stripped receipt now has to claim a
date before receipt anchoring began to be reported as self-consistent
only. Every real record and receipt keeps its verdict.

### v0.14.1: receipts dated from run 242 must seal anchor_required

Answers round eleven of the external review, which found no break and
suggested this. A receipt dated at or after run 242's clock without
`anchor_required` fails, even with `--allow-unanchored`; the new
`--self-hosted-receipt` flag exempts receipts the person checking knows
came from a deployment that does not anchor receipts. A stripped
receipt now has to claim an earlier date to be reported as
self-consistent only. The usage text now lists `-allow-unanchored` and
receipts. Every real record and receipt keeps its verdict.

### v0.14.0: receipt anchor v2, run numbers bound

Answers round ten of the external review. A v1 receipt's run number
was printed as part of its identity although no hash or log entry
binds it; it is now printed as "from the document, not checked", and
receipts lead with their envelope. Receipt anchor v2 binds the run
number in the leaf, and receipts anchored under v2 seal
`anchor_required`, so deleting, downgrading or moving their anchor
fails. Existing receipts and records keep their verdicts; run 241
verifies as before.

### v0.13.1: receipt messages name the receipt

Wording only; no verdict changes. A receipt document refused by strict
decoding is now reported as a receipt ("Receipt JSON"), not as a
bundle; a receipt followed by trailing data is refused for that data
instead of being read as a bundle with an unmodeled key; and a
public-log leaf mismatch says "the record claims" rather than "the
bundle claims". Adds the first production receipt anchored on the
public log (run 241, 2026-10-16, log-signing key 1) as a test vector.

### v0.13.0: receipts, and pinned number spelling

Checks refused and halted runs' receipt documents and their public-log
anchors (`receipt_anchor`, recipe `verdifax.ledger.receipt.v1`, window
600 seconds), with `--json` output carrying `receipt_hash_ok`,
`record_values`, `anchored`, `signer_fingerprint`, `anchored_at` and
`anchor_gap_seconds`. This replaces the private receipt checker the
documentation used to name. Numbers must now be written in their
canonical form; every public Verdifax record keeps its verdict.

### v0.12.1: one record, whoever reads it

Refuses bundles whose JSON is ambiguous across readers (keys equal
under case folding, exact duplicate keys) or carries keys this verifier
does not model, with `FAILED` and exit code 1, as described under
[What this verifier proves](#what-this-verifier-proves-and-doesnt-prove).
Every public Verdifax record decodes strictly and keeps its verdict.
The report prints the checked decision values (`Record says`; JSON
`record_values`).

A copy of a record downloaded before 2026-10-16 that still stores the
entry's shard position as its entry number now fails with a reason
that says so and asks for a fresh download (`stale_entry_number` in the
JSON report), instead of a message that reads as tampering. The default
failure verdict now reads "at least one check did not pass" rather than
naming hashes, since a failure can also be a signer, timestamp or
window check.

Upgrade from v0.12.0: it accepts the case-variant forgery.

### v0.12.0: who logged an entry, and when

Pins the Verdifax log-signing keys, verifies every entry's signature and
Rekor's signed entry timestamp, requires a run's two entries to share
one signer with the record entry no older than the run entry, and adds
pre-anchor table version 3 and the version-7 leaf with a sealed
anchoring window, as described under
[What this verifier proves](#what-this-verifier-proves-and-doesnt-prove).
The JSON report gains `entry_authentication` (`signer_fingerprint`,
`signer_name`, `run_anchored_at`, `record_anchored_at`, `clock_epoch`,
`anchor_gap_seconds`, `window_sealed`, `anchoring_window_seconds`,
`reason`), and the human report gains `Logged by`, `Logged at` and
`Anchoring window` lines.

Every public Verdifax record verified under v0.11.0 keeps its verdict
under v0.12.0: all 48 entries of the 46 public records on
`api.verdifax.com` are signed by key 1 with valid signed entry
timestamps. One published record did not: the hardware evidence bundle
on verdifax.com stored the entry's shard position (2953123752) where the
global entry number (3075028014) belongs, so its signed entry timestamp
could not verify. A repaired copy, with only `rekor_anchor.log_entry_id`
and `rekor_anchor.signed_entry_timestamp` taken from the public log, is
in `testdata/round8/` and verifies.

Upgrade before relying on any record: v0.11.0 and earlier accept a
record re-logged under any key, and do not know table version 3, so
they report every genuine leaf v7 record as FAILED (the table has 35
rows where they expect 34).

### v0.11.0: deleting the complete-record anchor is detectable

Adds pre-anchor table version 2 and the version-6 leaf, and fails any
record whose anchored table requires a complete-record anchor it does
not carry, as described under
[What this verifier proves](#what-this-verifier-proves-and-doesnt-prove).
The JSON report gains `complete_record_requirement` (`sealed`,
`satisfied`, `reason`) and `pre_anchor.table_form`; the evidence
summary gains `record_anchor_requirement`. Every v5 and older record
receives exactly the verdict and exit code it received under v0.10.0;
the six round-seven strip forgeries of run 238 are kept in
`testdata/round7/` with that honest partial verdict, beside a synthetic
v6 strip that fails.

Upgrade before relying on new records: v0.10.0 and earlier do not know
table version 2 and report every genuine leaf v6 record as FAILED (the
table has 34 rows where they expect 33). That is a refusal, never a
false pass, but it means a relying party on an older release cannot
accept records sealed after the leaf v6 deploy.

### v0.10.0: complete-record anchor, and a closed leaf-binding gap

Adds the complete-record anchor check and the honest partial verdict
described under
[What this verifier proves](#what-this-verifier-proves-and-doesnt-prove),
and recomputes the `reproducibility_context` section hash, which earlier
releases left unchecked even though the bundle hash covers it.

It also closes a verification gap present in v0.1.4 through v0.9.0. From
v0.1.4 (2026-05-29) the Rekor check computed the Merkle leaf from the
anchor's `entry_body`, as it must, but no release ever compared that body
to the bundle's `leaf_hash`. Every check that rebuilds the leaf from the
bundle's own contents (the run binding from v0.5.0, the v3 actor and
scaffold seal from v0.8.0, the v5 pre-anchor table from v0.9.0) compared
its result against `leaf_hash`, a value the log never saw. A party able to
rewrite a bundle could therefore change any value those checks protect,
recompute the leaf, write it into `leaf_hash`, and keep the genuine
body, proof and checkpoint; the bundle still verified as anchored. This
was found on 2026-10-16 while reproducing the round-six review, and it
was demonstrated against live run 237 by rewriting an anchored
pre-anchor value: v0.9.0 printed `VERIFIED AND ANCHORED, FULL PRE-ANCHOR
COVERAGE`. That forged bundle is kept as
`testdata/round6/L1_leaf_hash_swapped_genuine_entry_body.json` and fails
under v0.10.0. Releases v0.1.0 through v0.1.3 did not read `entry_body`; they
walked the proof from `leaf_hash` itself, so this gap did not arise in
them. Re-verify any bundle
you accepted with an earlier release using v0.17.2 or later.
