# verdifax-verify

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15320/badge)](https://www.bestpractices.dev/projects/15320)

`verdifax-verify` is the standalone, independent verifier for Verdifax
audit bundles. It reads a bundle JSON file (or stdin), recomputes every
section hash, the bundle hash, the pre-anchor table digest and the
anchored ledger leaf from the bundle's own content, and compares each
against the recorded value to detect tampering. It also confirms that
every section is bound to the same manifest hash. The run's public-log
anchor binds its identity values and, for version-5 bundles, a 33-value
pre-anchor table. From v0.10.0 a bundle may also carry a complete-record
anchor (`bundle_anchor`), a second public-log entry that binds every
section of the record; bundles without one have their descriptive
sections sealed inside the bundle only. From v0.11.0, records sealed with
the version-6 leaf state inside their anchored values that a
complete-record anchor must exist, so deleting it makes the record FAIL
instead of reading as partial coverage. From v0.12.0, every public-log
entry must be logged by a published Verdifax log-signing key, and its
anchoring time and entry number are authenticated by the log's signed
entry timestamp. See
[What this verifier proves](#what-this-verifier-proves-and-doesnt-prove). The manifest hash
itself is not recomputed here: its preimage includes fields held only
in the orchestrator's stored manifest, which the orchestrator re-derives
server-side for authenticated callers at `GET /runs/{id}/verify`. To
show the formula, production run 249's full manifest preimage is
published as `testdata/manifest-vectors/run-249-manifest-preimage.json`: its 67
parts, joined with `.`, hash to run 249's manifest hash, the last part
recomputes from the execution record fields, only the leading domain
tag contains a dot, and the parts include the bundle's envelope id,
public-log leaf and entry, and actor fields
(`round21_manifest_test.go`).

It is the offline-verification path for Verdifax bundles: given just a
bundle file, this binary decides whether the evidence is internally
consistent. Verification itself makes no network calls, needs no
Verdifax credentials, and places no trust in the Verdifax API server:
the Sigstore Rekor inclusion proof is checked offline against a Rekor
public key embedded in the binary, and the entries' signers against the
published Verdifax log-signing keys also embedded in it
([Log-signing keys](#log-signing-keys)). That makes those keys, which
Verdifax holds, part of what a passing verdict relies on. The one
network operation is
optional input retrieval: passing an `http://` or `https://` URL instead
of a file path makes the binary fetch the bundle with a single GET
request (30 second timeout, 32 MiB cap) before verifying it exactly as
it would a local file. Pass a file path or stdin to keep the whole run
offline.

## License

The Clear BSD License (SPDX `BSD-3-Clause-Clear`), see
[`LICENSE`](./LICENSE), from v0.5.0. Releases through v0.4.0 were
published under MIT and remain available under it. The Clear BSD
License is as permissive as MIT for using, copying and modifying the
code, and states explicitly that it grants no patent rights. The
verifier is intentionally open-source so auditors can read the code
that adjudicates evidence.
The verifier produces no attestations of its own; it only checks that
a received bundle is internally consistent.

## Install

### From source

```bash
go install github.com/Verdifax/verdifax-verify@latest
```

Requires Go 1.27 or later. The binary lands at `$(go env GOPATH)/bin/verdifax-verify`.

### Pre-built binaries

Pre-built binaries for Linux and macOS (amd64 and arm64) are attached
to each [GitHub release](https://github.com/Verdifax/verdifax-verify/releases).
There is no pre-built Windows binary; on Windows, build from source with
`go install` as above.

## Usage

```bash
verdifax-verify bundle.json           # verify a file, print human report
cat bundle.json | verdifax-verify     # verify from stdin
verdifax-verify --json bundle.json    # machine-readable JSON output
verdifax-verify --strict bundle.json  # also fail on any scaffold-flagged value
verdifax-verify --policy policy.json bundle.json  # also check a policy document against the sealed policy gate
verdifax-verify --allow-partial bundle.json       # exit 0 for a record the public log covers only in part
verdifax-verify --tamper-test bundle.json         # change every sealed value one at a time and confirm each change fails
verdifax-verify --tamper-test --recompute-hashes bundle.json  # the same, as a forger who also recomputes every hash the record stores
verdifax-verify --version
```

Flags go before the record path. Since v0.15.1 an argument after the
path is refused with exit code 2 instead of being ignored, so a
misplaced `--policy` can never pass as "checked".

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Every check passed, and the public log covers the complete record (or the input is a receipt, which its entry covers whole). |
| 1 | One or more verification checks failed (or `--strict` + scaffold), including JSON that strict reading refuses as malformed or ambiguous. |
| 2 | The input could not be read (a missing file or a failed download), it was read but could not be decoded as a bundle or receipt, or a flag was given that does not apply to the input's kind (since v0.17.11, instead of being ignored). |
| 3 | Every check passed, but the public log covers only part of the record (a record sealed before leaf v5, or one without a verified complete-record anchor), and `--allow-partial` was not given. Since v0.16.0. |

A script that treats exit 0 as a pass accepts only complete-record
anchored records. Until v0.15.3 a partial record exited 0, although its
descriptive sections, the decision among them, could have been rewritten
together with their hashes.

### `--tamper-test`: a changed record fails

`--tamper-test` changes every value of the record one at a time, empty,
false, zero and null values included (a string gains a character or an
empty one becomes "x", a hash changes its first digit, a number gains
one, a boolean flips, null becomes a string); deletes every key that
holds a value, whole sections and lists included; removes every list
item and appends a copy of each list's last item; and adds an unknown
key to every object. It runs the full verification on every changed
copy. Deleting a key whose value is empty, false, zero or null, or a
section made only of such values, is not tried: a missing value reads as
that value, so the record's meaning does not change. It reports how
many changes it tried and lists any copy that did not fail. It exits 0
only when every change fails, 1 when any change is accepted or the
record itself does not verify, and 2 when the record cannot be read.
On a record whose complete-record anchor is required (successful runs
sealed from run 239 on) every change fails: run 249 in `testdata/round18` takes
1,232 changes and rejects all of them.

On a record without a complete-record anchor, some fields are covered
by no hash, and changing one leaves the record verifying with its
partial-coverage verdict. Since v0.17.5 the normal report lists those
fields on a `Not hash-covered` line (and `--json` lists them as
`uncovered_fields`), found by the same method. The October 2026 hardware
run is such a record: 48 of its paths are uncovered, among them the AI
review summary (`aivp_t4`, which can also be deleted whole), the
attestation's report-data recipe and certificate text, the actor section
(`nrep`), the formal-verification section, the scaffold flags of the
attestation and proof-of-execution sections, the record's status and run
number, the label inside
each section's seal, and the reference hash in the final VFA's seal (the
five category sections' seal copies are compared with each section's
own hash since v0.17.11). Its raw SEV-SNP
report (`quote_b64`), which the verifier checks against AMD's root and
binds to the record's own values, its execution record and its
anchored identity values are covered.

Since v0.17.9 the verifier checks that copies of a value the record
stores more than once agree, and a record whose copies disagree fails,
so a reader of any checked copy reads the value the public-log entry or
AMD's report binds. The copies it checks are the 37 copy groups and one list group listed in
`boundcopies.go`: the envelope identifier in the envelope, transport and
AER sections; each section's sealed hash and its copy in the final VFA
(and, for the envelope, in the transport section); the AER hash in the
final VFA, the proof-of-execution section and the execution record; the
transport, program and payload hashes in the execution record, the
envelope and the payload; the six execution ids in the AER, the EFA
steps and the execution record, with the AIVP kernel's id again as the
PIA hash of the AI-review section; the run entry's number, time, checkpoint and
ledger name again in the proof-of-execution section; the transcript's
input hash (the execution record's proof hash from run 248 on, the AER
hash before it, decided by the record's anchored clock); a SEV-SNP record's measurement, platform and report data
again in its verification block; the sequence id, the record clock,
the manifest hash, the server commit, the migration token's state hash
and the transcript hash each stated twice; the caller's attested
decision in the EPA and the AER; and each category section's own hash
in its seal. Round 44 of the external review found
twelve copies the first list missed, so since v0.17.10 a test
enumerates every value the published records store more than once and
fails unless each is one of these groups, is checked another way (the
pre-anchor table, the seals' manifest hash, a section's own hash, the
anchors' inclusion proofs, the AMD report) or is a listed coincidence of
independently declared values with its reason. A SEV-SNP record's
verification block (report version, measurement, report id, TCB values,
report data, signing key type and certificate fingerprints) is compared
with the raw AMD report since v0.17.10, with the section's measurement
and report-data fields, instead of being trusted. A group that compares
nothing under some condition (an anchor that names no public log, an AI
review that did not run, a record without a SEV-SNP report or an
execution record, a record built before run 248) names the field that
decides it as a gate, since v0.17.11, with the value that switches the
group off; a test switches every gate off on every record generation
and requires the public log or AMD's report to catch it, unless that
record already publishes the field as rewritable, and a group that
reads no value for a path the record carries without a declared gate
fails the build. Round 45 of the external review found two groups a
declared field could switch off (the entry copies read the proof
section's own ledger name; a deleted PIA hash was skipped). Three groups describe values the server did not always write equal in its first months, so since v0.17.14 each is compared everywhere except inside the windows, by the time the public log signed the record's first entry (which the log's signed entry timestamp covers), where the server's stored records wrote them differently: the proof section's ledger name and Rekor time for records anchored from 2026-05-05T23:18:36Z to 2026-05-28T20:28:03Z, its checkpoint from 2026-05-05T23:18:36Z to 2026-05-29T14:12:37Z and from 2026-06-03T07:40:00Z to 17:26:01Z, and the PIA hash as the fifth execution id from 2026-05-06T09:40:55Z to 2026-10-02T16:25:46Z. Each window spans a run of consecutive stored records that all wrote the copies differently, found by running the verifier read-only over every record the server has stored, and a test fails if any window switches off copies a genuine fixture wrote equal. Those stored records are private, so the windows cannot be reproduced from public data; of the genuine fixtures in this repository, only run 208 falls inside a window, the PIA window, where its copies differ. v0.17.10 to v0.17.12 compared the groups on every record and so rejected genuine records sealed before those dates, run 208 (June 2, 2026) in `internal/artifacts/testdata` among them; v0.17.13 used one boundary per group, which left run 208's checkpoint copy, written equal, uncompared; v0.17.14 compares it again. Since v0.17.13 a test lists every record and receipt fixture in the repository with the verdict it must earn and fails on any fixture it does not list, and the copy, duplicate and gate tests read every genuine record from that list; since v0.17.14 the forger's rewritable-path count on every genuine fixture is pinned too.

For every change that fails, the report also names the checks that
caught it, since v0.17.7: an internal hash, the first public-log entry,
the complete-record entry, the entries' signer or timestamps, the actor
signature, AMD's report signature, a consistency check, or a record that
no longer decodes. A change can be caught by more than one.

### `--recompute-hashes`: does the public log catch it?

A single edit breaks the hash of the section it sits in, so the
default test shows that some hash covers each field, not that the public
log does. A forger who rewrites a record would also recompute the
hashes stored inside it. With `--tamper-test --recompute-hashes`
(since v0.17.7) the test plays that forger: after each change it
recomputes every hash the record itself determines and stores the new
value wherever the old one appeared, until every internal hash agrees.
What no rewrite can recompute is left as it was: the signed public-log
entry bodies and their timestamps, the actor signature and AMD's signed
report. Editing or deleting a stored hash is not counted, since the
recomputation restores the original record. Since v0.17.9 a change to a
value the record stores more than once is written into every copy that
held the same value, so the copy check is never what stops it. Since
v0.17.11 the forger tries each change in every copy that held the value,
in one copy alone, and in one copy with each gate of its group switched
off, and reports the variant it got furthest with (`--json` names it as
`variant`), so a change that verifies in one copy is never shown as
stopped because its spread form was caught.

Since v0.17.8 each change lands in one tier: stopped by the public log
(the first public-log entry, the complete-record entry, or the entries'
signer or timestamps caught it), stopped by AMD's signed report, refused
by strict reading (an unknown key, or a record that no longer reads as a
bundle, which the verifier refuses before any check), stopped only by
the actor signature, whose keys Verdifax holds, or not stopped. Since
v0.17.9 a change that only an internal hash or a consistency check
rejects, but whose rewritten record still fails, lands in its own tier
(rejected only by checks a rewrite might satisfy, no verifying rewrite
found) instead of not stopped: it is neither shown stopped nor shown
rewritable. "Not stopped" now means the rewritten record verifies. An edit
that no longer decodes, or that only checks a rewrite might satisfy
reject, is retried once with a well-formed value of the
same form (a number gains one, a timestamp a second, a hex or base64
value changes one character within its alphabet), since a forger writes
values the record can hold. The test exits 0 only when every change is
stopped by the public log, AMD's report or strict reading, and `--json`
lists every change with every check that caught it and its tier. A
change caught by several checks counts in the first of the tiers in the
order above (the public log before AMD's report, before strict reading,
before the actor signature).

The report also counts the rewritable paths: the paths where a change
verifies after the rewrite. A path is counted once however many changes
reach it: list indices read as `[]`, an unknown key added to an object
as `<object>.(added key)`, and an item appended to a list as
`<list>[] (appended item)`. `--json` lists them as `rewritable_paths`,
with their number in `rewritable_path_count`.

On every complete public record no change relies on the actor
signature and none is left unstopped: run 249 in `testdata/round18`
takes 1,134 changes; the public log stops 1,006 of them, and strict
reading refuses the other 128, each an unknown key added or the record's
kind removed. On the October 2026 hardware run, which predates the
complete-record anchor, a full rewrite can change 291 of its paths,
among them the decision, as the evidence page states; each is listed
with its rewritten record verifying. Of its other changes, 51 (mostly a
whole section or seal deleted) are rejected only by checks a rewrite
might satisfy, with no verifying rewrite found, and 3 are stopped only
by the actor signature. It cannot change the raw AMD report
or the execution record's inputs that report signs, the measurement,
report id, TCB values and report data the attestation summary states,
the envelope
identifier and the AER and binding seal hashes the public-log entry
binds, any copy of those values elsewhere in the record, or that entry
itself, with one exception: the AI review's PIA hash equals the fifth
execution id only while the review's outcome says the review ran, and
this record binds that outcome nowhere, so a rewrite that declares the
review skipped frees the PIA hash with the rest of the AI review summary
(since v0.17.11 the tool tries that rewrite and lists the path).

### `--strict` mode

By default, the verifier reports scaffold-flagged values (the ZK
transcript, hardware attestation, timing declarations and ZK-state-prover
binding; every hosted-API run carries all four, see
[Verdifax scaffold-gaps documentation](https://docs.verdifax.com/concepts/scaffold-gaps/))
without failing the run. Pass `--strict` to fail verification when any
scaffold flag is set. High-trust environments should always use
`--strict`.

## What this verifier proves and doesn't prove

**Proves:** the bundle is internally consistent: every recorded hash
matches its canonical preimage, so editing a field without also
recomputing the hashes over it fails verification. An editor who
rewrites the whole bundle can recompute every section hash and the
bundle hash; only the values bound to the public-log anchor, described
below, resist that.

**Also proves, since 2026-09-08:** that the Sigstore Rekor entry the
bundle names is *this run's* entry and not someone else's. The verifier
rebuilds the leaf preimage from the bundle's own `envelope_id`,
`aer_hash` and `zksp_binding_hash` (plus `input_nonce` where present)
and confirms it hashes to the anchored leaf.

That check did not exist before. Until then this tool proved two things
separately and never joined them: that the manifest was internally
consistent, and that some leaf was genuinely inside Rekor's tree. A
bundle citing a real Rekor entry belonging to a different run satisfied
both and verified cleanly. It now fails, and the failure is a failure,
not an advisory line.

**Also checks, since v0.7.0, with the honest wording tightened in
v0.7.1:** the Ed25519 actor signature in the bundle's `nrep` section,
rebuilt from this run's `envelope_id`, `aer_hash` and `signed_at` and
validated against the public key the bundle itself supplies. Read that
last clause carefully: because the key comes from the bundle, on records
sealed before the v3 leaf (v0.8.0), whose nrep section is covered by
neither the bundle hash nor the public-log leaf, an attacker can replace
the whole section with a self-consistent one of their own, and this
check cannot tell. A second external review
(2026-10-15) demonstrated exactly that against v0.7.0, which printed
"verified" for a forged identity; v0.7.1 therefore reports a passing
check as CONSISTENT, never verified, and states on every line that the
key is not pinned and the section is not sealed. An invalid signature
still fails the whole verdict, which catches tampering by anyone who
does not bother to re-sign. Pinning keys against a registry remains queued;
until it lands, even a sealed actor line is consistency, not identity.
Bundles sealed before `signed_at` shipped are reported as not
offline-checkable at all.

**Also proves, since v0.8.0:** that the actor section and the scaffold
flags of a version-3 anchored bundle are the ones that were anchored.
The v3 ledger leaf embeds digests of both, and this verifier recomputes
those digests from the bundle's own contents when rebuilding the leaf,
so replacing the actor section or clearing a placeholder flag breaks
the anchored leaf no matter how many unanchored hashes the editor
rewrites; both forgeries demonstrated against v0.7.0 are encoded as
tests and now fail. A sealed actor line reads "consistent and SEALED to
the anchor"; identity still waits on key pinning. Runtime stage timings
(real measurements, new in the same release) are digest-sealed at the
bundle level and reported with their honest boundary: the timing digest
is deliberately NOT in the anchored leaf, because per-run timings there
would break the replay-determinism promise, so an editor who rewrites
timings and digest together is outside what a bundle-level seal can
catch. Pre-v3 bundles report every one of these states explicitly
instead of pretending.

**Also proves, since v0.9.0:** that the 33 values in a version-5
bundle's pre-anchor table are the ones that were anchored. Since
v0.17.11 every row of the table is compared with the value the record
displays for it (the policy gate's outcome when the EPA carries its
block, the run clock the actor signature covers, and the deny-receipt
row, empty in a sealed run, included), checked for its one defined value
(the complete-record requirement and the anchoring window), or named
table-only with its reason (the allow token's hash, which the record
displays nowhere); the rows come from one list the check and the
enumeration test share. The v5 ledger
leaf binds the run's identity values (`envelope_id`, `aer_hash`,
`zksp_binding_hash`, `input_nonce`) and the digest of that table. The
table holds the program and route identifiers, the clock epoch, the
payload hash, the sealed pipeline artifact hashes, the policy-gate
outcome, the AIVP governance fields, the digest of the caller-attested
block (actor, model and attested decision), the actor section and the
scaffold flags, and the verifier checks every entry a section displays
against that section. Bundles sealed before leaf v5 carry no table, and
the verifier reports their anchor coverage as partial. v0.9.0 printed
`FULL PRE-ANCHOR COVERAGE` for a complete v5 table; that wording read as
whole-record coverage, which it was not, and v0.10.0 no longer prints it.

**Not bound to the anchor in a v5 bundle without `bundle_anchor`:** the
descriptive sections. The
AER section's decision record (`aer.decision`), `request_substance`,
`authorization_chain`, `causal_graph` (including `effect_log`),
`regulatory_scaffolding`, `system_provenance` (including the SLSA
level), the reproducibility context and the `formal_verification`
record are sealed only by section hashes and the bundle hash inside the
bundle. An external review on 2026-10-16 rewrote each of them,
recomputed those hashes, and v0.9.0 still reported VERIFIED AND
ANCHORED with exit code 0. In a bundle without a complete-record anchor
those sections therefore show the bundle is internally consistent, not
that a party able to rewrite the whole bundle has not changed them, and
v0.10.0 says so in the verdict: `VERIFIED AND ANCHORED, PARTIAL
COVERAGE`, naming the descriptive sections as bundle-sealed, NOT
anchored. The six round-six forgeries are kept in `testdata/round6/` and
received exactly that verdict until v0.17.9; since v0.17.10 the two that
flipped the decision in the AER alone fail on the EPA's copy of the
decision, and since v0.17.11 the four that rewrote a category section
and left its seal's copy of the section hash stale fail on that copy,
while the fuller rewrite that also updates the seal copy still earns the
partial verdict, as the tests show. Since v0.16.0 the partial verdict no
longer says VERIFIED: it reads `ANCHORED, PARTIAL COVERAGE`, the JSON
tier is `ANCHORED_PARTIAL_COVERAGE`, and the exit code is 3 unless
`--allow-partial` is given.

**Also proves, since v0.10.0:** that a bundle carrying `bundle_anchor`
is, section for section, the record that was anchored. After the bundle
is fully built, the orchestrator submits a second Rekor entry whose leaf
is `sha256("verdifax.ledger.bundle.v1" + "." + envelope_id + "." +
anchored_record_digest)`. The anchored record digest is a null-separated
SHA-256, under the domain `verdifax.bundle.anchor.v1`, over thirteen
named values: the bundle hash and the hash of every part of the record
the bundle hash does not cover (the pre-anchor table, the actor section,
the AIVP section, the formal-verification record, the execution record,
the runtime timings, the SEV-SNP evidence, the PoTE ledger fields, the
scaffold notes, the seal references, the section fields their own hashes
omit, and the run metadata). The verifier recomputes every one of them
from the bundle's contents, rebuilds the leaf, and checks the second
entry offline exactly as it checks the first. The frozen recipe is in
`internal/artifacts/bundle_anchor.go`, and a golden vector in
`internal/artifacts/testdata/` pins the expected values. When both
entries verify, the verdict reads `VERIFIED AND ANCHORED, COMPLETE
RECORD ANCHORED`. A `bundle_anchor` that is present but does not hold
fails the verification, exit code 1. The only proofs outside the digest
are `rekor_anchor` and `bundle_anchor` themselves. In a v5 record, a
bundle whose `bundle_anchor` was stripped cannot be told apart from one
sealed before the anchor shipped. It receives the partial verdict, never
the complete one, so a relying party that requires complete coverage
must require that exact verdict; since v0.16.0, exit code 0 without
`--allow-partial` means exactly that.

**Also proves, since v0.11.0:** that a record sealed with the version-6
leaf still carries the complete-record anchor it was sealed with. The
round-seven review showed that deleting `bundle_anchor` from a v5 record
(run 238) after rewriting its descriptive sections and recomputing
their hashes earned `VERIFIED AND ANCHORED, PARTIAL COVERAGE` with exit
code 0, the honest verdict for a record that never had the anchor.
Records sealed with leaf v6 close that: their pre-anchor table is
version 2, the frozen 33-name v1 list plus one row,
`complete_record_anchor` = `required`, digested under the domain
`verdifax.preanchor.v2`, and the run's first public-log entry binds that
digest through the leaf
`sha256(join(".", "verdifax.ledger.input.v6", envelope_id, aer_hash,
zksp_binding_hash, input_nonce, pre_anchor_digest_v2))`. Removing or
changing the requirement row breaks the first entry. Keeping it means
the verifier requires a `bundle_anchor` that is present, holds over the
record, and, for a run anchored on the public log, is itself a verified
public-log entry. A missing, failing or non-public one is `FAILED` with
exit code 1, whatever the flags, and the reason says the record's own
anchored values require a complete-record anchor that is missing.

This guarantee cannot be added after the fact. A v5 record, including
run 238 and every earlier run, states no requirement, and nothing a
verifier can do will make its deleted anchor detectable: those records
keep exactly their v0.10.0 verdicts, and the human report adds the
line `Anchor required:  not sealed (pre-v6 record; a deleted record anchor is not detectable)`.
**Relying parties should require the verdict
`VERIFIED AND ANCHORED, COMPLETE RECORD ANCHORED` for any record sealed
after the deploy that introduced leaf v6**, and treat a partial verdict
on such a record as a failure; the leaf form appears in the JSON report
as `leaf_binding.preimage_form` and the requirement as
`complete_record_requirement`.

**Also proves, since v0.12.0:** who logged each public-log entry, and
when. The round-seven review (2026-10-16) showed that every earlier
release read only an entry's kind and hash. Rekor accepts a hashedrekord
entry from anyone with any key, so a forger could rewrite a record,
recompute every digest, log the new leaves under a key of their own,
and the record verified as `COMPLETE RECORD ANCHORED` with exit code 0.
The anchoring time, the entry number and the signed entry timestamp
were stored but never checked, so a re-logged forgery could display
the original ones. v0.12.0 closes both:

- **Who.** The verifier decodes each entry's public key, verifies the
  entry's ECDSA P-256 signature over the logged digest, and requires
  the key to be a pinned Verdifax log-signing key, accepted only within
  its published period. A run's two entries must share one signer.
- **When.** The verifier checks Rekor's signed entry timestamp on each
  entry under the embedded Rekor key. It signs the entry body, the
  integrated time, the log id and the global entry index together, so
  all four are authenticated; editing any of them fails. The record
  entry may not predate the run entry.
- **Window.** Records sealed with pre-anchor table version 3 (leaf v7)
  carry one more anchored row, `anchoring_window_seconds`, and the
  verifier requires both entries to have been logged within that many
  seconds after the run's sealed `clock_epoch` (allowing five minutes
  of clock skew before it). Removing or changing the row breaks the
  first entry. This is what catches a later re-log by the holder of the
  signing key, Verdifax included: Rekor records the later time, and
  moving `clock_epoch` to match changes the record's own sealed date,
  so the record can no longer claim its original time.

Records sealed before table version 3 have no sealed window. The
verifier still authenticates who logged them and when, and reports the
gap between the anchoring time and the run's clock, but cannot fail
them on it: for those records a re-log by the key holder would show
only as a larger gap. The reviewer's tests are kept in `round8_test.go`
and a sweep over every field of an intact record finds none that can
change without breaking it.

**Also proves, since v0.12.1:** that the record this tool verified is
the record every other JSON reader sees. Round eight of the external
review (2026-10-16) showed that Go's `encoding/json`, which this tool
uses, matches object keys case-insensitively (with Unicode folding)
and lets the last match win, while jq, Python and JavaScript read keys
exactly. A bundle could carry a forged value under the exact key and
the original under a case variant after it, such as
`"result":"deny","RESULT":"approve"`: v0.12.0 verified the original,
every hash recomputed, and the record passed as `COMPLETE RECORD
ANCHORED`, while every other viewer showed the forgery. No key, log
entry or hash recomputation was needed. v0.12.1 decodes strictly
(`internal/artifacts/strictjson.go`): it refuses any object with two
keys equal under case folding, including exact duplicates, and any key
that is not byte-for-byte a field this verifier models, before any hash
is computed. Such a bundle receives `FAILED` with exit code 1. The
human report now also prints the decision-bearing values it checked
(`Record says`), and the JSON report carries them as `record_values`,
so a reader can compare them with any other view of the record.

**Also checks, since v0.13.0:** a refused or halted run's receipt.
Such a run produces a sealed receipt (deny, CCV halt, MACC halt, AIVP-T4
halt or attestation gap) instead of an audit bundle. Pass the receipt
document the Verdifax API serves (`GET /runs/{id}/deny-receipt` and its
siblings) and the verifier recomputes the receipt's hash from its own
fields and checks its `receipt_anchor`: a public-log entry whose leaf is
`sha256(join(".", "verdifax.ledger.receipt.v1", kind, envelope_id,
receipt_hash))`, verified exactly as a run's entries are (inclusion
proof, signed checkpoint, entry body, signed entry timestamp, pinned
Verdifax log-signing key within its period), and required to have been
logged within 600 seconds after the receipt's own clock. A receipt
without an anchor, or anchored only off the public log, is
`RECEIPT SELF-CONSISTENT ONLY, NOT ANCHORED`: its hash recomputing shows
only that its fields agree with each other, and it fails unless
`--allow-unanchored` is passed. Receipts issued before receipt anchoring
shipped carry no anchor. The same strict decoding applies, and since
v0.13.0 every number must be written in its canonical form (the exact
decimal digits for whole numbers, the shortest round-trip form for
fractions), so each number's spelling is pinned, not only its value.
String escapes, whitespace and key order are not pinned: the same
string may be written with or without `\u` escapes, and every reader
still reads the same text. A record is therefore identified by the
hashes the verifier recomputes (a bundle's bundle hash, a receipt's
receipt hash), not by a hash of the file, whose bytes can differ while
its values do not.

**Receipt anchor v2, since v0.14.0:** a v1 receipt leaf binds the
receipt's kind, envelope_id and hash but not the document's `run_id`,
so a genuine v1 receipt can be relabelled with another run number and
still verify. The report therefore prints a v1 receipt's run number as
"from the document, not checked" and identifies the receipt by its
envelope. A v2 anchor (`verdifax.receipt_anchor.v2`) has the leaf
`sha256(join(".", "verdifax.ledger.receipt.v2", kind, envelope_id,
receipt_hash, run_id))`, so the run number is bound, and every receipt
anchored under v2 seals `anchor_required: true` in its own hash. Such a
receipt fails if its anchor is deleted, replaced by a v1 anchor, or
moved off the public log. Since v0.14.1, a receipt dated at or after
run 242's clock (2026-10-16T23:48:35.104252967Z), from when every
receipt the Verdifax API issues seals `anchor_required`, fails if it
lacks the field, unless the person checking it passes
`--self-hosted-receipt` because they know it came from a test or
self-hosted deployment that does not anchor receipts. The clock is
inside the receipt's hash, so evading this rule means backdating the
receipt. Since v0.14.2, a receipt dated at or after run 241's clock
(2026-10-16T23:11:17.94873898Z), the first receipt the API anchored,
fails if it carries no public-log anchor, under the same
`--self-hosted-receipt` exemption; run 241 is the only receipt the API
issued before run 242. Single runs and batch rows share one run
counter, and both paths anchor receipts. The limit: any receipt dated
before run 241's clock, real or invented, carries nothing anchored that
could contradict it, because genuine receipts from before receipt
anchoring began carry no anchor either. Such a receipt, including one
invented from nothing with any run number, envelope or reason code, is
reported as self-consistent only and fails by default, but passes with
`--allow-unanchored`; it is only as trustworthy as whoever handed it to
you. A stripped receipt can no longer carry its real date. The document's `ok` field is the API's response
flag; since v0.17.11 a document with `ok` false is refused as not one
the API serves (it serves every receipt document with `ok` true), and
the flag is not reported. Receipts issued with
`anchor_required` need v0.14.0 or a later release, since earlier releases do not
model that field. Since v0.17.11 the flags that apply only to audit
bundles (`--strict`, `--allow-partial`, `--policy`,
`--show-evidence-summary`) are refused on a receipt document with exit
2, as `--self-hosted-receipt` is on a bundle, instead of being ignored,
and `--tamper-test`, with or without `--recompute-hashes`, runs on a
receipt document: it changes every value as it does for a bundle and
judges each change by the receipt's hash, its public-log entry and the
entry's signer and timestamps; the forger's recompute rebuilds the
receipt's hash and writes it wherever the old one appeared, the anchor's
copy included. On the anchored receipts in `testdata/round10`, run 241's receipt, whose v1 anchor does not bind the run number, has one rewritable path, `run_id`, and the forger test exits 1 on it; the four receipts with a v2 anchor have none.

**Also checks, since v0.10.0:** that each logged entry body names the
leaf the bundle claims for it. The Merkle proof covers the hashedrekord
entry body, not the bundle's `leaf_hash`, so the verifier now requires
the body to be a `hashedrekord` whose `spec.data.hash` is sha256 and
equal to `leaf_hash`, for both `rekor_anchor` and `bundle_anchor`. An
anchor with no `entry_body` cannot be bound to its proof at all and is
reported as NOT VERIFIABLE, never as anchored, so the bundle cannot
reach the anchored verdict. Bundles served by the Verdifax API carry the
body; older stored bundles are backfilled on read wherever the stored
manifest holds it.

**Does not prove:** that Verdifax did not seal a record with false
inputs in the first place, or re-log a changed record later. Pinning
shows a Verdifax key logged the record; the sealed window shows when.
A record re-logged by Verdifax inside the window it seals, or re-logged
later with a moved clock, verifies, and only a party holding the
original record (or watching the public log, where both entries stay
forever) can tell. Nor does it prove that the underlying execution actually happened on
Verdifax-operated hardware. Anchoring establishes that a bundle existed
and was publicly committed at a point in time; it does not establish
that the computation behind it was honest. An orchestrator that
controlled the whole pipeline could still anchor a fabricated but
internally consistent run. Closing that gap needs hardware-rooted
attestation, which the hosted API does not have today (its records carry
the hardware-attestation scaffold flag; a SEV-SNP deployment records a
real quote); see
[scaffold-gaps](https://docs.verdifax.com/concepts/scaffold-gaps/).

The `log_entry_id` field remains searchable on `search.sigstore.dev` if
you would rather confirm the entry by hand than trust this binary.

## Log-signing keys

Every public-log entry Verdifax makes is a Rekor `hashedrekord` signed
with one of these ECDSA P-256 keys. The fingerprint is the hex SHA-256
of the key's DER SubjectPublicKeyInfo. The verifier embeds all three
(`entryauth.go`) and checks the fingerprints when it starts. Each key is
accepted from the start of its period up to, but not including, its
end, so two keys that hand over at one moment never overlap.

**Key 3**, the production orchestrator at `api.verdifax.com` from
2026-10-24T15:59:19Z on. It is an asymmetric ECC_NIST_P256 key in AWS
Key Management Service (region us-east-2). Its private key never leaves
KMS: the server sends each leaf hash to KMS and receives the signature.
Accepted only for entries logged from 2026-10-24T15:59:19Z on.

    fingerprint df009371c140e355d6c9dd46b29ed7fb37ff835bf94192a1f13bded66c92a54f
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErfGSv8mLyB/dzWBfrf8K2EuO7Z1g
    gK6+Bq6yDgRDbbisjdAwHGmcT6Mo/7xNFNuOlr1Z/SJzkU5xvpFPieYj2A==
    -----END PUBLIC KEY-----

**Key 1**, the production orchestrator's key from the first entry
(2026-05-13) until the switch to key 3 at 2026-10-24T15:59:19Z. Its
private key was a file on the production API server's volume, not in a
hardware security module. Accepted only for entries logged before
2026-10-24T15:59:19Z, so a copy of it cannot vouch for anything logged
at or after that moment (v0.17.0 also accepted it at that exact
second; v0.17.1 does not).

    fingerprint 0822255b6c085f394088d1ce4142dc927941789be75faf084d163059551000b7
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsgyMROAY9glbF1VAFeKzSG7xN2Vg
    pIA8djKUggfjIOOLQ25gtyrQNUk2JLbDvOM015SmWZyoB8cPG0LdO/0SSA==
    -----END PUBLIC KEY-----

**Key 2**, generated on the AWS SEV-SNP instance that produced the
October 2026 hardware evidence run. It signed that run's single entry
(2026-10-03T15:00:47Z) and existed only on that instance, which was
destroyed after the run. Accepted only within one hour of that entry,
so it cannot vouch for anything logged later.

    fingerprint 16349c23103f9bd5fd59f0be45e199540e430ab02587e497f96856817d47fe0a
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtn//E+NR9JsyD5ssGshpIceKCMBo
    SjGPIXP3UGH1hTsdwx+uYHNJ5a0b6nsdiIf+Z0a4L5LWvfEQF1p8kev6Sw==
    -----END PUBLIC KEY-----

A new key is added here with the moment it takes effect, and a retired
key keeps its entries verifiable and is given an end date. Key 3 was
published in v0.17.0 on the day it took effect, after it had signed its
first three entries, all from private test runs on 2026-10-24
(entries 3441033974, 3441086489 and 3441086501); verifier releases
before v0.17.0 report entries signed by key 3 as signed by an
unpublished key.

### `--policy`: confirming which policy admitted a run

Records sealed from orchestrator 564f1d4 (October 19, 2026 UTC) on
carry the policy gate's decision in the EPA section (`epa.policy_gate`):
the policy's identifier, name and version, its hash, the rule that
admitted the request and the reason code. The report prints them on the
"Policy gate" line. Those values are covered by the EPA section hash, the
bundle hash and, on complete-record anchored records, the second
public-log entry, so editing them fails verification.

What the record cannot show on its own is that the named identifier and
version belong to the hashed document, because the record carries the
hash, not the policy. `--policy FILE` closes that gap for a reader who
holds the policy document: the verifier recomputes the document's policy
hash exactly as the orchestrator does (`internal/policyhash`, with
parity vectors against the orchestrator for 21 documents, including the
production default policy) and fails verification unless the hash,
identifier, name and version all equal the sealed values. Against a
record with no policy gate, `--policy` fails rather than passing
silently. `epa.policy_hash`, a separate field, is a fixed value (the
SHA-256 of `orchestrator.policy.v1`) kept for record stability; it does
not identify a policy.

## Supported versions

Use v0.17.2 or later; only the latest release receives fixes. Every
release before v0.17.2 is retracted in `go.mod`: `go get`, `go install`
and `go list -m -u` warn when one is requested, `@latest` and
`go list -m -versions` never resolve to one, and pkg.go.dev marks them
retracted. Go does not check a retraction for a commit or branch pin
(`@<commit>`, `@main`), for a go.mod that already requires a retracted
release (a plain `go build` uses it silently), or for a vendored copy, so
check the version you build with `verdifax-verify --version`. Their prebuilt binaries were built with Go versions that have
since received security fixes, and they lack later verification fixes
listed in [`RELEASE_NOTES.md`](./RELEASE_NOTES.md) (releases before v0.17.0 do not know
key 3). Their tags, binaries and provenance stay published, so evidence
checked with them earlier can still be traced.

## Release notes

Every release's notes, newest first, are in
[`RELEASE_NOTES.md`](./RELEASE_NOTES.md).

## Release verification (Cosign and SLSA provenance)

Every release binary ships with a Sigstore bundle and, from
v0.6.3, SLSA Build Level 3 provenance generated by the SLSA
project's trusted builder workflow rather than this repository's
own CI. Verify a download before trusting it:

```bash
# Signature (Cosign keyless, bound to this repository's CI identity)
cosign verify-blob \
  --bundle verdifax-verify-linux-amd64.bundle \
  --certificate-identity-regexp '^https://github.com/Verdifax/verdifax-verify/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  verdifax-verify-linux-amd64

# Build provenance (SLSA Level 3)
slsa-verifier verify-artifact verdifax-verify-linux-amd64 \
  --provenance-path verdifax-verify-v0.14.5.intoto.jsonl \
  --source-uri github.com/Verdifax/verdifax-verify \
  --source-tag v0.14.5
```

A passing provenance check proves the binary was built by this
repository's release workflow from the stated tag, with an
attestation signed outside the repository's own control.

The verifier's untrusted-input path is also fuzzed continuously:
a coverage-guided harness (`fuzz_test.go`) drives arbitrary bytes
through bundle parsing and verification weekly in CI, with the
runs public in the Actions history. The first baseline (October
2026) executed 5.38 million inputs with zero failures.

## Source provenance

This repository contains the verifier source code only. The full
Verdifax orchestrator (which produces the bundles this tool verifies)
is maintained separately and not currently open source. The verifier
was extracted from the orchestrator's `cmd/verdifax-verify/` directory
to provide an auditable, independent verification tool that any third
party can build from source.

## Reporting issues

Open an issue on GitHub or email `access@verdifax.com`.
