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
| 2 | The input could not be read (a missing file or a failed download), or it was read but could not be decoded as a bundle or receipt. |
| 3 | Every check passed, but the public log covers only part of the record (a record sealed before leaf v5, or one without a verified complete-record anchor), and `--allow-partial` was not given. Since v0.16.0. |

A script that treats exit 0 as a pass accepts only complete-record
anchored records. Until v0.15.3 a partial record exited 0, although its
descriptive sections, the decision among them, could have been rewritten
together with their hashes.

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
bundle's pre-anchor table are the ones that were anchored. The v5 ledger
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
received exactly that verdict. Since v0.16.0 the partial verdict no
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
flag; it is not checked and is not reported. Receipts issued with
`anchor_required` need v0.14.0 or a later release, since earlier releases do not
model that field.

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
of the key's DER SubjectPublicKeyInfo. The verifier embeds both
(`entryauth.go`) and checks the fingerprints when it starts.

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
hardware security module. Accepted only for entries logged up to
2026-10-24T15:59:19Z, so a copy of it cannot vouch for anything logged
later.

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

## Release notes

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
you accepted with an earlier release using the current release (v0.14.5).

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
