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
server-side for authenticated callers at `GET /runs/{id}/verify`.

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

Pre-built binaries for Linux / macOS / Windows are attached to each
[GitHub release](https://github.com/Verdifax/verdifax-verify/releases).

## Usage

```bash
verdifax-verify bundle.json           # verify a file, print human report
cat bundle.json | verdifax-verify     # verify from stdin
verdifax-verify --json bundle.json    # machine-readable JSON output
verdifax-verify --strict bundle.json  # also fail on any scaffold-flagged value
verdifax-verify --version
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All hashes verified, no failures. |
| 1 | One or more verification checks failed (or `--strict` + scaffold). |
| 2 | Could not parse the bundle. |

### `--strict` mode

By default, the verifier reports scaffold-flagged values (L6 ZK proof,
L8 hardware attestation, L10 formal verifier, see
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
last clause carefully: because the key comes from the bundle and the
nrep section is not yet covered by the bundle hash or the public-log
leaf, an attacker can replace the whole section with a self-consistent
one of their own, and this check cannot tell. A second external review
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
receive exactly that verdict.

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
must require that exact verdict.

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
attestation, which is currently a scaffold value; see
[scaffold-gaps](https://docs.verdifax.com/concepts/scaffold-gaps/).

The `log_entry_id` field remains searchable on `search.sigstore.dev` if
you would rather confirm the entry by hand than trust this binary.

## Log-signing keys

Every public-log entry Verdifax makes is a Rekor `hashedrekord` signed
with one of these ECDSA P-256 keys. The fingerprint is the hex SHA-256
of the key's DER SubjectPublicKeyInfo. The verifier embeds both
(`entryauth.go`) and checks the fingerprints when it starts.

**Key 1**, the production orchestrator at `api.verdifax.com`. It has
signed every public Verdifax entry from the first (2026-05-13) on and
has never been rotated. Custody: the private key is a file on the
production API server's volume, not in a hardware security module.
Accepted at any time.

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

A new key will be added here, with the date it took effect, before any
entry it signs; a retired key keeps its entries verifiable and is given
an end date.

## Release notes

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
you accepted with an earlier release using v0.10.0.

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
  --provenance-path verdifax-verify-v0.6.3.intoto.jsonl \
  --source-uri github.com/Verdifax/verdifax-verify \
  --source-tag v0.6.3
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
