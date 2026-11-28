package main

import (
	"fmt"
	"os"
)

func printUsage() {
	fmt.Fprintln(os.Stderr, `verdifax-verify, independent verifier for Verdifax audit bundles and receipts

USAGE
  verdifax-verify [flags] <bundle.json | receipt.json>
  cat bundle.json | verdifax-verify [flags]
  verdifax-verify -job <folder> [flags]

FLAGS
  -json                   emit machine-readable JSON output
  -strict                 fail on any scaffold-flagged value
  -allow-unanchored       exit 0 for a bundle or receipt that is
                          consistent but not anchored on the public log
  -allow-partial          exit 0 for a record whose public-log anchor
                          covers only part of it (sealed before leaf
                          v5, or without a complete-record anchor)
  -job FOLDER             check a folder of one job's records: each record
                          in full, then the map of links between them.
                          A deleted step is given as its sealed tombstone,
                          which stands for its record; the job then reads
                          complete except the deleted steps.
                          A job map covers what was sent; it cannot show
                          a step that was never sent
  -policy FILE            check a policy document against the policy
                          decision the record or receipt seals, and run its
                          rules on the sealed inputs. A pass shows the rules
                          were applied to what was declared; it does not
                          show that what was declared was true, or that the
                          rules are good ones. Verdifax's built-in policy is
                          carried here and checked without this flag
  -policy-history FILE    check a JSON list of a key's policy changes, oldest
                          first: every change and link must verify, and a
                          record given with it must name one of them. Runs
                          alone with no record
  -account-policy FILE    for a record from a key in an account with a
                          policy: check the account's policy document as
                          -policy checks the key's, and run its rules on the
                          sealed inputs. An allowed run must be allowed by
                          both. The account policy is the customer's;
                          Verdifax did not write, review or approve it
                          both, and a record's AI review must apply the
                          contradiction choice the fired rule makes
  -aivp-traces DIR        with -job, a folder holding the trace of every step
                          whose AI review ran, as <step>.txt for the step's
                          <step>.json; each must re-check as -aivp-trace
                          checks one
  -aivp-trace FILE        the trace the record's AI review checked, as the
                          run's response returned it (aivp_trace_text): its
                          SHA-256 must be the sealed trace hash, and the
                          contradiction check run again on it must reach the
                          sealed finding
  -account-policy-history FILE
                          check a JSON list of the account's policy changes,
                          oldest first, as -policy-history does; every change
                          must belong to the account the record names. Runs
                          alone with no record
  -signoff FILE           check the sign-offs given for the record or receipt:
                          each must verify, belong to the record's account
                          and name this exact result; the latest is the
                          decision in force, except on a job's final step,
                          where the latest sign-off on the whole job governs.
                          A sign-off shows a registered approver key signed
                          it, not that the review was careful or the result
                          right
  -approver-key FILE      with -signoff, pass only if the decision in force
                          was signed by this base64 Ed25519 public key
  -signoff-history FILE   check an account's whole chain of sign-offs,
                          oldest first, and, when it ends with Verdifax's
                          head statement, report it complete as of the
                          statement's time on the public log and its age.
                          Runs alone with no record
  -signoff-head-max-age D with -signoff-history, the oldest the history's
                          head statement may be (default 24h; for example
                          72h): an older head fails, so fetch the history
                          again or raise the limit
  -strict-signoff         fail (exit 1) a record whose rule requires a
                          person's sign-off when no sign-offs are given;
                          without it such a record, if every other check
                          passes, reads ANCHORED, SIGN-OFF NOT SHOWN and
                          exits 4
  -strict-hardware        fail a hardware-attested record whose AMD
                          SEV-SNP report has debug on or whose firmware
                          Verdifax does not pin; without it both are stated
                          on the record's hardware line
  -copy-statement HEADER  with -copy-token, the X-Verdifax-Hosted-Copy-
                          Statement header a hosted copy of a hardware-
                          attested record was served with: its signature
                          must verify with the pinned copy-statement key
                          within its period, and it must keep a copy of
                          this record's bytes, run and kind under that
                          token
  -copy-token TOKEN       with -copy-statement, the token of the public
                          link the record was fetched from
  -copy-signoff FILE      with -copy-statement, the sign-off file served
                          at the same link: its SHA-256 must be the one
                          the statement names; when the statement names
                          one and no file is given, -strict-signoff fails
  -signals FILE           check an account's signal feed, the body of
                          GET /signals: every event's entry must verify on
                          the public log as its kind, seal its place in the
                          feed and link to the event before it without a
                          gap. It shows the signals Verdifax recorded, not
                          ones it never recorded. Every account change and
                          deletion names who decided; an owner's carries
                          the owner's request-key signature, and a Verdifax
                          change after the owner's block fails. Each key's
                          request keys are followed from their registration,
                          every replacement approved by the key before it,
                          and an owner's change must be signed by the owner
                          key's request key of its time. A page that ends
                          with Verdifax's head statement is complete as of
                          its time on the public log, and a feed shorter
                          than its head fails. Runs alone with no record
  -signals-after N:hash   with -signals, the last event already read: the
                          feed must continue from it
  -owner-request-key FILE with -signals, the owner key's request key (base64
                          Ed25519 public key), or several files separated
                          by commas: fails unless one of them signed every
                          change the owner decided and every request key
                          registered or set for the owner key is one of them
  -signals-policy FILES   with -signals, the policy documents of the feed's
                          policy changes, separated by commas: the review
                          date each declares is recomputed, each review.due
                          must match it, and a feed whose head is past a
                          declared date with no review.due fails
  -feed-head-max-age D    with -signals, the oldest the feed's head
                          statement may be (default 24h; for example 72h):
                          an older head fails, so fetch the feed again or
                          raise the limit. Since v0.38.0 each stop and lift
                          is followed: each holder lifts only its own stop,
                          the owner's lift is signed, a member key stops
                          only with a sealed account_stop grant, a Verdifax
                          stop after the owner's verdifax_stop block fails,
                          every run or sign-off refused for a stop falls
                          inside one, and each stopped period is reported
  -response-times         with -signals, the feed is a response-time report
                          (GET /account/signoffs/response-times?pack=1):
                          its feed is checked, every stated figure is
                          recounted from it and any that differs fails;
                          given a plain feed page, the period -from to -to
                          is measured. A result unsigned as of the head or
                          longer than its target fails unless the head is
                          within -feed-head-max-age. Waits are stated as
                          measured, beside the customer's own target
  -target D               with -response-times, the request target (whole
                          seconds, or a duration such as 4h) for results
                          that seal none; a report must use the same one
  -from T                 with -response-times, the period's start
                          (RFC 3339, included)
  -to T                   with -response-times, the period's end
                          (RFC 3339, excluded)
  -summary FILE           with -signals, a period summary (GET
                          /account/summaries/{id}): its hash and public-log
                          entry are checked, its head must be the feed's
                          event and stated after the period, no later event
                          may be sealed before the period's end, and every
                          figure and events digest is recounted from the
                          feed and printed in plain words. A sign-off
                          figure shows a registered approver key signed.
                          -feed-head-max-age does not apply to the
                          summary's own head
  -summary-head FILE      with -summary, the summary's head statement (GET
                          /account/summaries/{id}/head) when the feed page
                          given does not end with it
  -signer-key FILE       pass only if the run was requested by the holder
                          of this base64 Ed25519 public key
  -request FILE           pass only if the record's version 2 signature
                          covers the exact bytes of this signed request
  -recompute-hashes       with -tamper-test, play a forger who rewrites
                          the whole record: after each change, recompute
                          every hash the record itself determines, and
                          count a change as stopped only when a check no
                          rewrite can satisfy catches it (the public-log
                          entries, their signer and timestamps, the actor
                          signature or AMD's report signature)
  -self-hosted-receipt    the receipt came from a test or self-hosted
                          deployment, not the Verdifax API; exempts it
                          from the rules that receipts dated from run
                          241 on must carry a public-log anchor and
                          from run 242 on must seal anchor_required
  -show-evidence-summary  print a one-glance maturity summary (real vs
                          scaffold counts, Rekor anchor status, PoTE
                          preimage version, strict-mode gate) and exit
  -tamper-test            change every value of the record one at a
                          time, delete every key holding a value, remove
                          and append list items and add unknown keys,
                          and report any change the verifier accepts and
                          which checks caught the rest; exit 0 only if
                          every change fails verification
  -keys                   print every key this verifier trusts, one per
                          line: the log-signing keys and the copy-statement
                          key, each with fingerprint, name, when it is
                          accepted, custody, purpose and first use; exit
  -log-keys               the same as -keys
  -version                print version and exit

EXIT
  0  all checks passed
  1  one or more checks failed, or the record is not anchored and
     -allow-unanchored was not passed (or -strict + scaffold)
  2  could not parse the input
  3  every check passed, but the public-log anchor covers only part
     of the record, or with -job the job has no final step or a
     deleted step, and -allow-partial was not passed
  4  every check passed and the complete record is anchored, but its
     rule requires a person's sign-off and no sign-offs were given
     (ANCHORED, SIGN-OFF NOT SHOWN), and -strict-signoff was not passed`)
}
