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
                          statement's time on the public log. Runs alone
                          with no record
  -strict-signoff         fail (exit 1) a record whose rule requires a
                          person's sign-off when no sign-offs are given;
                          without it such a record, if every other check
                          passes, reads ANCHORED, SIGN-OFF NOT SHOWN and
                          exits 4
  -signals FILE           check an account's signal feed, the body of
                          GET /signals: every event's entry must verify on
                          the public log as its kind, seal its place in the
                          feed and link to the event before it without a
                          gap. It shows the signals Verdifax recorded, not
                          ones it never recorded. Runs alone with no record
  -signals-after N:hash   with -signals, the last event already read: the
                          feed must continue from it
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
  -version                print version and exit

EXIT
  0  all checks passed
  1  one or more checks failed, or the record is not anchored and
     -allow-unanchored was not passed (or -strict + scaffold)
  2  could not parse the input
  3  every check passed, but the public-log anchor covers only part
     of the record, or with -job the job has no final step, and
     -allow-partial was not passed
  4  every check passed and the complete record is anchored, but its
     rule requires a person's sign-off and no sign-offs were given
     (ANCHORED, SIGN-OFF NOT SHOWN), and -strict-signoff was not passed`)
}
