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

FLAGS
  -json                   emit machine-readable JSON output
  -strict                 fail on any scaffold-flagged value
  -allow-unanchored       exit 0 for a bundle or receipt that is
                          consistent but not anchored on the public log
  -allow-partial          exit 0 for a record whose public-log anchor
                          covers only part of it (sealed before leaf
                          v5, or without a complete-record anchor)
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
     of the record, and -allow-partial was not passed`)
}
