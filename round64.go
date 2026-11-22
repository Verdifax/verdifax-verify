package main

// Round 64 (v0.38.0, part 1): the setup facts and the declared data-use basis.
//
// A record or receipt may now seal, each only when its account turned the
// feature on:
//
//   - data_use, the customer's declaration of the data use its decision rests
//     on, in its own field (an allowed run's EPA section, a receipt's context)
//     and, where a decision was made, in each policy gate's sealed inputs. The
//     copies are one value: a record whose copies differ tells two stories and
//     fails. Verdifax sealed the declaration as made and did not check it.
//   - attested_context.client_name and client_version, the AI assistant's own
//     declared name and version, inside the attested digest: declared, not
//     verified.
//   - inputs.setup, the setup facts a decision read under a policy with an
//     attested_setup condition, which repeat what the caller declared in its
//     attested context; the copies must agree, and a decision never reads what
//     Verdifax's AI review states, which comes only after the rules ran.
//   - setup_hash on a receipt's context, the run's setup fingerprint under a
//     setup watch that counts refused runs.
//
// Verifier v0.37.0 refuses every one of them as an unknown field, so a record
// carrying one never reads as verified there.

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
	"github.com/Verdifax/verdifax-verify/internal/psleval"
)

// The forms the server accepts (round 64, its policy gate and psl reader): a
// data-use code is lowercase letters, digits, dots, underscores, colons and
// hyphens, so a code cannot hold a space or an email address; a code can still spell a person's name, so do not put identifiers of people in one, and a
// reference is only a keyed digest the customer computed.
var (
	dataUseCodeForm      = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)
	dataUseReferenceForm = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
	setupHashForm        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// maxDataUseCategories and maxClientFieldBytes are the server's limits.
const (
	maxDataUseCategories = 20
	maxClientFieldBytes  = 128
)

// haltReasonReviewSetup is the AI review halt of a step whose allowing rule
// names the review's own setup, when the review stated something else or no
// review was sealed (orchestrator, round 64).
const haltReasonReviewSetup = "AIVP_T4_REVIEW_SETUP"

// DeclaredReport is what a record or receipt seals as declared, in plain
// words: the data-use declaration and the AI assistant's declared client.
// Each statement says who made it; none was checked by Verdifax.
type DeclaredReport struct {
	DataUse          *artifacts.DataUse `json:"data_use,omitempty"`
	DataUseStatement string             `json:"data_use_statement,omitempty"`
	ClientName       string             `json:"client_name,omitempty"`
	ClientVersion    string             `json:"client_version,omitempty"`
	ClientStatement  string             `json:"client_statement,omitempty"`
	// SetupHash is a receipt's sealed setup fingerprint, present only under
	// a setup watch that counts refused runs.
	SetupHash string `json:"setup_hash,omitempty"`
}

// checkDataUseForm is the server's checkDataUse: purpose and basis are
// codes, categories at most 20 distinct codes, a reference only a keyed
// digest.
func checkDataUseForm(du *artifacts.DataUse) error {
	if du == nil {
		return nil
	}
	if !dataUseCodeForm.MatchString(du.Purpose) {
		return fmt.Errorf("its data_use purpose %q is not a code of the form %s", safePrefix(du.Purpose), dataUseCodeForm)
	}
	if !dataUseCodeForm.MatchString(du.Basis) {
		return fmt.Errorf("its data_use basis %q is not a code of the form %s", safePrefix(du.Basis), dataUseCodeForm)
	}
	if du.Categories != nil && len(du.Categories) == 0 {
		return errors.New("its data_use names an empty list of categories, which the server never seals")
	}
	if len(du.Categories) > maxDataUseCategories {
		return fmt.Errorf("its data_use names %d categories, more than the %d the server accepts", len(du.Categories), maxDataUseCategories)
	}
	seen := map[string]bool{}
	for _, category := range du.Categories {
		if !dataUseCodeForm.MatchString(category) || seen[category] {
			return fmt.Errorf("its data_use categories must be distinct codes of the form %s", dataUseCodeForm)
		}
		seen[category] = true
	}
	if du.Reference != "" && !dataUseReferenceForm.MatchString(du.Reference) {
		return errors.New("its data_use reference is not hmac-sha256: and 64 lowercase hex digits, the only form the server seals")
	}
	return nil
}

// checkClientForm is the server's checkClient: each declared client field at
// most 128 bytes of printable ASCII, with no leading or trailing space.
func checkClientForm(ac artifacts.AttestedContext) error {
	for _, named := range []struct{ name, value string }{{"client_name", ac.ClientName}, {"client_version", ac.ClientVersion}} {
		if len(named.value) > maxClientFieldBytes || strings.TrimSpace(named.value) != named.value {
			return fmt.Errorf("its attested_context %s is not at most %d bytes with no leading or trailing space", named.name, maxClientFieldBytes)
		}
		for _, r := range named.value {
			if r < 0x20 || r > 0x7e {
				return fmt.Errorf("its attested_context %s is not printable ASCII", named.name)
			}
		}
	}
	return nil
}

// dataUseStatement says what a data-use declaration is, in plain words.
func dataUseStatement(du *artifacts.DataUse) string {
	parts := []string{"purpose " + du.Purpose, "basis " + du.Basis}
	if len(du.Categories) > 0 {
		parts = append(parts, "categories "+strings.Join(du.Categories, ", "))
	}
	if du.Reference != "" {
		parts = append(parts, "a reference the customer keyed itself, "+truncate(du.Reference, 24))
	}
	return "declared by the customer: " + strings.Join(parts, "; ") + ". Sealed as declared; Verdifax did not check it."
}

// clientStatement says what a declared client is, in plain words.
func clientStatement(name, version string) string {
	who := strings.TrimSpace(name + " " + version)
	return fmt.Sprintf("%s, declared by the AI assistant, not verified", who)
}

// declaredOfBundle reads what an allowed run's record seals as declared, or
// nil when it seals none of it, so a record without it reports as before.
func declaredOfBundle(b *artifacts.AuditBundle) *DeclaredReport {
	ac := b.EPA.AttestedContext
	if b.EPA.DataUse == nil && ac.ClientName == "" && ac.ClientVersion == "" {
		return nil
	}
	d := &DeclaredReport{DataUse: b.EPA.DataUse, ClientName: ac.ClientName, ClientVersion: ac.ClientVersion}
	if d.DataUse != nil {
		d.DataUseStatement = dataUseStatement(d.DataUse)
	}
	if ac.ClientName != "" || ac.ClientVersion != "" {
		d.ClientStatement = clientStatement(ac.ClientName, ac.ClientVersion)
	}
	return d
}

// declaredOfReceipt reads what a receipt's context seals as declared.
func declaredOfReceipt(c *artifacts.ReceiptContext) *DeclaredReport {
	if c == nil || (c.DataUse == nil && c.SetupHash == "") {
		return nil
	}
	d := &DeclaredReport{DataUse: c.DataUse, SetupHash: c.SetupHash}
	if d.DataUse != nil {
		d.DataUseStatement = dataUseStatement(d.DataUse)
	}
	return d
}

// declaredSetupOf is the server's declaredSetup: what the caller declared in
// its attested context, as a decision under an attested_setup condition
// reads it, or nil when it declared none of it.
func declaredSetupOf(ac artifacts.AttestedContext) *artifacts.DeclaredSetup {
	d := artifacts.DeclaredSetup{ModelProvider: ac.ModelProvider, ModelName: ac.ModelName, ModelVersion: ac.ModelVersion,
		PromptHash: ac.PromptHash, ClientName: ac.ClientName, ClientVersion: ac.ClientVersion}
	if ac.ModelTemperature != nil {
		if text, encodeErr := json.Marshal(*ac.ModelTemperature); encodeErr == nil {
			d.ModelTemperature = string(text)
		}
	}
	if d == (artifacts.DeclaredSetup{}) {
		return nil
	}
	return &d
}

// checkInputsSetup holds a decision's sealed setup facts to what a decision
// can read: only what the caller declared, never Verdifax's AI review (which
// states its setup after the rules ran). declared is the record's attested
// context's declaration, or nil on a receipt, which seals no attested context.
func checkInputsSetup(where string, in *artifacts.PolicyInputs, declared *artifacts.DeclaredSetup, haveDeclared bool) error {
	if in == nil || in.Setup == nil {
		return nil
	}
	s := in.Setup
	switch {
	case s.AttestedByVerdifax != nil:
		return fmt.Errorf("%s seals setup facts stated by Verdifax's AI review, which no decision reads: the review states them only after the rules ran", where)
	case s.DeclaredByCaller == nil:
		return fmt.Errorf("%s seals an empty setup, which the server never seals", where)
	case haveDeclared && !reflect.DeepEqual(s.DeclaredByCaller, declared):
		return fmt.Errorf("%s seals setup facts that differ from what the record's attested context declares: the record stores the declaration twice and its copies disagree", where)
	}
	return nil
}

// round64BundleProblems returns a failure for every round 64 fact an allowed
// run's record seals that the server could not have sealed.
func round64BundleProblems(b *artifacts.AuditBundle) []string {
	var out []string
	if b.EPA.DataUseCopiesAgree() != nil {
		out = append(out, "epa.data_use does not equal the data_use a policy gate's inputs seal: the record stores the data-use declaration more than once and its copies disagree")
	}
	if formErr := checkDataUseForm(b.EPA.DataUse); formErr != nil {
		out = append(out, "the record's data-use declaration: "+formErr.Error())
	}
	if clientErr := checkClientForm(b.EPA.AttestedContext); clientErr != nil {
		out = append(out, "the record's declared client: "+clientErr.Error())
	}
	declared := declaredSetupOf(b.EPA.AttestedContext)
	for _, g := range []struct {
		where string
		gate  *artifacts.PolicyGate
	}{{"the policy gate's inputs", b.EPA.PolicyGate}, {"the account policy gate's inputs", b.EPA.AccountPolicyGate}} {
		if g.gate == nil {
			continue
		}
		if setupErr := checkInputsSetup(g.where, g.gate.Inputs, declared, true); setupErr != nil {
			out = append(out, setupErr.Error())
		}
	}
	return out
}

// round64ReceiptProblem returns the first round 64 fact a receipt's context
// seals that the server could not have sealed.
func round64ReceiptProblem(c *artifacts.ReceiptContext) error {
	if c == nil {
		return nil
	}
	if c.DataUseCopiesAgree() != nil {
		return errors.New("the receipt's data_use does not equal the data_use its policy decision's inputs seal: the receipt stores the data-use declaration more than once and its copies disagree")
	}
	if formErr := checkDataUseForm(c.DataUse); formErr != nil {
		return fmt.Errorf("the receipt's data-use declaration: %w", formErr)
	}
	if c.SetupHash != "" && !setupHashForm.MatchString(c.SetupHash) {
		return errors.New("the receipt's setup_hash is not 64 lowercase hex characters")
	}
	for _, b := range []struct {
		where   string
		binding *artifacts.PolicyBinding
	}{{"the receipt's policy decision's inputs", c.Policy}, {"the receipt's account policy decision's inputs", c.AccountPolicy}} {
		if b.binding == nil {
			continue
		}
		if setupErr := checkInputsSetup(b.where, b.binding.Inputs, nil, false); setupErr != nil {
			return setupErr
		}
	}
	return nil
}

// printDeclared renders the declared facts of a record or receipt.
func printDeclared(d *DeclaredReport) {
	if d == nil {
		return
	}
	if d.DataUseStatement != "" {
		fmt.Printf("  %-18s%s\n", "Data use:", d.DataUseStatement)
	}
	if d.ClientStatement != "" {
		fmt.Printf("  %-18s%s\n", "AI assistant:", d.ClientStatement)
	}
	if d.SetupHash != "" {
		fmt.Printf("  %-18s%s, the run's setup fingerprint under its policy's setup watch\n", "Setup:", truncate(d.SetupHash, 16))
	}
}

// matcherText reads a policy matcher in plain words.
func matcherText(m psleval.Matcher) string {
	switch {
	case len(m.Values) > 0:
		return fmt.Sprintf("%s [%s]", m.Operator, strings.Join(m.Values, ", "))
	case m.Value != "":
		return fmt.Sprintf("%s %q", m.Operator, m.Value)
	}
	return string(m.Operator)
}

// setupFactLines says, for each setup fact the rule that decided names, what
// was stated and what the policy names: "the request declared X; the policy
// names Y" for a fact the caller declares, and what Verdifax's AI review
// stated for a fact it states. review is the sealed AI review, or nil.
func setupFactLines(fired *psleval.Rule, inputs *psleval.Inputs, review *artifacts.AivpReview) []string {
	if fired == nil {
		return nil
	}
	var lines []string
	for _, c := range fired.Conditions {
		if c.Type != psleval.ConditionAttestedSetup {
			continue
		}
		for _, f := range c.Facts {
			switch psleval.SetupFactSource(f.Fact) {
			case psleval.SetupDeclaredByCaller:
				value, stated := inputs.Setup.Fact(f.Fact)
				if !stated {
					value = "nothing"
				} else {
					value = fmt.Sprintf("%q", value)
				}
				lines = append(lines, fmt.Sprintf("%s: the request declared %s; the policy names %s", f.Fact, value, matcherText(f.Match)))
			case psleval.SetupAttestedByVerdifax:
				value, stated := reviewSetup(review).Fact(f.Fact)
				switch {
				case review == nil:
					value = "no review was sealed"
				case !stated:
					value = "Verdifax's AI review stated nothing"
				default:
					value = fmt.Sprintf("Verdifax's AI review stated %q", value)
				}
				lines = append(lines, fmt.Sprintf("%s: %s; the policy names %s", f.Fact, value, matcherText(f.Match)))
			}
		}
	}
	return lines
}

// reviewSetup is the setup Verdifax's AI review states about itself, as the
// server reads it (aivp RequireReviewSetup), or nil for no review.
func reviewSetup(review *artifacts.AivpReview) *psleval.Setup {
	if review == nil {
		return nil
	}
	return &psleval.Setup{AttestedByVerdifax: &psleval.AttestedSetup{ReviewModel: review.Model, ReviewPromptID: review.PromptID,
		ReviewCheckerID: review.CheckerID}}
}

// reviewSetupMismatch is the server's: the first review fact the rule names
// that the sealed review did not state, or stated with a value the rule does
// not accept, or "" when every named fact holds.
func reviewSetupMismatch(fired *psleval.Rule, review *artifacts.AivpReview) string {
	var stated *psleval.AttestedSetup
	if s := reviewSetup(review); s != nil {
		stated = s.AttestedByVerdifax
	}
	fact, _ := psleval.ReviewSetupMismatch(psleval.ReviewSetupNamed(fired), stated)
	return fact
}

// applyReviewSetupHalt holds an AI review halt for the review's setup
// (AIVP_T4_REVIEW_SETUP) to the rules once both decisions it seals have been
// run again: the halt stands only when a rule that allowed the step names a
// review fact the sealed review did not meet. With one decision not run
// again, the report says the halt was not confirmed.
func applyReviewSetupHalt(r *ReceiptReport) {
	if r.reviewSetupHalt == nil || !r.AllPassed {
		return
	}
	gates := []*PolicyGateCheck{&r.PolicyGate}
	if r.AccountPolicyGate != nil {
		gates = append(gates, r.AccountPolicyGate)
	}
	allRun := true
	for _, g := range gates {
		if !g.Present || g.Outcome == "" {
			continue
		}
		if !g.RulesChecked {
			allRun = false
			continue
		}
		if g.ReviewSetupMismatch != "" {
			r.ReviewSetupHalt = fmt.Sprintf("confirmed: rule %q names the AI review's %s, and the sealed review did not meet it", g.FiredRuleID, g.ReviewSetupMismatch)
			return
		}
	}
	if !allRun {
		r.ReviewSetupHalt = "not confirmed: give the policy documents of both decisions to run the rules again"
		return
	}
	r.VerdictTier, r.AllPassed = "FAILED", false
	r.Reason = "the receipt says the step stopped because the AI review's setup did not meet the rule that allowed it, and every rule that allowed it is met by the sealed review"
	r.ReviewSetupHalt = "not met: " + r.Reason
}
