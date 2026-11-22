package artifacts

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Account stops (round 64, design 03). The account's owner and Verdifax each
// hold a stop of their own on the account and lift only their own: the
// account runs only while neither holds one. Each stop and each lift is one
// record, verdifax.account-stop.v1, anchored on the public log under its own
// leaf kind and carrying its place in the account's feed (account.stopped or
// account.resumed). The record states who stopped or resumed the account,
// when, with what scope, and how many runs were already in progress; it says
// nothing about why a stop was right.
//
// A stop touches no key: every key works as before for every route a stop
// does not refuse, and reads every record.
const (
	// AccountStopFormat is the format field of an account-stop record.
	AccountStopFormat = "verdifax.account-stop.v1"

	// StopActionStop and StopActionResume are a record's two actions.
	StopActionStop   = "stop"
	StopActionResume = "resume"

	// StopSignoffsAccept and StopSignoffsRefuse are a stop's choice for
	// sign-offs on results already sealed: accepted (the default) or
	// refused while it stands.
	StopSignoffsAccept = "accept"
	StopSignoffsRefuse = "refuse"
	// StopWebhooksContinue and StopWebhooksPause are a stop's choice for
	// webhook deliveries: they continue (the default) or wait until it is
	// lifted.
	StopWebhooksContinue = "continue"
	StopWebhooksPause    = "pause"

	// StopRuleID and StopReasonCode are what a run refused during a stop
	// seals in its deny receipt: fired_rule_id and decision_reason_code. No
	// built-in policy carries them; a customer's own policy may use the
	// same words for its own rules.
	StopRuleID     = "account_stop"
	StopReasonCode = "ACCOUNT_STOPPED"

	// StopUnsigned is the statement an owner's stop seals when no request-key
	// signature came with it: the owner's key, or a member key the owner
	// granted the stop, asked for the stop, and the record is the server's
	// word for that. A resume of the owner's stop is always signed.
	StopUnsigned = "unsigned: the server's word that this account's key asked for the stop; no request-key signature came with it"

	// AccountSettingVerdifaxStop is the owner's setting that allows or
	// blocks Verdifax's own stop (round 64), beside the round 60 blocks.
	AccountSettingVerdifaxStop = "setting.verdifax_stop"
)

// StopScope is what a stop leaves working: sign-offs on results already
// sealed, and webhook deliveries.
type StopScope struct {
	Signoffs string `json:"signoffs"`
	Webhooks string `json:"webhooks"`
}

// AccountStop is one stop placed on an account, or one lifted.
type AccountStop struct {
	Format string `json:"format"`
	// Action is stop or resume.
	Action string `json:"action"`
	// DecidedBy is owner, for the owner's stop, or verdifax_admin, for
	// Verdifax's. Each holder lifts only its own.
	DecidedBy string `json:"decided_by"`
	// KeyID is the account's key that asked: the owner key, or a member
	// key the owner granted the stop (its key.created record seals the
	// grant). 0 for a Verdifax decision.
	KeyID int64 `json:"key_id,omitempty"`
	// Scope is a stop's choice for sign-offs and webhooks; a resume carries
	// none.
	Scope *StopScope `json:"scope,omitempty"`
	// ReasonSHA256 is the SHA-256 of the reason text sent, or empty when
	// none was; the text itself is not kept.
	ReasonSHA256 string `json:"reason_sha256,omitempty"`
	// RunsInProgress counts, on a stop, the account's runs admitted before
	// the stop and still running when it was sealed: they finish. 0 on a
	// resume.
	RunsInProgress int64 `json:"runs_in_progress"`
	// LiftsSequence is, on a resume, the feed place of the stop it lifts.
	LiftsSequence int64 `json:"lifts_sequence,omitempty"`
	// OwnerSignature is the owner's request-key signature over the action,
	// on an owner's resume always and on an owner's stop when one came.
	OwnerSignature *OwnerSignature `json:"owner_signature,omitempty"`
	// Unsigned is StopUnsigned on an owner's stop sent without a signature.
	Unsigned        string         `json:"unsigned,omitempty"`
	ChangedAt       string         `json:"changed_at"`
	Signal          SignalLink     `json:"signal"`
	AccountStopHash string         `json:"account_stop_hash"`
	Anchor          *ReceiptAnchor `json:"anchor,omitempty"`
}

var reasonHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// StopSubject is what the owner's request key signs for a stop or a resume:
// the action, the key that asked, the scope or the place lifted, and the
// reason's hash.
func StopSubject(action string, keyID int64, scope *StopScope, liftsSequence int64, reasonSHA256 string) string {
	parts := []string{action, "key=" + strconv.FormatInt(keyID, 10)}
	if scope != nil {
		parts = append(parts, "signoffs="+scope.Signoffs, "webhooks="+scope.Webhooks)
	}
	if liftsSequence > 0 {
		parts = append(parts, "lifts="+strconv.FormatInt(liftsSequence, 10))
	}
	return strings.Join(append(parts, "reason_sha256="+reasonSHA256), " ")
}

// Subject is the record's own StopSubject.
func (s *AccountStop) Subject() string {
	return StopSubject(s.Action, s.KeyID, s.Scope, s.LiftsSequence, s.ReasonSHA256)
}

// Kind is the feed kind of the record's event.
func (s *AccountStop) Kind() string {
	if s.Action == StopActionResume {
		return SignalAccountResumed
	}
	return SignalAccountStopped
}

// Holder is whose stop the record places or lifts: owner or verdifax.
func (s *AccountStop) Holder() string {
	if s.DecidedBy == DecidedByVerdifax {
		return "verdifax"
	}
	return "owner"
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed, the optional parts behind labels.
func (s *AccountStop) ComputeHash() string {
	fields := []string{s.Format, s.Action, s.DecidedBy, strconv.FormatInt(s.KeyID, 10)}
	if s.Scope != nil {
		fields = append(fields, "scope", s.Scope.Signoffs, s.Scope.Webhooks)
	} else {
		fields = append(fields, "no_scope")
	}
	fields = append(fields, s.ReasonSHA256, strconv.FormatInt(s.RunsInProgress, 10), strconv.FormatInt(s.LiftsSequence, 10))
	switch {
	case s.OwnerSignature != nil:
		fields = append(append(fields, "owner_signature"), s.OwnerSignature.fields()...)
	case s.Unsigned != "":
		fields = append(fields, "unsigned", s.Unsigned)
	default:
		fields = append(fields, "no_signature")
	}
	fields = append(fields, s.ChangedAt)
	return lengthPrefixedHash(append(fields, s.Signal.fields()...))
}

// Validate checks the record's shape: every value its hash and leaf are built
// from, and who may make it: the owner's stop is signed or marked unsigned,
// the owner's resume is always signed, and Verdifax's carries neither.
func (s *AccountStop) Validate() error {
	owner := s.DecidedBy == DecidedByOwner
	switch {
	case s.Format != AccountStopFormat:
		return errors.New("account stop: unknown format")
	case s.Action != StopActionStop && s.Action != StopActionResume:
		return errors.New("account stop: action must be stop or resume")
	case !owner && s.DecidedBy != DecidedByVerdifax:
		return errors.New("account stop: decided_by must be owner or verdifax_admin")
	case owner && s.KeyID <= 0:
		return errors.New("account stop: an owner's stop or resume names the account key that asked")
	case !owner && s.KeyID != 0:
		return errors.New("account stop: a Verdifax stop or resume names no account key")
	case s.ReasonSHA256 != "" && !reasonHashPattern.MatchString(s.ReasonSHA256):
		return errors.New("account stop: reason_sha256 must be 64 lowercase hex characters")
	case s.RunsInProgress < 0:
		return errors.New("account stop: runs_in_progress cannot be negative")
	case s.ChangedAt == "":
		return errors.New("account stop: changed_at is required")
	case !jobHashPattern.MatchString(s.AccountStopHash):
		return errors.New("account stop: account_stop_hash must be 64 lowercase hex characters")
	}
	if s.Action == StopActionStop {
		switch {
		case s.Scope == nil:
			return errors.New("account stop: a stop seals its scope")
		case s.Scope.Signoffs != StopSignoffsAccept && s.Scope.Signoffs != StopSignoffsRefuse:
			return errors.New("account stop: scope.signoffs must be accept or refuse")
		case s.Scope.Webhooks != StopWebhooksContinue && s.Scope.Webhooks != StopWebhooksPause:
			return errors.New("account stop: scope.webhooks must be continue or pause")
		case s.LiftsSequence != 0:
			return errors.New("account stop: only a resume names the stop it lifts")
		}
	} else {
		switch {
		case s.Scope != nil:
			return errors.New("account stop: a resume carries no scope")
		case s.LiftsSequence <= 0 || s.LiftsSequence >= s.Signal.Sequence:
			return errors.New("account stop: a resume names the earlier feed place of the stop it lifts")
		case s.RunsInProgress != 0:
			return errors.New("account stop: a resume counts no runs")
		}
	}
	switch {
	case !owner && (s.OwnerSignature != nil || s.Unsigned != ""):
		return errors.New("account stop: a Verdifax stop or resume carries no owner signature and no unsigned statement")
	case owner && s.OwnerSignature != nil && s.Unsigned != "":
		return errors.New("account stop: a record is signed or unsigned, not both")
	case owner && s.Action == StopActionResume && s.OwnerSignature == nil:
		return errors.New("account stop: the owner's resume carries the owner's request-key signature")
	case owner && s.OwnerSignature == nil && s.Unsigned != StopUnsigned:
		return errors.New("account stop: an owner's stop without a signature seals the fixed unsigned statement")
	case s.OwnerSignature != nil:
		if sigErr := s.OwnerSignature.Check(DecidedByOwner, s.Signal.Account, s.Kind(), s.Subject()); sigErr != nil {
			return errors.New("account stop: " + sigErr.Error())
		}
	}
	return s.Signal.Validate()
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (s *AccountStop) LeafHash() string {
	return ComputeReceiptLeafHashV3(AccountStopKind, s.Signal.Account, s.AccountStopHash, s.Signal.Sequence, s.Signal.PreviousSignalHash)
}

// The AI agent tools (round 64, design 05). An owner may give a member key a
// tool allowlist when it creates the key: the names of the verdifax-mcp tools
// the key may be used for (mcp-tools.json), and, apart from them, the stop
// permission. The allowlist is sealed in the key's key.created record and the
// server refuses the key on every route outside it. No owner power and no
// approver key is ever in the list: resuming, managing keys, policies or
// approvers, and signing off stay with the owner and the approvers.
const (
	// AgentStopPermission lets a member key place the owner's stop on the
	// account. It never lets the key lift a stop.
	AgentStopPermission = "account_stop"
)

// AgentTools lists the verdifax-mcp tool names, in the contract's order.
var AgentTools = []string{"verify_record", "verify_feed", "get_record", "list_records", "read_feed",
	"list_pending_signoffs", "get_signoffs", "test_policy", "seal_decision", "prepare_signoff"}

// IsGrantableTool reports a name a member key's allowlist may hold: one of
// AgentTools, or AgentStopPermission.
func IsGrantableTool(name string) bool {
	return name == AgentStopPermission || oneOf(name, AgentTools)
}

// validAllowedTools reports an allowlist that is 1 or more grantable names,
// distinct and sorted.
func validAllowedTools(tools []string) bool {
	if len(tools) == 0 {
		return false
	}
	for i, t := range tools {
		if !IsGrantableTool(t) || (i > 0 && tools[i-1] >= t) {
			return false
		}
	}
	return true
}
