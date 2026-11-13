package artifacts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Account changes and run deletions (round 60). Each is one record, anchored
// on the public log as its own entry and carrying its place in the account's
// signal feed, so everything the owner or Verdifax changes in an account is
// in that account's feed, with who decided. A deletion leaves its tombstone
// in the feed when the record itself is gone, so the feed and the public log
// still account for every entry.
const (
	// AccountChangeFormat is the format field of an account-change record.
	AccountChangeFormat = "verdifax.account-change.v1"
	// AccountChangeKind is the leaf kind of its public-log entry.
	AccountChangeKind = "account_change"
	// RunDeletionFormat is the format field of a run-deletion record.
	RunDeletionFormat = "verdifax.run-deletion.v1"
	// RunDeletionKind is the leaf kind of its public-log entry.
	RunDeletionKind = "run_deletion"

	// The account-change actions.
	AccountCreated           = "account.created"
	AccountRequestKeyCleared = "request_key.cleared"
	// AccountRequestKeyRegistered and AccountRequestKeyRotated (round 61,
	// N22): a key's holder registers its first request key, or replaces it
	// with the current one's approval. The value is the new public key.
	AccountRequestKeyRegistered  = "request_key.registered"
	AccountRequestKeyRotated     = "request_key.rotated"
	AccountKeyTierSet            = "key.tier_set"
	AccountKeySubmitterClassSet  = "key.submitter_class_set"
	AccountKeyBillingSet         = "key.billing_set"
	AccountOwnerKeyReplacement   = "owner_key.replacement_requested"
	AccountSettingOwnerReplace   = "setting.owner_replacement"
	AccountSettingVerdifaxDelete = "setting.verdifax_deletion"
	// AccountWebhookSubscribed and AccountWebhookDeleted (round 62): the
	// owner added or removed an address that receives a copy of the
	// account's events. The value is WebhookValue: the SHA-256 of the
	// address, never the address, which can carry a token, and the event
	// kinds it takes. Signed by the owner's request key, so Verdifax cannot
	// add a destination for the account's events.
	AccountWebhookSubscribed = "webhook.subscribed"
	AccountWebhookDeleted    = "webhook.deleted"

	// SettingAllowed and SettingBlocked are a setting's two values.
	SettingAllowed = "allowed"
	SettingBlocked = "blocked"

	// OwnerChangeSignatureForm opens the preimage the owner's request key
	// signs for a change the owner decides: a setting or a deletion. Verdifax
	// never holds that key, so the signature shows the owner made the change.
	OwnerChangeSignatureForm = "verdifax.owner-change-signature.v1"
)

// webhookValuePattern is the form of a webhook change's value.
var webhookValuePattern = regexp.MustCompile(`^sha256=[0-9a-f]{64} kinds=(all|[a-z]+\.[a-z]+(,[a-z]+\.[a-z]+)*)$`)

// WebhookValue is the value a webhook change seals and the owner signs: the
// SHA-256 of the address exactly as stored, and its event kinds sorted and
// joined with commas, or "all" for every kind.
func WebhookValue(address string, kinds []string) string {
	sum := sha256.Sum256([]byte(address))
	sorted := append([]string(nil), kinds...)
	sort.Strings(sorted)
	joined := strings.Join(sorted, ",")
	if joined == "" {
		joined = "all"
	}
	return "sha256=" + hex.EncodeToString(sum[:]) + " kinds=" + joined
}

// OwnerSignature is the owner's request-key signature over a change the owner
// decided.
type OwnerSignature struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	SignedAt  string `json:"signed_at"`
	Nonce     string `json:"nonce"`
}

// OwnerChangePreimage is what the owner's request key signs: the account, the
// change, its subject, the time and a nonce.
func OwnerChangePreimage(account, change, subject, signedAt, nonce string) []byte {
	return []byte(strings.Join([]string{OwnerChangeSignatureForm, account, change, subject, signedAt, nonce}, "\x00"))
}

func (o *OwnerSignature) fields() []string {
	if o == nil {
		return nil
	}
	return []string{o.PublicKey, o.Signature, o.SignedAt, o.Nonce}
}

// Check verifies the signature over the change: an owner-decided change
// carries one, made by the key it names, and a Verdifax change carries none.
func (o *OwnerSignature) Check(decidedBy, account, change, subject string) error {
	if decidedBy != DecidedByOwner {
		if o != nil {
			return errors.New("only a change the owner decided carries the owner's signature")
		}
		return nil
	}
	if o == nil {
		return errors.New("a change the owner decided carries the owner's request-key signature")
	}
	pub, pubErr := base64.StdEncoding.DecodeString(o.PublicKey)
	sig, sigErr := base64.StdEncoding.DecodeString(o.Signature)
	nonce, nonceErr := hex.DecodeString(o.Nonce)
	switch {
	case pubErr != nil || len(pub) != ed25519.PublicKeySize:
		return errors.New("the owner's signature names no Ed25519 public key")
	case sigErr != nil || nonceErr != nil || len(nonce) != 16 || o.SignedAt == "":
		return errors.New("the owner's signature is malformed")
	case !ed25519.Verify(pub, OwnerChangePreimage(account, change, subject, o.SignedAt, o.Nonce), sig):
		return errors.New("the owner's signature does not verify")
	}
	return nil
}

// RequestKeyApproval is a key's current request key approving the change to
// its next one (round 61, N22): its signature over the new public key, or
// over the empty key for a clear, as the key's holder sent it. Verdifax never
// holds that key, so the approval shows the holder of the key before made the
// change, and a verifier can follow each key's chain from its registration.
type RequestKeyApproval struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	SignedAt  string `json:"signed_at"`
	Nonce     string `json:"nonce"`
}

// fields are the approval's values as they join the record's hash, after a
// label, so they can never stand for an owner signature's.
func (a *RequestKeyApproval) fields() []string {
	if a == nil {
		return nil
	}
	return []string{"request_key_approval", a.PublicKey, a.Signature, a.SignedAt, a.Nonce}
}

// Check verifies the approval: the key it names signed the change to newKey.
func (a *RequestKeyApproval) Check(newKey string) error {
	pub, pubErr := base64.StdEncoding.DecodeString(a.PublicKey)
	sig, sigErr := base64.StdEncoding.DecodeString(a.Signature)
	nonce, nonceErr := hex.DecodeString(a.Nonce)
	switch {
	case pubErr != nil || len(pub) != ed25519.PublicKeySize:
		return errors.New("the request-key approval names no Ed25519 public key")
	case sigErr != nil || nonceErr != nil || len(nonce) != 16 || a.SignedAt == "":
		return errors.New("the request-key approval is malformed")
	case !ed25519.Verify(pub, RequestKeyChangePreimage(newKey, a.SignedAt, a.Nonce), sig):
		return errors.New("the request-key approval does not verify")
	}
	return nil
}

// accountChangeRule says, for one action, who may decide it and whether it
// names a key. keyHolder marks a change the key's own holder makes to its
// request key: it is the account's side (owner), and is proven by the key's
// request-key chain instead of the owner key's signature. approval says the
// change carries the current request key's approval when the key holder
// makes it.
type accountChangeRule struct {
	ownerMay, verdifaxMay, namesKey bool
	keyHolder, approval             bool
	publicKeyValue                  bool
	webhookValue                    bool
	values                          []string
}

var accountChangeRules = map[string]accountChangeRule{
	AccountCreated:               {verdifaxMay: true, values: []string{"trial", "production"}},
	AccountRequestKeyCleared:     {ownerMay: true, verdifaxMay: true, namesKey: true, keyHolder: true, approval: true, values: []string{""}},
	AccountRequestKeyRegistered:  {ownerMay: true, namesKey: true, keyHolder: true, publicKeyValue: true},
	AccountRequestKeyRotated:     {ownerMay: true, namesKey: true, keyHolder: true, approval: true, publicKeyValue: true},
	AccountKeyTierSet:            {verdifaxMay: true, namesKey: true, values: []string{"trial", "production"}},
	AccountKeySubmitterClassSet:  {verdifaxMay: true, namesKey: true, values: []string{"third-party", "same-legal-entity"}},
	AccountKeyBillingSet:         {verdifaxMay: true, namesKey: true, values: []string{"linked", "unlinked"}},
	AccountOwnerKeyReplacement:   {verdifaxMay: true},
	AccountSettingOwnerReplace:   {ownerMay: true, values: []string{SettingAllowed, SettingBlocked}},
	AccountSettingVerdifaxDelete: {ownerMay: true, values: []string{SettingAllowed, SettingBlocked}},
	AccountWebhookSubscribed:     {ownerMay: true, webhookValue: true},
	AccountWebhookDeleted:        {ownerMay: true, webhookValue: true},
}

// AccountChangeActions lists every account-change action, in a fixed order.
var AccountChangeActions = []string{AccountCreated, AccountRequestKeyCleared, AccountKeyTierSet, AccountKeySubmitterClassSet,
	AccountKeyBillingSet, AccountOwnerKeyReplacement, AccountSettingOwnerReplace, AccountSettingVerdifaxDelete,
	AccountRequestKeyRegistered, AccountRequestKeyRotated, AccountWebhookSubscribed, AccountWebhookDeleted}

// IsRequestKeyAction reports a change to one key's request key: registered,
// rotated or cleared.
func IsRequestKeyAction(action string) bool {
	return accountChangeRules[action].keyHolder
}

// AccountChange is one change to an account's settings or to one of its keys'
// terms.
type AccountChange struct {
	Format    string `json:"format"`
	Action    string `json:"action"`
	DecidedBy string `json:"decided_by"`
	// KeyID names the key a key action changes, and is 0 otherwise.
	KeyID int64 `json:"key_id"`
	// Value is the new value: a tier, a submitter class, linked or unlinked,
	// allowed or blocked, a claim expiry, or empty.
	Value     string `json:"value"`
	ChangedAt string `json:"changed_at"`
	// OwnerSignature is the owner's request-key signature, on a change the
	// owner decided, over the account, the action and the value.
	OwnerSignature *OwnerSignature `json:"owner_signature,omitempty"`
	// RequestKeyApproval, on a request key rotated or cleared by the key's
	// holder (round 61, N22), is the current request key's approval.
	RequestKeyApproval *RequestKeyApproval `json:"request_key_approval,omitempty"`
	Signal             SignalLink          `json:"signal"`
	AccountChangeHash  string              `json:"account_change_hash"`
	Anchor             *ReceiptAnchor      `json:"anchor,omitempty"`
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed. The approval joins only when present, so a
// record sealed before it hashes as before.
func (c *AccountChange) ComputeHash() string {
	fields := append([]string{c.Format, c.Action, c.DecidedBy, strconv.FormatInt(c.KeyID, 10), c.Value, c.ChangedAt},
		c.OwnerSignature.fields()...)
	fields = append(append(fields, c.RequestKeyApproval.fields()...), c.Signal.fields()...)
	return lengthPrefixedHash(fields)
}

// Validate checks the record's shape: every value its hash and leaf are built
// from, and that the decider may make this change.
func (c *AccountChange) Validate() error {
	rule, known := accountChangeRules[c.Action]
	switch {
	case c.Format != AccountChangeFormat:
		return errors.New("account change: unknown format")
	case !known:
		return errors.New("account change: unknown action")
	case c.DecidedBy != DecidedByOwner && c.DecidedBy != DecidedByVerdifax:
		return errors.New("account change: decided_by must be owner or verdifax_admin")
	case c.DecidedBy == DecidedByOwner && !rule.ownerMay:
		return errors.New("account change: only Verdifax makes this change")
	case c.DecidedBy == DecidedByVerdifax && !rule.verdifaxMay:
		return errors.New("account change: only the account's owner makes this change")
	case rule.namesKey != (c.KeyID > 0) || c.KeyID < 0:
		return errors.New("account change: a key action names its key, and only a key action does")
	case rule.values != nil && !oneOf(c.Value, rule.values):
		return errors.New("account change: value is not one this action takes")
	case rule.publicKeyValue && !validBase64Len(c.Value, ed25519.PublicKeySize):
		return errors.New("account change: a registered or rotated request key's value is its base64 Ed25519 public key")
	case rule.webhookValue && !webhookValuePattern.MatchString(c.Value):
		return errors.New("account change: a webhook change's value is sha256=<the address's SHA-256> kinds=<all, or the kinds joined with commas>")
	case rule.values == nil && (c.Value == "" || len(c.Value) > 200):
		return errors.New("account change: value must be 1 to 200 bytes")
	case c.ChangedAt == "":
		return errors.New("account change: changed_at is required")
	case !jobHashPattern.MatchString(c.AccountChangeHash):
		return errors.New("account change: account_change_hash must be 64 lowercase hex characters")
	}
	// A key holder's change to its own request key is proven by the key's
	// chain: the current key approves a rotation or a clear. It carries no
	// owner-key signature; every other owner change carries one.
	holderChange := rule.keyHolder && c.DecidedBy == DecidedByOwner
	switch {
	case holderChange && c.OwnerSignature != nil:
		return errors.New("account change: a key holder's change to its request key is approved by that key, not signed by the owner key")
	case (holderChange && rule.approval) != (c.RequestKeyApproval != nil):
		return errors.New("account change: a rotated request key, and one its holder cleared, carry the current key's approval, and no other change does")
	case c.RequestKeyApproval != nil:
		if approvalErr := c.RequestKeyApproval.Check(c.Value); approvalErr != nil {
			return errors.New("account change: " + approvalErr.Error())
		}
	case !holderChange:
		if sigErr := c.OwnerSignature.Check(c.DecidedBy, c.Signal.Account, c.Action, c.Value); sigErr != nil {
			return errors.New("account change: " + sigErr.Error())
		}
	}
	return c.Signal.Validate()
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (c *AccountChange) LeafHash() string {
	return ComputeReceiptLeafHashV3(AccountChangeKind, c.Signal.Account, c.AccountChangeHash, c.Signal.Sequence, c.Signal.PreviousSignalHash)
}

// RunDeletion is one of the account's records deleted, by its owner or by
// Verdifax. It binds the record's hash, so the tombstone names the exact
// record that was deleted.
type RunDeletion struct {
	Format     string `json:"format"`
	DecidedBy  string `json:"decided_by"`
	RunID      int64  `json:"run_id"`
	RecordHash string `json:"record_hash"`
	// JobID and StepID name the record's place in a job, when it had one.
	JobID  string `json:"job_id,omitempty"`
	StepID string `json:"step_id,omitempty"`
	// JobLinks (round 61) are the deleted record's own job links, when it
	// was a job step and was deleted since the server release that came
	// with verdifax-verify v0.34.0: the records it followed and whether it
	// closed the job. A job stays checkable through the tombstone; a
	// tombstone written before carries none and cannot vouch for links.
	JobLinks *DeletedJobLinks `json:"job_links,omitempty"`
	// LogEntries are the public-log entries of the deleted record, in
	// ascending order, so the log still accounts for every entry once the
	// record is gone.
	LogEntries []string `json:"log_entries,omitempty"`
	ChangedAt  string   `json:"changed_at"`
	// OwnerSignature is the owner's request-key signature, on a deletion the
	// owner decided, over the account, the run and its record hash.
	OwnerSignature *OwnerSignature `json:"owner_signature,omitempty"`
	Signal         SignalLink      `json:"signal"`
	DeletionHash   string          `json:"deletion_hash"`
	Anchor         *ReceiptAnchor  `json:"anchor,omitempty"`
}

// DeletedJobLinks are a deleted job step's own links, as its job link held
// them: the records it followed, its links to other accounts' records, and
// whether it was the job's final step.
type DeletedJobLinks struct {
	PreviousRecordHashes []string `json:"previous_record_hashes,omitempty"`
	ExternalPrevious     []string `json:"external_previous,omitempty"`
	Final                bool     `json:"final,omitempty"`
}

// fields are the links' values as they join the tombstone's hash, after a
// label and with each list's length, so no value can run into another.
func (l *DeletedJobLinks) fields() []string {
	if l == nil {
		return nil
	}
	out := append([]string{"job_links", strconv.Itoa(len(l.PreviousRecordHashes))}, l.PreviousRecordHashes...)
	out = append(append(out, strconv.Itoa(len(l.ExternalPrevious))), l.ExternalPrevious...)
	return append(out, strconv.FormatBool(l.Final))
}

// ComputeHash returns the record's hash: every field but the hash and the
// anchor, each length-prefixed. The job links join only when present, so a
// tombstone sealed before them hashes as before.
func (d *RunDeletion) ComputeHash() string {
	head := []string{d.Format, d.DecidedBy, strconv.FormatInt(d.RunID, 10), d.RecordHash, d.JobID, d.StepID,
		strconv.Itoa(len(d.LogEntries))}
	head = append(append(head, d.LogEntries...), d.ChangedAt)
	fields := append(append(head, d.OwnerSignature.fields()...), d.JobLinks.fields()...)
	return lengthPrefixedHash(append(fields, d.Signal.fields()...))
}

// Validate checks the record's shape: every value its hash and leaf are built
// from.
func (d *RunDeletion) Validate() error {
	switch {
	case d.Format != RunDeletionFormat:
		return errors.New("run deletion: unknown format")
	case d.DecidedBy != DecidedByOwner && d.DecidedBy != DecidedByVerdifax:
		return errors.New("run deletion: decided_by must be owner or verdifax_admin")
	case d.RunID <= 0:
		return errors.New("run deletion: run_id must be positive")
	case !jobHashPattern.MatchString(d.RecordHash):
		return errors.New("run deletion: record_hash must be 64 lowercase hex characters")
	case len(d.JobID) > 200 || len(d.StepID) > 200:
		return errors.New("run deletion: job_id and step_id are at most 200 bytes")
	case (d.JobID == "") != (d.StepID == ""):
		return errors.New("run deletion: a record in a job names both its job and its step")
	case d.JobLinks != nil && d.JobID == "":
		return errors.New("run deletion: only a job step's tombstone carries job links")
	case !ascendingLogEntries(d.LogEntries):
		return errors.New("run deletion: log_entries must be distinct decimal entry numbers in ascending order")
	case d.ChangedAt == "":
		return errors.New("run deletion: changed_at is required")
	case !jobHashPattern.MatchString(d.DeletionHash):
		return errors.New("run deletion: deletion_hash must be 64 lowercase hex characters")
	}
	if l := d.JobLinks; l != nil {
		if err := validateHashList("previous_record_hashes", l.PreviousRecordHashes, MaxJobPrevious); err != nil {
			return errors.New("run deletion: " + err.Error())
		}
		if err := validateHashList("external_previous", l.ExternalPrevious, MaxJobExternal); err != nil {
			return errors.New("run deletion: " + err.Error())
		}
	}
	if sigErr := d.OwnerSignature.Check(d.DecidedBy, d.Signal.Account, SignalRunDeleted, d.DeletionSubject()); sigErr != nil {
		return errors.New("run deletion: " + sigErr.Error())
	}
	return d.Signal.Validate()
}

// DeletionSubject is what the owner signs for a deletion: the run and the
// hash of its record.
func (d *RunDeletion) DeletionSubject() string {
	return strconv.FormatInt(d.RunID, 10) + ":" + d.RecordHash
}

// LeafHash is the public-log leaf that binds this record: its hash and its
// place in the account's feed.
func (d *RunDeletion) LeafHash() string {
	return ComputeReceiptLeafHashV3(RunDeletionKind, d.Signal.Account, d.DeletionHash, d.Signal.Sequence, d.Signal.PreviousSignalHash)
}

// ascendingLogEntries reports log entry numbers that are each 1 to 20 digits,
// with no leading zero, distinct and in ascending numeric order.
func ascendingLogEntries(entries []string) bool {
	var previous uint64
	for i, e := range entries {
		if len(e) == 0 || len(e) > 20 || (len(e) > 1 && e[0] == '0') {
			return false
		}
		n, err := strconv.ParseUint(e, 10, 64)
		if err != nil || (i > 0 && n <= previous) {
			return false
		}
		previous = n
	}
	return true
}

func oneOf(v string, set []string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}
