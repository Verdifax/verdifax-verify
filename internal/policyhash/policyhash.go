// Package policyhash recomputes the policy_hash the Verdifax policy gate
// (PEPG) seals into allow tokens, deny receipts and attestation gap
// receipts, starting from the PSL policy JSON document itself.
//
// It is a port of the server's psl package (PolicyHash, Parse and
// Canonicalize) and must stay byte-identical to it: the parity vectors
// in policyhash_test.go were produced by the server's own code. It
// imports nothing from the rest of this verifier, so it can be read and
// audited on its own.
//
// Decoding mirrors the server's psl.Parse, which is encoding/json into
// the Policy struct followed by Validate:
//
//   - field names, Go types and type errors are the server's (a float
//     in an integer field, a string where an array belongs, data after
//     the document and invalid JSON are all refused, as the server
//     refuses them);
//   - unknown fields are ignored, because the server ignores them;
//   - keys match fields case-insensitively and invalid UTF-8 becomes
//     U+FFFD, because that is what encoding/json does on the server;
//   - schema must be "psl.v1", policy_id must be set and default_effect
//     must be "allow" or "deny" (psl.Validate).
//
// One deliberate difference: two keys in one object that are equal
// under Unicode case folding (which includes exact duplicates) are
// refused anywhere in the document. The server lets the last one win,
// so such a document is ambiguous: another reader could show a value
// the hash did not cover. A genuine policy never carries one.
package policyhash

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode"
)

// Result is what a policy document seals: its identity and its hash.
type Result struct {
	PolicyID      string
	PolicyName    string
	PolicyVersion string
	PolicyHash    string // 64 lowercase hex characters
}

// ErrDuplicateKey wraps every refusal of a repeated (or case-fold
// equal) key, so callers can name it.
var ErrDuplicateKey = errors.New("policyhash: duplicate key in policy document")

// FromDocument decodes a PSL policy document the way the server does
// and returns its identity and policy_hash.
func FromDocument(doc []byte) (Result, error) {
	if dupErr := checkDuplicateKeys(doc); dupErr != nil {
		return Result{}, dupErr
	}
	var p policy
	if parseErr := json.Unmarshal(doc, &p); parseErr != nil {
		return Result{}, fmt.Errorf("policyhash: parse json: %w", parseErr)
	}
	if validErr := validate(&p); validErr != nil {
		return Result{}, validErr
	}
	hash, hashErr := canonicalSHA256(canonicalPolicyForHash(&p))
	if hashErr != nil {
		return Result{}, fmt.Errorf("policyhash: policy_hash: %w", hashErr)
	}
	return Result{
		PolicyID:      p.PolicyID,
		PolicyName:    p.PolicyName,
		PolicyVersion: p.PolicyVersion,
		PolicyHash:    hash,
	}, nil
}

// The types below copy the server's psl types field for field: same
// JSON names, same Go kinds, so encoding/json accepts and refuses
// exactly what it does on the server. Fields the hash excludes
// (metadata, tags, rule_name, priority, signature_base64, signed_at)
// are still declared, because the server type-checks them while
// decoding. The server's named string types (Effect, SubjectType and
// so on) are plain strings here; encoding/json treats them alike.

type policy struct {
	Schema                 string            `json:"schema"`
	PolicyID               string            `json:"policy_id"`
	PolicyName             string            `json:"policy_name"`
	PolicyVersion          string            `json:"policy_version"`
	EffectiveAt            string            `json:"effective_at"`
	DefaultEffect          string            `json:"default_effect"`
	Rules                  []rule            `json:"rules"`
	Metadata               map[string]any    `json:"metadata,omitempty"` // excluded from policy_hash
	Tags                   []string          `json:"tags,omitempty"`     // excluded from policy_hash
	RequiredAttestedFields []string          `json:"required_attested_fields,omitempty"`
	RequiredOutcomeFields  []string          `json:"required_outcome_fields,omitempty"`
	ProfileTag             string            `json:"profile_tag,omitempty"`
	SignaturePolicy        *signaturePolicy  `json:"signature_policy,omitempty"`
	Signers                []policySignature `json:"signers,omitempty"`
}

type policySignature struct {
	SignerID        string `json:"signer_id"`
	KeyAlgorithm    string `json:"key_algorithm"`
	KeyFingerprint  string `json:"key_fingerprint"`
	SignatureBase64 string `json:"signature_base64"` // excluded from policy_hash
	SignedAt        string `json:"signed_at"`        // excluded from policy_hash
}

type signaturePolicy struct {
	Type      string   `json:"type"`
	Threshold int      `json:"threshold,omitempty"`
	Required  []string `json:"required,omitempty"`
}

type rule struct {
	RuleID             string      `json:"rule_id"`
	RuleName           string      `json:"rule_name,omitempty"` // excluded from policy_hash
	Effect             string      `json:"effect"`
	Subject            subject     `json:"subject"`
	Verb               verb        `json:"verb"`
	Object             object      `json:"object"`
	Conditions         []condition `json:"conditions,omitempty"`
	Priority           int         `json:"priority,omitempty"` // excluded from policy_hash
	ReasonCodeOverride string      `json:"reason_code,omitempty"`
}

type subject struct {
	Type      string   `json:"type"`
	IDMatch   matcher  `json:"id_match"`
	RoleMatch *matcher `json:"role_match,omitempty"`
}

type verb struct {
	Match matcher `json:"match"`
}

type object struct {
	Type              string  `json:"type"`
	IDMatch           matcher `json:"id_match"`
	ClassificationMax string  `json:"classification_max,omitempty"`
	ClassificationMin string  `json:"classification_min,omitempty"`
}

type condition struct {
	Type          string `json:"type"`
	MaxPerWindow  int    `json:"max_per_window,omitempty"`
	WindowSeconds int    `json:"window_seconds,omitempty"`
	StartUTC      string `json:"start_utc,omitempty"`
	EndUTC        string `json:"end_utc,omitempty"`
	Required      bool   `json:"required,omitempty"`
	Seconds       int    `json:"seconds,omitempty"`
	Role          string `json:"role,omitempty"`
}

type matcher struct {
	Operator string   `json:"operator"`
	Value    string   `json:"value,omitempty"`
	Values   []string `json:"values,omitempty"`
}

// validate is the server's psl.Validate.
func validate(p *policy) error {
	if p.Schema != "psl.v1" {
		return fmt.Errorf("policyhash: unsupported schema version: got %q want %q", p.Schema, "psl.v1")
	}
	if p.PolicyID == "" {
		return errors.New("policyhash: policy_id is missing")
	}
	if p.DefaultEffect != "allow" && p.DefaultEffect != "deny" {
		return fmt.Errorf("policyhash: default_effect must be allow or deny: got %q", p.DefaultEffect)
	}
	return nil
}

// canonicalPolicyForHash is the server's preimage: the substantive
// policy content, with metadata, tags, rule_name, priority and each
// signer's signature bytes and timestamp left out. Optional parts are
// added only when present, so policies without them keep the hash they
// had before those parts existed.
func canonicalPolicyForHash(p *policy) map[string]any {
	rules := make([]any, 0, len(p.Rules))
	for _, r := range p.Rules {
		rules = append(rules, ruleHashPreimage(r))
	}
	out := map[string]any{
		"default_effect": p.DefaultEffect,
		"effective_at":   p.EffectiveAt,
		"policy_id":      p.PolicyID,
		"policy_name":    p.PolicyName,
		"policy_version": p.PolicyVersion,
		"rules":          rules,
		"schema":         p.Schema,
	}
	if p.SignaturePolicy != nil {
		out["signature_policy"] = signaturePolicyPreimage(p.SignaturePolicy)
	}
	if len(p.Signers) > 0 {
		signers := make([]any, 0, len(p.Signers))
		for _, s := range p.Signers {
			signers = append(signers, signerPreimage(s))
		}
		out["signers"] = signers
	}
	if len(p.RequiredAttestedFields) > 0 {
		out["required_attested_fields"] = stringsAsAny(p.RequiredAttestedFields)
	}
	if len(p.RequiredOutcomeFields) > 0 {
		out["required_outcome_fields"] = stringsAsAny(p.RequiredOutcomeFields)
	}
	if p.ProfileTag != "" {
		out["profile_tag"] = p.ProfileTag
	}
	return out
}

func stringsAsAny(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// signerPreimage binds who signed (identity and key), not the
// signature bytes or time, so re-signing leaves policy_hash unchanged.
func signerPreimage(s policySignature) map[string]any {
	return map[string]any{
		"key_algorithm":   s.KeyAlgorithm,
		"key_fingerprint": s.KeyFingerprint,
		"signer_id":       s.SignerID,
	}
}

// signaturePolicyPreimage omits a threshold that is not positive and an
// empty required list, as the server does.
func signaturePolicyPreimage(sp *signaturePolicy) map[string]any {
	out := map[string]any{"type": sp.Type}
	if sp.Threshold > 0 {
		out["threshold"] = sp.Threshold
	}
	if len(sp.Required) > 0 {
		out["required"] = stringsAsAny(sp.Required)
	}
	return out
}

func ruleHashPreimage(r rule) map[string]any {
	out := map[string]any{
		"effect":  r.Effect,
		"object":  objectPreimage(r.Object),
		"rule_id": r.RuleID,
		"subject": subjectPreimage(r.Subject),
		"verb":    map[string]any{"match": matcherPreimage(r.Verb.Match)},
	}
	if len(r.Conditions) > 0 {
		conds := make([]any, 0, len(r.Conditions))
		for _, c := range r.Conditions {
			conds = append(conds, conditionPreimage(c))
		}
		out["conditions"] = conds
	}
	if r.ReasonCodeOverride != "" {
		out["reason_code"] = r.ReasonCodeOverride
	}
	return out
}

func subjectPreimage(s subject) map[string]any {
	out := map[string]any{
		"id_match": matcherPreimage(s.IDMatch),
		"type":     s.Type,
	}
	if s.RoleMatch != nil {
		out["role_match"] = matcherPreimage(*s.RoleMatch)
	}
	return out
}

func objectPreimage(o object) map[string]any {
	out := map[string]any{
		"id_match": matcherPreimage(o.IDMatch),
		"type":     o.Type,
	}
	if o.ClassificationMax != "" {
		out["classification_max"] = o.ClassificationMax
	}
	if o.ClassificationMin != "" {
		out["classification_min"] = o.ClassificationMin
	}
	return out
}

func matcherPreimage(m matcher) map[string]any {
	out := map[string]any{"operator": m.Operator}
	if m.Value != "" {
		out["value"] = m.Value
	}
	if len(m.Values) > 0 {
		out["values"] = stringsAsAny(m.Values)
	}
	return out
}

// conditionPreimage carries only the fields the condition's type uses;
// an unknown type contributes its type alone.
func conditionPreimage(c condition) map[string]any {
	out := map[string]any{"type": c.Type}
	switch c.Type {
	case "rate_limit":
		out["max_per_window"] = c.MaxPerWindow
		out["window_seconds"] = c.WindowSeconds
	case "time_window":
		out["start_utc"] = c.StartUTC
		out["end_utc"] = c.EndUTC
	case "mfa_required":
		out["required"] = c.Required
	case "min_session_age":
		out["seconds"] = c.Seconds
	case "requires_role":
		out["role"] = c.Role
	}
	return out
}

// canonicalSHA256 is the server's CanonicalSHA256: lowercase hex
// SHA-256 of canonicalize(v).
func canonicalSHA256(v any) (string, error) {
	b, canonErr := canonicalize(v)
	if canonErr != nil {
		return "", canonErr
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum), nil
}

// canonicalize is the server's Canonicalize, kept step for step: marshal
// v, decode it back with UseNumber, then write it with object keys
// sorted by byte order, no whitespace, strings escaped by encoding/json
// (so <, > and & become <, > and &) and numbers as
// writeCanonicalNumber spells them.
func canonicalize(v any) ([]byte, error) {
	raw, marshalErr := json.Marshal(v)
	if marshalErr != nil {
		return nil, fmt.Errorf("canonicalize: marshal: %w", marshalErr)
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if decodeErr := dec.Decode(&generic); decodeErr != nil {
		return nil, fmt.Errorf("canonicalize: unmarshal: %w", decodeErr)
	}
	var buf bytes.Buffer
	if writeErr := writeCanonical(&buf, generic); writeErr != nil {
		return nil, writeErr
	}
	return buf.Bytes(), nil
}

func writeCanonical(w *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		w.WriteString("null")
	case bool:
		if x {
			w.WriteString("true")
		} else {
			w.WriteString("false")
		}
	case json.Number:
		return writeCanonicalNumber(w, string(x))
	case float64:
		return writeCanonicalNumber(w, strconv.FormatFloat(x, 'g', -1, 64))
	case string:
		b, strErr := json.Marshal(x)
		if strErr != nil {
			return strErr
		}
		w.Write(b)
	case []any:
		w.WriteByte('[')
		for i, elem := range x {
			if i > 0 {
				w.WriteByte(',')
			}
			if elemErr := writeCanonical(w, elem); elemErr != nil {
				return elemErr
			}
		}
		w.WriteByte(']')
	case map[string]any:
		w.WriteByte('{')
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				w.WriteByte(',')
			}
			keyBytes, keyErr := json.Marshal(k)
			if keyErr != nil {
				return keyErr
			}
			w.Write(keyBytes)
			w.WriteByte(':')
			if valErr := writeCanonical(w, x[k]); valErr != nil {
				return valErr
			}
		}
		w.WriteByte('}')
	default:
		return fmt.Errorf("canonicalize: unsupported type %T", v)
	}
	return nil
}

// writeCanonicalNumber is the server's rule: an integer-valued number
// is written as an integer, any other number in the shortest form that
// round-trips. Every number in today's preimage is a Go int, so only
// the first branch is reached in practice; the rest is kept so the two
// implementations cannot drift if that changes.
func writeCanonicalNumber(w *bytes.Buffer, s string) error {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		fmt.Fprintf(w, "%d", i)
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f == float64(int64(f)) {
			fmt.Fprintf(w, "%d", int64(f))
			return nil
		}
		w.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
		return nil
	}
	return fmt.Errorf("canonicalize: unparseable number %q", s)
}

// checkDuplicateKeys walks the whole document and refuses any object
// holding two keys that are equal under Unicode simple case folding.
// Malformed JSON is left for json.Unmarshal to report, so the error a
// caller sees for it is the server's.
func checkDuplicateKeys(doc []byte) error {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := walkValue(dec, "$"); errors.Is(err, ErrDuplicateKey) {
		return err
	}
	return nil
}

func walkValue(dec *json.Decoder, path string) error {
	tok, tokErr := dec.Token()
	if tokErr != nil {
		return tokErr
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]string{}
		for dec.More() {
			keyTok, keyErr := dec.Token()
			if keyErr != nil {
				return keyErr
			}
			key, _ := keyTok.(string)
			folded := foldKey(key)
			if first, dup := seen[folded]; dup {
				return fmt.Errorf("%w: %s holds %q and %q", ErrDuplicateKey, path, first, key)
			}
			seen[folded] = key
			if nestedErr := walkValue(dec, path+"."+key); nestedErr != nil {
				return nestedErr
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if elemErr := walkValue(dec, path+"["+strconv.Itoa(i)+"]"); elemErr != nil {
				return elemErr
			}
		}
	}
	_, closeErr := dec.Token() // the closing delimiter
	return closeErr
}

// foldKey maps every rune to the smallest rune of its simple case
// folding orbit, so two keys fold to the same string exactly when
// strings.EqualFold reports them equal.
func foldKey(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		min := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < min {
				min = f
			}
		}
		out = append(out, min)
	}
	return string(out)
}
