package policyhash

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// serverVectors were produced by the orchestrator's own psl.Parse and
// psl.PolicyHash over the documents in testdata/, so each row is the
// value the server seals for that document. production_baseline_permit
// is the production default policy (productionBaselinePermitPolicy in
// the orchestrator's internal/api/phase101112.go) written out as JSON;
// its hash is the policy_hash production receipts carry. The psl_ and
// profile_ files are the orchestrator's own policy fixtures, copied
// unchanged. The synthetic_ files cover every part of the preimage.
var serverVectors = []struct {
	file, id, name, version, hash string
}{
	{"production_baseline_permit.json", "verdifax-default-baseline-permit", "Verdifax Default Baseline-Permit Policy", "1.0.0", "1a090975c0515a14296a0e68bb6840c5de4d76465369c50022e390b3da1e25d0"},
	{"profile_financial_governance_v1.json", "financial-governance-v1", "Financial Governance (SOX/FINRA-aligned attestation)", "1.0.0", "12da5a77120c6ea7883b702abb8ddf6a981e6faed99fedff94bd6c442612520b"},
	{"profile_gdpr_aligned_attestation_v1.json", "gdpr-aligned-attestation-v1", "GDPR-Aligned Attestation", "1.0.0", "e57e838fc0bae8d5cb66dfc865c71fd72f61c57c496e665a5f18d8c9e2a63f6e"},
	{"profile_healthcare_baseline_v1.json", "healthcare-baseline-v1", "Healthcare Baseline (HIPAA-aligned attestation)", "1.0.0", "1ad9e31e3f3e9fc061de0280af852be6e268d0786fbe3c0ab5f7236d0184ee8e"},
	{"profile_internal_audit_v1.json", "internal-audit-v1", "Internal Audit Baseline", "1.0.0", "85f7a338ca225d570ecee79c94c6bf6ee95f6de5235cbaac94ededcd7a10e273"},
	{"psl_policy_minimal.json", "policy-cross-lang-test", "Cross-language determinism test policy", "1.0.0", "70a63237f8cb0538db06d82b2fc29b7cfd01159e67c12ae362173aa4614e70ac"},
	{"psl_policy_signed.json", "policy-cross-lang-signed-test", "Cross-language determinism test policy (signed)", "1.0.0", "1a93993fd0ce09f48310a87ba22c3d4dd56b39f16d868c999ebfc3e6e09d5204"},
	{"synthetic_all_rule_shapes.json", "synthetic-all-rule-shapes", "Every subject, verb, object and condition shape", "4.2.0", "3bac3c125b3e527f49d62c525cc121d6d526172bc53751b487b68a537f2eae8a"},
	{"synthetic_case_variant_and_unknown_keys.json", "synthetic-case-variant-keys", "Case variant keys and unknown fields at every level", "1.0.0", "d1229bea0a59c16df83a13c15874e55d3848c92b3f7482035d062ee22a7e8b76"},
	{"synthetic_empty_optionals.json", "synthetic-empty-optionals", "Every optional part present but empty", "1.0.0", "16cd9f574245006c5eb23de21c7e571a3dc260ccbc2c9805c227191ea7169758"},
	{"synthetic_empty_optionals_omitted.json", "synthetic-empty-optionals", "Every optional part present but empty", "1.0.0", "16cd9f574245006c5eb23de21c7e571a3dc260ccbc2c9805c227191ea7169758"},
	{"synthetic_integers.json", "synthetic-integers", "Integer edge values", "1.0.0", "55fa9b4a5b7128e8a83b7f1457054cde893d02f7b4b89d3add70224798161b9b"},
	{"synthetic_invalid_utf8.json", "synthetic-invalid-utf8", "bad byte \ufffd\ufffd here", "1.0.0", "80f66e88bbea3474668fdff2dbcffdecbf4b966b7fbdefa74888d764e651765c"},
	{"synthetic_kitchen_sink.json", "synthetic-kitchen-sink", "Every hashed part at once", "5.0.0", "809adb722b883978f54255efd09a41854a217116b5d7efc000cc526f8dbe21a4"},
	{"synthetic_lone_surrogate.json", "synthetic-lone-surrogate", "lone high \ufffd and low \ufffd surrogates", "1.0.0", "9716d457fc7150aef8f931a95995e7926d3e9153a5f9264ea9d596faa379dd89"},
	{"synthetic_metadata_tags.json", "synthetic-metadata-tags", "Metadata and tags carrying every JSON kind", "1.0.0", "468cb35d657fcb1c14e1c3e5a17d76fab5e4545dd9099b14644042706eb104e6"},
	{"synthetic_metadata_tags_stripped.json", "synthetic-metadata-tags", "Metadata and tags carrying every JSON kind", "1.0.0", "468cb35d657fcb1c14e1c3e5a17d76fab5e4545dd9099b14644042706eb104e6"},
	{"synthetic_nulls.json", "synthetic-nulls", "", "", "428ad5725f51ade8d7691d653809ac077685c1efdf0d55e39b2de199e4969733"},
	{"synthetic_required_fields_profile.json", "synthetic-required-fields", "Required attested and outcome fields with a profile tag", "3.0.0", "188832856d9ae4854e2c2abc7e9c5ce43ceff8b1ae26641d1d4d30ea8a3baab6"},
	{"synthetic_signature_policy_only.json", "synthetic-signature-policy-only", "Signature policy with zero threshold and empty required", "1", "ae35c5889ad136ffa1c65954951e5f740fde803a7243c2f4e1e6f7d923c66c19"},
	{"synthetic_signed_n_of_m.json", "synthetic-signed-n-of-m", "Signed policy, three signers, n_of_m", "2.1.0", "2da1af3d3b4fd0790f4bde70215d9026d5a65b633ceed3d4b518c86f9c237bf7"},
	{"synthetic_signers_negative_threshold.json", "synthetic-signers-negative-threshold", "Signers with an all policy and a negative threshold", "1.0.0", "0b08d04a4cc5d81477afcd3fd61e7ca820cf3782d207e40fbd8cd8b88e151743"},
	{"synthetic_signers_without_signature_policy.json", "synthetic-signers-only", "Signers without a signature policy", "1.0.0", "e89343762024a47b4287619d407cb33969f33df983482e46a31919739cc54759"},
	{"synthetic_unicode_strings.json", "synthetic-unicode-é中🚀", "Café “quoted” <b>&amp;</b> \"q\" \\ / tab\tnl\n ctl\x01 del\x7f ls\u2028 ps\u2029 bom\ufeff", "v².①", "63444c42561611fdde099491a3d8483fa38152c33357fd412b0e023115a7914b"},
}

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServerParityVectors(t *testing.T) {
	for _, v := range serverVectors {
		got, err := FromDocument(readVector(t, v.file))
		if err != nil {
			t.Errorf("%s: refused a document the server accepts: %v", v.file, err)
			continue
		}
		want := Result{PolicyID: v.id, PolicyName: v.name, PolicyVersion: v.version, PolicyHash: v.hash}
		if got != want {
			t.Errorf("%s:\n got %+v\nwant %+v", v.file, got, want)
		}
	}
}

// Every top-level document in testdata/ must have a vector, so a new
// fixture cannot sit there untested.
func TestEveryTestdataDocumentHasAVector(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, v := range serverVectors {
		have[v.file] = true
	}
	for _, f := range files {
		if !have[filepath.Base(f)] {
			t.Errorf("%s has no server vector", f)
		}
	}
	if len(files) != len(serverVectors) {
		t.Errorf("%d documents, %d vectors", len(files), len(serverVectors))
	}
}

// The server's canonical preimage for synthetic_kitchen_sink.json,
// captured from psl.Canonicalize, pins the exact bytes and not only
// their hash.
const kitchenSinkPreimage = `{"default_effect":"deny","effective_at":"2026-06-14T00:00:00Z","policy_id":"synthetic-kitchen-sink","policy_name":"Every hashed part at once","policy_version":"5.0.0","profile_tag":"kitchen_sink_v1","required_attested_fields":["actor_id","model_provider"],"required_outcome_fields":["decision_result"],"rules":[{"conditions":[{"max_per_window":100,"type":"rate_limit","window_seconds":3600},{"end_utc":"20:00","start_utc":"08:00","type":"time_window"},{"required":true,"type":"mfa_required"},{"seconds":300,"type":"min_session_age"},{"role":"approver","type":"requires_role"}],"effect":"allow","object":{"classification_max":"RESTRICTED","classification_min":"PUBLIC","id_match":{"operator":"substring","value":"repo"},"type":"code"},"reason_code":"RULE_ALLOWED","rule_id":"r1","subject":{"id_match":{"operator":"prefix","value":"u-"},"role_match":{"operator":"in","values":["engineer","sre"]},"type":"user"},"verb":{"match":{"operator":"exact","value":"execute"}}},{"effect":"deny","object":{"id_match":{"operator":"any"},"type":"data"},"rule_id":"r2","subject":{"id_match":{"operator":"any"},"type":"agent"},"verb":{"match":{"operator":"any"}}}],"schema":"psl.v1","signature_policy":{"required":["compliance"],"threshold":2,"type":"n_of_m"},"signers":[{"key_algorithm":"ed25519","key_fingerprint":"1111","signer_id":"ciso"},{"key_algorithm":"ed25519","key_fingerprint":"2222","signer_id":"compliance"}]}`

func TestKitchenSinkPreimageBytes(t *testing.T) {
	var p policy
	if err := json.Unmarshal(readVector(t, "synthetic_kitchen_sink.json"), &p); err != nil {
		t.Fatal(err)
	}
	got, err := canonicalize(canonicalPolicyForHash(&p))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != kitchenSinkPreimage {
		t.Fatalf("preimage differs from the server's:\n got %s\nwant %s", got, kitchenSinkPreimage)
	}
}

// The server's psl.Parse refuses every document in testdata/refused/
// (type errors, failed validation, malformed JSON); so must this port.
func TestServerRefusalsAreRefused(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "refused", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 19 {
		t.Fatalf("expected the 19 refusal vectors, found %d", len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := FromDocument(b); err == nil {
			t.Errorf("%s: accepted a document the server refuses", f)
		} else if errors.Is(err, ErrDuplicateKey) {
			t.Errorf("%s: refused for the wrong reason: %v", f, err)
		}
	}
}

// The one deliberate difference from the server: it accepts these and
// lets the last of two fold-equal keys win (the hash it computed is
// noted for each), this port refuses them as ambiguous.
func TestDuplicateKeysAreRefused(t *testing.T) {
	for file, serverHash := range map[string]string{
		"top_level_exact.json":     "b81147fb5c9b9fd88543628b181fd79b27950584f9c511bb63dea23a23153111",
		"top_level_case_fold.json": "b2d3951d176e4e730f511f428fd50f7306e515ec6633f3cda3a7376fd2cf6422",
		"long_s_fold.json":         "22bcf1db1d25cd53f1e6f9f18fc851b43a5c47f76cd1d284a03d48814dc62e47",
		"nested_matcher.json":      "279e2ccc1fbc2109de336c777a893c0782795e1d95383221df1364053c5f6886",
		"in_metadata_kelvin.json":  "22bcf1db1d25cd53f1e6f9f18fc851b43a5c47f76cd1d284a03d48814dc62e47",
		"in_signer.json":           "9f968d7a647dd1f07d0d8161922acbf3bd2e6e0b8fc02fe4b80f52cf2c24eef9",
	} {
		_, err := FromDocument(readVector(t, filepath.Join("duplicate", file)))
		if !errors.Is(err, ErrDuplicateKey) {
			t.Errorf("%s (server hash %s): want ErrDuplicateKey, got %v", file, serverHash[:12], err)
		}
	}
}

// mutate returns the kitchen-sink document with the value at path (dot
// separated, numeric parts index arrays) replaced, or removed when
// value is the sentinel remove.
var remove = struct{}{}

func mutate(t *testing.T, base []byte, path string, value any) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(base))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(path, ".")
	cur := doc
	for i, part := range parts {
		last := i == len(parts)-1
		switch node := cur.(type) {
		case map[string]any:
			if last {
				if value == remove {
					delete(node, part)
				} else {
					node[part] = value
				}
			} else {
				cur = node[part]
			}
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil || idx >= len(node) {
				t.Fatalf("bad path %s", path)
			}
			if last {
				node[idx] = value
			} else {
				cur = node[idx]
			}
		default:
			t.Fatalf("bad path %s", path)
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSingleFieldChanges(t *testing.T) {
	base := readVector(t, "synthetic_kitchen_sink.json")
	baseResult, err := FromDocument(base)
	if err != nil {
		t.Fatal(err)
	}

	substantive := []struct {
		path  string
		value any
	}{
		{"policy_id", "other-id"},
		{"policy_name", "other name"},
		{"policy_version", "5.0.1"},
		{"effective_at", "2026-06-14T00:00:01Z"},
		{"default_effect", "allow"},
		{"profile_tag", "kitchen_sink_v2"},
		{"profile_tag", remove},
		{"required_attested_fields.0", "actor_role"},
		{"required_attested_fields", remove},
		{"required_outcome_fields.0", "outcome"},
		{"required_outcome_fields", remove},
		{"signature_policy.type", "all"},
		{"signature_policy.threshold", 1},
		{"signature_policy.required.0", "ciso"},
		{"signature_policy", remove},
		{"signers.0.signer_id", "ciso-2"},
		{"signers.0.key_algorithm", "ed448"},
		{"signers.0.key_fingerprint", "3333"},
		{"signers", remove},
		{"rules.0.rule_id", "r1b"},
		{"rules.0.effect", "deny"},
		{"rules.0.reason_code", "RULE_DENIED"},
		{"rules.0.reason_code", remove},
		{"rules.0.subject.type", "agent"},
		{"rules.0.subject.id_match.operator", "suffix"},
		{"rules.0.subject.id_match.value", "v-"},
		{"rules.0.subject.role_match.values.1", "oncall"},
		{"rules.0.subject.role_match", remove},
		{"rules.0.verb.match.value", "run"},
		{"rules.0.object.type", "file"},
		{"rules.0.object.id_match.value", "repo2"},
		{"rules.0.object.classification_max", "TOP_SECRET"},
		{"rules.0.object.classification_min", "INTERNAL"},
		{"rules.0.conditions.0.max_per_window", 101},
		{"rules.0.conditions.0.window_seconds", 60},
		{"rules.0.conditions.1.start_utc", "09:00"},
		{"rules.0.conditions.1.end_utc", "21:00"},
		{"rules.0.conditions.2.required", false},
		{"rules.0.conditions.3.seconds", 301},
		{"rules.0.conditions.4.role", "auditor"},
		{"rules.0.conditions.4.type", "requires_mfa"},
		{"rules.0.conditions", remove},
		{"rules.1.subject.id_match.value", "x"},
		{"rules.1.verb.match.values", []any{"a"}},
	}
	seen := map[string]string{baseResult.PolicyHash: "base"}
	for _, m := range substantive {
		got, err := FromDocument(mutate(t, base, m.path, m.value))
		if err != nil {
			t.Errorf("%s: %v", m.path, err)
			continue
		}
		if got.PolicyHash == baseResult.PolicyHash {
			t.Errorf("changing %s left policy_hash unchanged", m.path)
		}
		if prev, dup := seen[got.PolicyHash]; dup && prev != "base" {
			t.Errorf("changing %s gave the same hash as changing %s", m.path, prev)
		}
		seen[got.PolicyHash] = m.path
	}

	excluded := []struct {
		path  string
		value any
	}{
		{"metadata.owner", "someone else"},
		{"metadata.ratio", 0.25},
		{"metadata.added", []any{1.5, "x", nil}},
		{"metadata", remove},
		{"tags.0", "uno"},
		{"tags", []any{}},
		{"tags", remove},
		{"rules.0.rule_name", "renamed"},
		{"rules.0.priority", 99},
		{"signers.0.signature_base64", "CCCC"},
		{"signers.1.signed_at", "2027-01-01T00:00:00Z"},
		{"rules.0.conditions.0.role", "unused by rate_limit"},
		{"future_field", "ignored by the server"},
	}
	for _, m := range excluded {
		got, err := FromDocument(mutate(t, base, m.path, m.value))
		if err != nil {
			t.Errorf("%s: %v", m.path, err)
			continue
		}
		if got != baseResult {
			t.Errorf("changing %s changed the result: %+v", m.path, got)
		}
	}
}
