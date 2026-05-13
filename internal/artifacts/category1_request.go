package artifacts

// Category 1 — Request Substance
//
// Captures what the request actually was. Most fields are caller-attested
// (the orchestrator does not see the prompt or the model output). A few
// — latency breakdown, request origin, auth method — are observed by the
// orchestrator itself and populated server-side.

// RequestSubstance is the canonical record of "what exactly happened in
// the request." It sits alongside the existing 14 pipeline artifacts in
// the audit bundle as a top-level metadata block. All fields are optional;
// missing fields produce a record that says "the caller did not supply
// this evidence."
type RequestSubstance struct {
	Kind string `json:"kind"` // "verdifax.request_substance.v1"

	// Prompt — the input the caller fed to a model (if any).
	Prompt PromptRecord `json:"prompt,omitempty"`

	// Output — what the model produced before any post-processing.
	Output OutputRecord `json:"output,omitempty"`

	// Post-processing — any transformations the caller applied to the
	// raw model output before turning it into a decision. Each entry is
	// hash-bound so the chain is reconstructable.
	PostProcessing []PostProcessingStep `json:"post_processing,omitempty"`

	// Cost — how expensive the run was. Auditors and finance teams care.
	Cost CostBreakdown `json:"cost,omitempty"`

	// Latency — per-stage timing breakdown. Used both for SLA evidence
	// and for side-channel anomaly detection (substitution attacks
	// usually leave a latency signature). Server-observed.
	Latency LatencyBreakdown `json:"latency,omitempty"`

	// Origin — where the request came from. Server-observed from the
	// HTTP request headers. IPs and user-agent are hashed by default
	// to avoid storing raw PII; opt-in inline available for debugging.
	Origin RequestOrigin `json:"origin,omitempty"`

	// Authentication — how the caller authenticated. Server-observed.
	Authentication AuthenticationRecord `json:"authentication,omitempty"`

	Hash string        `json:"hash"`
	Seal SealReference `json:"seal,omitempty"`
}

// PromptRecord captures the model input. Either inline or hashed. The
// caller chooses based on confidentiality requirements.
type PromptRecord struct {
	Hash             string `json:"hash,omitempty"`              // sha256 of the full prompt
	TemplateID       string `json:"template_id,omitempty"`       // e.g. "approve_transaction_v3"
	TemplateVersion  string `json:"template_version,omitempty"`  // e.g. "2026.05.01"
	SystemHash       string `json:"system_hash,omitempty"`       // sha256 of system instructions
	UserHash         string `json:"user_hash,omitempty"`         // sha256 of user-supplied portion
	ContentInline    string `json:"content_inline,omitempty"`    // opt-in raw bytes
	TokenCount       int    `json:"token_count,omitempty"`
	ContentEncoding  string `json:"content_encoding,omitempty"`  // "utf-8" by default
}

// OutputRecord captures the model output before any post-processing.
type OutputRecord struct {
	Hash            string `json:"hash,omitempty"`             // sha256 of model output
	ContentInline   string `json:"content_inline,omitempty"`   // opt-in raw bytes
	TokenCount      int    `json:"token_count,omitempty"`
	FinishReason    string `json:"finish_reason,omitempty"`    // "stop", "length", "content_filter", "tool_use"
	StopSequences   []string `json:"stop_sequences,omitempty"`
	StreamingClosed bool   `json:"streaming_closed,omitempty"` // true if streaming completed cleanly
}

// PostProcessingStep records one transformation applied to the model
// output between the model returning and the caller making a decision.
// Every step records its input and output hash so the chain is
// reconstructable.
type PostProcessingStep struct {
	StepIndex   int    `json:"step_index"`
	StepType    string `json:"step_type"`              // "filter" | "rephrase" | "augment" | "redact" | "block" | "format"
	Description string `json:"description,omitempty"`
	InputHash   string `json:"input_hash"`             // hash going in
	OutputHash  string `json:"output_hash"`            // hash coming out
	ToolID      string `json:"tool_id,omitempty"`      // e.g. "regex_filter_v1"
}

// CostBreakdown — caller-attested cost, unit-of-account in USD. The
// orchestrator does not compute this; the caller records what their AI
// provider billed them.
type CostBreakdown struct {
	InputTokens      int     `json:"input_tokens,omitempty"`
	OutputTokens     int     `json:"output_tokens,omitempty"`
	TotalTokens      int     `json:"total_tokens,omitempty"`
	EstimatedCostUSD float64 `json:"estimated_cost_usd,omitempty"`
	BillingTier      string  `json:"billing_tier,omitempty"` // "standard" | "batch" | "priority"
}

// LatencyBreakdown — per-stage timing in milliseconds, observed by the
// orchestrator. Used for SLA evidence and anomaly detection.
type LatencyBreakdown struct {
	TotalMs       int64            `json:"total_ms"`
	PerStageMs    []StageLatency   `json:"per_stage_ms,omitempty"`
	NetworkInMs   int64            `json:"network_in_ms,omitempty"`
	NetworkOutMs  int64            `json:"network_out_ms,omitempty"`
	ModelLatencyMs int64           `json:"model_latency_ms,omitempty"` // caller-attested (model call time)
}

// StageLatency is one row of the per-stage timing record.
type StageLatency struct {
	Stage       string `json:"stage"` // "DOG", "DTL", "DKEC", ...
	DurationMs  int64  `json:"duration_ms"`
}

// RequestOrigin describes where the request came from. Hashed by default
// for privacy; opt-in inline available.
type RequestOrigin struct {
	SourceIPHash          string `json:"source_ip_hash,omitempty"`
	UserAgentHash         string `json:"user_agent_hash,omitempty"`
	DeviceFingerprintHash string `json:"device_fingerprint_hash,omitempty"`
	GeoCountry            string `json:"geo_country,omitempty"`            // e.g. "US"
	GeoRegion             string `json:"geo_region,omitempty"`             // e.g. "VA"
	OriginInline          *RequestOriginInline `json:"origin_inline,omitempty"` // opt-in unredacted
}

// RequestOriginInline is the unredacted form of RequestOrigin. Operators
// who need raw values for forensic investigation can opt in by setting
// VERDIFAX_AUDIT_INCLUDE_RAW_ORIGIN=true; default is hashed-only.
type RequestOriginInline struct {
	SourceIP   string `json:"source_ip,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
}

// AuthenticationRecord describes how the caller authenticated. Note that
// API keys themselves are never recorded (only their ID); raw secrets do
// not appear in audit bundles under any circumstance.
type AuthenticationRecord struct {
	Method            string `json:"method"`                       // "api_key" | "oauth" | "sso" | "passwordless" | "anonymous"
	Provider          string `json:"provider,omitempty"`           // e.g. "github", "okta", "azure_ad", "google"
	APIKeyID          int64  `json:"api_key_id,omitempty"`         // numeric id; raw key never recorded
	APIKeyName        string `json:"api_key_name,omitempty"`       // human-readable key name (caller-supplied label)
	KeyLastRotatedAt  string `json:"key_last_rotated_at,omitempty"`
	SessionAgeSeconds int64  `json:"session_age_seconds,omitempty"`
	MFASatisfied      *bool  `json:"mfa_satisfied,omitempty"`      // pointer so absent is distinct from false
	MFAMethod         string `json:"mfa_method,omitempty"`         // "totp" | "u2f" | "webauthn" | "sms" | "push"
}
