package artifacts

// Category 3, Regulatory Scaffolding
//
// Records the regulatory framework that applied to this decision: which
// data classifications, which sovereignty regimes, which retention rules,
// which compliance frameworks (EU AI Act, HIPAA, SOX, FedRAMP, etc.),
// which bias / fairness checks were referenced.
//
// US government classification is supported as a first-class structure
// per Executive Order 13526, including SCI compartments, Special Access
// Programs, and dissemination caveats. Export-control (ITAR / EAR) and
// NATO classifications are also supported.
//
// Most fields are caller-attested. The orchestrator does not run a
// classification engine; it records what the caller declared. Empty
// fields produce honest "not declared" output rather than fabricated
// classifications.

// RegulatoryScaffolding is the top-level container for regulatory metadata.
type RegulatoryScaffolding struct {
	Kind string `json:"kind"` // "verdifax.regulatory_scaffolding.v1"

	PolicySnapshot     PolicySnapshot     `json:"policy_snapshot,omitempty"`
	DataClassification DataClassification `json:"data_classification,omitempty"`
	DataResidency      DataResidency      `json:"data_residency,omitempty"`
	RetentionPolicy    RetentionPolicy    `json:"retention_policy,omitempty"`

	// Frameworks, every applicable compliance regime, with the
	// caller's reference to the assessment ID for that regime.
	Frameworks []FrameworkRef `json:"frameworks,omitempty"`

	// BiasCheck, for AI systems where bias / fairness testing is
	// required by regulation (e.g., EU AI Act high-risk, US ECOA, NYC
	// AEDT Local Law 144). Caller-attested reference to their most
	// recent test result.
	BiasCheck *BiasCheckRef `json:"bias_check,omitempty"`

	// RightToExplanation, auto-generated plain-English summary that
	// can be served to an affected data subject under GDPR Art. 22 or
	// equivalent right-to-explanation provisions. Caller-supplied.
	RightToExplanation string `json:"right_to_explanation,omitempty"`

	Hash string        `json:"hash"`
	Seal SealReference `json:"seal,omitempty"`
}

// PolicySnapshot, the actual policy that applied at decision time, not
// just its ID. Policies change; the audit must record which version
// applied to *this* run.
type PolicySnapshot struct {
	PolicyID       string `json:"policy_id"`                  // e.g. "policy_financial_approval"
	PolicyVersion  string `json:"policy_version"`             // e.g. "v2.3.1"
	PolicyHash     string `json:"policy_hash"`                // sha256 of the policy bytes
	PolicyURL      string `json:"policy_url,omitempty"`       // immutable URL (e.g. content-addressed)
	SnapshotInline string `json:"snapshot_inline,omitempty"`  // opt-in raw policy bytes
	EffectiveAt    string `json:"effective_at,omitempty"`     // RFC3339
}

// DataClassification supports commercial, US government, export-control,
// and NATO classifications simultaneously. Each subsystem is independent
// and may be filled in or left empty.
type DataClassification struct {
	// Commercial / industry classifications. Multi-valued, a single
	// payload may be both PII and PCI.
	//
	// Recognized values (non-exhaustive):
	//   "PUBLIC": no restrictions
	//   "INTERNAL": internal use only
	//   "CONFIDENTIAL": business-confidential (commercial)
	//   "BUSINESS_SENSITIVE", competitive / strategic
	//   "PII": personally identifiable information
	//   "PHI": protected health information (HIPAA)
	//   "PCI": payment card industry (PCI-DSS scope)
	//   "FERPA": education records (US FERPA scope)
	//   "GLBA_NPI": financial nonpublic personal info (US GLBA)
	//   "TRADE_SECRET": trade-secret material
	//   "ATTORNEY_CLIENT": privileged communication
	//   "WORK_PRODUCT": attorney work product
	//   "EU_PERSONAL_DATA": GDPR personal data
	//   "EU_SPECIAL_CATEGORY", GDPR Art. 9 special category (health, race, etc.)
	Commercial []string `json:"commercial,omitempty"`

	// US government classification per Executive Order 13526 and
	// related statutes. Either fill all USGov fields or leave the
	// whole sub-struct empty.
	USGov *USGovClassification `json:"us_gov,omitempty"`

	// Export-control classifications. Multi-valued.
	ExportControl *ExportControlClassification `json:"export_control,omitempty"`

	// NATO classification.
	NATO *NATOClassification `json:"nato,omitempty"`

	// Allied / multinational classifications (Five Eyes, AUKUS, ABCA, etc.).
	Allied *AlliedClassification `json:"allied,omitempty"`

	// Free-form additional markings the caller wants recorded but that
	// don't fit the structured fields above. Discouraged in favor of
	// the structured options.
	OtherMarkings []string `json:"other_markings,omitempty"`
}

// USGovClassification, Executive Order 13526 + related authorities.
//
// Reference: https://www.archives.gov/cui/registry/category-detail
//
// Levels (from EO 13526 Sec. 1.2):
//
//   "UNCLASSIFIED" , no classification; not for restricted handling
//   "CUI": Controlled Unclassified Information (32 CFR 2002)
//   "CONFIDENTIAL" , unauthorized disclosure could cause damage to national security
//   "SECRET": unauthorized disclosure could cause serious damage
//   "TOP_SECRET": unauthorized disclosure could cause exceptionally grave damage
//
// Compartments and SAP go beyond the level. SCI is access-controlled
// information held to a higher need-to-know standard than ordinary
// Top Secret. SAP (Special Access Program) is even more restricted.
type USGovClassification struct {
	// Level is one of the values above.
	Level string `json:"level"`

	// SCI flag, true when the information is in the Sensitive
	// Compartmented Information (SCI) control system. Implies
	// Level == "TOP_SECRET" in current US doctrine.
	SCI bool `json:"sci,omitempty"`

	// Compartments, recognized SCI compartments and sub-compartments.
	// Multi-valued. The canonical full marking format is
	// "TS//SI/TK//NOFORN", Level//Compartments//Caveats.
	//
	// Recognized SCI compartments (non-exhaustive):
	//   "SI": Special Intelligence (signals intelligence / COMINT)
	//   "TK": Talent Keyhole (overhead imagery, IMINT)
	//   "G": Gamma (special-handling COMINT subset)
	//   "HCS": Humint Control System (HUMINT)
	//   "RSEN": Restricted Sensitive (overhead reconnaissance)
	//   "ECI": Exceptionally Controlled Information
	//   "KLONDIKE", geospatial intelligence subset
	//   "RESERVE", RD (Restricted Data, atomic energy)
	//   "FRD": Formerly Restricted Data
	Compartments []string `json:"compartments,omitempty"`

	// SpecialAccessPrograms, code-named programs requiring SAP-tier
	// access beyond TS or TS/SCI. Strings here are program nicknames
	// or unclassified code words; classified codenames must not be
	// recorded in audit bundles.
	SpecialAccessPrograms []string `json:"special_access_programs,omitempty"`

	// Caveats, dissemination markings that further restrict who may
	// receive the information.
	//
	// Recognized values (non-exhaustive):
	//   "NOFORN": Not Releasable to Foreign Nationals
	//   "ORCON": Originator Controlled (dissemination)
	//   "PROPIN": Proprietary Information Involved
	//   "IMCON": Controlled Imagery
	//   "RELIDO": Releasable by Information Disclosure Official
	//   "FISA": FISA-derived
	//   "WNINTEL": Warning Notice, Intelligence Sources & Methods
	//   "DISPLAY ONLY" , limited dissemination
	//   "REL TO USA, FVEY": Releasable to Five Eyes
	//   "REL TO USA, GBR": Releasable to UK only
	//   "REL TO USA, AUS, GBR, CAN, NZL" , Five Eyes (verbose)
	//   "FOUO": For Official Use Only (legacy; now CUI)
	//   "LES": Law Enforcement Sensitive
	Caveats []string `json:"caveats,omitempty"`

	// CUICategory, when Level == "CUI", which CUI category applies
	// (NARA Registry). Examples: "PRIIM" (Privacy/PII), "PROCURE"
	// (Procurement), "EXPT" (Export Controlled), "ISVI" (Investigation),
	// "LEI" (Law Enforcement), "NUC" (Nuclear), "SP-PRIV" (Sensitive
	// Personally Identifiable Information).
	CUICategory string `json:"cui_category,omitempty"`

	// CUIDecontrolDate, RFC3339 date when CUI controls expire.
	CUIDecontrolDate string `json:"cui_decontrol_date,omitempty"`

	// Atomic Energy Act material flags.
	RestrictedData         bool `json:"restricted_data,omitempty"`           // RD
	FormerlyRestrictedData bool `json:"formerly_restricted_data,omitempty"`  // FRD
	TransclassifiedFRD     bool `json:"transclassified_frd,omitempty"`       // TFNI

	// Original Classification Authority (OCA) and derivative info.
	OCAOrgID         string `json:"oca_org_id,omitempty"`         // e.g. "DCSA-12345"
	DerivedFrom      string `json:"derived_from,omitempty"`       // source classification ref
	DeclassifyOn     string `json:"declassify_on,omitempty"`      // RFC3339 date OR exemption code "X1".."X8"
	DeclassifyExemption string `json:"declassify_exemption,omitempty"` // "25X1-human" etc.

	// Marking string, the human-readable banner line e.g.
	// "TOP SECRET//SI//NOFORN". Recorded for forensic purposes.
	BannerMarking string `json:"banner_marking,omitempty"`

	// PortionMarking, single-paragraph marking abbreviation, e.g. "(TS//SI//NF)".
	PortionMarking string `json:"portion_marking,omitempty"`
}

// ExportControlClassification, ITAR / EAR / sanctions regimes.
type ExportControlClassification struct {
	// ITAR (22 CFR 120-130), defense articles and services on the
	// United States Munitions List (USML).
	ITARControlled  bool   `json:"itar_controlled,omitempty"`
	USMLCategory    string `json:"usml_category,omitempty"`    // e.g. "Category VIII"

	// EAR (15 CFR 730-774), dual-use items on the Commerce Control List.
	EARControlled bool   `json:"ear_controlled,omitempty"`
	ECCN          string `json:"eccn,omitempty"`             // e.g. "5A002"
	EAR99         bool   `json:"ear99,omitempty"`            // catch-all for non-listed items
	LicenseException string `json:"license_exception,omitempty"` // e.g. "ENC", "TSR", "CIV"

	// Sanctions
	OFACSanctions []string `json:"ofac_sanctions,omitempty"` // e.g. ["IRAN", "RUSSIA-EO14024"]

	// Embargoed destinations the data may not flow to.
	EmbargoedCountries []string `json:"embargoed_countries,omitempty"` // ISO 3166-1 alpha-2

	// Deemed export flag, non-US persons accessed the data on US soil.
	DeemedExport bool `json:"deemed_export,omitempty"`
}

// NATOClassification, NATO security classifications.
type NATOClassification struct {
	// Level, one of:
	//   "NATO_UNCLASSIFIED"
	//   "NATO_RESTRICTED"
	//   "NATO_CONFIDENTIAL"
	//   "NATO_SECRET"
	//   "COSMIC_TOP_SECRET"        // NATO TS equivalent
	//   "ATOMAL"                   // atomic-related NATO marking
	Level string `json:"level"`

	// Atomal flag, separately controlled atomic information.
	Atomal bool `json:"atomal,omitempty"`

	// Caveats, NATO releasability and handling caveats.
	Caveats []string `json:"caveats,omitempty"`
}

// AlliedClassification, multinational sharing markings beyond NATO.
type AlliedClassification struct {
	// Five Eyes (FVEY): USA, GBR, CAN, AUS, NZL.
	FVEYReleasable bool `json:"fvey_releasable,omitempty"`

	// AUKUS: AUS, GBR, USA.
	AUKUSReleasable bool `json:"aukus_releasable,omitempty"`

	// ABCA: USA, GBR, CAN, AUS, NZL, Armies Cooperation Program.
	ABCAReleasable bool `json:"abca_releasable,omitempty"`

	// Specific country list, ISO 3166-1 alpha-3 codes (e.g. ["USA","GBR"]).
	ReleasableTo []string `json:"releasable_to,omitempty"`
}

// DataResidency, where the data was processed, hosted, and stored.
type DataResidency struct {
	ProcessingRegion   string   `json:"processing_region"`             // e.g. "us-east-1", "fly:iad"
	ModelHostingRegion string   `json:"model_hosting_region,omitempty"` // for caller-attested AI calls
	StorageRegion      string   `json:"storage_region"`                 // where this audit record is stored
	CrossBorderTransfer bool    `json:"cross_border_transfer,omitempty"` // any data crossed a national border
	TransferMechanism  string   `json:"transfer_mechanism,omitempty"`   // "SCC", "BCR", "adequacy_decision", "consent"
	Sovereignty        []string `json:"sovereignty,omitempty"`          // ["GDPR", "EU_AI_ACT", "FedRAMP_HIGH", "IL5", "PCIDSS"]
}

// RetentionPolicy, how long this audit record is kept.
type RetentionPolicy struct {
	RetentionDays      int    `json:"retention_days"`             // 0 means indefinite
	LegalHold          bool   `json:"legal_hold"`                 // record is held for litigation
	LegalHoldReason    string `json:"legal_hold_reason,omitempty"`
	LegalHoldUntil     string `json:"legal_hold_until,omitempty"` // RFC3339 or empty for indefinite
	DeletionEligible   bool   `json:"deletion_eligible"`
	GDPRRightToErase   bool   `json:"gdpr_right_to_erase"`        // can be deleted under GDPR Art. 17
	HIPAARetentionMin  bool   `json:"hipaa_retention_minimum,omitempty"` // 6-year HIPAA minimum applies
	SOXRetentionMin    bool   `json:"sox_retention_minimum,omitempty"`   // 7-year SOX minimum applies
}

// FrameworkRef, one applicable compliance framework.
type FrameworkRef struct {
	Framework      string `json:"framework"`              // "EU_AI_ACT", "HIPAA", "SOX", "FedRAMP", "ISO27001", "SOC2", "GDPR", "CCPA", "NIS2"
	AssessmentID   string `json:"assessment_id,omitempty"` // DPIA / AI conformity assessment / audit ID
	AssessmentURL  string `json:"assessment_url,omitempty"`
	RiskClass      string `json:"risk_class,omitempty"`   // EU AI Act tier: "minimal" | "limited" | "high" | "unacceptable"
	ControlIDs     []string `json:"control_ids,omitempty"` // specific control references
	AttestationID  string `json:"attestation_id,omitempty"` // FedRAMP Authorization, SOC2 report, etc.
}

// BiasCheckRef, caller-attested fairness / bias test reference.
type BiasCheckRef struct {
	TestID         string  `json:"test_id"`
	LastRunAt      string  `json:"last_run_at"`             // RFC3339
	Outcome        string  `json:"outcome"`                 // "passed" | "flagged" | "failed"
	OverallScore   float64 `json:"overall_score,omitempty"`
	ProtectedAttributes []string `json:"protected_attributes,omitempty"` // ["race","gender","age",...]
	ReportURL      string  `json:"report_url,omitempty"`
	Methodology    string  `json:"methodology,omitempty"`   // e.g. "demographic_parity", "equalized_odds"
}
