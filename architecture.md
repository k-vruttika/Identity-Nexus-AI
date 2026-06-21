# Identity Nexus AI — Architecture Specification
**AI-Powered Cross-Platform Identity Intelligence & Privileged Access Abuse Detection Platform**
Version: 2.0 | Phase: 10 — Final (updated to reflect built implementation)
Status: LIVE REFERENCE — updated to match the actual Phase 1–8 implementation. Phase 1 design decisions that were revised during build are noted inline.

---

## 1. SYSTEM ARCHITECTURE

The platform is organised into five strictly ordered layers. Dependencies flow **downward only**: a layer may read from any layer below it but must never import from a layer above it. All inter-layer state exchange is via files written to and read from `generated_data/`, which acts as the single source of truth for the entire pipeline.

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                          PRESENTATION LAYER                                    ║
║                                                                                ║
║  ┌────────────────────────────────────────────────────────────────────────────┐ ║
║  │              Streamlit Dashboard  (src/app.py)                             │ ║
║  │  · Executive Overview         · Identity Explorer  · Risk Register        │ ║
║  │  · Incident Explorer          · Identity Graph     · Attack Path Simulator │ ║
║  │  · Compliance Dashboard       · AI Narratives                             │ ║
║  │                                                                            │ ║
║  │  Dark SOC theme · Glassmorphism panels · Plotly charts · Detection badges  │ ║
║  └────────────────────────────────────────────────────────────────────────────┘ ║
║                            │ reads generated_data/ (read-only)                 ║
╚════════════════════════════╪═══════════════════════════════════════════════════╝
                   ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║                          INTELLIGENCE LAYER                                    ║
║                                                                                ║
║  ┌──────────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐ ║
║  │  LLMNarrativeGenerator   │  │   RemediationEngine  │  │ AttackPath       │ ║
║  │  llm_narrative_          │  │   remediation_       │  │ Simulator        │ ║
║  │  generator.py            │  │   engine.py          │  │ attack_path_     │ ║
║  │                          │  │                      │  │ simulator.py     │ ║
║  │  · Claude API calls      │  │  · Priority ranking  │  │                  │ ║
║  │  · Incident narratives   │  │  · Action templates  │  │ · BFS blast-     │ ║
║  │  · Remediation rationale │  │  │ Risk-reduction est │  │   radius         │ ║
║  └──────────────────────────┘  └──────────────────────┘  │ · Pre/post-      │ ║
║                                                           │   remediation    │ ║
║  ┌──────────────────────────────────────────────────────┐ │   scenarios      │ ║
║  │             ComplianceMapper                         │ └──────────────────┘ ║
║  │             compliance_mapper.py                     │                      ║
║  │  · SOX / ISO 27001 / NIST CSF / SOC 2 control maps  │                      ║
║  │  · Per-incident control violation tagging           │                      ║
║  └──────────────────────────────────────────────────────┘                      ║
║            │ reads risk_scores.csv, incidents.csv, attack_paths.csv            ║
╚════════════╪═══════════════════════════════════════════════════════════════════╝
             ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           ANALYTICS LAYER                                      ║
║                                                                                ║
║  ┌──────────────────────────────┐   ┌──────────────────────────────────────┐  ║
║  │      AnomalyDetection        │   │          RiskScoringEngine           │  ║
║  │      anomaly_detection.py    │   │          risk_scoring.py             │  ║
║  │  HYBRID DETECTION ENGINE     │   │  · Weighted multi-factor scoring     │  ║
║  │  Layer 1 -- ML ensemble:     │   │  · Risk tier assignment              │  ║
║  │  · Isolation Forest (w=0.50) │   │  · Delta tracking                   │  ║
║  │  · Local Outlier Factor(0.20)│   └──────────────────────────────────────┘  ║
║  │  · Autoencoder      (w=0.30) │                                              ║
║  │  Layer 2 -- IAM domain rules │                                              ║
║  │  · ORPHANED_ACCOUNT [RULE]   │                                              ║
║  │  · TOKEN_ABUSE      [RULE]   │                                              ║
║  │  (NOT ML-detected)           │                                              ║
║  └──────────────────────────────┘                                              ║
║                                                                                ║
║  ┌──────────────────────────────┐   ┌──────────────────────────────────────┐  ║
║  │     IncidentClustering       │   │        FeatureEngineering            │  ║
║  │     incident_clustering.py   │   │        feature_engineering.py        │  ║
║  │  · DBSCAN / KMeans           │   │  · Behavioural feature extraction    │  ║
║  │  · Incident type labelling   │   │  · Privilege feature extraction      │  ║
║  │  · Severity assignment       │   │  · Peer-deviation computation        │  ║
║  └──────────────────────────────┘   └──────────────────────────────────────┘  ║
║          │ reads effective_privileges.csv, feature_matrix.csv,                 ║
║          │       anomaly_scores.csv                                            ║
╚══════════╪═════════════════════════════════════════════════════════════════════╝
           ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║                       GRAPH & RESOLUTION LAYER                                 ║
║                                                                                ║
║  ┌────────────────────────────┐   ┌──────────────────────────────────────────┐ ║
║  │       GraphBuilder         │   │       EffectivePrivilegeEngine           │ ║
║  │       graph_builder.py     │   │       effective_privilege_engine.py      │ ║
║  │  · MultiDiGraph assembly   │   │  · BFS traversal with cycle detection    │ ║
║  │  · Node/Edge hydration     │   │  · Nested group resolution              │ ║
║  │  · Serialise → .gpickle    │   │  · Privilege materialisation           │ ║
║  └────────────────────────────┘   └──────────────────────────────────────────┘ ║
║                                                                                ║
║  ┌────────────────────────────────────────────────────────────────────────────┐ ║
║  │                         IdentityResolver                                   │ ║
║  │                         identity_resolver.py                               │ ║
║  │  · Cross-platform entity resolution (AD ↔ Okta ↔ AWS ↔ GitHub …)          │ ║
║  │  · Deterministic deduplication via email / username normalisation          │ ║
║  │  · Canonical identity_id assignment                                        │ ║
║  └────────────────────────────────────────────────────────────────────────────┘ ║
║          │ reads unified_identities.csv, group_mappings.csv,                   ║
║          │       role_mappings.csv, resource_access_logs.csv                   ║
╚══════════╪═════════════════════════════════════════════════════════════════════╝
           ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║                             DATA LAYER                                         ║
║                                                                                ║
║  ┌────────────────────────────────────────────────────────────────────────────┐ ║
║  │  DataSimulator  (data_simulator.py)                                        │ ║
║  │  · Faker-based synthetic identity generation for 500+ identities           │ ║
║  │  · Platform simulation: AD, Okta, AWS IAM, GitHub, Salesforce, ServiceNow  │ ║
║  │  · Deliberate anomaly injection:                                            │ ║
║  │      – Orphaned accounts (offboarded, access still active)                 │ ║
║  │      – Dormant privileged accounts (no login > 90 days)                   │ ║
║  │      – Excessive privilege / SoD violations                               │ ║
║  │      – Off-hours access bursts, geo-impossible logins                     │ ║
║  │      – Nested group privilege escalation chains                            │ ║
║  └────────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                ║
║  ┌────────────────────────────────────────────────────────────────────────────┐ ║
║  │  generated_data/   — Single Source of Truth                                │ ║
║  │  unified_identities.csv · group_mappings.csv · role_mappings.csv           │ ║
║  │  audit_events.csv · offboarding_records.csv · resource_access_logs.csv     │ ║
║  │  effective_privileges.csv · feature_matrix.csv · anomaly_scores.csv        │ ║
║  │  risk_scores.csv · incidents.csv · attack_paths.csv                        │ ║
║  │  remediation_actions.csv · compliance_mappings.csv · narratives.json       │ ║
║  │  models/ — identity_graph.gpickle · isolation_forest.pkl · lof.pkl        │ ║
║  │            mlp_autoencoder.pkl · feature_scaler.pkl                        │ ║
║  └────────────────────────────────────────────────────────────────────────────┘ ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 2. COMPONENT DIAGRAM

**DataSimulator** (`src/data_simulator.py`) — Single responsibility: generate all synthetic raw data using the `Faker` library. It produces six foundational CSVs (unified identities, group mappings, role mappings, audit events, offboarding records, resource access logs) and deliberately injects realistic anomaly patterns (dormant admins, orphaned accounts, SoD violations, geo-anomalies, off-hours bursts) at a configurable injection rate. It has no dependencies on any other src module and writes exclusively to `generated_data/`.

**IdentityResolver** (`src/identity_resolver.py`) — Single responsibility: perform cross-platform identity correlation and deduplication. It reads the raw `unified_identities.csv` and resolves the same real-world person's records across AD, Okta, AWS IAM, GitHub, Salesforce, and ServiceNow into a single canonical `identity_id` using deterministic matching on normalised email and username. It writes a resolved, deduplicated version of `unified_identities.csv` (overwrite in place) where every row carries its final canonical key.

**GraphBuilder** (`src/graph_builder.py`) — Single responsibility: construct the NetworkX `MultiDiGraph` identity graph from the resolved identity, group, role, and resource data. It creates typed nodes (Identity, Group, Role, Resource, Platform) with full attribute payloads and typed directed edges (MEMBER_OF, HAS_ROLE, GRANTS_ACCESS, NESTED_IN, FEDERATES_TO) with metadata, then serialises the resulting graph to `models/identity_graph.gpickle` for downstream consumers.

**EffectivePrivilegeEngine** (`src/effective_privilege_engine.py`) — Single responsibility: traverse the identity graph via breadth-first search to materialise the complete set of effective privileges for every identity, correctly resolving nested group chains and avoiding cycles. It reads `identity_graph.gpickle` and produces `effective_privileges.csv`, flagging each privilege as `is_excessive` (provisioned but never used) or `is_dormant` (unused for 90+ days).

**FeatureEngineering** (`src/feature_engineering.py`) — Single responsibility: compute the per-identity behavioural and privilege feature vector that feeds the ML anomaly detectors. It joins `unified_identities.csv`, `audit_events.csv`, `resource_access_logs.csv`, and `effective_privileges.csv` to produce a flat `feature_matrix.csv` with 17 numeric features covering login frequency, off-hours access ratios, peer deviation, privilege counts, and data-exfiltration indicators.

**AnomalyDetection** (`src/anomaly_detection.py`) — Single responsibility: flag anomalous identities using a **hybrid detection engine** that combines an unsupervised ML ensemble with explicit IAM domain rules. The ML layer runs Isolation Forest (weight=0.50, contamination=0.25, max_features=3), Local Outlier Factor (weight=0.20), and an Autoencoder (weight=0.30, hidden=6 units) against `feature_matrix.csv`, fusing normalised scores into a weighted `ensemble_anomaly_score`. An identity is flagged `is_anomaly=True` if any of three tiers fire: (1) ensemble score > 0.30, (2) Isolation Forest `predict()` returns -1, or (3) an explicit IAM domain rule matches. The two domain rules are deterministic, not probabilistic: `ORPHANED_ACCOUNT` is detected when `access_revocation_failure=1` AND `offboarding_gap_score > 0.5`; `TOKEN_ABUSE` when `risk_event_ratio > 0.45`. **These two categories must be labelled "Rule-based detection" in all downstream outputs (narratives, dashboards, reports) -- never "ML-detected" or "AI-detected".** The `detection_method` column in `anomaly_scores.csv` records the trigger layer per identity. The module persists trained model artefacts to `models/` and writes `anomaly_scores.csv`.

**RiskScoringEngine** (`src/risk_scoring.py`) — Single responsibility: translate raw anomaly signals and privilege data into an interpretable, business-oriented risk score (0–100) per identity. It applies a weighted formula across four risk dimensions (privilege, behavioural, identity hygiene, compliance), assigns a risk tier (CRITICAL / HIGH / MEDIUM / LOW), and tracks score deltas versus prior runs. Output is `risk_scores.csv`.

**IncidentClustering** (`src/incident_clustering.py`) — Single responsibility: group high-risk identities with similar anomaly signatures into typed incidents using DBSCAN followed by a KMeans pass for dense core clusters. It reads `anomaly_scores.csv` and `risk_scores.csv`, labels each cluster with an incident type (PRIVILEGE_ABUSE, LATERAL_MOVEMENT, DATA_EXFIL, DORMANT_ADMIN, ORPHANED_ACCOUNT, SOD_VIOLATION, BEHAVIORAL_OUTLIER), assigns severity, and writes `incidents.csv`. Each row also carries a placeholder `llm_narrative` field populated later by `LLMNarrativeGenerator`.

**AttackPathSimulator** (`src/attack_path_simulator.py`) — Single responsibility: simulate adversarial lateral movement from compromised high-risk identities across the identity graph to enumerate all reachable resources (blast radius). It runs two scenarios per high-risk identity — Current State and Post-Remediation (with recommended edges/nodes removed) — computes the Blast Radius Score and Risk/Blast Reduction percentages, and writes all paths to `attack_paths.csv`. This is the platform's flagship demo capability.

**RemediationEngine** (`src/remediation_engine.py`) — Single responsibility: generate a prioritised, actionable remediation action for every open incident, templated across six action types (REVOKE_ROLE, DISABLE_ACCOUNT, ENFORCE_MFA, REMOVE_GROUP, SCOPE_REDUCTION, REQUIRE_RECERTIFICATION), with estimated risk-reduction and blast-radius-reduction percentages. It reads `incidents.csv` and `attack_paths.csv` and writes `remediation_actions.csv`.

**ComplianceMapper** (`src/compliance_mapper.py`) — Single responsibility: map each incident and remediation action to the specific control IDs it violates or satisfies across SOX, ISO 27001, NIST CSF, and SOC 2 Type II frameworks. It enriches `incidents.csv` (compliance tags column) and `remediation_actions.csv` (compliance_frameworks column) without replacing any other field.

**LLMNarrativeGenerator** (`src/llm_narrative_generator.py`) — Single responsibility: call the Anthropic Claude API (claude-sonnet-4-6) to generate one concise plain-English investigative narrative (<= 200 words) per incident and one plain-English rationale per remediation action. It reads `incidents.csv` and `remediation_actions.csv`, enriches the `llm_narrative` and `llm_rationale` columns in place, and writes the updated files back to `generated_data/`. **Phase 6 constraint**: prompts must read the `detection_method` column from `anomaly_scores.csv` and pass it to the LLM as context. For incidents where `detection_method` contains `DOMAIN_RULE` (i.e. `ORPHANED_ACCOUNT` and `TOKEN_ABUSE`), the prompt must explicitly instruct the model to describe detection as rule-based and deterministic. The LLM must never describe these as "the AI identified" or "the model flagged". For ML-detected incidents, standard language is permitted.

**Streamlit app** (`src/app.py`) — Single responsibility: serve an interactive multi-page web dashboard that reads exclusively from `generated_data/`. Pages: (1) Identity Risk Explorer with sortable/filterable risk table, (2) Incident Investigation Console with LLM narratives, (3) Attack Path Visualiser using PyVis/NetworkX graph rendering, (4) Remediation Action Board, (5) Compliance Scorecard. No business logic lives in `app.py` -- it only reads, filters, and presents pre-computed data. **Phase 8 constraint**: the Incident Investigation Console (page 2) must display a detection method badge per incident derived from the `detection_method` column in `anomaly_scores.csv`. Use "Rule-based" (amber badge) for `DOMAIN_RULE` detections and "ML ensemble" (blue badge) for `ML_ENSEMBLE` or `IF_PREDICT` detections. A single "AI Detected" badge for all types is incorrect and must not be used.

**Streamlit app** (`src/app.py`) — Single responsibility: serve an interactive 8-page SOC dashboard that reads exclusively from `generated_data/`. All data is pre-computed by the pipeline; `app.py` contains no business logic. Pages: (1) Executive Overview with KPI cards and detection method breakdown, (2) Identity Explorer with per-identity risk gauge and effective privilege table, (3) Risk Register with sortable filtered table, (4) Incident Explorer with detection-method badge cards, (5) Identity Graph with Plotly network visualisation, (6) Attack Path Simulator with side-by-side before/after blast-radius graphs, (7) Compliance Dashboard per framework, (8) AI Narratives. **Phase 8 constraint**: dashboard must display a detection method badge per incident — "Rule-based" (amber) for `DOMAIN_RULE`, "ML Ensemble" (blue) for `ML_ENSEMBLE` or `IF_PREDICT`. A unified "AI Detected" label for all types is incorrect and is not used.

---

## 3. DATA FLOW DIAGRAM

```
[Faker / DataSimulator]
        │
        │  writes: unified_identities.csv, group_mappings.csv, role_mappings.csv,
        │           audit_events.csv, offboarding_records.csv, resource_access_logs.csv
        ▼
[IdentityResolver]
        │
        │  reads:  unified_identities.csv (raw)
        │  writes: unified_identities.csv (resolved, deduped — overwrites)
        ▼
[GraphBuilder]
        │
        │  reads:  unified_identities.csv, group_mappings.csv, role_mappings.csv,
        │           resource_access_logs.csv
        │  writes: identity_graph.gpickle
        ▼
[EffectivePrivilegeEngine]
        │
        │  reads:  identity_graph.gpickle, resource_access_logs.csv
        │  writes: effective_privileges.csv
        ▼
[FeatureEngineering]
        │
        │  reads:  unified_identities.csv, audit_events.csv,
        │           resource_access_logs.csv, effective_privileges.csv
        │  writes: feature_matrix.csv
        ▼
[AnomalyDetection]
        │
        │  reads:  feature_matrix.csv
        │  writes: anomaly_scores.csv
        │  saves:  models/isolation_forest.pkl, models/lof.pkl, models/autoencoder.h5
        ▼
[RiskScoringEngine]
        │
        │  reads:  anomaly_scores.csv, effective_privileges.csv,
        │           unified_identities.csv, offboarding_records.csv
        │  writes: risk_scores.csv
        ▼
[IncidentClustering]
        │
        │  reads:  anomaly_scores.csv, risk_scores.csv, feature_matrix.csv
        │  writes: incidents.csv  (llm_narrative field = "" placeholder)
        ▼
[AttackPathSimulator]
        │
        │  reads:  identity_graph.gpickle, incidents.csv, risk_scores.csv
        │  writes: attack_paths.csv
        ▼
[RemediationEngine]
        │
        │  reads:  incidents.csv, attack_paths.csv, effective_privileges.csv
        │  writes: remediation_actions.csv
        ▼
[ComplianceMapper]
        │
        │  reads:  incidents.csv, remediation_actions.csv
        │  writes: incidents.csv (adds compliance_tags column — in-place update)
        │           remediation_actions.csv (adds compliance_frameworks — in-place update)
        ▼
[LLMNarrativeGenerator]
        │
        │  reads:  incidents.csv, remediation_actions.csv, risk_scores.csv,
        │           attack_paths.csv
        │  writes: incidents.csv (populates llm_narrative — in-place update)
        │           remediation_actions.csv (populates llm_rationale — in-place update)
        ▼
        │
[Streamlit app.py]
  reads all generated_data/ CSVs
  serves interactive 8-page SOC dashboard
```

---

## 4. MODULE RESPONSIBILITIES TABLE

| File | Inputs | Outputs |
|---|---|---|
| `src/data_simulator.py` | None (uses Faker + random seed) | `generated_data/unified_identities.csv`, `generated_data/group_mappings.csv`, `generated_data/role_mappings.csv`, `generated_data/audit_events.csv`, `generated_data/offboarding_records.csv`, `generated_data/resource_access_logs.csv` |
| `src/identity_resolver.py` | `generated_data/unified_identities.csv` (raw) | `generated_data/unified_identities.csv` (overwrite — resolved/deduped) |
| `src/graph_builder.py` | `generated_data/unified_identities.csv`, `generated_data/group_mappings.csv`, `generated_data/role_mappings.csv`, `generated_data/resource_access_logs.csv` | `models/identity_graph.gpickle` (NetworkX MultiDiGraph) |
| `src/effective_privilege_engine.py` | `models/identity_graph.gpickle`, `generated_data/resource_access_logs.csv` | `generated_data/effective_privileges.csv` |
| `src/feature_engineering.py` | `generated_data/unified_identities.csv`, `generated_data/audit_events.csv`, `generated_data/resource_access_logs.csv`, `generated_data/effective_privileges.csv` | `generated_data/feature_matrix.csv` |
| `src/anomaly_detection.py` | `generated_data/feature_matrix.csv` | `generated_data/anomaly_scores.csv`, `models/isolation_forest.pkl`, `models/lof.pkl`, `models/mlp_autoencoder.pkl`, `models/feature_scaler.pkl` |
| `src/risk_scoring.py` | `generated_data/anomaly_scores.csv`, `generated_data/effective_privileges.csv`, `generated_data/unified_identities.csv`, `generated_data/offboarding_records.csv` | `generated_data/risk_scores.csv` |
| `src/incident_clustering.py` | `generated_data/anomaly_scores.csv`, `generated_data/risk_scores.csv`, `generated_data/feature_matrix.csv` | `generated_data/incidents.csv` |
| `src/attack_path_simulator.py` | `models/identity_graph.gpickle`, `generated_data/incidents.csv`, `generated_data/risk_scores.csv` | `generated_data/attack_paths.csv` |
| `src/remediation_engine.py` | `generated_data/incidents.csv`, `generated_data/attack_paths.csv`, `generated_data/effective_privileges.csv` | `generated_data/remediation_actions.csv` |
| `src/compliance_mapper.py` | `generated_data/incidents.csv`, `generated_data/remediation_actions.csv` | `generated_data/incidents.csv` (in-place, adds `compliance_tags`), `generated_data/remediation_actions.csv` (in-place, adds `compliance_frameworks`) |
| `src/llm_narrative_generator.py` | `generated_data/incidents.csv`, `generated_data/remediation_actions.csv`, `generated_data/risk_scores.csv`, `generated_data/attack_paths.csv` | `generated_data/incidents.csv` (in-place, populates `llm_narrative`), `generated_data/remediation_actions.csv` (in-place, populates `llm_rationale`) |
| `src/main.py` | All `generated_data/` CSVs (orchestrator — no computation) | Console logs, `reports/pipeline_run_summary.md` |
| `src/app.py` | All `generated_data/` CSVs (read-only, presentation) | Streamlit web dashboard (in-process, no files written) |

---

## 5. DATA MODELS

All files reside in `generated_data/`. Date columns use `YYYY-MM-DD`. Datetime columns use `YYYY-MM-DD HH:MM:SS` (UTC). UUID columns use `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` format. Foreign key relationships are noted inline.

---

### 5.1 `unified_identities.csv`
Primary key: `identity_id`

| Column | Type | Description |
|---|---|---|
| `identity_id` | string (UUID) | Canonical unique identifier — master key referenced by all other tables |
| `display_name` | string | Full name of the person or service (e.g. "Alice Nakamura") |
| `email` | string | Normalised corporate email address |
| `username` | string | Platform login handle (normalised lowercase) |
| `platform` | string | Source platform: `AD` / `Okta` / `AWS` / `GitHub` / `Salesforce` / `ServiceNow` |
| `account_type` | string | `human` / `service` / `machine` |
| `department` | string | Organisational department (e.g. "Finance", "Engineering") |
| `job_title` | string | Role/job title (e.g. "Senior Developer") |
| `manager_id` | string (UUID, nullable) | FK → `unified_identities.identity_id` of direct manager |
| `created_date` | date | Date the account was provisioned |
| `last_login` | datetime (nullable) | Timestamp of most recent successful login |
| `is_active` | boolean | Whether the account is currently enabled |
| `is_privileged` | boolean | Has at least one admin or elevated role |
| `mfa_enabled` | boolean | MFA is configured and enforced |
| `geo_location` | string | Primary assigned geography (e.g. "US-East", "EU-West") |
| `canonical_id` | string (UUID) | Resolved canonical identity (may differ from identity_id pre-resolution; same post-resolution) |

---

### 5.2 `group_mappings.csv`
Primary key: `mapping_id`

| Column | Type | Description |
|---|---|---|
| `mapping_id` | string (UUID) | Unique row identifier |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` |
| `group_id` | string (format: `GRP-{UUID}`) | Unique group identifier |
| `group_name` | string | Human-readable group name (e.g. "AWS-Admin-Global") |
| `platform` | string | Platform this group belongs to |
| `is_nested` | boolean | True if this membership is inherited through a parent group |
| `parent_group_id` | string (nullable) | FK → `group_id` of the parent group (null if direct membership) |
| `assigned_date` | date | Date the identity was added to the group |

---

### 5.3 `role_mappings.csv`
Primary key: `mapping_id`

| Column | Type | Description |
|---|---|---|
| `mapping_id` | string (UUID) | Unique row identifier |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` |
| `role_id` | string (format: `ROLE-{UUID}`) | Unique role identifier |
| `role_name` | string | Human-readable role name (e.g. "GlobalAdmin", "S3FullAccess") |
| `platform` | string | Platform this role belongs to |
| `assignment_type` | string | `direct` / `inherited` (via group or nested group) |
| `assigned_by` | string (UUID) | FK → `unified_identities.identity_id` of provisioner |
| `assigned_date` | date | Date of role assignment |
| `expiry_date` | date (nullable) | Expiry date of time-limited role (null = permanent) |

---

### 5.4 `audit_events.csv`
Primary key: `event_id`

| Column | Type | Description |
|---|---|---|
| `event_id` | string (UUID) | Unique event identifier |
| `timestamp` | datetime | UTC timestamp of the event |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` (actor) |
| `event_type` | string | `LOGIN` / `LOGOUT` / `ACCESS` / `PRIVILEGE_ESCALATION` / `EXPORT` / `DELETE` / `CONFIG_CHANGE` / `ADMIN_ACTION` |
| `platform` | string | Platform where the event occurred |
| `resource_id` | string (nullable) | FK → `resource_access_logs.resource_id` (if applicable) |
| `resource_name` | string (nullable) | Human-readable resource name |
| `action` | string | `READ` / `WRITE` / `DELETE` / `EXECUTE` / `ADMIN` |
| `outcome` | string | `SUCCESS` / `FAILURE` / `BLOCKED` |
| `source_ip` | string | Source IP address |
| `geo_location` | string | Observed geography of the event |
| `risk_indicator` | boolean | True if Faker injected this as an anomalous event |
| `session_id` | string (UUID) | Groups events belonging to the same session |

---

### 5.5 `offboarding_records.csv`
Primary key: `record_id`

| Column | Type | Description |
|---|---|---|
| `record_id` | string (UUID) | Unique record identifier |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` |
| `offboarding_date` | date | Date the employee or contractor ended |
| `offboarding_type` | string | `RESIGNED` / `TERMINATED` / `CONTRACTOR_END` / `TRANSFER` |
| `accounts_disabled` | boolean | Whether all platform accounts were disabled |
| `access_revoked` | boolean | Whether all access was formally revoked |
| `data_retained` | boolean | Whether data-retention hold was applied |
| `revocation_delay_days` | integer | Number of days between offboarding and access revocation (0 = same-day; >0 = delayed; deliberately inflated for anomalies) |
| `reviewed_by` | string (UUID) | FK → `unified_identities.identity_id` of reviewer |
| `compliance_status` | string | `COMPLIANT` / `NON_COMPLIANT` / `PENDING` |

---

### 5.6 `resource_access_logs.csv`
Primary key: `log_id`
Note: `resource_id` in this table is the canonical resource key referenced by `audit_events.resource_id`, `effective_privileges.resource_id`, and `attack_paths.target_resource_id`.

| Column | Type | Description |
|---|---|---|
| `log_id` | string (UUID) | Unique log entry identifier |
| `resource_id` | string (format: `RES-{UUID}`) | Canonical resource identifier |
| `resource_name` | string | Human-readable resource name (e.g. "prod-s3-finance") |
| `resource_type` | string | `DATABASE` / `S3_BUCKET` / `API` / `REPOSITORY` / `APPLICATION` / `SECRET` / `COMPUTE` |
| `resource_criticality` | string | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` — used in blast radius formula |
| `platform` | string | Platform hosting the resource |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` (accessor) |
| `access_type` | string | `READ` / `WRITE` / `EXECUTE` / `ADMIN` |
| `timestamp` | datetime | UTC timestamp of the access |
| `duration_seconds` | integer | Session or operation duration |
| `bytes_transferred` | integer (nullable) | Data volume moved (null for non-data operations) |
| `outcome` | string | `SUCCESS` / `FAILURE` |

---

### 5.7 `effective_privileges.csv`
Primary key: `privilege_id`

| Column | Type | Description |
|---|---|---|
| `privilege_id` | string (UUID) | Unique privilege record identifier |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` |
| `resource_id` | string | FK → `resource_access_logs.resource_id` |
| `resource_name` | string | Human-readable resource name |
| `resource_type` | string | FK semantic: same value set as `resource_access_logs.resource_type` |
| `resource_criticality` | string | FK semantic: same value as `resource_access_logs.resource_criticality` |
| `platform` | string | Platform of the resource |
| `privilege_level` | string | `READ` / `WRITE` / `EXECUTE` / `ADMIN` / `FULL_CONTROL` |
| `grant_path` | string | How the privilege was obtained: `DIRECT` / `GROUP:<group_name>` / `ROLE:<role_name>` / `NESTED:<chain>` |
| `is_excessive` | boolean | Provisioned but never used (no matching access log) |
| `is_dormant` | boolean | No usage in the last 90 days |
| `last_used` | date (nullable) | Most recent access date (null if never used) |
| `computed_date` | datetime | Timestamp when this row was computed by EffectivePrivilegeEngine |

---

### 5.8 `feature_matrix.csv`
Primary key: `canonical_id`

Note: Phase 4 implemented 13 features on the canonical-identity grain (453 identities).
The Phase 1 spec listed 17 placeholder columns; the table below reflects the actual implementation.

| Column | Type | Description |
|---|---|---|
| `canonical_id` | string (UUID) | Canonical identity key (post-resolution) |
| `platform_count` | integer | Number of distinct platforms the identity has accounts on |
| `privilege_count` | integer | Total effective privileges across all platforms |
| `admin_role_count` | integer | Count of admin/elevated roles held |
| `login_frequency` | float | Mean login events per day across audit history |
| `dormant_days` | float | Days since most recent login (0 if active) |
| `privilege_usage_ratio` | float [0,1] | Fraction of held privileges that have been exercised |
| `cross_platform_exposure` | float | Count of platforms with ADMIN-level access |
| `risk_accumulation_score` | float | Weighted sum of high-severity audit event types |
| `privilege_velocity` | float | Rate of new privilege assignments per day |
| `offboarding_gap_score` | float >= 0 | Days between offboarding date and access revocation (0 if compliant or no offboarding record) |
| `access_revocation_failure` | float {0,1} | 1 if identity has an offboarding record with access_revoked=False; primary ORPHANED_ACCOUNT signal used in IAM domain rule |
| `risk_event_ratio` | float [0,1] | Fraction of audit events flagged risk_indicator=True by SIEM; primary TOKEN_ABUSE signal used in IAM domain rule |
| `privilege_peer_deviation` | float [0,5] | Z-score of privilege_count vs department cohort, clipped at 5; primary OVERPRIVILEGED signal |

---

### 5.9 `anomaly_scores.csv`
Primary key: `identity_id`

| Column | Type | Description |
|---|---|---|
| `canonical_id` | string (UUID) | Canonical identity key (post-resolution); FK → `unified_identities.canonical_id` |
| `isolation_forest_score` | float [0,1] | Normalised Isolation Forest anomaly score (higher = more anomalous) |
| `lof_score` | float [0,1] | Normalised Local Outlier Factor score |
| `autoencoder_loss` | float >= 0 | Reconstruction loss from Autoencoder (raw, not normalised) |
| `autoencoder_loss_normalised` | float [0,1] | Min-max normalised autoencoder loss |
| `ensemble_anomaly_score` | float [0,1] | Weighted ensemble: 0.50 x IF + 0.20 x LOF + 0.30 x AE_norm |
| `is_anomaly` | boolean | True if ensemble_anomaly_score > 0.30, OR Isolation Forest predict()==-1, OR an IAM domain rule fires |
| `detection_method` | string | Pipe-delimited set of triggers that fired: ML_ENSEMBLE, IF_PREDICT, DOMAIN_RULE. ORPHANED_ACCOUNT and TOKEN_ABUSE will always contain DOMAIN_RULE and must be labelled "Rule-based detection" in all downstream UI, narratives, and reports -- never "AI-detected". |
| `anomaly_rank` | integer | Rank 1 = highest anomaly score across all identities |
| `detection_timestamp` | datetime | UTC timestamp when this run's scores were computed |

---

### 5.10 `risk_scores.csv`
Primary key: `risk_id`

| Column | Type | Description |
|---|---|---|
| `risk_id` | string (UUID) | Unique risk record identifier |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` |
| `privilege_risk_component` | float [0,100] | Sub-score from privilege dimension |
| `behavioural_risk_component` | float [0,100] | Sub-score from anomaly / behavioural dimension |
| `identity_risk_component` | float [0,100] | Sub-score from identity hygiene (MFA, dormancy, orphan status) |
| `compliance_risk_component` | float [0,100] | Sub-score from offboarding compliance status |
| `final_risk_score` | float [0,100] | Weighted composite: 0.35×privilege + 0.35×behavioural + 0.20×identity + 0.10×compliance |
| `risk_tier` | string | `CRITICAL` (≥80) / `HIGH` (60–79) / `MEDIUM` (40–59) / `LOW` (<40) |
| `risk_drivers` | string (JSON array) | Top contributing factors e.g. `["excessive_privileges","off_hours_access","mfa_disabled"]` |
| `previous_risk_score` | float (nullable) | `final_risk_score` from the immediately prior pipeline run |
| `score_delta` | float | `final_risk_score − previous_risk_score` (null if first run) |
| `computed_timestamp` | datetime | UTC timestamp of computation |

---

### 5.11 `incidents.csv`
Primary key: `incident_id`

| Column | Type | Description |
|---|---|---|
| `incident_id` | string (UUID) | Unique incident identifier -- FK referenced by `remediation_actions.incident_id` |
| `cluster_id` | integer | Cluster label from DBSCAN (-1 = noise/singleton) |
| `canonical_id` | string (UUID) | FK → `unified_identities.canonical_id` (primary identity of the incident) |
| `member_count` | integer | Number of identities consolidated into this incident (1 for singletons) |
| `related_canonical_ids` | string (JSON array) | All canonical_ids merged into this incident; for member_count=1 contains just the primary |
| `incident_type` | string | `PRIVILEGE_ABUSE` / `LATERAL_MOVEMENT` / `DATA_EXFIL` / `DORMANT_ADMIN` / `ORPHANED_ACCOUNT` / `SOD_VIOLATION` / `BEHAVIORAL_OUTLIER` |
| `severity` | string | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `detection_method` | string | Detection layer that triggered: `ML_ENSEMBLE`, `IF_PREDICT`, `DOMAIN_RULE`, or combinations. Derived from `anomaly_scores.detection_method` of the primary identity. Used by LLMNarrativeGenerator and Streamlit dashboard to set correct attribution labels. |
| `detection_timestamp` | datetime | UTC timestamp when incident was detected |
| `anomaly_score` | float [0,1] | `ensemble_anomaly_score` for the primary identity |
| `risk_score` | float [0,100] | `final_risk_score` for the primary identity |
| `affected_resources` | string (JSON array) | List of `resource_id` values involved (FK → `resource_access_logs.resource_id`) |
| `contributing_features` | string (JSON array) | Feature names from feature_matrix most relevant to this incident type |
| `status` | string | `OPEN` / `INVESTIGATING` / `RESOLVED` / `FALSE_POSITIVE` |
| `platform` | string | Primary platform where the incident was observed |
| `compliance_tags` | string (JSON array) | Control IDs violated -- populated by `ComplianceMapper` (e.g. `["SOX-AC-1","ISO-A.9.2.6"]`) |
| `llm_narrative` | string | Plain-English investigative summary -- populated by `LLMNarrativeGenerator`; must reference detection_method |

---

### 5.12 `attack_paths.csv`
Primary key: `path_id`

| Column | Type | Description |
|---|---|---|
| `path_id` | string (UUID) | Unique path record identifier |
| `source_identity_id` | string (UUID) | FK → `unified_identities.identity_id` (starting compromised identity) |
| `target_resource_id` | string | FK → `resource_access_logs.resource_id` (reachable resource) |
| `target_resource_name` | string | Human-readable name of the target resource |
| `target_resource_criticality` | string | FK semantic: same as `resource_access_logs.resource_criticality` |
| `path_nodes` | string (JSON array) | Ordered list of node IDs traversed (graph node IDs) |
| `path_edges` | string (JSON array) | Ordered list of edge type labels traversed (e.g. `["MEMBER_OF","HAS_ROLE","GRANTS_ACCESS"]`) |
| `path_length` | integer | Number of hops (edges) in the path |
| `blast_radius_score` | float [0,100] | Blast Radius Score for this source identity (same for all rows with same source in a scenario) |
| `reachable_node_count` | integer | Total resource nodes reachable from this source in this scenario |
| `scenario` | string | `CURRENT_STATE` / `POST_REMEDIATION` |
| `simulation_timestamp` | datetime | UTC timestamp when this simulation was run |

---

### 5.13 `remediation_actions.csv`
Primary key: `action_id`

| Column | Type | Description |
|---|---|---|
| `action_id` | string (UUID) | Unique action identifier |
| `incident_id` | string (UUID) | FK → `incidents.incident_id` |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` |
| `action_type` | string | `REVOKE_ROLE` / `DISABLE_ACCOUNT` / `ENFORCE_MFA` / `REMOVE_GROUP` / `SCOPE_REDUCTION` / `REQUIRE_RECERTIFICATION` |
| `priority` | string | `P1` (act within 4 h) / `P2` (24 h) / `P3` (72 h) / `P4` (next sprint) |
| `affected_resource_id` | string (nullable) | FK → `resource_access_logs.resource_id` (null for account-level actions) |
| `estimated_risk_reduction` | float [0,100] | Expected percentage reduction in `final_risk_score` if action is applied |
| `blast_radius_reduction` | float [0,100] | Expected percentage reduction in `blast_radius_score` if action is applied |
| `compliance_frameworks` | string (JSON array) | Frameworks this action satisfies — populated by `ComplianceMapper` (e.g. `["SOX","ISO27001","NIST-CSF"]`) |
| `status` | string | `RECOMMENDED` / `IN_PROGRESS` / `COMPLETED` / `REJECTED` |
| `generated_timestamp` | datetime | UTC timestamp when action was generated |
| `llm_rationale` | string | Plain-English explanation of why this action is recommended — populated by `LLMNarrativeGenerator` |

---

## 6. IDENTITY GRAPH DESIGN

### Graph Type
`networkx.MultiDiGraph` — directed, allows multiple edges between the same pair of nodes (required because a Group can have both a MEMBER_OF and a NESTED_IN relationship to another Group).

### Node Types and Attributes

| Node Type | Node ID Format | Attributes |
|---|---|---|
| `Identity` | `identity_id` (UUID) | `type="Identity"`, `display_name`, `email`, `account_type`, `platform`, `is_active`, `is_privileged`, `risk_score`, `department` |
| `Group` | `group_id` (GRP-UUID) | `type="Group"`, `group_name`, `platform`, `member_count` |
| `Role` | `role_id` (ROLE-UUID) | `type="Role"`, `role_name`, `platform`, `permission_scope` (e.g. "global", "read-only") |
| `Resource` | `resource_id` (RES-UUID) | `type="Resource"`, `resource_name`, `resource_type`, `resource_criticality`, `platform` |
| `Platform` | `platform_id` (e.g. `"PLAT-AD"`) | `type="Platform"`, `platform_name`, `federation_protocol` (e.g. "SAML", "OIDC") |

### Edge Types and Attributes

| Edge Type | Source Node Type | Target Node Type | Attributes |
|---|---|---|---|
| `MEMBER_OF` | Identity | Group | `assigned_date`, `is_nested` (False for direct membership) |
| `MEMBER_OF` | Group | Group | `assigned_date`, `is_nested` (True — used for nested group membership) |
| `HAS_ROLE` | Identity | Role | `assigned_date`, `assignment_type` ("direct"/"inherited"), `expiry_date` |
| `HAS_ROLE` | Group | Role | `assigned_date`, `assignment_type` ("group_assigned") |
| `GRANTS_ACCESS` | Role | Resource | `privilege_level`, `platform`, `grant_mechanism` (e.g. "IAM Policy", "RBAC") |
| `GRANTS_ACCESS` | Group | Resource | `privilege_level`, `platform`, `grant_mechanism` |
| `NESTED_IN` | Group | Group | `nesting_depth` (integer — 1 = direct parent), `platform` |
| `FEDERATES_TO` | Identity | Identity | `federation_protocol` (e.g. "SAML"), `source_platform`, `target_platform` — links the same person's accounts across platforms |

### Effective Privilege Traversal Algorithm

The `EffectivePrivilegeEngine` uses a **Breadth-First Search (BFS) with a visited-node set** to prevent cycles (which can occur via NESTED_IN loops in misconfigured directories):

```
function compute_effective_privileges(graph, identity_node):
    privileges = []
    visited    = {identity_node}
    queue      = deque([identity_node])

    while queue is not empty:
        current = queue.popleft()

        for each outgoing edge (current → neighbor, edge_type) in graph:

            if edge_type == "GRANTS_ACCESS":
                # neighbor is a Resource node
                record effective privilege:
                    (identity_node → resource=neighbor,
                     privilege_level = edge.privilege_level,
                     grant_path      = build_path_string(identity_node, current, neighbor))

            elif edge_type in {"MEMBER_OF", "HAS_ROLE", "NESTED_IN"}:
                # neighbor is a Group or Role node — continue traversal
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

            # FEDERATES_TO and Platform edges are NOT followed
            # during privilege computation (handled separately)

    return deduplicated privileges
    # Deduplication: if same (identity, resource) pair appears via multiple paths,
    # retain the row with the highest privilege_level.
    # Record all grant_paths as a semicolon-delimited list in the grant_path column.
```

**Cycle detection**: the `visited` set guarantees each Group/Role node is expanded at most once per identity traversal, so circular NESTED_IN references (Group A → Group B → Group A) cannot cause infinite loops.

**Path labelling**: `build_path_string` builds a human-readable string like `NESTED:Engineering-Leads→AWS-Admins→AWS-Admin-Global` that is stored in `effective_privileges.grant_path` for audit traceability.

---

## 7. ATTACK PATH SIMULATOR DESIGN

The `AttackPathSimulator` is the platform's flagship feature. It answers: *"If this identity's credentials were compromised, what resources could an attacker reach, and how much does remediation reduce that blast radius?"*

### 7.1 Current State — Blast Radius Computation

**Step 1 — Source selection**: Only identities with `risk_tier ∈ {CRITICAL, HIGH}` in `risk_scores.csv` are simulated (configurable; default: top 20 by `final_risk_score`).

**Step 2 — BFS traversal from compromised identity node**: Starting from the Identity node in `identity_graph.gpickle`, perform BFS following edges in this order: `MEMBER_OF → HAS_ROLE → GRANTS_ACCESS`. The traversal collects every Resource node reachable from the source identity following these edge types only (FEDERATES_TO edges are also followed, which can bridge to additional Identity nodes on other platforms, extending the traversal).

**Step 3 — Resource enumeration**: All Resource nodes reached are recorded. For each, the shortest path (minimum hop count) is stored as `path_nodes` and `path_edges` in `attack_paths.csv`.

**Step 4 — Blast Radius Score formula**:

```
resource_criticality_weight:
    CRITICAL  → 4
    HIGH      → 3
    MEDIUM    → 2
    LOW       → 1

weighted_reachable = Σ resource_criticality_weight(r)  for r in reachable_resources
max_possible       = Σ resource_criticality_weight(r)  for r in ALL resources in graph

Blast Radius Score = (weighted_reachable / max_possible) × 100
```

This yields a 0–100 score where 100 means the compromised identity can reach all resources at maximum criticality weight.

`reachable_node_count` stores the raw count of reachable Resource nodes (unweighted) alongside the score.

---

### 7.2 Post-Remediation Scenario

For each source identity, the `RemediationEngine` will have already produced a ranked list of recommended actions. The `AttackPathSimulator` performs a **graph surgery simulation**:

1. **Create a copy** of `identity_graph` in memory (do not mutate the original).
2. **Apply recommended remediation actions** to the copy:
   - `REVOKE_ROLE`: remove all `HAS_ROLE` edges from `identity_node → role_node` for the specified role.
   - `REMOVE_GROUP`: remove all `MEMBER_OF` edges from `identity_node → group_node` for the specified group.
   - `DISABLE_ACCOUNT`: remove all outgoing edges from `identity_node` (simulates full account lockout).
   - `SCOPE_REDUCTION`: replace a `GRANTS_ACCESS` edge attribute `privilege_level` with `READ` (downgrade, do not remove edge).
   - `ENFORCE_MFA` and `REQUIRE_RECERTIFICATION`: no graph structural change — these affect the identity node attribute `mfa_enabled=True` and are noted in the scenario but do not reduce blast radius directly.
3. **Re-run the same BFS traversal** on the modified graph copy.
4. Record all resulting paths under `scenario = "POST_REMEDIATION"` in `attack_paths.csv`.

---

### 7.3 Reduction Metric Formulas

```
Let:
    BRS_current  = Blast Radius Score (CURRENT_STATE)   for identity i
    BRS_post     = Blast Radius Score (POST_REMEDIATION) for identity i
    RS_current   = final_risk_score (from risk_scores.csv)
    RS_post      = estimated post-remediation risk score
                   = RS_current × (1 − Σ estimated_risk_reduction / 100)
                     for all P1+P2 actions against identity i
                   (capped at 0)

Blast Radius Reduction %  = ((BRS_current − BRS_post) / BRS_current) × 100
Risk Reduction %          = ((RS_current − RS_post)   / RS_current)  × 100
```

Both metrics are written to `remediation_actions.csv` columns `blast_radius_reduction` and `estimated_risk_reduction`.

**Demo narrative hook**: The Streamlit "Attack Path Visualiser" page renders the CURRENT_STATE graph in red (hot nodes = reachable resources) and the POST_REMEDIATION graph in green, side-by-side, with the two percentage reductions displayed as headline KPIs. This directly shows the executive audience *what applying the recommendation actually buys them*.

---

## 8. BI EXPORT LAYER

> **NOT IMPLEMENTED** — The Phase 1 design included a Power BI star-schema export layer (star-schema CSVs written to `powerbi/`, consumed by a `.pbix` template). This layer was out of scope for the final implementation. The `powerbi/` directory exists on disk as a legacy artefact but is not generated or maintained by the current pipeline. All presentation is delivered through the Streamlit dashboard (`src/app.py`).

The original star-schema design (DimIdentity, DimPlatform, DimResource, DimDate, FactRiskScores, FactIncidents, FactAttackPaths, FactRemediationActions) is preserved below for reference only.

```
                    ┌──────────────────┐
                    │   DimDate        │
                    │  date_key (PK)   │
                    │  full_date       │
                    │  year, quarter   │
                    │  month, week     │
                    │  day_of_week     │
                    └────────┬─────────┘
                             │
          ┌──────────────────┼───────────────────────┐
          │                  │                       │
          ▼                  ▼                       ▼
┌──────────────────┐  ┌─────────────────┐  ┌─────────────────────┐
│  FactRiskScores  │  │  FactIncidents  │  │  FactAttackPaths    │
│  risk_id (PK)    │  │  incident_id(PK)│  │  path_id (PK)       │
│  identity_id(FK) │  │  identity_id(FK)│  │  identity_id (FK)   │
│  date_key (FK)   │  │  date_key (FK)  │  │  resource_id (FK)   │
│  platform_id(FK) │  │  platform_id(FK)│  │  date_key (FK)      │
│  final_risk_score│  │  severity       │  │  blast_radius_score │
│  risk_tier       │  │  incident_type  │  │  scenario           │
│  score_delta     │  │  status         │  │  path_length        │
│  privilege_risk  │  │  anomaly_score  │  │  reachable_count    │
│  behavioural_risk│  │  risk_score     │  └──────────┬──────────┘
│  identity_risk   │  └────────┬────────┘             │
│  compliance_risk │           │           ┌──────────▼──────────┐
└──────────┬───────┘           │           │    DimResource       │
           │           ┌───────▼───────┐   │  resource_id (PK)   │
           │           │FactRemediation│   │  resource_name       │
           │           │Actions        │   │  resource_type       │
           │           │  action_id(PK)│   │  resource_criticality│
           │           │  incident_id  │   │  platform_id (FK)    │
           │           │  identity_id  │   └─────────────────────┘
           │           │  date_key(FK) │
           │           │  action_type  │
           │           │  priority     │
           │           │  est_risk_red │
           │           │  br_reduction │
           │           │  status       │
           │           └───────────────┘
           │
    ┌──────▼──────────────────────────────────────┐
    │              DimIdentity (PK: identity_id)   │
    │  display_name, email, department, job_title  │
    │  account_type, platform_id (FK), is_active   │
    │  is_privileged, mfa_enabled, geo_location    │
    └──────┬───────────────────────────────────────┘
           │
    ┌──────▼────────┐         ┌──────────────┐
    │  DimPlatform  │         │   DimRole    │
    │  platform_id  │         │  role_id(PK) │
    │  (PK)         │         │  role_name   │
    │  platform_name│         │  platform_id │
    │  platform_type│         │  permission_ │
    └───────────────┘         │  scope       │
                              └──────────────┘
```

### 8.2 Table Relationships

| From Table | From Column | To Table | To Column | Cardinality |
|---|---|---|---|---|
| `FactRiskScores` | `identity_id` | `DimIdentity` | `identity_id` | Many-to-One |
| `FactRiskScores` | `date_key` | `DimDate` | `date_key` | Many-to-One |
| `FactRiskScores` | `platform_id` | `DimPlatform` | `platform_id` | Many-to-One |
| `FactIncidents` | `identity_id` | `DimIdentity` | `identity_id` | Many-to-One |
| `FactIncidents` | `date_key` | `DimDate` | `date_key` | Many-to-One |
| `FactIncidents` | `platform_id` | `DimPlatform` | `platform_id` | Many-to-One |
| `FactAttackPaths` | `identity_id` | `DimIdentity` | `identity_id` | Many-to-One |
| `FactAttackPaths` | `resource_id` | `DimResource` | `resource_id` | Many-to-One |
| `FactAttackPaths` | `date_key` | `DimDate` | `date_key` | Many-to-One |
| `FactRemediationActions` | `incident_id` | `FactIncidents` | `incident_id` | Many-to-One |
| `FactRemediationActions` | `identity_id` | `DimIdentity` | `identity_id` | Many-to-One |
| `FactRemediationActions` | `date_key` | `DimDate` | `date_key` | Many-to-One |
| `DimResource` | `platform_id` | `DimPlatform` | `platform_id` | Many-to-One |
| `DimRole` | `platform_id` | `DimPlatform` | `platform_id` | Many-to-One |

### 8.3 Required DAX Measures

| Measure Name | DAX Expression | Description |
|---|---|---|
| `High Risk Count` | `CALCULATE(COUNTROWS(FactRiskScores), FactRiskScores[risk_tier] IN {"CRITICAL","HIGH"})` | Count of identities at CRITICAL or HIGH risk |
| `Dormant Admin Count` | `CALCULATE(COUNTROWS(DimIdentity), DimIdentity[is_privileged]=TRUE(), RELATED(FactRiskScores[days_since_last_login])>90)` | Privileged accounts with no login in 90+ days |
| `Avg Blast Radius` | `AVERAGE(FactAttackPaths[blast_radius_score])` filtered to `scenario="CURRENT_STATE"` | Mean blast radius score across high-risk identities |
| `Compliance Score` | `DIVIDE(CALCULATE(COUNTROWS(FactIncidents), FactIncidents[status]="RESOLVED"), COUNTROWS(FactIncidents)) * 100` | Percentage of incidents resolved (proxy compliance KPI) |
| `Risk Trend` | `[current_period_avg_risk] - [prior_period_avg_risk]` using `DATEADD` on `DimDate` | Period-over-period change in average risk score |
| `Alert Reduction %` | `DIVIDE([open_incidents_post_remediation] - [open_incidents_pre_remediation], [open_incidents_pre_remediation]) * -100` | Projected alert reduction if all P1 remediations are applied |
| `Critical Incident Count` | `CALCULATE(COUNTROWS(FactIncidents), FactIncidents[severity]="CRITICAL", FactIncidents[status]="OPEN")` | Open CRITICAL incidents requiring immediate action |
| `Avg Risk Score` | `AVERAGE(FactRiskScores[final_risk_score])` | Mean risk score across all identities |
| `Remediation Coverage %` | `DIVIDE(CALCULATE(COUNTROWS(FactRemediationActions), FactRemediationActions[status] IN {"IN_PROGRESS","COMPLETED"}), COUNTROWS(FactRemediationActions)) * 100` | Fraction of recommendations acted upon |
| `Blast Radius Reduction %` | `AVERAGE(FactAttackPaths[blast_radius_score] [POST_REMEDIATION scenario]) / AVERAGE(FactAttackPaths[blast_radius_score] [CURRENT_STATE scenario]) * -100 + 100` | Average blast radius reduction across all simulated identities |

---

## 9. END-TO-END WORKFLOW

### 9.1 `main.py` Orchestration

`main.py` is the single entry point for the full pipeline. It contains no business logic — it imports and calls each module's public `run()` function in the exact sequence below, passing only file paths and a shared configuration dictionary. Each step is wrapped in a try/except with structured logging so partial failures are clearly reported.

```
main.py execution sequence:

1.  Load config (seed, n_identities, anomaly_injection_rate, risk_threshold,
                  anomaly_threshold, llm_model_id, output_dir)

2.  DataSimulator.run(config)
        → writes 6 raw CSVs to generated_data/

3.  IdentityResolver.run(config)
        → resolves and overwrites unified_identities.csv

4.  GraphBuilder.run(config)
        → writes identity_graph.gpickle

5.  EffectivePrivilegeEngine.run(config)
        → writes effective_privileges.csv

6.  FeatureEngineering.run(config)
        → writes feature_matrix.csv

7.  AnomalyDetection.run(config)
        → writes anomaly_scores.csv + saves model artefacts to models/

8.  RiskScoringEngine.run(config)
        → writes risk_scores.csv

9.  IncidentClustering.run(config)
        → writes incidents.csv

10. AttackPathSimulator.run(config)
        → writes attack_paths.csv

11. RemediationEngine.run(config)
        → writes remediation_actions.csv

12. ComplianceMapper.run(config)
        → enriches incidents.csv + remediation_actions.csv in-place

13. LLMNarrativeGenerator.run(config)
        → enriches incidents.csv + remediation_actions.csv in-place

14. Write summary report to reports/pipeline_run_summary.md
        → total identities, risk tier breakdown, incident count, alert reduction %,
           blast radius stats, step timings, consistency check results

    NOTE: Steps 1–13 are implemented. Step 14 writes pipeline_run_summary.md.
    The Power BI export step from the Phase 1 design was not implemented.
```

### 9.2 Single Source of Truth Contract

`generated_data/` is the exclusive inter-module communication channel. This contract is enforced:

- **No module passes in-memory DataFrames to another module** — all state is materialised to disk between steps. This ensures reproducibility (each step can be re-run independently) and debuggability (intermediate state is always inspectable).
- **`app.py` reads exclusively from `generated_data/`** — it does not call any `src/` module functions. It is a pure consumer.
- **`ground_truth_labels.csv` is never read by the main pipeline** — it is only accessed inside `_validate_against_ground_truth()` in `anomaly_detection.py`, which is called exclusively when `--validate` is passed to `main.py` or `anomaly_detection.py`. This ensures evaluation labels cannot contaminate model training.

### 9.3 `app.py` Page Structure (actual implementation — 8 pages)

| Page | Data Sources Read | Key Visualisations |
|---|---|---|
| Executive Overview | `risk_scores.csv`, `anomaly_scores.csv`, `incidents.csv`, `attack_paths.csv` | 5 KPI cards, risk tier donut, detection method bar chart, incident type chart, top-15 risk bar |
| Identity Explorer | `risk_scores.csv`, `unified_identities.csv`, `effective_privileges.csv`, `remediation_actions.csv` | Filterable identity table, per-identity risk gauge, evidence/root-cause blocks, privilege table |
| Risk Register | `risk_scores.csv` | Sortable risk table with ProgressColumn, risk score histogram with tier thresholds |
| Incident Explorer | `incidents.csv` | Severity/type breakdown bar charts, scrolling incident cards with detection-method badges |
| Identity Graph | `attack_paths_detail.json` | Plotly hierarchical network (Identity → Role → Resource), per-identity subgraph |
| Attack Path Simulator | `attack_paths_detail.json`, `attack_paths.csv` | Before/after grouped bar, side-by-side Plotly network graphs (removed nodes greyed out), path breadcrumb |
| Compliance Dashboard | `compliance_mappings.csv` | Framework pie chart, incident mappings bar, top-violated controls per framework |
| AI Narratives | `narratives.json`, `incidents.csv` | Narrative cards with detection-method badge, narrative type indicator (LLM vs template) |

**Implementation notes vs Phase 1 design:**
- Attack path graphs use Plotly scatter traces with NetworkX hierarchical layout, not PyVis (PyVis was not installed).
- The `attack_paths.csv` produced by Phase 5 is at **identity grain** (20 rows, one per simulated identity) rather than the per-path grain described in the Phase 1 schema. `attack_paths_detail.json` provides the full node/edge graph data for the Attack Path Simulator page.
- `risk_scores.csv` uses `canonical_id` as the join key (not `identity_id`) consistent with the canonical-identity grain established by Phase 3.
