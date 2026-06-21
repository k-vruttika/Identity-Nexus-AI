# Identity Nexus AI — Data Dictionary
**Reference table for all columns in every CSV produced by the pipeline**
Version: 1.0 | Phase: 1 — Design & Architecture
All files reside in `generated_data/`. Date format: `YYYY-MM-DD`. Datetime format: `YYYY-MM-DD HH:MM:SS` (UTC).

---

## `unified_identities.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `identity_id` | string (UUID) | Canonical unique identifier — primary key, referenced by all other tables as a foreign key | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `display_name` | string | Full human-readable name of the person or service account | `"Alice Nakamura"` |
| `email` | string | Normalised corporate email address (lowercase) | `"alice.nakamura@corp.example.com"` |
| `username` | string | Platform login handle (lowercase, no spaces) | `"anakamura"` |
| `platform` | string | Source platform where this account originates: `AD`, `Okta`, `AWS`, `GitHub`, `Salesforce`, `ServiceNow` | `"AD"` |
| `account_type` | string | Class of account: `human` / `service` / `machine` | `"human"` |
| `department` | string | Organisational department | `"Finance"` |
| `job_title` | string | Formal job title | `"Senior Developer"` |
| `manager_id` | string (UUID, nullable) | FK → `unified_identities.identity_id` of the direct line manager; null for top-level accounts | `"b4d3e2f1-9c0d-4e8b-a2b1-c0d4e6f08a1b"` |
| `created_date` | date | Date the account was provisioned | `"2022-03-15"` |
| `last_login` | datetime (nullable) | UTC timestamp of the most recent successful authentication; null if the account has never been used | `"2025-11-20 09:42:00"` |
| `is_active` | boolean | Whether the account is currently enabled in its source platform | `True` |
| `is_privileged` | boolean | True if the identity holds at least one admin, elevated, or sensitive role | `False` |
| `mfa_enabled` | boolean | True if multi-factor authentication is configured and enforced for this account | `True` |
| `geo_location` | string | Primary assigned geography for this account | `"US-East"` |
| `canonical_id` | string (UUID) | Resolved canonical identity key after cross-platform deduplication by `IdentityResolver`; matches `identity_id` after resolution is applied | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |

---

## `group_mappings.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `mapping_id` | string (UUID) | Unique row identifier for this membership record | `"c5e4f3a2-0d1e-4f7c-b4d3-e2f1a0b9c8d7"` |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` — the identity that belongs to the group | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `group_id` | string | Unique group identifier, formatted as `GRP-{UUID}` | `"GRP-d6f5a4b3-1e2f-4a8d-c5e4-f3a2b1c0d9e8"` |
| `group_name` | string | Human-readable group name | `"AWS-Admin-Global"` |
| `platform` | string | Platform this group is defined on | `"AWS"` |
| `is_nested` | boolean | True if this membership is inherited transitively through a parent group, False if the identity is a direct member | `False` |
| `parent_group_id` | string (nullable) | FK → `group_id` of the immediate parent group when `is_nested=True`; null for direct memberships | `null` |
| `assigned_date` | date | Date the identity was added to the group | `"2023-07-01"` |

---

## `role_mappings.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `mapping_id` | string (UUID) | Unique row identifier for this role assignment | `"e7a6b5c4-2f3a-4b9e-d6f5-a4b3c2d1e0f9"` |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `role_id` | string | Unique role identifier, formatted as `ROLE-{UUID}` | `"ROLE-f8b7c6d5-3a4b-4c0f-e7a6-b5c4d3e2f1a0"` |
| `role_name` | string | Human-readable role name | `"GlobalAdmin"` |
| `platform` | string | Platform this role is defined on | `"Okta"` |
| `assignment_type` | string | How the role was granted: `direct` (assigned explicitly to identity), `inherited` (via a group or nested group membership) | `"direct"` |
| `assigned_by` | string (UUID) | FK → `unified_identities.identity_id` of the person or service that provisioned this role | `"b4d3e2f1-9c0d-4e8b-a2b1-c0d4e6f08a1b"` |
| `assigned_date` | date | Date the role was assigned | `"2023-01-10"` |
| `expiry_date` | date (nullable) | Date after which this role assignment is no longer valid; null means the assignment is permanent | `"2026-01-10"` |
| `ticket_id` | string (nullable) | **Phase 2 addition.** IT ticket reference justifying this role assignment. Populated for `LEGITIMATE_EXCEPTION` identities and some authorised elevated assignments; empty for normal and true-anomaly assignments. Used by Phase 10 evaluation to distinguish justified from unjustified elevation. | `"TKT-202601-45231"` |
| `approval_date` | date (nullable) | **Phase 2 addition.** Date the role assignment was formally approved; paired with `ticket_id`. Empty when no approval record exists. | `"2026-01-05"` |
| `approver_id` | string (UUID, nullable) | **Phase 2 addition.** FK → `unified_identities.identity_id` of the approver who authorised the role. Empty when no approval exists. | `"b4d3e2f1-9c0d-4e8b-a2b1-c0d4e6f08a1b"` |

---

## `audit_events.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `event_id` | string (UUID) | Unique identifier for this audit log entry | `"09c8d7e6-f5a4-4b3c-2d1e-0f9a8b7c6d5e"` |
| `timestamp` | datetime | UTC date and time when the event occurred | `"2025-12-03 02:17:45"` |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` — the identity that performed the action | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `event_type` | string | Category of the event: `LOGIN`, `LOGOUT`, `ACCESS`, `PRIVILEGE_ESCALATION`, `EXPORT`, `DELETE`, `CONFIG_CHANGE`, `ADMIN_ACTION` | `"ACCESS"` |
| `platform` | string | Platform where the event was recorded | `"AWS"` |
| `resource_id` | string (nullable) | FK → `resource_access_logs.resource_id` — the resource involved; null for events not tied to a specific resource (e.g. LOGIN) | `"RES-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"` |
| `resource_name` | string (nullable) | Human-readable resource name corresponding to `resource_id` | `"prod-s3-finance"` |
| `action` | string | Specific operation performed: `READ`, `WRITE`, `DELETE`, `EXECUTE`, `ADMIN` | `"READ"` |
| `outcome` | string | Result of the action: `SUCCESS`, `FAILURE`, `BLOCKED` | `"SUCCESS"` |
| `source_ip` | string | IPv4 or IPv6 address of the client that initiated the event | `"203.0.113.42"` |
| `geo_location` | string | Observed geography where the event originated | `"EU-West"` |
| `risk_indicator` | boolean | True if the `DataSimulator` deliberately injected this event as an anomalous pattern | `False` |
| `session_id` | string (UUID) | Groups multiple events belonging to the same authenticated session | `"1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"` |
| `ticket_id` | string (nullable) | **Phase 2 addition.** IT ticket reference authorising this specific event (e.g. on-call rotation, emergency access). Present on `ADMIN_ACTION` events for `LEGITIMATE_EXCEPTION` identities; empty otherwise. | `"TKT-202603-88012"` |

---

## `offboarding_records.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `record_id` | string (UUID) | Unique identifier for this offboarding record | `"2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f"` |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` — the identity that was offboarded | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `offboarding_date` | date | Date the employment or contractor engagement ended | `"2025-09-30"` |
| `offboarding_type` | string | Reason for offboarding: `RESIGNED`, `TERMINATED`, `CONTRACTOR_END`, `TRANSFER` | `"RESIGNED"` |
| `accounts_disabled` | boolean | True if all platform accounts were disabled as part of offboarding | `True` |
| `access_revoked` | boolean | True if all access rights were formally revoked across all platforms | `False` |
| `data_retained` | boolean | True if a data-retention or legal hold was placed on this identity's data | `False` |
| `revocation_delay_days` | integer | Number of calendar days between `offboarding_date` and actual access revocation; 0 means same-day; deliberately inflated (up to 90+) for anomaly injection | `0` |
| `reviewed_by` | string (UUID) | FK → `unified_identities.identity_id` of the HR or security reviewer who signed off | `"b4d3e2f1-9c0d-4e8b-a2b1-c0d4e6f08a1b"` |
| `compliance_status` | string | Current compliance state of the offboarding process: `COMPLIANT`, `NON_COMPLIANT`, `PENDING` | `"COMPLIANT"` |

---

## `resource_access_logs.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `log_id` | string (UUID) | Unique identifier for this access log entry | `"3d4e5f6a-7b8c-4d9e-0f1a-2b3c4d5e6f7a"` |
| `resource_id` | string | Canonical resource identifier, formatted as `RES-{UUID}` — primary key for resources, referenced by `audit_events.resource_id`, `effective_privileges.resource_id`, and `attack_paths.target_resource_id` | `"RES-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"` |
| `resource_name` | string | Human-readable resource name | `"prod-s3-finance"` |
| `resource_type` | string | Category of resource: `DATABASE`, `S3_BUCKET`, `API`, `REPOSITORY`, `APPLICATION`, `SECRET`, `COMPUTE` | `"S3_BUCKET"` |
| `resource_criticality` | string | Business criticality rating used in blast radius formula: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | `"CRITICAL"` |
| `platform` | string | Platform hosting this resource | `"AWS"` |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` — the identity that accessed the resource | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `access_type` | string | Type of access performed: `READ`, `WRITE`, `EXECUTE`, `ADMIN` | `"READ"` |
| `timestamp` | datetime | UTC date and time of the access event | `"2025-11-15 14:33:22"` |
| `duration_seconds` | integer | Duration of the session or operation in seconds | `47` |
| `bytes_transferred` | integer (nullable) | Volume of data transferred in bytes; null for non-data operations such as EXECUTE or ADMIN | `102400` |
| `outcome` | string | Result of the access: `SUCCESS`, `FAILURE` | `"SUCCESS"` |

---

## `effective_privileges.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `privilege_id` | string (UUID) | Unique identifier for this materialised privilege record | `"4e5f6a7b-8c9d-4e0f-1a2b-3c4d5e6f7a8b"` |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` — the identity that holds this privilege | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `resource_id` | string | FK → `resource_access_logs.resource_id` — the resource this privilege grants access to | `"RES-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"` |
| `resource_name` | string | Human-readable resource name (denormalised for query convenience) | `"prod-s3-finance"` |
| `resource_type` | string | Same value set as `resource_access_logs.resource_type` | `"S3_BUCKET"` |
| `resource_criticality` | string | Same value as `resource_access_logs.resource_criticality` for this resource | `"CRITICAL"` |
| `platform` | string | Platform of the resource | `"AWS"` |
| `privilege_level` | string | Effective access level on this resource: `READ`, `WRITE`, `EXECUTE`, `ADMIN`, `FULL_CONTROL` | `"ADMIN"` |
| `grant_path` | string | Audit trail of how this privilege was obtained, e.g. direct assignment or chain of nested groups/roles; semicolon-delimited if multiple paths exist | `"NESTED:Engineering-Leads→AWS-Admins→AWS-Admin-Global"` |
| `is_excessive` | boolean | True if the identity was provisioned this access but has no corresponding row in `resource_access_logs` (never used) | `True` |
| `is_dormant` | boolean | True if the most recent matching access event in `resource_access_logs` is more than 90 days ago | `False` |
| `last_used` | date (nullable) | Date of most recent access to this resource by this identity; null if the privilege has never been exercised | `null` |
| `computed_date` | datetime | UTC timestamp when `EffectivePrivilegeEngine` computed this row | `"2025-12-10 08:00:00"` |

---

## `feature_matrix.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` — primary key for this table | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `login_frequency_7d` | integer | Count of successful LOGIN events in the rolling 7-day window | `12` |
| `login_frequency_30d` | integer | Count of successful LOGIN events in the rolling 30-day window | `48` |
| `unique_resources_accessed_7d` | integer | Count of distinct `resource_id` values accessed in the rolling 7-day window | `5` |
| `failed_login_count_7d` | integer | Count of LOGIN events with `outcome=FAILURE` in the rolling 7-day window | `0` |
| `off_hours_access_ratio` | float [0,1] | Fraction of all access events (across full audit history) that occurred outside 08:00–18:00 in the identity's assigned `geo_location` timezone | `0.08` |
| `geo_anomaly_score` | float [0,1] | Normalised score (0 = normal, 1 = highly anomalous) indicating geo-impossible logins (simultaneous logins from distant locations) or consistently unusual geographies | `0.00` |
| `privilege_count` | integer | Total count of rows in `effective_privileges.csv` for this identity (total effective privileges) | `14` |
| `excessive_privilege_ratio` | float [0,1] | Fraction of `effective_privileges` rows where `is_excessive=True` | `0.43` |
| `dormant_privilege_ratio` | float [0,1] | Fraction of `effective_privileges` rows where `is_dormant=True` | `0.14` |
| `cross_platform_access_count` | integer | Count of distinct platform values in `resource_access_logs` for this identity in the rolling 30-day window | `3` |
| `admin_action_count_7d` | integer | Count of audit events with `event_type ∈ {ADMIN_ACTION, PRIVILEGE_ESCALATION}` in the rolling 7-day window | `0` |
| `data_exfil_indicators` | integer | Count of events matching exfiltration heuristics: `event_type=EXPORT` AND `off_hours=True` AND `bytes_transferred > 50MB` | `0` |
| `peer_deviation_score` | float [0,1] | Z-score normalised Euclidean distance from this identity's feature vector to the centroid of all identities in the same `department`; normalised to [0,1] via min-max scaling across all identities | `0.12` |
| `days_since_last_login` | integer | Calendar days elapsed since `unified_identities.last_login`; set to `999` if `last_login` is null (never logged in) | `2` |
| `mfa_bypass_count` | integer | Count of successful LOGIN events where `mfa_enabled=True` for the identity but MFA challenge was absent in the audit record (simulated via Faker injection) | `0` |
| `escalation_event_count_7d` | integer | Count of events with `event_type=PRIVILEGE_ESCALATION` in the rolling 7-day window | `0` |

---

## `anomaly_scores.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` — primary key for this table | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `isolation_forest_score` | float [0,1] | Anomaly score from Isolation Forest; raw output of `decision_function` rescaled to [0,1] where 1 = most anomalous | `0.23` |
| `lof_score` | float [0,1] | Anomaly score from Local Outlier Factor; raw negative LOF scores min-max normalised to [0,1] where 1 = most anomalous | `0.19` |
| `autoencoder_loss` | float ≥ 0 | Raw mean-squared reconstruction error from the Autoencoder model; higher = more anomalous; not normalised | `0.0034` |
| `autoencoder_loss_normalised` | float [0,1] | Min-max normalisation of `autoencoder_loss` across all identities in this pipeline run | `0.21` |
| `ensemble_anomaly_score` | float [0,1] | Weighted fusion: `0.35 × isolation_forest_score + 0.35 × lof_score + 0.30 × autoencoder_loss_normalised` | `0.21` |
| `is_anomaly` | boolean | True if `ensemble_anomaly_score` exceeds the configured threshold (default 0.65) | `False` |
| `anomaly_rank` | integer | Rank of this identity by `ensemble_anomaly_score` descending; rank 1 = highest anomaly score | `312` |
| `detection_timestamp` | datetime | UTC timestamp when this pipeline run computed these scores | `"2025-12-10 08:05:00"` |

---

## `risk_scores.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `risk_id` | string (UUID) | Unique identifier for this risk record | `"5f6a7b8c-9d0e-4f1a-2b3c-4d5e6f7a8b9c"` |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `privilege_risk_component` | float [0,100] | Sub-score from privilege dimension: driven by `excessive_privilege_ratio`, `dormant_privilege_ratio`, `privilege_count`, and `resource_criticality` of effective privileges | `34.5` |
| `behavioural_risk_component` | float [0,100] | Sub-score from behavioural dimension: driven by `ensemble_anomaly_score`, `off_hours_access_ratio`, `geo_anomaly_score`, `admin_action_count_7d`, `data_exfil_indicators` | `15.2` |
| `identity_risk_component` | float [0,100] | Sub-score from identity hygiene dimension: driven by `mfa_enabled`, `days_since_last_login`, `is_active`, `accounts_disabled` (from offboarding), `mfa_bypass_count` | `10.0` |
| `compliance_risk_component` | float [0,100] | Sub-score from compliance dimension: driven by `offboarding_records.compliance_status` and `revocation_delay_days` | `0.0` |
| `final_risk_score` | float [0,100] | Weighted composite score: `0.35×privilege + 0.35×behavioural + 0.20×identity + 0.10×compliance` | `21.5` |
| `risk_tier` | string | Tier assigned based on `final_risk_score`: `CRITICAL` (≥80), `HIGH` (60–79), `MEDIUM` (40–59), `LOW` (<40) | `"LOW"` |
| `risk_drivers` | string (JSON array) | Ordered list of the top contributing factor names from the feature vector | `["excessive_privileges","mfa_disabled"]` |
| `previous_risk_score` | float (nullable) | `final_risk_score` from the immediately preceding pipeline run; null if this is the first run | `null` |
| `score_delta` | float (nullable) | Signed change: `final_risk_score − previous_risk_score`; positive = risk increased; null if `previous_risk_score` is null | `null` |
| `computed_timestamp` | datetime | UTC timestamp when this score was computed | `"2025-12-10 08:10:00"` |

---

## `incidents.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `incident_id` | string (UUID) | Unique incident identifier — primary key, referenced by `remediation_actions.incident_id` | `"6a7b8c9d-0e1f-4a2b-3c4d-5e6f7a8b9c0d"` |
| `cluster_id` | integer | Cluster label assigned by DBSCAN/KMeans; −1 denotes a noise point (outlier not in any cluster) | `3` |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` — primary identity involved in this incident | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `incident_type` | string | Classification of the incident: `PRIVILEGE_ABUSE`, `LATERAL_MOVEMENT`, `DATA_EXFIL`, `DORMANT_ADMIN`, `ORPHANED_ACCOUNT`, `SOD_VIOLATION`, `GEO_ANOMALY` | `"DORMANT_ADMIN"` |
| `severity` | string | Business impact severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | `"HIGH"` |
| `detection_timestamp` | datetime | UTC timestamp when the incident was detected (i.e., when the clustering run completed) | `"2025-12-10 08:12:00"` |
| `anomaly_score` | float [0,1] | `ensemble_anomaly_score` from `anomaly_scores.csv` for the primary identity | `0.82` |
| `risk_score` | float [0,100] | `final_risk_score` from `risk_scores.csv` for the primary identity | `78.4` |
| `affected_resources` | string (JSON array) | List of `resource_id` values (FK → `resource_access_logs.resource_id`) involved in the incident | `["RES-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"]` |
| `contributing_features` | string (JSON array) | Names of feature columns from `feature_matrix.csv` that had the highest influence on detection | `["dormant_privilege_ratio","days_since_last_login","admin_action_count_7d"]` |
| `status` | string | Current investigation status: `OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE` | `"OPEN"` |
| `platform` | string | Primary platform where the incident activity was observed | `"AWS"` |
| `compliance_tags` | string (JSON array) | Control IDs violated — populated by `ComplianceMapper`; empty array `[]` until `ComplianceMapper` runs | `["SOX-AC-1","ISO-A.9.2.6","NIST-PR.AC-4"]` |
| `llm_narrative` | string | Plain-English investigative summary (≤200 words) generated by `LLMNarrativeGenerator`; empty string until that module runs | `"Alice Nakamura's account exhibits hallmarks of a dormant privileged account abuse scenario..."` |

---

## `attack_paths.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `path_id` | string (UUID) | Unique identifier for this attack path record | `"7b8c9d0e-1f2a-4b3c-4d5e-6f7a8b9c0d1e"` |
| `source_identity_id` | string (UUID) | FK → `unified_identities.identity_id` — the compromised identity from which the BFS traversal starts | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `target_resource_id` | string | FK → `resource_access_logs.resource_id` — the resource reachable from the source identity | `"RES-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"` |
| `target_resource_name` | string | Human-readable resource name (denormalised) | `"prod-s3-finance"` |
| `target_resource_criticality` | string | Criticality of the target resource (same value set as `resource_access_logs.resource_criticality`) | `"CRITICAL"` |
| `path_nodes` | string (JSON array) | Ordered list of graph node IDs traversed from source to target, inclusive | `["a3f2c1d4-...","GRP-d6f5a4b3-...","ROLE-f8b7c6d5-...","RES-1a2b3c4d-..."]` |
| `path_edges` | string (JSON array) | Ordered list of edge type labels traversed, same length as `path_nodes` minus one | `["MEMBER_OF","HAS_ROLE","GRANTS_ACCESS"]` |
| `path_length` | integer | Number of hops (edges) in the path; minimum path is length 1 (direct GRANTS_ACCESS) | `3` |
| `blast_radius_score` | float [0,100] | Blast Radius Score computed for this `source_identity_id` in this `scenario`; same value repeated across all rows with the same source and scenario | `62.5` |
| `reachable_node_count` | integer | Total count of distinct Resource nodes reachable from this source in this scenario (raw count, unweighted) | `18` |
| `scenario` | string | Which simulation this path belongs to: `CURRENT_STATE` or `POST_REMEDIATION` | `"CURRENT_STATE"` |
| `simulation_timestamp` | datetime | UTC timestamp when this simulation run was executed | `"2025-12-10 08:15:00"` |

---

## `remediation_actions.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `action_id` | string (UUID) | Unique identifier for this remediation action | `"8c9d0e1f-2a3b-4c4d-5e6f-7a8b9c0d1e2f"` |
| `incident_id` | string (UUID) | FK → `incidents.incident_id` — the incident this action addresses | `"6a7b8c9d-0e1f-4a2b-3c4d-5e6f7a8b9c0d"` |
| `identity_id` | string (UUID) | FK → `unified_identities.identity_id` — the identity on which to take this action | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `action_type` | string | The remediation operation to perform: `REVOKE_ROLE`, `DISABLE_ACCOUNT`, `ENFORCE_MFA`, `REMOVE_GROUP`, `SCOPE_REDUCTION`, `REQUIRE_RECERTIFICATION` | `"REVOKE_ROLE"` |
| `priority` | string | Urgency tier: `P1` (act within 4 hours), `P2` (24 hours), `P3` (72 hours), `P4` (next sprint / backlog) | `"P1"` |
| `affected_resource_id` | string (nullable) | FK → `resource_access_logs.resource_id` for resource-scoped actions (e.g. SCOPE_REDUCTION); null for account-level actions (e.g. DISABLE_ACCOUNT, ENFORCE_MFA) | `"RES-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"` |
| `estimated_risk_reduction` | float [0,100] | Estimated percentage reduction in `final_risk_score` if this action is applied, computed by `RemediationEngine` | `35.0` |
| `blast_radius_reduction` | float [0,100] | Estimated percentage reduction in `blast_radius_score` if this action is applied, derived from the `POST_REMEDIATION` scenario in `attack_paths.csv` | `42.0` |
| `compliance_frameworks` | string (JSON array) | Compliance frameworks this action satisfies — populated by `ComplianceMapper`; empty array `[]` until that module runs | `["SOX","ISO27001","NIST-CSF"]` |
| `status` | string | Lifecycle state of this action: `RECOMMENDED`, `IN_PROGRESS`, `COMPLETED`, `REJECTED` | `"RECOMMENDED"` |
| `generated_timestamp` | datetime | UTC timestamp when `RemediationEngine` generated this action | `"2025-12-10 08:18:00"` |
| `llm_rationale` | string | Plain-English explanation of why this specific action is recommended, generated by `LLMNarrativeGenerator`; empty string until that module runs | `"Revoking the GlobalAdmin role from this account eliminates the highest-criticality privilege path..."` |

---

## Foreign Key Cross-Reference

| Column (in file) | References | Notes |
|---|---|---|
| `unified_identities.manager_id` | `unified_identities.identity_id` | Self-referential; null for top-level identities |
| `group_mappings.identity_id` | `unified_identities.identity_id` | |
| `group_mappings.parent_group_id` | `group_mappings.group_id` | Self-referential within group_mappings; null for direct memberships |
| `role_mappings.identity_id` | `unified_identities.identity_id` | |
| `role_mappings.assigned_by` | `unified_identities.identity_id` | The provisioner identity |
| `audit_events.identity_id` | `unified_identities.identity_id` | |
| `audit_events.resource_id` | `resource_access_logs.resource_id` | Nullable; same RES-UUID namespace |
| `offboarding_records.identity_id` | `unified_identities.identity_id` | |
| `offboarding_records.reviewed_by` | `unified_identities.identity_id` | |
| `resource_access_logs.identity_id` | `unified_identities.identity_id` | |
| `effective_privileges.identity_id` | `unified_identities.identity_id` | |
| `effective_privileges.resource_id` | `resource_access_logs.resource_id` | |
| `feature_matrix.identity_id` | `unified_identities.identity_id` | One row per identity |
| `anomaly_scores.identity_id` | `unified_identities.identity_id` | One row per identity |
| `risk_scores.identity_id` | `unified_identities.identity_id` | One row per identity per run |
| `incidents.identity_id` | `unified_identities.identity_id` | Primary actor |
| `incidents.affected_resources[]` | `resource_access_logs.resource_id` | JSON array of FK values |
| `attack_paths.source_identity_id` | `unified_identities.identity_id` | |
| `attack_paths.target_resource_id` | `resource_access_logs.resource_id` | |
| `remediation_actions.incident_id` | `incidents.incident_id` | |
| `remediation_actions.identity_id` | `unified_identities.identity_id` | |
| `remediation_actions.affected_resource_id` | `resource_access_logs.resource_id` | Nullable |
| `role_mappings.approver_id` | `unified_identities.identity_id` | Phase 2 addition; nullable |
| `group_definitions.parent_group_id` | `group_definitions.group_id` | Self-referential; empty for root groups |
| `role_definitions.resource_ids[]` | `resource_catalog.resource_id` | JSON array of FK values |

---

## Phase 2 Additions

The following files and columns are introduced in Phase 2 (`data_simulator.py`) and are not in the Phase 1 architecture spec. All paths are relative to `generated_data/`.

### Column additions to existing spec tables

| Table | Column | Reason |
|---|---|---|
| `role_mappings.csv` | `ticket_id`, `approval_date`, `approver_id` | Required to encode `LEGITIMATE_EXCEPTION` anomaly justification records for Phase 10 precision/recall evaluation |
| `audit_events.csv` | `ticket_id` | Required to mark authorised elevated audit events for `LEGITIMATE_EXCEPTION` identities |

---

### Per-platform raw identity files (Phase 2 artefacts — consumed by IdentityResolver in Phase 3)

Each file contains platform-native attributes with realistic quirks that create fuzzy-matching challenges for `identity_resolver.py`.

#### `ad_identities.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `ad_object_guid` | string (UUID) | AD objectGUID — maps to `identity_id` in `unified_identities.csv` | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `sam_account_name` | string | sAMAccountName — short login handle, typically `firstinitiallastname` | `"anakamura"` |
| `user_principal_name` | string | UPN in `user@corp.nexusai.com` format | `"alice.nakamura@corp.nexusai.com"` |
| `distinguished_name` | string | Full LDAP DN e.g. `CN=Alice Nakamura,OU=Finance,DC=corp,DC=nexusai,DC=com` | `"CN=Alice Nakamura,OU=Finance,DC=corp,DC=nexusai,DC=com"` |
| `display_name` | string | Full display name | `"Alice Nakamura"` |
| `given_name` | string | First name | `"Alice"` |
| `surname` | string | Last name | `"Nakamura"` |
| `email` | string | Corporate email (primary correlation key) | `"alice.nakamura@corp.nexusai.com"` |
| `department` | string | Organisational department | `"Finance"` |
| `job_title` | string | Job title (`title` attribute in AD) | `"Financial Analyst"` |
| `manager_dn` | string (nullable) | Distinguished name of direct manager | `"CN=Bob Smith,OU=Finance,DC=corp,DC=nexusai,DC=com"` |
| `account_enabled` | boolean | Maps to `unified_identities.is_active`; `False` for ORPHANED_ACCOUNT on AD | `True` |
| `user_account_control` | integer | AD UAC bitmask: 512 = normal, 514 = disabled | `512` |
| `password_last_set` | datetime | Last password change timestamp | `"2025-11-01 09:00:00"` |
| `last_logon` | datetime (nullable) | Last successful logon; empty for dormant accounts | `"2026-06-19 08:45:00"` |
| `account_created` | date | Account creation date | `"2022-03-15"` |
| `ou` | string | Organisational unit path | `"OU=Finance"` |

#### `azuread_identities.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `aad_object_id` | string (UUID) | Azure AD objectId — maps to `identity_id` | `"b4d3e2f1-9c0d-4e8b-a2b1-c0d4e6f08a1b"` |
| `user_principal_name` | string | UPN; ~30% use `@nexusai.onmicrosoft.com` (resolver challenge) | `"alice.nakamura@nexusai.onmicrosoft.com"` |
| `display_name` | string | Full display name | `"Alice Nakamura"` |
| `given_name` | string | First name | `"Alice"` |
| `surname` | string | Last name | `"Nakamura"` |
| `email` | string | `mail` attribute — reliable cross-platform correlation field | `"alice.nakamura@corp.nexusai.com"` |
| `department` | string | Department | `"Finance"` |
| `job_title` | string | Job title | `"Financial Analyst"` |
| `account_enabled` | boolean | `False` for ORPHANED_ACCOUNT on AzureAD | `True` |
| `last_sign_in` | datetime (nullable) | Most recent sign-in | `"2026-06-19 08:45:00"` |
| `created_date_time` | date | Account provisioning date | `"2022-03-15"` |
| `on_premises_sync_enabled` | boolean | True if synced from on-prem AD (~75%) | `True` |
| `on_premises_sam_account_name` | string (nullable) | sAMAccountName from AD sync; empty for cloud-only | `"anakamura"` |
| `assigned_licenses` | string (JSON array) | Microsoft license SKUs | `["ENTERPRISEPACK"]` |
| `mfa_registered` | boolean | MFA registration status | `True` |
| `tenant_id` | string (UUID) | Azure tenant ID | `"a1b2c3d4-e5f6-7890-abcd-ef1234567890"` |

#### `aws_identities.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `arn` | string | Full IAM ARN: `arn:aws:iam::ACCOUNT:user/username` | `"arn:aws:iam::123456789012:user/a.nakamura"` |
| `username` | string | IAM username — format intentionally varies (dots, hyphens, initials) creating resolver challenge | `"a.nakamura"` |
| `user_id` | string | AWS-generated unique ID (`AIDA…` prefix) | `"AIDAXXXXXXXXXXXXXXXXX"` |
| `account_id` | string | 12-digit AWS account ID | `"123456789012"` |
| `path` | string | IAM path for organisational grouping | `"/finance/"` |
| `email_tag` | string (nullable) | Email stored as IAM tag — absent for ~30% of accounts (resolver challenge) | `"alice.nakamura@corp.nexusai.com"` |
| `created_date` | date | IAM user creation date | `"2022-03-15"` |
| `password_last_used` | datetime (nullable) | Last console sign-in | `"2026-06-19 08:45:00"` |
| `access_key_last_used` | datetime (nullable) | Last programmatic API call | `"2026-06-20 02:14:00"` |
| `account_type` | string | `human` / `service` / `machine` | `"human"` |
| `has_console_access` | boolean | Has AWS Management Console password | `True` |
| `has_programmatic_access` | boolean | Has active access keys | `False` |
| `tags` | string (JSON object) | Resource tags including Department and Email | `{"Department":"Finance","Email":"alice.nakamura@corp.nexusai.com"}` |

#### `okta_identities.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `okta_id` | string | Okta system user ID (`00u…` prefix) | `"00uabcde12345fghij"` |
| `login` | string | Email-based login — highest-fidelity correlation field across platforms | `"alice.nakamura@corp.nexusai.com"` |
| `email` | string | Email address (same as login for most users) | `"alice.nakamura@corp.nexusai.com"` |
| `first_name` | string | First name | `"Alice"` |
| `last_name` | string | Last name | `"Nakamura"` |
| `display_name` | string | Full display name | `"Alice Nakamura"` |
| `department` | string | Department | `"Finance"` |
| `title` | string | Job title | `"Financial Analyst"` |
| `status` | string | `ACTIVE` / `INACTIVE` / `DEPROVISIONED` / `SUSPENDED` | `"ACTIVE"` |
| `activated` | datetime | Date/time account was activated | `"2022-03-16 09:00:00"` |
| `last_login` | datetime (nullable) | Last successful authentication | `"2026-06-19 08:45:00"` |
| `last_updated` | datetime | Last profile update | `"2026-05-10 11:22:00"` |
| `mfa_enrolled` | boolean | MFA factor enrolled | `True` |
| `external_id` | string (nullable) | AD objectGUID stored as Okta external_id for linked accounts | `"a3f2c1d4-8b0e-4f9a-b3c2-d1e5f7a09b2c"` |
| `user_type` | string | `regular` / `service` | `"regular"` |

#### `salesforce_identities.csv`

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `sf_user_id` | string | Salesforce 18-char User ID (`005…` prefix) | `"005XXXXXXXXXXXXXXXX"` |
| `username` | string | SF username using `@nexusai.salesforce.com` domain — **different domain from corp email** (resolver challenge) | `"alice.nakamura@nexusai.salesforce.com"` |
| `email` | string | Corporate email stored on the SF User record (reliable correlation field) | `"alice.nakamura@corp.nexusai.com"` |
| `first_name` | string | First name | `"Alice"` |
| `last_name` | string | Last name | `"Nakamura"` |
| `alias` | string | Short alias (max 8 chars) | `"anakamur"` |
| `profile_name` | string | Salesforce profile name | `"Standard User"` |
| `department` | string | Department | `"Finance"` |
| `title` | string | Job title | `"Financial Analyst"` |
| `is_active` | boolean | Account active status | `True` |
| `created_date` | date | Account creation date | `"2022-03-15"` |
| `last_login_date` | datetime (nullable) | Last login | `"2026-06-19 08:45:00"` |
| `federation_id` | string (nullable) | SAML federation identifier — matches corporate email for SSO | `"alice.nakamura@corp.nexusai.com"` |
| `user_role` | string (nullable) | Salesforce role hierarchy entry | `"Finance"` |
| `org_id` | string | Salesforce organisation ID | `"00D000000000001EAA"` |

---

### Supplementary reference files (Phase 2 additions — consumed by GraphBuilder in Phase 4)

#### `group_definitions.csv`

Defines the complete group catalog and parent-child nesting hierarchy.
GraphBuilder uses this to create `NESTED_IN` edges in the identity graph.

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `group_id` | string (`GRP-{UUID}`) | Unique group identifier | `"GRP-d6f5a4b3-1e2f-4a8d-c5e4-f3a2b1c0d9e8"` |
| `group_name` | string | Human-readable group name | `"AD-Finance-Analysts"` |
| `platform` | string | Platform this group belongs to | `"AD"` |
| `parent_group_id` | string (nullable) | FK → `group_id` of the parent group; empty for root groups | `"GRP-a1b2c3d4-..."` |
| `parent_group_name` | string (nullable) | Human-readable parent name; empty for root groups | `"AD-Finance"` |
| `nesting_depth` | integer | 0 = root group, 1 = one level nested, 2 = two levels nested | `1` |
| `is_privileged` | boolean | True if membership in this group confers privileged/admin rights | `False` |

#### `role_definitions.csv`

Defines the complete role catalog with permission scopes and resource grants.
GraphBuilder uses this to create `GRANTS_ACCESS` edges from roles to resources.

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `role_id` | string (`ROLE-{UUID}`) | Unique role identifier | `"ROLE-f8b7c6d5-3a4b-4c0f-e7a6-b5c4d3e2f1a0"` |
| `role_name` | string | Human-readable role name | `"AWS-AdministratorAccess"` |
| `platform` | string | Platform this role is defined on | `"AWS"` |
| `permission_scope` | string | Scope of permissions: `global`, `user_mgmt`, `read-only`, `read`, `standard`, `finance`, `iam`, `power`, `marketing`, `contracts`, `org_mgmt`, `schema`. Note: `read` and `read-only` are both valid and both map to privilege level `READ`; `read-only` is the preferred form but `read` appears for AD-Standard-User. | `"global"` |
| `is_privileged` | boolean | True if this role grants admin/elevated access | `True` |
| `resource_ids` | string (JSON array) | List of `resource_id` values (FK → `resource_catalog.resource_id`) this role grants access to | `["RES-...", "RES-..."]` |
| `resource_names` | string (JSON array) | Human-readable resource names corresponding to `resource_ids` | `["prod-s3-finance", "aws-api-finance"]` |

#### `resource_catalog.csv`

Master registry of all resources across all platforms.
Referenced by `resource_access_logs.resource_id` and `effective_privileges.resource_id`.

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `resource_id` | string (`RES-{UUID}`) | Canonical resource identifier — primary key | `"RES-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"` |
| `resource_name` | string | Human-readable resource name | `"prod-s3-finance"` |
| `resource_type` | string | `DATABASE` / `S3_BUCKET` / `API` / `REPOSITORY` / `APPLICATION` / `SECRET` / `COMPUTE` | `"S3_BUCKET"` |
| `resource_criticality` | string | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` | `"CRITICAL"` |
| `platform` | string | Platform hosting this resource | `"AWS"` |

#### `ground_truth_labels.csv` ⚠️ EVALUATION ONLY

**MUST NOT be read by any analytics pipeline module (Phases 3–9).**
Used exclusively in Phase 10 for precision/recall evaluation of the ML anomaly detectors.

| Column | Data Type | Description | Example Value |
|---|---|---|---|
| `identity_id` | string | Canonical person identifier (email address used as stable key pre-resolution) | `"alice.nakamura@corp.nexusai.com"` |
| `ground_truth_anomaly_type` | string | `ORPHANED_ACCOUNT` / `OVERPRIVILEGED` / `PRIVILEGE_ESCALATION` / `TOKEN_ABUSE` / `DORMANT_ADMIN` / `LEGITIMATE_EXCEPTION` / `NORMAL` | `"DORMANT_ADMIN"` |
| `ground_truth_is_anomalous` | boolean | `True` for all true-positive anomaly types; `False` for `LEGITIMATE_EXCEPTION` and `NORMAL` | `True` |
| `anomaly_subtype` | string | Finer-grained subtype used for evaluation slicing (e.g. `"active_on_cloud_after_offboard"`) | `"privileged_no_login_90d"` |
| `injection_details` | string (JSON object) | Free-form JSON describing exactly what was modified in the data for this identity | `{}` |
