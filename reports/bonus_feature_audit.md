# Identity Nexus AI — Bonus Feature Audit
**Audit Date:** 2026-06-21
**Auditor note:** All findings are based on reading the live source files and generated data
directly — not documentation claims. Every evidence citation is a specific file + function
or a real data sample you can verify with `python -c "..."`.

---

## Summary Table

| # | Feature | Level | Max Pts | **Status** | Defensible Points |
|---|---------|-------|---------|------------|-------------------|
| 1 | Real-time alert dashboard | L1 | 5 | PARTIAL | **3** |
| 2 | Privilege graph visualization | L1 | 5 | **FULLY** | **5** |
| 3 | Automated remediation playbook | L1 | 5 | PARTIAL | **3** |
| 4 | Multi-system correlation | L1 | 5 | PARTIAL | **3** |
| 5 | Behavioral clustering | L2 | 10 | PARTIAL | **6** |
| 6 | Breach impact simulation | L2 | 10 | **FULLY** | **10** |
| 7 | False positive feedback loop | L2 | 10 | **NOT IMPL** | **0** |
| 8 | Real Okta/Azure AD API integration | L2 | 10 | **NOT IMPL** | **0** |
| 9 | Organizational anomaly detection | L3 | 15 | PARTIAL | **5** |
| 10 | Separation of duties violations | L3 | 15 | **LABEL ONLY** | **2** |
| 11 | Compliance gap analysis | L3 | 15 | PARTIAL | **7** |
| 12 | DLP integration | L3 | 15 | **NOT IMPL** | **0** |
| | | | **115 total** | | **44 defensible** |

---

## Detailed Findings

---

### 1. Real-time Alert Dashboard
**Level 1 — 5 pts | STATUS: PARTIAL | Defensible: 3 pts**

**What is honest:** `src/app.py` is a genuine, running Streamlit web application (HTTP 200 confirmed). It has 8 sidebar-navigated pages with interactive Plotly charts (zoom, pan, hover), a selectable data table with `on_select="rerun"` for row-level detail, and a glassmorphism dark theme. It is not a static image or a PDF.

**What is not honest:** The word "real-time" implies auto-refresh. There is no auto-refresh of any kind in the code. Grep for `st.rerun`, `@st.fragment`, `experimental_rerun`, `time.sleep`, polling loops, WebSocket subscriptions — all return nothing related to periodic refresh. The only `on_select="rerun"` (line 754) is a row-selection event triggered by the user clicking a table row, not a timed update.

The README itself admits: *"All data is pre-computed — no pipeline re-run on page load. The dashboard reads exclusively from `generated_data/`."*

Data is current as of the last manual `python src/main.py` run. If a new anomaly appeared in a live system, the dashboard would not show it until the pipeline is manually re-run and the page is manually refreshed.

**Evidence:** `src/app.py:64` (`set_page_config` — no `auto_refresh` param); README line 162. No `@st.fragment` or timer anywhere in the 1,540-line file.

**Claim as:** "Interactive SOC dashboard" — yes. "Real-time" — no. Say "near-real-time" only if you can demonstrate the pipeline being re-run on a schedule (e.g., a cron job or a background thread) — which does not exist in the current codebase.

**Gap-to-close:** 2–3 hours. Add `@st.fragment(run_every=60)` wrapper around the KPI card block, or a `streamlit_autorefresh` component. Requires pipeline to also run in a background thread or as a scheduled job, otherwise auto-refresh just re-reads the same static CSVs.

---

### 2. Privilege Graph Visualization (NetworkX → interactive)
**Level 1 — 5 pts | STATUS: FULLY IMPLEMENTED | Defensible: 5 pts**

**What is honest:** `page_identity_graph()` (`src/app.py:1077`) renders a real, interactive Plotly graph of the identity's access subgraph from live data. The graph comes from `attack_paths_detail.json` — which was itself produced by BFS traversal of the NetworkX MultiDiGraph in `attack_path_simulator.py`. The JSON contains typed nodes (Identity, Role, Group, Resource) with attributes and directed edges with `edge_type` labels.

`build_attack_graph()` (`src/app.py:438`) takes `all_nodes` and `all_edges`, computes a hierarchical layout by node type (Identity at top, Role in middle, Resource at bottom), and renders Plotly `go.Scatter` traces with hover text, color-coded by node type, with colored edge lines. The user selects from a dropdown of 20 CRITICAL/HIGH identities.

**Evidence:** `src/app.py:443–527` (build_attack_graph), `src/app.py:1085–1128` (page_identity_graph). Attack path simulator (`src/attack_path_simulator.py:175–241`) is genuine BFS on NetworkX MultiDiGraph loaded from `models/identity_graph.gpickle`.

**Defensible claim:** "Interactive privilege-path graph built from NetworkX identity graph via BFS, rendered as interactive Plotly network for each CRITICAL/HIGH identity."

**Caveat for judges:** The dashboard does not render the full 544-node graph interactively — only the per-identity access subgraph (typically 5–30 nodes). The full NetworkX graph lives server-side in the pickle; what the dashboard shows is the pre-serialized traversal output. This is the right architecture, but mention it if asked.

---

### 3. Automated Remediation Playbook (step-by-step fix)
**Level 1 — 5 pts | STATUS: PARTIAL | Defensible: 3 pts**

**What is honest:** `remediation_actions.csv` has a real, algorithmic recommendation per identity: action type (REVOKE_ROLE, ENFORCE_MFA, DISABLE_ACCOUNT, REQUIRE_RECERTIFICATION), a specific target role identified by weighted blast-radius impact (`remediation_scenario` from attack_path_simulator.py names the exact role and platform), a quantified `estimated_risk_reduction` (%), `blast_radius_reduction` (%), priority tier (P1 urgent → P4 low), `estimated_effort`, `requires_approval`, and a list of `compliance_frameworks` the action satisfies.

**What is not honest:** "Playbook" implies a numbered, multi-step runbook. There are none. The `recommended_action` column is a single enum value (`REVOKE_ROLE`). The `justification` column is 1–2 sentences of free text. There is no "Step 1: Raise a ticket in ServiceNow. Step 2: Remove role X in AWS IAM console. Step 3: Confirm revocation via compliance scan." The system correctly identifies WHAT to do and WHY, but not HOW (no procedural steps).

**Evidence:** `generated_data/remediation_actions.csv` — columns: `action_type`, `recommended_action`, `justification`, `priority`, `action_priority`, `estimated_risk_reduction`, `blast_radius_reduction`, `compliance_frameworks`, `status`. No `steps`, `procedure`, `instructions`, or `playbook` column exists.

**Claim as:** "Prioritised, impact-quantified remediation recommendations with compliance mapping" — fully defensible. "Step-by-step playbook" — not defensible.

**Gap-to-close:** 4–6 hours. Add a `playbook_steps` JSON column to `remediation_engine.py` with a templated multi-step procedure per action type (e.g., `REVOKE_ROLE` → 5 steps: identify role, raise ticket, remove assignment, verify in effective_privileges, confirm scan).

---

### 4. Multi-System Correlation (link related risks across systems)
**Level 1 — 5 pts | STATUS: PARTIAL | Defensible: 3 pts**

**What is honest:** Incident clusters genuinely span multiple platforms. Real examples from `incidents.csv`:
- ORPHANED_ACCOUNT cluster: 31 members, platforms `['Okta', 'Salesforce']`
- DORMANT_ADMIN cluster: 12 members, platforms `['Okta', 'AzureAD', 'Salesforce']`
- PRIVILEGE_ABUSE cluster: 11 members, platforms `['Okta', 'AWS', 'Salesforce']`

The `related_canonical_ids` field in each cluster incident links multiple canonical identities affected by the same incident pattern.

The feature matrix itself is inherently cross-platform: `platform_count`, `cross_platform_exposure`, `privilege_count`, `admin_role_count` all aggregate signals from all of an identity's accounts across AD, AzureAD, AWS, Okta, Salesforce. A single canonical identity's feature vector represents their combined exposure across platforms.

**What is not honest:** The clustering groups different identities by behavioral similarity — it is NOT designed to detect that the SAME identity is showing anomalous signals independently on Platform A AND Platform B. That would require platform-stratified anomaly scoring (e.g., flag when an identity's AWS score AND their Okta score are both elevated). The current system collapses all platform data into a single canonical feature vector before any anomaly detection happens. Cross-platform grouping in clusters is emergent from feature aggregation, not from correlating per-platform signals.

**Evidence:** `incident_clustering.py:209–240` (DBSCAN on 13-feature vectors), `feature_engineering.py:278–317` (multi-platform features aggregated per canonical identity).

**Claim as:** "Cross-platform identity risk correlation via unified feature vectors and behavioral incident clustering across 5 platforms" — defensible. "Real-time per-platform signal correlation" — not defensible.

**Gap-to-close:** 8–12 hours. Per-platform anomaly subscoring (run IF separately on per-platform feature subsets), then correlate when the same identity exceeds threshold on 2+ platforms. Requires restructuring feature_engineering.py to output platform-stratified rows.

---

### 5. Behavioral Clustering (group similar risky patterns)
**Level 2 — 10 pts | STATUS: PARTIAL | Defensible: 6 pts**

**What is honest:** `incident_clustering.py` runs real DBSCAN (eps=1.5, min_samples=2) on a 13-dimensional feature space that genuinely contains behavioral features: `login_frequency`, `dormant_days`, `privilege_velocity`, `risk_event_ratio`, `offboarding_gap_score`. Two identities end up in the same cluster if their full feature vectors are close in Euclidean space after StandardScaler normalization.

Cluster assignment is NOT arbitrary — the `_classify_incident_type()` function uses the cluster centroid's raw feature values against documented thresholds to assign a label. A DORMANT_ADMIN cluster genuinely has high `dormant_days` and `admin_role_count` as its defining features (confirmed by `contributing_features` column in incidents.csv).

DBSCAN was chosen specifically because it discovers cluster count from the data without prespecifying k, and it handles noise points (each singleton gets its own incident with its own feature-based type assignment).

**What is partially misleading:**

1. **BEHAVIORAL_OUTLIER is a catch-all, not a behavioral subtype.** `_classify_incident_type()` returns `"BEHAVIORAL_OUTLIER"` as its last `return` statement — the default when no other feature threshold is met. This is honest labeling (renamed from the original `GEO_ANOMALY` which falsely implied geographic detection), but it means 12 of 62 incidents (19.4%) don't have a specific behavioral pattern identified.

2. **Behavioral features are a minority of the 13.** The clustering uses a mix of behavioral (5 features) and structural/privilege features (8 features). The DBSCAN distance is dominated by whichever features have the most variance. Calling this "behavioral clustering" is partially accurate but overclaims the behavioral specificity.

**Evidence:** `incident_clustering.py:441–479` (`_classify_incident_type`), `incident_clustering.py:237–239` (DBSCAN call), `feature_engineering.py:107–122` (FEATURE_COLS list).

**Defensible claim:** "DBSCAN clustering on behavioral and privilege feature vectors, producing typed incident classes." The catch-all bucket is now labeled `BEHAVIORAL_OUTLIER` — honest about what it is.

**Gap closed:** Renamed from `GEO_ANOMALY` → `BEHAVIORAL_OUTLIER` in `incident_clustering.py`, `compliance_mapper.py`, all reports, and regenerated `incidents.csv`.

---

### 6. Breach Impact Simulation
**Level 2 — 10 pts | STATUS: FULLY IMPLEMENTED | Defensible: 10 pts**

This is the best-implemented feature in the project. It is genuinely real.

`attack_path_simulator.py` performs:
1. **BFS traversal** from the identity node through `MEMBER_OF → NESTED_IN → HAS_ROLE → GRANTS_ACCESS → FEDERATES_TO` edges on the live NetworkX MultiDiGraph loaded from `models/identity_graph.gpickle` (`bfs_blast_radius()`, lines 175–241). Cycle safety enforced via `visited` set.
2. **Weighted Blast Radius Score** (BRS): `sum(criticality_weight(r) for r in reachable) / max_possible × 100`, where max_possible = 91 (11 CRITICAL×4 + 11 HIGH×3 + 5 MEDIUM×2 + 4 LOW×1) — formula is exact, not estimated (`compute_brs()`, lines 244–258).
3. **Targeted remediation** via `choose_remediation()`: identifies the specific HAS_ROLE edge whose target role has the highest `_role_weighted_reach()` (sum of criticality weights of resources reachable via GRANTS_ACCESS). Removes that single edge from a deep copy of the graph (original is never mutated — assertion guard at line 727).
4. **Post-remediation BFS** re-runs on the modified graph copy, producing an exact post-remediation BRS (not an estimate).
5. **Graph mutation guard** (`assert self._G.number_of_edges() == self._original_edge_count`) fires after every simulation to confirm the original graph was not mutated.

The dashboard (`page_attack_path_simulator()`) renders genuine before/after Plotly graphs with removed nodes greyed out.

**Evidence:** `src/attack_path_simulator.py:175–258` (BFS + BRS), `:276–373` (remediation), `:726–731` (mutation guard). Sample from `attack_paths.csv`: canonical_id=ba2c98ce, current_blast_radius=84.62, remediated_blast_radius=35.16, reduction=58.43%, action=REVOKE_ROLE.

**Defensible claim:** Full marks. This is a genuine adversarial simulation on the live identity graph with verified mutation safety. You can walk through the BFS logic line-by-line if challenged.

---

### 7. False Positive Feedback Loop
**Level 2 — 10 pts | STATUS: NOT IMPLEMENTED | Defensible: 0 pts**

Confirmed absent. There is:
- No UI element in `app.py` for marking a finding as false positive (no thumbs-down, no dismiss button, no correction form).
- No feedback column in `incidents.csv`, `anomaly_scores.csv`, or `risk_scores.csv`.
- No code path that reads user corrections and adjusts model thresholds, contamination parameters, or rule weights.
- No persisted feedback store of any kind.

The `@st.cache_data` decorators load read-only data; there is no write path from the dashboard to any data file.

**Do not claim this feature.**

---

### 8. Integration with Real Okta/Azure AD APIs
**Level 2 — 10 pts | STATUS: NOT IMPLEMENTED | Defensible: 0 pts**

Confirmed absent. Grep across all `src/` files for `requests`, `httpx`, `azure.identity`, `msal`, `okta`, `boto3`, `msgraph`, `graph.microsoft` — all return no matches (other than string literals inside Faker-generated data field names and comments).

All identity data is generated by `src/data_simulator.py` using the Python `Faker` library. The five platforms (AD, AzureAD, AWS, Okta, Salesforce) are synthetic. No HTTP calls are made to external APIs anywhere in the pipeline.

**Do not claim this feature.** If asked, say: "The pipeline is architected to be connector-ready — each platform source is a distinct CSV that a real connector would populate. The current implementation uses high-fidelity synthetic data from Faker to demonstrate the full analytics pipeline without requiring live API credentials."

---

### 9. Organizational Anomaly Detection (dept-level baseline)
**Level 3 — 15 pts | STATUS: PARTIAL | Defensible: 5 pts**

**What is partially real:** `feature_engineering.py:_privilege_peer_deviation()` (lines 476–512) computes a genuine per-department z-score. It groups canonical identities by `department` from `unified_identities.csv`, computes mean and standard deviation of `privilege_count` per department, then produces a z-score for each identity relative to their own department's distribution. This is clipped to [0, 5] (one-sided — only flags over-provisioning relative to peers).

This feature (`privilege_peer_deviation`) feeds directly into the ML ensemble and is one of the 13 features DBSCAN clusters on. It is a real department-level computation with real departmental grouping.

**What is not implemented:** The anomaly detection models themselves are global — IsolationForest, LOF, and the MLP Autoencoder are each trained on all 453 identities as a single population. There is no per-department anomaly model, no per-department contamination threshold, and no per-department score normalization. The system does NOT ask "is this identity unusual for a Finance employee?" — it asks "is this identity unusual globally, using a feature that includes how unusual they are for their department."

The comment in `anomaly_detection.py` (lines 93, 107, 134) references `privilege_peer_deviation` but only as one of 13 features fed to the global models.

**Evidence:** `feature_engineering.py:476–512` (genuine dept z-score for ONE feature). `anomaly_detection.py` — zero references to `department`, `cohort`, or `groupby` by dept.

**Defensible claim:** "One behavioral feature (privilege_peer_deviation) computes per-department privilege baseline as a z-score. The ML ensemble uses this as one of 13 inputs." Do NOT claim full organizational anomaly detection.

**Gap-to-close:** 6–10 hours. Add department-level IsolationForest models (one per department with ≥ 10 members, fall back to global model for small departments). Requires wrapping the existing IF training loop with a `groupby("department")` step.

---

### 10. Separation of Duties Violations
**Level 3 — 15 pts | STATUS: LABEL ONLY | Defensible: 2 pts**

**The hard truth:** There is no SOD logic in this codebase. SOD detection requires a conflict matrix — a set of role pairs that are incompatible (e.g., "Accounts Payable Approver + Accounts Payable Preparer" or "AWS EC2 Admin + AWS Billing Admin"). No such matrix exists anywhere in the project.

`SOD_VIOLATION` is assigned by `_classify_incident_type()` in `incident_clustering.py` when a cluster centroid satisfies:
```python
if peer_dev > 2.0 and admin > ADMIN_HIGH_THRESHOLD:   # > 5 admin privileges
    return "SOD_VIOLATION"
if priv_count > PRIV_COUNT_HIGH_THRESHOLD and admin > ADMIN_HIGH_THRESHOLD:  # > 10 total, > 5 admin
    return "SOD_VIOLATION"
```

This detects **over-provisioning** (many admin privileges relative to peers), which is related to but definitionally distinct from SOD violations. An identity could have 20 admin roles that are all in the same domain with no conflicts, and still receive this label. Conversely, an identity with exactly 2 conflicting roles would receive no SOD flag if both `peer_dev ≤ 2.0` and `priv_count ≤ 10`.

The 2 defensible points: the feature is real (not just a hardcoded label), and over-provisioning is a prerequisite for many SOD violations, so the cluster does identify identities at elevated SOD risk. But it does not validate that conflicting roles are simultaneously held.

**Evidence:** `incident_clustering.py:466–472` (the full SOD detection logic — 2 lines). No conflict matrix in any file. `grep -rn "conflict.*role\|role.*conflict\|incompatible\|separation.*dut" src/` — returns only comments and the `compliance_mapper.py:183` NIST mapping entry.

**Do not claim:** "We detect specific SOD conflicts between incompatible roles." You will be asked which roles conflict and there is no answer.

**Claim as (2 pts worth):** "We flag identities with privilege accumulation patterns consistent with SOD risk — high admin concentration relative to department peers." Hedged, but defensible.

**Gap-to-close:** 6–8 hours. Define a conflict matrix (even a toy one: e.g., AWS AdministratorAccess + AWS ReadOnlyAccess constitutes a trivial example; better: define business-domain pairs). Extend `effective_privilege_engine.py` to check held role-pairs against the matrix and write a `sod_violations` column. Wire into `incident_clustering.py` as a priority-0 rule before the existing thresholds.

---

### 11. Compliance Gap Analysis (per user, per system)
**Level 3 — 15 pts | STATUS: PARTIAL | Defensible: 7 pts**

**What is real:** `compliance_mappings.csv` (3,474 rows) maps every incident and remediation action to specific compliance controls (NIST, CIS, ISO 27001, MITRE ATT&CK, GDPR, SOX). ALL 453 identities have compliance rows (verified: `df['canonical_id'].nunique() == 453`). The mapping covers 7 frameworks per identity. The dashboard Compliance page shows per-framework incident counts and which controls appear most frequently.

The compliance mapper runs for every identity through their remediation actions, so even LOW-risk identities with REQUIRE_RECERTIFICATION or ENFORCE_MFA actions get compliance rows.

**What is missing for a true gap analysis:** The current schema is a **violation and remediation catalog** — it says "this incident violated control X" and "this action satisfies control Y." It does NOT have:
- A baseline "which controls does this identity NEED to satisfy" (required control set per identity)
- A "currently satisfied" status field
- A binary "GAP = required but not satisfied" indicator

Columns: `mapping_id, source_type, source_id, canonical_id, incident_type, action_type, framework, control_id, tag, mapped_timestamp`. No `status`, `is_gap`, `coverage_status`, `is_met`, or similar column exists.

You cannot currently answer: "Identity X has controls A, B, C required by GDPR — they're meeting B and C but gap on A." You can only answer: "Identity X has an incident that maps to NIST-AC-6 and a remediation that would satisfy NIST-AC-6(1)."

**Evidence:** Python sample showing 3-row compliance_mappings head — all columns confirmed above. `df['status']` → column does not exist.

**Claim as:** "Per-identity, per-framework compliance violation and remediation mapping across 7 frameworks (NIST, CIS, ISO 27001, SOC 2, MITRE ATT&CK, GDPR, SOX), covering all 453 identities." This is 7 pts worth — real, comprehensive, but missing the explicit gap/coverage structure.

**Gap-to-close:** 4–6 hours. Add a `required_controls` table (define which frameworks each identity type needs to satisfy), join against `compliance_mappings.csv` to produce a `control_status` column (VIOLATED / REMEDIATED / NOT_ASSESSED), and add a `is_gap` boolean. The hard part is defining the required baseline — without that, gap analysis is structurally impossible.

---

### 12. DLP Integration (prevent exfiltration based on detected risk)
**Level 3 — 15 pts | STATUS: NOT IMPLEMENTED | Defensible: 0 pts**

Confirmed absent. No DLP connector, no data classification, no file access monitoring, no exfiltration prevention hook anywhere in the codebase. `DATA_EXFIL` is an incident type label (3 incidents) assigned by `_classify_incident_type()` when `cross_platform_exposure > 3.5 AND privilege_velocity > 0.2` — a statistical proxy for exfiltration risk, not an actual DLP signal.

**Do not claim this feature.**

---

## Honest Talking Points for Judges

**What you can defend with full confidence:**
- Breach impact simulation (BFS, exact BRS, before/after graphs) — show the code
- Interactive privilege graph (Plotly, from real graph data) — demo it
- Hybrid detection engine (ML ensemble vs deterministic rules) — show the badge distinction

**What you can defend if you hedge correctly:**
- "Interactive SOC dashboard" (yes); "real-time" (no — static snapshot)
- "Cross-platform behavioral incident clustering" (yes); catch-all bucket is now `BEHAVIORAL_OUTLIER` — no false geographic implication
- "Impact-quantified remediation recommendations" (yes); "step-by-step playbook" (no)
- "SOD risk flagging based on privilege accumulation" (weak yes); "conflict-pair SOD detection" (no)
- "Compliance violation catalog per identity across 7 frameworks" (yes); "gap analysis with coverage baseline" (no)

**What to not mention unless directly asked:**
- False positive feedback loop — not implemented
- Real API integrations — not implemented; say "connector-ready architecture"
- DLP — not implemented
- Full organizational/dept anomaly detection — only `privilege_peer_deviation` feature is dept-scoped
