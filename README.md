# Identity Nexus AI

**AI-Powered Cross-Platform Identity Threat Detection & Privileged Access Intelligence**

Identity Nexus AI is an end-to-end security operations platform that ingests synthetic enterprise identity data from five platforms (Active Directory, Azure AD, AWS IAM, Okta, Salesforce), resolves cross-platform identities into canonical profiles, and detects threats using a **hybrid detection engine** that combines an unsupervised ML ensemble (Isolation Forest + Local Outlier Factor + MLP Autoencoder) with deterministic IAM domain rules — then surfaces results through an interactive Streamlit SOC dashboard with attack-path blast-radius simulation, compliance mapping, and AI-generated incident narratives.

---

## Problem Statement

Modern enterprises manage identities across 5–10 disconnected platforms, making it nearly impossible to see:
- Who has elevated privileges they have never used
- Which offboarded employees still have active access
- What resources an attacker could reach if one account were compromised
- Which compliance controls are being violated right now

Traditional SIEM solutions generate hundreds of raw alerts per day with no de-duplication or prioritisation. Security teams spend more time triaging noise than investigating real threats. Identity Nexus AI solves this by resolving all platform identities into canonical profiles, scoring them with a multi-factor risk model, clustering alerts into typed incidents (62 from 157 raw anomalies — a **60.5% alert reduction**), and simulating attacker blast radius with before/after remediation comparison.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DATA LAYER                               │
│  DataSimulator → generated_data/ (6 raw CSVs, 5 platforms)      │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   GRAPH & RESOLUTION LAYER                      │
│  IdentityResolver → unified_identities.csv (453 canonical IDs)  │
│  GraphBuilder     → identity_graph.gpickle (544 nodes/2900 edges)│
│  EffPrivEngine    → effective_privileges.csv (3,332 rows)        │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ANALYTICS LAYER                            │
│  FeatureEngineering  → feature_matrix.csv (453 × 13 features)   │
│                                                                 │
│  AnomalyDetection [HYBRID ENGINE]                               │
│  ├─ ML Ensemble: IsolationForest(w=0.50) + LOF(w=0.20)         │
│  │              + MLP Autoencoder(w=0.30)                       │
│  │  → flags OVERPRIVILEGED, PRIVILEGE_ESCALATION, DORMANT_ADMIN │
│  └─ IAM Domain Rules (deterministic — NOT probabilistic)        │
│     · ORPHANED_ACCOUNT  (access_revocation_failure + gap score) │
│     · TOKEN_ABUSE       (risk_event_ratio > 0.45)               │
│  → anomaly_scores.csv (157 flagged, detection_method per row)   │
│                                                                 │
│  RiskScoringEngine    → risk_scores.csv (0–100, 4 tiers)        │
│  IncidentClustering   → incidents.csv (62 incidents)            │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    INTELLIGENCE LAYER                           │
│  AttackPathSimulator  → attack_paths.csv + attack_paths_detail  │
│                         (BFS blast-radius, current + post-remed)│
│  RemediationEngine    → remediation_actions.csv (453 actions)   │
│  ComplianceMapper     → compliance_mappings.csv (3,474 rows)    │
│  LLMNarrativeGenerator → narratives.json + enriched incidents   │
│                          (Claude API or template fallback)      │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   PRESENTATION LAYER                            │
│  Streamlit Dashboard (src/app.py) — 8 sidebar-navigated pages   │
│  · Executive Overview    · Identity Explorer   · Risk Register  │
│  · Incident Explorer     · Identity Graph      · Attack Path Sim│
│  · Compliance Dashboard  · AI Narratives                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Features

### Hybrid Detection Engine (critical distinction)

The detection engine operates in two clearly separated layers. This distinction is preserved end-to-end through all outputs, dashboard badges, and LLM narratives:

| Layer | Method | Anomaly Types | Dashboard Badge |
|-------|--------|---------------|----------------|
| ML Ensemble | IsolationForest + LOF + MLP Autoencoder | OVERPRIVILEGED, PRIVILEGE_ESCALATION, DORMANT_ADMIN, BEHAVIORAL_OUTLIER | 🤖 Blue "ML Ensemble" |
| IAM Domain Rules | Deterministic thresholds (NOT probabilistic) | ORPHANED_ACCOUNT, TOKEN_ABUSE | ⚙ Amber "Rule-based" |

Rule-based detections are **never** labelled "AI detected" or "ML detected" anywhere in the UI, narratives, or reports. The `detection_method` column flows from `anomaly_scores.csv` through every downstream file to enforce this.

### Cross-Platform Identity Resolution
Resolves 1,377 platform accounts (AD, AzureAD, AWS, Okta, Salesforce) into **453 canonical identities** using deterministic email-normalisation deduplication, preserving multi-platform context for risk scoring.

### Blast Radius Attack Path Simulation
For all 20 CRITICAL/HIGH identities: BFS graph traversal enumerates every reachable resource, scored by criticality weight. Side-by-side before/after graphs show exactly what each remediation recommendation buys.

- Average blast radius (current state): **66.9%** of total weighted resources reachable
- Average blast radius reduction post-remediation: **54.4%**
- Maximum single-identity reduction: **79.0%**

### Alert Reduction via Incident Clustering
DBSCAN + KMeans consolidation reduces 157 raw anomaly flags into **62 typed incidents** — a **60.5% noise reduction** before any alert reaches an analyst.

### Compliance Mapping
3,474 audit rows automatically mapped to NIST CSF, CIS Controls, ISO 27001, SOC 2, MITRE ATT&CK, GDPR, and SOX per incident and remediation action.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Data generation | Python 3.13, Faker 40.x |
| Identity resolution | pandas 3.x, rapidfuzz 3.x (fuzzy dedup) |
| Graph construction | NetworkX 3.6 (MultiDiGraph) |
| ML anomaly detection | scikit-learn 1.9 (IsolationForest, LOF, MLPRegressor) |
| Risk scoring / clustering | scikit-learn (DBSCAN, KMeans), pandas |
| LLM narratives | Anthropic Claude (`claude-sonnet-4-6`) — optional |
| Dashboard | Streamlit 1.58, Plotly 6.8 |
| Attack path graphs | NetworkX hierarchical layout + Plotly Scatter traces |

---

## How to Run

### 1. Setup

```bash
# Python 3.10+ required (tested on 3.13)
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

For LLM-generated narratives (optional):
```bash
pip install anthropic
export ANTHROPIC_API_KEY="sk-ant-..."   # Windows: $env:ANTHROPIC_API_KEY = "..."
```

### 2. Run the Pipeline

```bash
# Full pipeline (skips LLM — no API key needed):
python src/main.py --skip-llm

# Full pipeline with LLM narratives (requires ANTHROPIC_API_KEY + anthropic package):
python src/main.py

# Evaluate detection performance against ground-truth labels:
python src/main.py --skip-llm --validate

# Regenerate synthetic data (DESTRUCTIVE — overwrites all generated_data/):
python src/main.py --regenerate-data --skip-llm
```

Pipeline completes in **~5–7 seconds** on a modern laptop (skip-llm mode).

### 3. Launch the Dashboard

```bash
streamlit run src/app.py
# Opens at http://localhost:8501
```

All data is pre-computed — no pipeline re-run on page load. The dashboard reads exclusively from `generated_data/`.

---

## Current Performance Metrics

*Live numbers from the most recent pipeline run and `--validate` evaluation against 398 matched ground-truth labels:*

### Detection Performance

| Metric | Value | Phase 1 Target | Status |
|--------|-------|----------------|--------|
| Precision | **88.4%** | ≥ 75% | ✅ Met |
| Recall (hybrid system) | **82.7%** | ≥ 70% | ✅ Met |
| F1-score | **85.4%** | — | — |

**Per-category recall breakdown:**

| Anomaly Type | Detection Method | Detected | Total | Recall |
|---|---|---|---|---|
| ORPHANED_ACCOUNT | Rule-based (deterministic) | 48 | 48 | **100%** |
| TOKEN_ABUSE | Rule-based (deterministic) | 16 | 16 | **100%** |
| DORMANT_ADMIN | ML Ensemble | 28 | 28 | **100%** |
| OVERPRIVILEGED | ML Ensemble | 23 | 40 | **57.5%** |
| PRIVILEGE_ESCALATION | ML Ensemble | 14 | 24 | **58.3%** |

### Pipeline Output Metrics

| Metric | Value |
|--------|-------|
| Canonical identities processed | 453 (from 1,377 platform accounts) |
| Anomalies flagged | 157 / 453 (34.7%) |
| Incidents after clustering | 62 |
| Alert reduction | **60.5%** |
| CRITICAL risk identities | 6 |
| HIGH risk identities | 14 |
| Attack paths simulated | 20 |
| Avg blast radius (current) | 66.9% |
| Avg blast radius reduction | **54.4%** |
| Remediation actions generated | 453 |
| Compliance audit rows | 3,474 |
| Pipeline runtime (skip-llm) | ~5.4 s |

---

## Known Limitations

### 1. Partial ML Recall on OVERPRIVILEGED / PRIVILEGE_ESCALATION
The ML ensemble achieves only **57.5% recall on OVERPRIVILEGED** and **58.3% on PRIVILEGE_ESCALATION**. These are genuine shortfalls, not reporting artefacts.

**Root cause**: Both categories are detected solely by the unsupervised ML layer (no deterministic rule covers them). The injection logic creates subtle privilege anomalies that blend with legitimately privileged users — particularly in departments with large ADMIN role counts, making the Z-score signal noisy. The ensemble contamination parameter (0.25) was tuned to avoid excessive false positives, which unavoidably depresses recall for the subtler ML-detected categories.

**Path to improvement**: A labelled training set would allow supervised fine-tuning. Raising the contamination rate improves recall but inflates false positives. In production, peer-group cohort baselines per job-title would sharpen the Z-score signal.

### 2. Two Unresolved Ground-Truth Identities
The ground-truth file contains 400 labelled identities; `--validate` matches only 398. The 2-identity gap is a canonicalization edge case where the resolution step assigned canonical_ids that do not surface in anomaly scores output. This does not affect the main pipeline (all 453 canonical identities flow through correctly) and is confined to the `--validate` evaluation path.

### 3. Synthetic Data Only
All data is Faker-generated with controlled injection. Real enterprise data would contain more noise, partial observability, and legitimately complex privilege chains that may reduce ML recall further.

### 4. LLM Narratives Require API Key and Package
Without `ANTHROPIC_API_KEY` and the `anthropic` package installed, `LLMNarrativeGenerator` falls back to deterministic templates. All pipeline logic and the Streamlit dashboard function fully without it.

---

## Screenshots

*[Add screenshots before submission]*

Suggested captures:
1. **Executive Overview** — KPI row + risk tier donut + detection method breakdown
2. **Identity Explorer** — filtered table + expanded detail panel (risk gauge + evidence block)
3. **Attack Path Simulator** — side-by-side before/after graphs for a CRITICAL identity
4. **Incident Explorer** — incident cards showing ML Ensemble vs Rule-based badges side by side
5. **Compliance Dashboard** — framework coverage pie + top violated NIST controls bar chart

---

## Project Structure

```
IdentityNexusAI/
├── src/
│   ├── main.py                        # Pipeline orchestrator (Phase 7)
│   ├── app.py                         # Streamlit dashboard (Phase 8)
│   ├── data_simulator.py              # Synthetic data generation
│   ├── identity_resolver.py           # Cross-platform identity resolution
│   ├── graph_builder.py               # NetworkX identity graph
│   ├── effective_privilege_engine.py  # BFS privilege materialisation
│   ├── feature_engineering.py         # 13-feature ML input matrix
│   ├── anomaly_detection.py           # Hybrid ML + rule-based detection
│   ├── risk_scoring.py                # 4-component 0–100 risk score
│   ├── incident_clustering.py         # DBSCAN + KMeans alert grouping
│   ├── attack_path_simulator.py       # Blast radius BFS simulation
│   ├── remediation_engine.py          # Prioritised action generation
│   ├── compliance_mapper.py           # NIST/CIS/ISO/SOC2/MITRE mapping
│   └── llm_narrative_generator.py     # Claude API + template fallback
├── generated_data/                    # All pipeline outputs (single source of truth)
├── models/                            # Persisted sklearn model artefacts (.pkl)
├── reports/                           # Pipeline summary, evaluation, sample reports
├── architecture.md                    # Full system design specification
├── data_dictionary.md                 # Schema reference for all CSVs
├── deployment_guide.md                # Setup and troubleshooting guide
└── requirements.txt                   # Python dependencies with version pins
```
