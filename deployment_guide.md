# Identity Nexus AI — Deployment Guide

## Prerequisites

| Requirement | Minimum | Tested On |
|-------------|---------|-----------|
| Python | 3.10 | 3.13.x |
| RAM | 2 GB | 8 GB |
| Disk (for generated data) | 100 MB | — |
| OS | Any (Windows/macOS/Linux) | Windows 11 |
| Network | None (offline capable) | — |

---

## 1. Local Setup from Scratch

### 1.1 Clone / download the project

```bash
# If using git:
git clone <repo-url> IdentityNexusAI
cd IdentityNexusAI

# Or unzip the submission archive and enter the directory.
```

### 1.2 Create and activate a virtual environment

```bash
# Create venv
python -m venv venv

# Activate — Linux/macOS:
source venv/bin/activate

# Activate — Windows PowerShell:
venv\Scripts\Activate.ps1

# Activate — Windows cmd:
venv\Scripts\activate.bat
```

### 1.3 Install dependencies

```bash
pip install -r requirements.txt
```

This installs: `faker`, `pandas`, `numpy`, `networkx`, `rapidfuzz`, `scikit-learn`, `streamlit`, `plotly`.

### 1.4 (Optional) Enable LLM narratives

LLM narrative generation requires the Anthropic API. Without it, the pipeline runs fully with deterministic template fallback.

```bash
pip install anthropic

# Linux / macOS:
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Windows PowerShell:
$env:ANTHROPIC_API_KEY = "sk-ant-api03-..."

# Windows cmd:
set ANTHROPIC_API_KEY=sk-ant-api03-...
```

**What happens without the key:** `LLMNarrativeGenerator` detects the missing key at runtime, logs a warning, and generates template-based narratives instead. The `narratives.json` file is still written and the Streamlit dashboard displays it normally. No error is raised and the pipeline exits with code 0.

---

## 2. Running the Pipeline

### 2.1 Standard run (recommended for demo)

```bash
python src/main.py --skip-llm
```

Runs all 11 pipeline steps in order (DataSimulator is skipped — uses existing `generated_data/`). Completes in ~5–7 seconds. Writes `reports/pipeline_run_summary.md`.

### 2.2 Full run with LLM narratives

```bash
python src/main.py
```

Same as above but calls the Anthropic Claude API for each CRITICAL/HIGH incident. Requires `ANTHROPIC_API_KEY` and the `anthropic` package. Adds ~30–60 seconds depending on API latency.

### 2.3 Regenerate synthetic data (DESTRUCTIVE)

```bash
python src/main.py --regenerate-data --skip-llm
```

**Warning:** this overwrites all files in `generated_data/` including `ground_truth_labels.csv`. Use only when you want a completely fresh dataset. The `--regenerate-data` flag is gated in `main.py` and skipped by default specifically to prevent accidental data loss.

### 2.4 Evaluate detection performance

```bash
python src/main.py --skip-llm --validate
```

After running the pipeline, reads `ground_truth_labels.csv` and prints precision/recall/F1 and per-category recall. This flag is the **only** code path that reads `ground_truth_labels.csv` — all other pipeline steps are completely blind to it.

### 2.5 Pipeline flags summary

| Flag | Effect |
|------|--------|
| *(no flags)* | Full pipeline with LLM narratives |
| `--skip-llm` | Skip LLMNarrativeGenerator; use template fallback |
| `--regenerate-data` | Run DataSimulator to create fresh synthetic data |
| `--validate` | Run precision/recall evaluation after anomaly detection |
| `--log-level DEBUG` | Verbose logging from all modules |

---

## 3. Launching the Dashboard

```bash
streamlit run src/app.py
```

Opens at `http://localhost:8501`. The dashboard reads exclusively from `generated_data/` — you must run the pipeline at least once before opening it.

### Port conflicts

If port 8501 is already in use:

```bash
streamlit run src/app.py --server.port 8502
```

Or kill the existing process:
```bash
# Windows PowerShell:
Get-Process -Name streamlit | Stop-Process -Force

# Linux/macOS:
pkill -f streamlit
```

---

## 4. Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `ANTHROPIC_API_KEY` | Optional | Enables live LLM narrative generation via Claude API. Without it, deterministic template fallback is used. |

No other environment variables are required. All file paths are resolved relative to the project root via `pathlib.Path(__file__).parent`.

---

## 5. Troubleshooting

### 5.1 "No module named X" on pipeline run

**Cause:** Virtual environment not activated, or `pip install -r requirements.txt` was not run.

**Fix:**
```bash
# Confirm you're in the venv:
which python    # Linux/macOS — should point to venv/bin/python
python -c "import streamlit; print(streamlit.__version__)"

# If not installed:
pip install -r requirements.txt
```

---

### 5.2 Missing or empty generated_data/ files

**Symptom:** Pipeline step exits with `[HALT] Output file missing or empty` error.

**Cause:** A prior step failed or `generated_data/` was manually cleaned.

**Fix:** Run the full pipeline from the beginning:
```bash
python src/main.py --skip-llm
```

If you deleted raw data files (unified_identities.csv, audit_events.csv, etc.), you must regenerate:
```bash
python src/main.py --regenerate-data --skip-llm
```

---

### 5.3 Streamlit port already in use / dashboard blank

**Symptom:** `OSError: [Errno 98] Address already in use` on port 8501, or the browser opens but shows a blank page.

**Fix (port conflict):**
```bash
streamlit run src/app.py --server.port 8502
```

**Fix (blank page / data not loaded):**
1. Ensure the pipeline has been run at least once: `python src/main.py --skip-llm`
2. Verify `generated_data/risk_scores.csv` exists and has 453 rows
3. Refresh the browser (Ctrl+Shift+R for a hard refresh)
4. Check the terminal running Streamlit for Python tracebacks

---

### 5.4 LLM narratives not appearing

**Symptom:** Narratives page shows "Narratives Not Available" or all narrative types show "TEMPLATE".

**Cause A:** `--skip-llm` was passed (expected behaviour — template fallback is intentional).
**Cause B:** `ANTHROPIC_API_KEY` is not set.
**Cause C:** `anthropic` package not installed.

**Fix:**
```bash
pip install anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
python src/main.py    # no --skip-llm flag
```

---

### 5.5 Slow or stale dashboard charts

**Symptom:** Dashboard shows old data after re-running the pipeline.

**Cause:** Streamlit's `@st.cache_data` caches data loads across page interactions. The cache is keyed to the function, not the file modification time.

**Fix:** Press **C** in the Streamlit browser to clear cache, or restart the Streamlit process.

---

## 6. File Manifest

```
generated_data/
  ad_identities.csv           # Raw AD accounts (pre-resolution)
  azuread_identities.csv      # Raw Azure AD accounts
  aws_identities.csv          # Raw AWS IAM accounts
  okta_identities.csv         # Raw Okta accounts
  salesforce_identities.csv   # Raw Salesforce accounts
  unified_identities.csv      # Resolved cross-platform identities (1,377 rows)
  group_mappings.csv          # Identity → Group memberships
  role_mappings.csv           # Identity → Role assignments
  audit_events.csv            # Behavioural audit log
  resource_access_logs.csv    # Resource access events
  offboarding_records.csv     # Employee departure records
  resource_catalog.csv        # 31 platform resources with criticality
  group_definitions.csv       # Group metadata
  role_definitions.csv        # Role metadata
  ground_truth_labels.csv     # [EVAL ONLY] True anomaly labels
  resolution_report.csv       # Identity resolution audit trail
  effective_privileges.csv    # Materialised privilege set (3,332 rows)
  feature_matrix.csv          # 453 × 13 ML feature matrix
  anomaly_scores.csv          # Per-identity anomaly scores + detection_method
  risk_scores.csv             # 0–100 risk scores + tier + evidence
  incidents.csv               # 62 typed, clustered incidents
  attack_paths.csv            # 20 identity-grain blast-radius simulations
  attack_paths_detail.json    # Full node/edge graph per identity (for dashboard)
  remediation_actions.csv     # 453 prioritised remediation actions
  compliance_mappings.csv     # 3,474 framework control mappings
  narratives.json             # LLM/template narratives for CRITICAL+HIGH identities

models/
  feature_scaler.pkl          # StandardScaler fitted on training feature matrix
  isolation_forest.pkl        # Fitted IsolationForest
  lof.pkl                     # Fitted LocalOutlierFactor
  mlp_autoencoder.pkl         # Fitted MLPRegressor (autoencoder surrogate)

reports/
  pipeline_run_summary.md     # Generated by main.py after each run
  evaluation_report.md        # Detection performance vs Phase 1 targets
  sample_risk_report.md       # Analyst-style report for one CRITICAL identity
  phase4_detection_report.md  # Phase 4 ML tuning notes
```
