"""
src/main.py
Identity Nexus AI — Phase 7: Full Pipeline Orchestrator

Entry point for the complete end-to-end pipeline. Calls each module in
strict dependency order, verifies outputs after every step, runs mandatory
consistency checks on completion, and writes a timestamped summary report.

Usage (default safe path — uses existing generated_data/, runs all steps
except --skip-llm to avoid API calls):

    python src/main.py --skip-llm

Flags:
    --regenerate-data   Run DataSimulator first, wiping and reseeding all
                        generated_data/ CSV files. DESTRUCTIVE — data is
                        regenerated from scratch. Omit for normal reruns.
    --skip-llm          Skip LLMNarrativeGenerator (no API calls, no cost).
                        Incidents and remediation actions retain template
                        narratives from any previous LLM run.
    --validate          After anomaly detection, run ground-truth precision/
                        recall evaluation (reads ground_truth_labels.csv).
                        This is the ONLY code path that touches that file.
    --log-level         DEBUG / INFO / WARNING / ERROR (default: INFO)

Output files (all in generated_data/ unless noted):
    unified_identities.csv  identity_graph.gpickle  effective_privileges.csv
    feature_matrix.csv      anomaly_scores.csv       risk_scores.csv
    incidents.csv           attack_paths.csv          remediation_actions.csv
    compliance_mappings.csv narratives.json
    reports/pipeline_run_summary.md   <- timestamped run record

The built-in consistency checks (section _run_consistency_checks) run
automatically after every full pipeline completion and will EXIT NON-ZERO
if the pipeline has produced internally inconsistent data.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

# ---------------------------------------------------------------------------
# Path setup — src/ directory must be on sys.path so sibling modules import
# ---------------------------------------------------------------------------

SRC_DIR = Path(__file__).parent
PROJECT_ROOT = SRC_DIR.parent
sys.path.insert(0, str(SRC_DIR))

DATA_DIR = PROJECT_ROOT / "generated_data"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Step timing helpers
# ---------------------------------------------------------------------------

_step_times: dict[str, float] = {}


def _run_step(name: str, fn: Any) -> Any:
    """
    Execute a pipeline step with timing and structured logging.
    On any exception, logs the error and exits with code 1 (never silently
    continues with potentially stale downstream data).
    """
    logger.info("")
    logger.info("=" * 62)
    logger.info("  [STEP] %s", name)
    logger.info("=" * 62)
    t0 = time.perf_counter()
    try:
        result = fn()
    except SystemExit:
        raise  # let explicit sys.exit() propagate
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        logger.error("STEP FAILED after %.1f s: %s", elapsed, name)
        logger.error("  Error: %s", exc, exc_info=True)
        logger.error(
            "  Pipeline halted. Fix the error above before rerunning. "
            "Downstream steps have NOT been executed."
        )
        sys.exit(1)
    elapsed = time.perf_counter() - t0
    _step_times[name] = elapsed
    logger.info("  [DONE] %s — %.1f s", name, elapsed)
    return result


# ---------------------------------------------------------------------------
# Output verification helpers
# ---------------------------------------------------------------------------


def _verify_csv(step_name: str, path: Path, min_rows: int = 1) -> None:
    """
    Assert that a CSV output from a pipeline step exists, is non-empty, and
    has at least min_rows data rows. Exits with code 1 on failure.
    """
    if not path.exists():
        logger.error(
            "OUTPUT MISSING after step '%s': %s\n"
            "  The step ran without error but did not produce its expected output. "
            "Check the step's save() method.",
            step_name, path,
        )
        sys.exit(1)
    if path.stat().st_size == 0:
        logger.error("EMPTY OUTPUT after step '%s': %s", step_name, path)
        sys.exit(1)
    try:
        # Read only the first (min_rows + 1) rows to keep verification fast
        sample = pd.read_csv(path, nrows=min_rows + 1)
    except Exception as exc:
        logger.error(
            "UNREADABLE OUTPUT after step '%s': %s\n  Error: %s",
            step_name, path, exc,
        )
        sys.exit(1)
    if len(sample) < min_rows:
        logger.error(
            "TOO FEW ROWS in %s after step '%s': expected >= %d, got %d",
            path.name, step_name, min_rows, len(sample),
        )
        sys.exit(1)


def _verify_binary(step_name: str, path: Path) -> None:
    """Assert that a binary/JSON output file exists and is non-empty."""
    if not path.exists() or path.stat().st_size == 0:
        logger.error(
            "OUTPUT MISSING or EMPTY after step '%s': %s", step_name, path
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Built-in consistency checks (run after full pipeline, always)
# ---------------------------------------------------------------------------


def _run_consistency_checks() -> None:
    """
    Cross-file consistency checks. These run automatically at the end of every
    full pipeline run. Exit code 1 if any check fails — a broken pipeline must
    never be reported as "successful".

    Checks:
      1. canonical_id set is identical across feature_matrix, anomaly_scores,
         risk_scores (all 453, same IDs)
      2. attack_paths.csv canonical_ids are a strict subset of CRITICAL+HIGH
         identities in risk_scores.csv
      3. remediation_actions.csv has exactly one row per canonical_id in
         risk_scores.csv (no duplicates, no gaps)
      4. effective_privileges.csv has zero orphan FKs against
         unified_identities.csv and resource_catalog.csv
    """
    logger.info("")
    logger.info("=" * 62)
    logger.info("  [CHECK] Running built-in consistency checks")
    logger.info("=" * 62)
    errors: list[str] = []

    # --- Load key files (minimal columns) ---
    fm_ids = set(
        pd.read_csv(DATA_DIR / "feature_matrix.csv", usecols=["canonical_id"])["canonical_id"]
    )
    as_ids = set(
        pd.read_csv(DATA_DIR / "anomaly_scores.csv", usecols=["canonical_id"])["canonical_id"]
    )
    rs = pd.read_csv(DATA_DIR / "risk_scores.csv", usecols=["canonical_id", "risk_tier"])
    rs_ids = set(rs["canonical_id"])

    # --- Check 1: canonical_id set alignment ---
    expected_count = 453  # known ground truth for this dataset
    for name, id_set in (
        ("feature_matrix.csv", fm_ids),
        ("anomaly_scores.csv", as_ids),
        ("risk_scores.csv", rs_ids),
    ):
        if len(id_set) != expected_count:
            errors.append(
                f"CHECK 1: {name} has {len(id_set)} canonical_ids, "
                f"expected {expected_count}"
            )

    if fm_ids != as_ids:
        diff_fm = fm_ids - as_ids
        diff_as = as_ids - fm_ids
        errors.append(
            f"CHECK 1: canonical_id mismatch feature_matrix vs anomaly_scores "
            f"({len(diff_fm)} only in FM, {len(diff_as)} only in AS)"
        )

    if fm_ids != rs_ids:
        diff_fm = fm_ids - rs_ids
        diff_rs = rs_ids - fm_ids
        errors.append(
            f"CHECK 1: canonical_id mismatch feature_matrix vs risk_scores "
            f"({len(diff_fm)} only in FM, {len(diff_rs)} only in RS)"
        )

    if not errors:
        logger.info(
            "  CHECK 1 PASS: canonical_id set consistent across all 3 files "
            "(%d identities)", len(fm_ids),
        )

    # --- Check 2: attack_paths subset of CRITICAL+HIGH ---
    high_crit_ids = set(rs[rs["risk_tier"].isin({"CRITICAL", "HIGH"})]["canonical_id"])
    ap_ids = set(
        pd.read_csv(DATA_DIR / "attack_paths.csv", usecols=["canonical_id"])["canonical_id"]
    )
    orphan_ap = ap_ids - high_crit_ids
    if orphan_ap:
        errors.append(
            f"CHECK 2: {len(orphan_ap)} attack_path canonical_ids are NOT in "
            f"CRITICAL/HIGH risk tier: {sorted(orphan_ap)[:3]}..."
        )
    else:
        logger.info(
            "  CHECK 2 PASS: all %d attack-path identities are CRITICAL/HIGH tier",
            len(ap_ids),
        )

    # --- Check 3: remediation_actions — one row per canonical_id ---
    act = pd.read_csv(DATA_DIR / "remediation_actions.csv", usecols=["canonical_id"])
    act_ids = set(act["canonical_id"])

    if len(act) != len(rs_ids):
        errors.append(
            f"CHECK 3: remediation_actions has {len(act)} rows, "
            f"expected {len(rs_ids)} (one per identity)"
        )

    missing_act = rs_ids - act_ids
    if missing_act:
        errors.append(
            f"CHECK 3: {len(missing_act)} risk_score canonical_ids missing "
            f"from remediation_actions"
        )

    extra_act = act_ids - rs_ids
    if extra_act:
        errors.append(
            f"CHECK 3: {len(extra_act)} canonical_ids in remediation_actions "
            f"not in risk_scores"
        )

    dup_mask = act["canonical_id"].duplicated(keep=False)
    n_dup = dup_mask.sum()
    if n_dup > 0:
        errors.append(
            f"CHECK 3: remediation_actions has {n_dup} rows with duplicate "
            f"canonical_ids (expected exactly one per identity)"
        )

    if not any(e.startswith("CHECK 3") for e in errors):
        logger.info(
            "  CHECK 3 PASS: remediation_actions has exactly %d rows "
            "(one per canonical identity, no duplicates)", len(act),
        )

    # --- Check 4: effective_privileges FK integrity ---
    ep = pd.read_csv(
        DATA_DIR / "effective_privileges.csv",
        usecols=["identity_id", "resource_id"],
    )
    ui_ids = set(
        pd.read_csv(DATA_DIR / "unified_identities.csv", usecols=["identity_id"])["identity_id"]
    )
    rc_ids = set(
        pd.read_csv(DATA_DIR / "resource_catalog.csv", usecols=["resource_id"])["resource_id"]
    )

    orphan_identity = set(ep["identity_id"]) - ui_ids
    orphan_resource = set(ep["resource_id"]) - rc_ids

    if orphan_identity:
        errors.append(
            f"CHECK 4: {len(orphan_identity)} effective_privileges.identity_id "
            f"values not present in unified_identities.csv"
        )
    if orphan_resource:
        errors.append(
            f"CHECK 4: {len(orphan_resource)} effective_privileges.resource_id "
            f"values not present in resource_catalog.csv"
        )

    if not orphan_identity and not orphan_resource:
        logger.info(
            "  CHECK 4 PASS: zero orphan FKs in effective_privileges "
            "(%d identity refs, %d resource refs — all valid)",
            len(set(ep["identity_id"])), len(set(ep["resource_id"])),
        )

    # --- Final gate ---
    if errors:
        logger.error("")
        logger.error("CONSISTENCY CHECKS FAILED — %d error(s):", len(errors))
        for i, err in enumerate(errors, 1):
            logger.error("  [%d] %s", i, err)
        logger.error(
            "\nThe pipeline produced internally inconsistent data. "
            "Review the errors above and re-run the affected steps."
        )
        sys.exit(1)

    logger.info("")
    logger.info("  ALL CONSISTENCY CHECKS PASSED")


# ---------------------------------------------------------------------------
# Pipeline summary builder
# ---------------------------------------------------------------------------


def _build_summary(run_ts: str, skip_llm: bool, total_elapsed: float) -> str:
    """
    Build the pipeline run summary. Reads final output files for statistics.
    Returns a markdown-formatted string suitable for printing and saving.
    """
    rs = pd.read_csv(DATA_DIR / "risk_scores.csv", usecols=["canonical_id", "risk_tier"])
    anom = pd.read_csv(DATA_DIR / "anomaly_scores.csv", usecols=["is_anomaly"])
    inc = pd.read_csv(DATA_DIR / "incidents.csv", usecols=["incident_id", "incident_type", "severity"])
    ap = pd.read_csv(DATA_DIR / "attack_paths.csv", usecols=["canonical_id"])

    total_identities = len(rs)
    anomalies_flagged = int(anom["is_anomaly"].sum())
    incident_count = len(inc)
    alert_reduction_pct = (
        (1 - incident_count / anomalies_flagged) * 100
        if anomalies_flagged > 0 else 0.0
    )
    tier_breakdown = rs["risk_tier"].value_counts().to_dict()
    attack_paths_count = ap["canonical_id"].nunique()

    narratives_line = (
        "skipped (--skip-llm)" if skip_llm
        else "20 (CRITICAL+HIGH identities)"
    )

    total_runtime = total_elapsed

    lines = [
        f"# Identity Nexus AI — Pipeline Run Summary",
        f"",
        f"**Run timestamp:** {run_ts} UTC",
        f"",
        f"## Key Metrics",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total identities processed | {total_identities} |",
        f"| Anomalies flagged (is_anomaly=True) | {anomalies_flagged} |",
        f"| Incidents after clustering | {incident_count} |",
        f"| Alert reduction % (alerts -> incidents) | {alert_reduction_pct:.1f}% |",
        f"| Attack paths simulated (CRITICAL+HIGH) | {attack_paths_count} |",
        f"| Remediation actions generated | {total_identities} |",
        f"| LLM narratives | {narratives_line} |",
        f"",
        f"## Risk Tier Distribution",
        f"",
        f"| Tier | Count |",
        f"|------|-------|",
    ]
    for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        lines.append(f"| {tier} | {tier_breakdown.get(tier, 0)} |")

    lines += [
        f"",
        f"## Incident Type Breakdown",
        f"",
        f"| Incident Type | Count |",
        f"|---------------|-------|",
    ]
    for itype, cnt in inc["incident_type"].value_counts().items():
        lines.append(f"| {itype} | {cnt} |")

    lines += [
        f"",
        f"## Step Timings",
        f"",
        f"| Step | Duration (s) |",
        f"|------|-------------|",
    ]
    for step_name, elapsed in _step_times.items():
        lines.append(f"| {step_name} | {elapsed:.1f} |")
    lines += [
        f"| **TOTAL (wall clock)** | **{total_runtime:.1f}** |",
        f"",
        f"## Consistency Checks",
        f"",
        f"All built-in cross-file consistency checks passed.",
        f"",
        f"---",
        f"_Generated by src/main.py — Identity Nexus AI Phase 7_",
    ]
    return "\n".join(lines)


def _print_summary(run_ts: str, skip_llm: bool, total_elapsed: float) -> None:
    """Print the consolidated summary report to console."""
    rs = pd.read_csv(DATA_DIR / "risk_scores.csv", usecols=["canonical_id", "risk_tier"])
    anom = pd.read_csv(DATA_DIR / "anomaly_scores.csv", usecols=["is_anomaly"])
    inc = pd.read_csv(DATA_DIR / "incidents.csv", usecols=["incident_id", "incident_type", "severity"])
    ap = pd.read_csv(DATA_DIR / "attack_paths.csv", usecols=["canonical_id"])

    anomalies_flagged = int(anom["is_anomaly"].sum())
    incident_count = len(inc)
    alert_reduction_pct = (
        (1 - incident_count / anomalies_flagged) * 100
        if anomalies_flagged > 0 else 0.0
    )
    tier_breakdown = rs["risk_tier"].value_counts().to_dict()
    total_runtime = total_elapsed

    print()
    print("=" * 62)
    print("  IDENTITY NEXUS AI — PIPELINE RUN COMPLETE")
    print("=" * 62)
    print(f"  Run timestamp      : {run_ts} UTC")
    print(f"  Total runtime      : {total_runtime:.1f} s")
    print()
    print("  IDENTITY SUMMARY")
    print(f"    Total processed  : {len(rs)}")
    print(f"    Anomalies flagged: {anomalies_flagged}")
    print(f"    Risk tiers       : CRITICAL={tier_breakdown.get('CRITICAL',0)}  "
          f"HIGH={tier_breakdown.get('HIGH',0)}  "
          f"MEDIUM={tier_breakdown.get('MEDIUM',0)}  "
          f"LOW={tier_breakdown.get('LOW',0)}")
    print()
    print("  INCIDENT SUMMARY")
    print(f"    Raw alerts       : {anomalies_flagged}")
    print(f"    After clustering : {incident_count}  "
          f"({alert_reduction_pct:.1f}% reduction)")
    for itype, cnt in inc["incident_type"].value_counts().items():
        print(f"      {itype:<28} {cnt}")
    print()
    print("  ATTACK PATHS")
    print(f"    Identities simulated: {ap['canonical_id'].nunique()}")
    print()
    print("  NARRATIVES")
    if skip_llm:
        print("    Status: SKIPPED (--skip-llm flag set)")
    else:
        narr_path = DATA_DIR / "narratives.json"
        if narr_path.exists():
            with open(narr_path, encoding="utf-8") as fh:
                narr = json.load(fh)
            llm_count = sum(1 for n in narr if n.get("narrative_type") == "LLM")
            print(f"    Generated       : {len(narr)} total "
                  f"({llm_count} LLM, {len(narr) - llm_count} template)")
        else:
            print("    narratives.json not found")
    print()
    print("  STEP TIMINGS")
    for step_name, elapsed in _step_times.items():
        bar = "#" * max(1, int(elapsed / 2))
        print(f"    {step_name:<35} {elapsed:>6.1f} s  {bar}")
    print(f"    {'-' * 44}")
    print(f"    {'TOTAL (wall clock)':<35} {total_runtime:>6.1f} s")
    print("=" * 62)
    print()


# ---------------------------------------------------------------------------
# Individual pipeline steps
# ---------------------------------------------------------------------------


def _step_data_simulator() -> None:
    from data_simulator import DataSimulator, CONFIG
    from datetime import date
    cfg = dict(CONFIG)
    sim = DataSimulator(cfg)
    written = sim.run()
    sim.print_summary(written)
    for fname in ("unified_identities.csv", "group_mappings.csv",
                  "role_mappings.csv", "audit_events.csv",
                  "offboarding_records.csv", "resource_access_logs.csv"):
        _verify_csv("DataSimulator", DATA_DIR / fname, min_rows=10)


def _step_identity_resolver() -> None:
    from identity_resolver import IdentityResolver
    resolver = IdentityResolver(data_dir=DATA_DIR)
    resolver.load().resolve().save()
    resolver.print_summary()
    _verify_csv("IdentityResolver", DATA_DIR / "unified_identities.csv", min_rows=100)


def _step_graph_builder() -> None:
    from graph_builder import GraphBuilder
    builder = GraphBuilder(data_dir=DATA_DIR, models_dir=MODELS_DIR)
    builder.build()
    builder.print_summary()
    builder.save()
    _verify_binary("GraphBuilder", MODELS_DIR / "identity_graph.gpickle")


def _step_effective_privilege_engine() -> None:
    from effective_privilege_engine import EffectivePrivilegeEngine
    engine = EffectivePrivilegeEngine(data_dir=DATA_DIR, models_dir=MODELS_DIR)
    engine.load()
    df = engine.run()
    engine.save(df)
    engine.print_summary(df)
    _verify_csv("EffectivePrivilegeEngine", DATA_DIR / "effective_privileges.csv", min_rows=100)


def _step_feature_engineering() -> None:
    from feature_engineering import FeatureEngineer
    fe = FeatureEngineer(data_dir=DATA_DIR)
    fe.load()
    fm = fe.build()
    fe.save(fm)
    fe.print_summary(fm)
    _verify_csv("FeatureEngineering", DATA_DIR / "feature_matrix.csv", min_rows=400)


def _step_anomaly_detection(validate: bool) -> None:
    from anomaly_detection import AnomalyDetector, _validate_against_ground_truth
    fm = pd.read_csv(DATA_DIR / "feature_matrix.csv")
    logger.info("Loaded feature_matrix.csv: %d rows", len(fm))
    det = AnomalyDetector(data_dir=DATA_DIR, models_dir=MODELS_DIR)
    det.fit(fm)
    scores = det.score()
    det.save(scores)
    det.persist_models()
    det.print_summary(scores)
    _verify_csv("AnomalyDetection", DATA_DIR / "anomaly_scores.csv", min_rows=400)
    if validate:
        logger.info("[VALIDATE] Running ground-truth precision/recall evaluation")
        _validate_against_ground_truth(scores, DATA_DIR)


def _step_risk_scoring() -> None:
    from risk_scoring import RiskScoringEngine
    engine = RiskScoringEngine(data_dir=DATA_DIR)
    engine.load()
    rs = engine.score()
    engine.save(rs)
    engine.print_summary(rs)
    _verify_csv("RiskScoring", DATA_DIR / "risk_scores.csv", min_rows=400)


def _step_incident_clustering() -> None:
    from incident_clustering import IncidentClusterer
    ic = IncidentClusterer(data_dir=DATA_DIR)
    ic.load()
    incidents = ic.cluster()
    ic.save(incidents)
    ic.print_summary(incidents)
    _verify_csv("IncidentClustering", DATA_DIR / "incidents.csv", min_rows=1)


def _step_attack_path_simulator() -> None:
    from attack_path_simulator import AttackPathSimulator
    sim = AttackPathSimulator(data_dir=DATA_DIR, models_dir=MODELS_DIR)
    sim.load()
    df, detail = sim.run()
    sim.save(df, detail)
    sim.print_summary(df)
    _verify_csv("AttackPathSimulator", DATA_DIR / "attack_paths.csv", min_rows=1)
    _verify_binary("AttackPathSimulator", DATA_DIR / "attack_paths_detail.json")


def _step_remediation_engine() -> None:
    from remediation_engine import RemediationEngine
    engine = RemediationEngine(data_dir=DATA_DIR)
    engine.load()
    df = engine.run()
    engine.save(df)
    engine.print_summary(df)
    _verify_csv("RemediationEngine", DATA_DIR / "remediation_actions.csv", min_rows=400)


def _step_compliance_mapper() -> None:
    from compliance_mapper import ComplianceMapper
    mapper = ComplianceMapper(data_dir=DATA_DIR)
    mapper.load()
    inc_df, act_df, audit_df = mapper.run()
    mapper.save(inc_df, act_df, audit_df)
    mapper.print_summary(inc_df, act_df, audit_df)
    _verify_csv("ComplianceMapper", DATA_DIR / "compliance_mappings.csv", min_rows=100)


def _step_llm_narrative_generator() -> None:
    from llm_narrative_generator import LLMNarrativeGenerator
    gen = LLMNarrativeGenerator(data_dir=DATA_DIR)
    gen.load()
    inc_df, act_df, narratives = gen.run()
    gen.save(inc_df, act_df, narratives)
    gen.print_summary(narratives)
    _verify_binary("LLMNarrativeGenerator", DATA_DIR / "narratives.json")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identity Nexus AI — Full Pipeline Orchestrator (Phase 7)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/main.py --skip-llm          # fast run, no API calls
  python src/main.py                     # full run with LLM narratives
  python src/main.py --regenerate-data   # wipe and regenerate all data first
  python src/main.py --validate --skip-llm  # with ground-truth evaluation
        """,
    )
    parser.add_argument(
        "--regenerate-data",
        action="store_true",
        default=False,
        help=(
            "Run DataSimulator to regenerate all raw CSV files. "
            "WARNING: this wipes and reseeds all generated_data/ CSVs. "
            "Default: skip (use existing files). DESTRUCTIVE."
        ),
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        default=False,
        help=(
            "Skip LLMNarrativeGenerator. Useful for fast iteration "
            "without incurring Anthropic API calls or costs. "
            "Incident and action records will retain any previously "
            "generated narratives."
        ),
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        default=False,
        help=(
            "After anomaly detection, run precision/recall evaluation "
            "against ground_truth_labels.csv. "
            "This is the ONLY pipeline path that reads that file. "
            "Results are printed to console and do not affect pipeline outputs."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s -- %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )

    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    REPORTS_DIR.mkdir(exist_ok=True)
    MODELS_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)

    logger.info("Identity Nexus AI — Pipeline starting at %s UTC", run_ts)
    logger.info("Flags: regenerate-data=%s  skip-llm=%s  validate=%s",
                args.regenerate_data, args.skip_llm, args.validate)

    pipeline_start = time.perf_counter()

    # -----------------------------------------------------------------------
    # Step 1: DataSimulator (only with --regenerate-data)
    # -----------------------------------------------------------------------
    if args.regenerate_data:
        _run_step("1. DataSimulator", _step_data_simulator)
    else:
        logger.info("")
        logger.info("  [SKIP] Step 1: DataSimulator (omit --regenerate-data to keep existing data)")
        logger.info("         Verifying required raw files are present...")
        for fname in ("unified_identities.csv", "audit_events.csv",
                      "resource_access_logs.csv", "offboarding_records.csv",
                      "group_mappings.csv", "role_mappings.csv",
                      "resource_catalog.csv"):
            _verify_csv("pre-check (raw data)", DATA_DIR / fname, min_rows=1)
        logger.info("         Raw data files verified.")

    # -----------------------------------------------------------------------
    # Step 2: IdentityResolver
    # -----------------------------------------------------------------------
    _run_step("2. IdentityResolver", _step_identity_resolver)

    # -----------------------------------------------------------------------
    # Step 3: GraphBuilder
    # -----------------------------------------------------------------------
    _run_step("3. GraphBuilder", _step_graph_builder)

    # -----------------------------------------------------------------------
    # Step 4: EffectivePrivilegeEngine
    # -----------------------------------------------------------------------
    _run_step("4. EffectivePrivilegeEngine", _step_effective_privilege_engine)

    # -----------------------------------------------------------------------
    # Step 5: FeatureEngineering
    # -----------------------------------------------------------------------
    _run_step("5. FeatureEngineering", _step_feature_engineering)

    # -----------------------------------------------------------------------
    # Step 6: AnomalyDetection
    # -----------------------------------------------------------------------
    _run_step(
        "6. AnomalyDetection",
        lambda: _step_anomaly_detection(validate=args.validate),
    )

    # -----------------------------------------------------------------------
    # Step 7: RiskScoring
    # -----------------------------------------------------------------------
    _run_step("7. RiskScoring", _step_risk_scoring)

    # -----------------------------------------------------------------------
    # Step 8: IncidentClustering
    # -----------------------------------------------------------------------
    _run_step("8. IncidentClustering", _step_incident_clustering)

    # -----------------------------------------------------------------------
    # Step 9: AttackPathSimulator
    # -----------------------------------------------------------------------
    _run_step("9. AttackPathSimulator", _step_attack_path_simulator)

    # -----------------------------------------------------------------------
    # Step 10: RemediationEngine
    # -----------------------------------------------------------------------
    _run_step("10. RemediationEngine", _step_remediation_engine)

    # -----------------------------------------------------------------------
    # Step 11: ComplianceMapper
    # -----------------------------------------------------------------------
    _run_step("11. ComplianceMapper", _step_compliance_mapper)

    # -----------------------------------------------------------------------
    # Step 12: LLMNarrativeGenerator (optional)
    # -----------------------------------------------------------------------
    if args.skip_llm:
        logger.info("")
        logger.info("  [SKIP] Step 12: LLMNarrativeGenerator (--skip-llm flag set)")
    else:
        _run_step("12. LLMNarrativeGenerator", _step_llm_narrative_generator)

    # Record total wall-clock time (including any skipped steps)
    total_elapsed = time.perf_counter() - pipeline_start

    # -----------------------------------------------------------------------
    # Built-in consistency checks (always run, not optional)
    # -----------------------------------------------------------------------
    _run_consistency_checks()

    # -----------------------------------------------------------------------
    # Consolidated summary report
    # -----------------------------------------------------------------------
    _print_summary(run_ts, args.skip_llm, total_elapsed)

    summary_md = _build_summary(run_ts, args.skip_llm, total_elapsed)
    report_path = REPORTS_DIR / "pipeline_run_summary.md"
    report_path.write_text(summary_md, encoding="utf-8")
    logger.info("Pipeline run summary written to %s", report_path)

    logger.info(
        "Pipeline complete. Total runtime: %.1f s", total_elapsed
    )


if __name__ == "__main__":
    main()
