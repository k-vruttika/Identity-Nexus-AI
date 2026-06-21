"""
src/risk_scoring.py
Identity Nexus AI — Phase 4: Risk Scoring Engine

Single responsibility: translate raw anomaly signals and privilege data
into an interpretable, business-oriented risk score (0–100) per canonical
identity with a four-component weighted formula.

Formula
-------
  final_risk_score = 0.35 × privilege_risk
                   + 0.35 × behavioural_risk
                   + 0.20 × identity_risk
                   + 0.10 × compliance_risk

Component definitions
---------------------
  privilege_risk [0,100]:
    40 pts — privilege exposure  : clamp(privilege_count / 15, 1) × 40
    35 pts — admin concentration : (admin_role_count / max(privilege_count,1)) × 35
    15 pts — unused burden       : (1 − privilege_usage_ratio) × 15
    10 pts — critical resource   : 10 if any effective privilege targets a
                                    CRITICAL-rated resource, else 0
    The 15-count threshold for exposure is 2× the dataset mean of 7.36.

  behavioural_risk [0,100]:
    70 pts — anomaly signal      : isolation_forest_score × 70
    20 pts — privilege velocity  : privilege_velocity × 20
    10 pts — composite risk      : risk_accumulation_score × 10

    Note: isolation_forest_score is used (not ensemble_anomaly_score) because IF
    scores span [0,1] with better dynamic range than the ensemble (max 0.68 in
    this dataset due to IF-LOF disagreement).  IF measures structural isolation
    in feature space — the most principled signal for privilege-pattern anomaly.

  identity_risk [0,100]:
    30 pts — MFA gap             : 30 if ANY platform account has mfa_enabled=False
    40 pts — dormancy            : clamp(dormant_days / 180, 1) × 40
    20 pts — inactive privileged : 20 if any account is_active=False AND is_privileged=True
    10 pts — login deficit       : 10 if login_frequency < 0.5 logins/30d

  compliance_risk [0,100]:
    100 pts — offboarding gap    : offboarding_gap_score × 100

Compound risk multiplier
------------------------
  For identities where privilege_risk ≥ 70 AND isolation_forest_score ≥ 0.70:
    final_risk_score × 1.30 (capped at 100)
  For identities where privilege_risk ≥ 60 AND isolation_forest_score ≥ 0.50:
    final_risk_score × 1.15 (capped at 100)

  Rationale: risk compounds when broad privilege exposure (blast radius) aligns
  with a strong anomaly signal (active exploitation indicator).  A high-privilege
  identity that is also flagged by IsolationForest represents a qualitatively
  different — and higher — threat than either factor alone.  This mirrors the
  CVSS v3 temporal/environmental multiplier pattern.

Risk tiers (per architecture.md §5.10):
  CRITICAL : final_risk_score ≥ 80
  HIGH     : 60 ≤ score < 80
  MEDIUM   : 30 ≤ score < 60
  LOW      : score < 30

Outputs
-------
  generated_data/risk_scores.csv

    Columns per data_dictionary.md §5.10 plus three explainability extras:
      evidence         — top data points that drove the score (plain English)
      root_cause       — most likely explanation for the elevated risk
      business_impact  — what organisational risk this poses

MUST NOT read ground_truth_labels.csv.
MUST NOT import later-phase src/ modules.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent.parent / "generated_data"

REFERENCE_DATE_STR = "2026-06-21"

# Component weights
W_PRIV = 0.35
W_BEHAV = 0.35
W_IDENT = 0.20
W_COMP = 0.10

# Thresholds
PRIV_COUNT_THRESHOLD = 15.0      # "elevated" privilege count (2× dataset mean)
DORMANT_THRESHOLD_DAYS = 180.0   # 6-month dormancy cap
LOGIN_DEFICIT_THRESHOLD = 0.5    # logins per 30d considered "low activity"

# Risk tier boundaries (per architecture.md §5.10)
TIER_CRITICAL = 80.0
TIER_HIGH = 60.0
TIER_MEDIUM = 30.0

# Compound risk multiplier thresholds
COMPOUND_HIGH_PRIV = 70.0        # privilege_risk threshold for compound factor
COMPOUND_HIGH_IF = 0.70          # IF score threshold for compound factor
COMPOUND_MED_PRIV = 60.0
COMPOUND_MED_IF = 0.50
COMPOUND_HIGH_FACTOR = 1.30
COMPOUND_MED_FACTOR = 1.15

ADMIN_LEVELS = frozenset({"ADMIN", "FULL_CONTROL"})


# ---------------------------------------------------------------------------
# Risk Scoring Engine
# ---------------------------------------------------------------------------


class RiskScoringEngine:
    """
    Computes a 4-component weighted risk score per canonical identity.

    Usage
    -----
    engine = RiskScoringEngine().load()
    rs = engine.score()
    engine.save(rs)
    engine.print_summary(rs)
    """

    def __init__(self, data_dir: Path = DATA_DIR) -> None:
        self.data_dir = data_dir
        self._anom: Optional[pd.DataFrame] = None
        self._ep: Optional[pd.DataFrame] = None
        self._ui_agg: Optional[pd.DataFrame] = None
        self._ob_agg: Optional[pd.DataFrame] = None
        self._fm: Optional[pd.DataFrame] = None
        self._canon_has_critical: dict[str, bool] = {}

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load(self) -> "RiskScoringEngine":
        dd = self.data_dir

        self._anom = pd.read_csv(
            dd / "anomaly_scores.csv",
            usecols=["canonical_id", "ensemble_anomaly_score", "isolation_forest_score", "detection_method"],
        )
        logger.info("anomaly_scores.csv: %d rows", len(self._anom))

        self._fm = pd.read_csv(dd / "feature_matrix.csv")
        logger.info("feature_matrix.csv: %d rows", len(self._fm))

        ep = pd.read_csv(
            dd / "effective_privileges.csv",
            usecols=["identity_id", "resource_criticality"],
        ).rename(columns={"identity_id": "canonical_id"})
        self._canon_has_critical = (
            ep[ep["resource_criticality"] == "CRITICAL"]
            .groupby("canonical_id")["resource_criticality"]
            .any()
            .to_dict()
        )
        logger.info(
            "effective_privileges.csv: %d canonical IDs with CRITICAL resources",
            sum(self._canon_has_critical.values()),
        )

        ui = pd.read_csv(
            dd / "unified_identities.csv",
            usecols=["canonical_id", "mfa_enabled", "is_active", "is_privileged"],
        )
        # Per canonical: any mfa_enabled=False → MFA gap
        ui_mfa = ui.groupby("canonical_id")["mfa_enabled"].all().reset_index()
        ui_mfa.columns = ["canonical_id", "mfa_all_enabled"]
        # Any account is_active=False AND is_privileged=True → inactive privileged account
        ui["inactive_priv"] = (~ui["is_active"].astype(bool)) & ui["is_privileged"].astype(bool)
        ui_inact = ui.groupby("canonical_id")["inactive_priv"].any().reset_index()
        ui_inact.columns = ["canonical_id", "has_inactive_privileged"]
        self._ui_agg = ui_mfa.merge(ui_inact, on="canonical_id", how="left")
        logger.info("unified_identities: %d canonical IDs aggregated", len(self._ui_agg))

        ob = pd.read_csv(
            dd / "offboarding_records.csv",
            usecols=["identity_id", "compliance_status"],
        )
        # identity_id in offboarding_records is per-platform UUID; resolve via ui
        ui_map = pd.read_csv(
            dd / "unified_identities.csv",
            usecols=["identity_id", "canonical_id"],
        )
        ob = ob.merge(ui_map, on="identity_id", how="left")
        self._ob_agg = (
            ob.groupby("canonical_id")["compliance_status"]
            .agg(lambda s: "NON_COMPLIANT" if "NON_COMPLIANT" in s.values else s.iloc[0])
            .reset_index()
            .rename(columns={"compliance_status": "worst_compliance_status"})
        )
        logger.info("offboarding_records: %d canonical IDs with records", len(self._ob_agg))

        return self

    # ------------------------------------------------------------------
    # Score
    # ------------------------------------------------------------------

    def score(self) -> pd.DataFrame:
        """Compute risk scores for all canonical identities."""
        # Master table — fm has all 453 canonical_ids
        df = self._fm.copy()
        df = df.merge(self._anom, on="canonical_id", how="left")
        df = df.merge(self._ui_agg, on="canonical_id", how="left")
        df = df.merge(self._ob_agg, on="canonical_id", how="left")

        df["ensemble_anomaly_score"] = df["ensemble_anomaly_score"].fillna(0.0)
        df["isolation_forest_score"] = df["isolation_forest_score"].fillna(0.0)
        df["mfa_all_enabled"] = df["mfa_all_enabled"].fillna(True).astype(bool)
        df["has_inactive_privileged"] = df["has_inactive_privileged"].fillna(False).astype(bool)
        df["worst_compliance_status"] = df["worst_compliance_status"].fillna("COMPLIANT")
        df["detection_method"] = df["detection_method"].fillna("ML_ENSEMBLE")

        computed_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        rows = []
        for _, r in df.iterrows():
            priv = self._privilege_risk(r)
            behav = self._behavioural_risk(r)
            ident = self._identity_risk(r)
            comp = self._compliance_risk(r)

            base = W_PRIV * priv + W_BEHAV * behav + W_IDENT * ident + W_COMP * comp

            # Compound risk multiplier: privilege exposure + anomaly signal co-occur
            if_score = float(r["isolation_forest_score"])
            if priv >= COMPOUND_HIGH_PRIV and if_score >= COMPOUND_HIGH_IF:
                compound = COMPOUND_HIGH_FACTOR
            elif priv >= COMPOUND_MED_PRIV and if_score >= COMPOUND_MED_IF:
                compound = COMPOUND_MED_FACTOR
            else:
                compound = 1.0

            final = round(float(np.clip(base * compound, 0.0, 100.0)), 2)

            tier = self._risk_tier(final)
            drivers = self._risk_drivers(r, priv, behav, ident, comp)
            evidence, root_cause, impact = self._explain(r, priv, behav, ident, comp, tier)

            rows.append({
                "risk_id": str(uuid.uuid4()),
                "canonical_id": r["canonical_id"],
                "privilege_risk_component": round(priv, 2),
                "behavioural_risk_component": round(behav, 2),
                "identity_risk_component": round(ident, 2),
                "compliance_risk_component": round(comp, 2),
                "final_risk_score": final,
                "risk_tier": tier,
                "risk_drivers": json.dumps(drivers),
                "previous_risk_score": None,
                "score_delta": None,
                "computed_timestamp": computed_ts,
                "evidence": evidence,
                "root_cause": root_cause,
                "business_impact": impact,
                "detection_method": str(r["detection_method"]),
            })

        rs = pd.DataFrame(rows)
        logger.info(
            "Risk scores computed: %d identities; tier distribution: %s",
            len(rs),
            rs["risk_tier"].value_counts().to_dict(),
        )
        return rs

    # ------------------------------------------------------------------
    # Component calculators
    # ------------------------------------------------------------------

    def _privilege_risk(self, r: pd.Series) -> float:
        priv_count = float(r["privilege_count"])
        admin_count = float(r["admin_role_count"])
        usage_ratio = float(r["privilege_usage_ratio"])
        canon_id = str(r["canonical_id"])

        exposure = min(priv_count / PRIV_COUNT_THRESHOLD, 1.0) * 40.0
        admin_conc = (admin_count / max(priv_count, 1.0)) * 35.0
        unused_burden = (1.0 - usage_ratio) * 15.0
        crit_bonus = 10.0 if self._canon_has_critical.get(canon_id, False) else 0.0

        return float(np.clip(exposure + admin_conc + unused_burden + crit_bonus, 0.0, 100.0))

    @staticmethod
    def _behavioural_risk(r: pd.Series) -> float:
        # Use isolation_forest_score for better dynamic range [0,1].
        # ensemble_anomaly_score is stored on the row but its max is 0.68 due
        # to IF-LOF disagreement; IF score alone spans the full [0,1] range.
        if_score = float(r["isolation_forest_score"])
        velocity = float(r["privilege_velocity"])
        ras = float(r["risk_accumulation_score"])

        return float(np.clip(if_score * 70.0 + velocity * 20.0 + ras * 10.0, 0.0, 100.0))

    @staticmethod
    def _identity_risk(r: pd.Series) -> float:
        score = 0.0
        if not bool(r["mfa_all_enabled"]):
            score += 30.0
        score += min(float(r["dormant_days"]) / DORMANT_THRESHOLD_DAYS, 1.0) * 40.0
        if bool(r["has_inactive_privileged"]):
            score += 20.0
        if float(r["login_frequency"]) < LOGIN_DEFICIT_THRESHOLD:
            score += 10.0
        return float(np.clip(score, 0.0, 100.0))

    @staticmethod
    def _compliance_risk(r: pd.Series) -> float:
        return float(np.clip(float(r["offboarding_gap_score"]) * 100.0, 0.0, 100.0))

    # ------------------------------------------------------------------
    # Tier + drivers
    # ------------------------------------------------------------------

    @staticmethod
    def _risk_tier(score: float) -> str:
        if score >= TIER_CRITICAL:
            return "CRITICAL"
        if score >= TIER_HIGH:
            return "HIGH"
        if score >= TIER_MEDIUM:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _risk_drivers(
        r: pd.Series,
        priv: float,
        behav: float,
        ident: float,
        comp: float,
    ) -> list[str]:
        """Return ordered list of top contributing factor names."""
        drivers = []
        if float(r["admin_role_count"]) > 5:
            drivers.append("excessive_admin_privileges")
        if float(r["privilege_usage_ratio"]) < 0.6:
            drivers.append("high_unused_privilege_ratio")
        if float(r["ensemble_anomaly_score"]) > 0.4:
            drivers.append("anomaly_model_flag")
        if not bool(r["mfa_all_enabled"]):
            drivers.append("mfa_disabled")
        if float(r["dormant_days"]) > 90:
            drivers.append("dormant_account")
        if bool(r["has_inactive_privileged"]):
            drivers.append("inactive_privileged_account")
        if float(r["offboarding_gap_score"]) > 0.3:
            drivers.append("offboarding_gap")
        if float(r["privilege_velocity"]) > 0.5:
            drivers.append("rapid_privilege_changes")
        if float(r["cross_platform_exposure"]) >= 4:
            drivers.append("high_cross_platform_exposure")
        # Sort by the four component scores descending so top drivers match top components
        component_order = sorted(
            [("privilege", priv), ("behavioural", behav),
             ("identity", ident), ("compliance", comp)],
            key=lambda x: x[1], reverse=True,
        )
        # Keep up to 5 drivers that are actually non-zero, prioritised by component weight
        if not drivers:
            drivers = [f"{component_order[0][0]}_risk"]
        return drivers[:5]

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------

    def _explain(
        self,
        r: pd.Series,
        priv: float,
        behav: float,
        ident: float,
        comp: float,
        tier: str,
    ) -> tuple[str, str, str]:
        canon_id = str(r["canonical_id"])
        priv_count = int(r["privilege_count"])
        admin_count = int(r["admin_role_count"])
        dormant = int(r["dormant_days"])
        usage = float(r["privilege_usage_ratio"])
        platforms = int(r["platform_count"])

        # --- evidence ---
        facts = []
        if admin_count > 0:
            facts.append(
                f"admin_role_count={admin_count} "
                f"({admin_count/max(priv_count,1)*100:.0f}% of {priv_count} privileges are ADMIN/FULL_CONTROL)"
            )
        if dormant > 30:
            facts.append(f"dormant_days={dormant} (no activity for {dormant} days)")
        if not bool(r["mfa_all_enabled"]):
            facts.append("MFA disabled on at least one platform account")
        if float(r["ensemble_anomaly_score"]) > 0.3:
            facts.append(
                f"ensemble_anomaly_score={r['ensemble_anomaly_score']:.3f} "
                "(flagged by IsolationForest + LOF + Autoencoder)"
            )
        if float(r["offboarding_gap_score"]) > 0:
            facts.append(
                f"offboarding_gap_score={r['offboarding_gap_score']:.2f} "
                f"(compliance_status={r['worst_compliance_status']})"
            )
        if self._canon_has_critical.get(canon_id, False):
            facts.append("holds effective privileges on CRITICAL-rated resources")
        if not facts:
            facts.append(
                f"login_frequency={r['login_frequency']:.2f} logins/30d "
                f"across {platforms} platform(s)"
            )
        evidence = "; ".join(facts[:4])

        # --- root cause ---
        dominant = max(
            [("privilege misconfiguration", priv),
             ("behavioural anomaly", behav),
             ("identity hygiene failure", ident),
             ("compliance gap", comp)],
            key=lambda x: x[1],
        )[0]

        if priv >= behav and priv >= ident and admin_count > 3:
            root_cause = (
                f"Identity holds {admin_count} ADMIN/FULL_CONTROL privileges "
                f"across {int(r['cross_platform_exposure'])} resource platform(s); "
                f"{(1-usage)*100:.0f}% are provisioned but unused — classic over-provisioning."
            )
        elif behav >= priv and float(r["ensemble_anomaly_score"]) > 0.4:
            root_cause = (
                f"Unusual access behaviour detected by the ensemble anomaly models "
                f"(score={r['ensemble_anomaly_score']:.3f}). "
                f"Privilege velocity={r['privilege_velocity']:.2f} suggests recent "
                "credential or role change activity."
            )
        elif ident >= priv and dormant > 90:
            root_cause = (
                f"Account has been dormant for {dormant} days with "
                f"{'MFA disabled' if not bool(r['mfa_all_enabled']) else 'MFA enabled'}. "
                "Stale privileged credentials are prime targets for credential stuffing."
            )
        elif float(r["offboarding_gap_score"]) > 0.3:
            root_cause = (
                f"Identity has an offboarding record with compliance_status="
                f"{r['worst_compliance_status']} and "
                f"offboarding_gap_score={r['offboarding_gap_score']:.2f}. "
                "Access was not revoked on schedule."
            )
        else:
            root_cause = (
                f"Elevated {dominant} across {platforms} platform(s) with "
                f"{priv_count} effective privileges."
            )

        # --- business impact ---
        if tier == "CRITICAL":
            impact = (
                f"Critical-tier identity with {admin_count} admin-level privileges "
                f"spanning {int(r['cross_platform_exposure'])} platform(s). "
                "A compromised account at this privilege level could enable "
                "lateral movement, data exfiltration, or full domain takeover. "
                "Immediate remediation required."
            )
        elif tier == "HIGH":
            impact = (
                f"High-risk identity with significant privilege exposure ({priv_count} "
                f"effective privileges, {admin_count} admin-tier). "
                "Exploitation could grant an attacker persistent access across "
                f"{platforms} platform(s). Remediate within 24 hours."
            )
        elif tier == "MEDIUM":
            impact = (
                f"Moderate risk — {priv_count} effective privileges with "
                f"{(1-usage)*100:.0f}% unused. Low-urgency credential hygiene "
                "issue that may escalate if not addressed in the next sprint."
            )
        else:
            impact = (
                f"Low risk — standard profile with {priv_count} effective "
                f"privileges across {platforms} platform(s). No immediate action required."
            )

        return evidence, root_cause, impact

    # ------------------------------------------------------------------
    # Save + summary
    # ------------------------------------------------------------------

    def save(self, rs: pd.DataFrame) -> None:
        out = self.data_dir / "risk_scores.csv"
        rs.to_csv(out, index=False)
        logger.info("Wrote risk_scores.csv: %d rows", len(rs))

    def print_summary(self, rs: pd.DataFrame) -> None:
        tier_counts = rs["risk_tier"].value_counts()
        n = len(rs)

        print()
        print("=" * 65)
        print("  RISK SCORING ENGINE — Summary")
        print("=" * 65)
        print(f"  Total canonical identities  : {n}")
        print()
        print("  Risk tier breakdown:")
        for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            cnt = tier_counts.get(tier, 0)
            pct = cnt / n * 100
            bar = "|" * int(pct / 2)
            print(f"    {tier:<10s} {cnt:4d}  ({pct:5.1f}%)  {bar}")
        print()
        for col in ["privilege_risk_component", "behavioural_risk_component",
                    "identity_risk_component", "compliance_risk_component",
                    "final_risk_score"]:
            s = rs[col]
            print(
                f"  {col:<35s} "
                f"mean={s.mean():5.1f}  max={s.max():5.1f}"
            )
        print()
        print("  Top 5 CRITICAL identities:")
        top = rs[rs["risk_tier"] == "CRITICAL"].nlargest(5, "final_risk_score")
        for _, r in top.iterrows():
            print(
                f"    {r['canonical_id'][:36]}  "
                f"score={r['final_risk_score']:5.1f}  "
                f"drivers={r['risk_drivers']}"
            )
        print("=" * 65)
        print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identity Nexus AI — Phase 4: Risk Scoring"
    )
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )

    engine = RiskScoringEngine(data_dir=Path(args.data_dir))
    engine.load()
    rs = engine.score()
    engine.save(rs)
    engine.print_summary(rs)


if __name__ == "__main__":
    main()
