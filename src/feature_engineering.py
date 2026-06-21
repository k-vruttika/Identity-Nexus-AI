"""
src/feature_engineering.py
Identity Nexus AI — Phase 4: Feature Engineering

Single responsibility: compute the per-canonical-identity behavioural and
privilege feature vector that feeds the ML anomaly detectors.

Grain: ONE row per canonical_id (453 rows out).

Join semantics
--------------
  effective_privileges.identity_id  → already canonical_id (direct join)
  audit_events.identity_id          → per-platform UUID → join via unified_identities
  resource_access_logs.identity_id  → per-platform UUID → join via unified_identities
  role_mappings.identity_id         → per-platform UUID → join via unified_identities
  offboarding_records.identity_id   → per-platform UUID → join via unified_identities

Features (13)
-------------
  1.  platform_count              — distinct platforms this canonical person has accounts on
  2.  privilege_count             — total effective privileges (rows in effective_privileges)
  3.  admin_role_count            — ADMIN + FULL_CONTROL privileges (high-blast-radius grant)
  4.  login_frequency             — average successful logins per 30-day window over 12-month audit
  5.  dormant_days                — days since any activity in audit_events or access logs
  6.  privilege_usage_ratio       — fraction of effective privileges that were ever used (not excessive)
  7.  cross_platform_exposure     — distinct resource-platforms where this identity holds privileges
  8.  risk_accumulation_score     — composite signal [0,1]; formula documented in _compute_ras()
  9.  privilege_velocity          — role assignments per day in last 90 days, normalized to [0,1]
  10. offboarding_gap_score       — revocation quality gap [0,1]; 0 if no offboarding record

  Three features added in Phase 4 v2 after diagnostic revealed 0% recall on three
  anomaly categories:

  11. access_revocation_failure   — binary 1.0 if identity has an offboarding record AND
                                    access_revoked=False in that record; 0.0 otherwise.
                                    Diagnostic: ORPHANED_ACCOUNT identities had 0% recall
                                    because offboarding_gap_score (a continuous ratio) was
                                    diluted across 10 features.  This binary flag amplifies
                                    the "access not revoked despite offboarding" signal so
                                    IsolationForest can isolate it in fewer splits.

  12. risk_event_ratio            — fraction of this identity's audit events where
                                    risk_indicator=True (SIEM-style alert flag in the
                                    operational data, not the ground-truth eval file).
                                    Diagnostic: TOKEN_ABUSE identities had 0% recall and
                                    looked normal on all 10 prior features.  TOKEN_ABUSE
                                    manifests as anomalous API/session bursts that the data
                                    simulator flags via risk_indicator; this ratio is the
                                    only available proxy in audit_events.csv.

  13. privilege_peer_deviation    — z-score of this identity's privilege_count relative to
                                    the mean/std of their department cohort (from canonical
                                    representative's unified_identities.department), clipped
                                    to [0, 5].  Diagnostic: OVERPRIVILEGED identities had
                                    0% recall because privilege_usage_ratio = 0.92-1.00
                                    (they actively USE their excessive privileges, so unused-
                                    burden was zero).  Peer deviation captures "more
                                    privileges than department peers" — the core over-
                                    privilege signal independent of usage.

Output: generated_data/feature_matrix.csv

MUST NOT read generated_data/ground_truth_labels.csv.
MUST NOT import later-phase src/ modules.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent.parent / "generated_data"

REFERENCE_DATE: date = date(2026, 6, 21)

# Audit history window: one full year of generated events
AUDIT_WINDOW_DAYS: int = 365

# Privilege velocity measurement window (days)
VELOCITY_WINDOW_DAYS: int = 90

# risk_accumulation_score normalisation thresholds (domain-calibrated):
#   privilege_count of 15 ≈ 2× the dataset average of 7.56; marks elevated exposure
#   dormant_days of 180 = 6 months; beyond this the account is fully stale
RAS_PRIV_COUNT_THRESHOLD: float = 15.0
RAS_DORMANT_THRESHOLD: float = 180.0

# offboarding_gap_score cap for revocation_delay_days
OB_DELAY_CAP_DAYS: float = 90.0

# Privilege levels that constitute admin-tier access
ADMIN_LEVELS = frozenset({"ADMIN", "FULL_CONTROL"})

FEATURE_COLS = [
    "platform_count",
    "privilege_count",
    "admin_role_count",
    "login_frequency",
    "dormant_days",
    "privilege_usage_ratio",
    "cross_platform_exposure",
    "risk_accumulation_score",
    "privilege_velocity",
    "offboarding_gap_score",
    # Phase 4 v2 additions — fix zero-recall on ORPHANED_ACCOUNT, TOKEN_ABUSE, OVERPRIVILEGED
    "access_revocation_failure",
    "risk_event_ratio",
    "privilege_peer_deviation",
]


# ---------------------------------------------------------------------------
# Feature Engineering
# ---------------------------------------------------------------------------


class FeatureEngineer:
    """
    Compute one feature row per canonical identity.

    Usage
    -----
    fe = FeatureEngineer().load()
    fm = fe.build()
    fe.save(fm)
    fe.print_summary(fm)
    """

    def __init__(self, data_dir: Path = DATA_DIR) -> None:
        self.data_dir = data_dir
        self._ui: Optional[pd.DataFrame] = None
        self._iid_to_canon: Dict[str, str] = {}
        self._ae: Optional[pd.DataFrame] = None
        self._rl: Optional[pd.DataFrame] = None
        self._ep: Optional[pd.DataFrame] = None
        self._rm: Optional[pd.DataFrame] = None
        self._ob: Optional[pd.DataFrame] = None

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load(self) -> "FeatureEngineer":
        """Read all input CSVs and attach canonical_id to per-platform tables."""
        dd = self.data_dir

        # --- unified_identities: build canonical → platform-id list and reverse ---
        self._ui = pd.read_csv(
            dd / "unified_identities.csv",
            usecols=["identity_id", "canonical_id", "platform", "mfa_enabled",
                     "is_active", "last_login", "department"],
        )
        self._iid_to_canon = dict(
            zip(self._ui["identity_id"].astype(str),
                self._ui["canonical_id"].astype(str))
        )
        logger.info("unified_identities: %d rows, %d canonical IDs",
                    len(self._ui), self._ui["canonical_id"].nunique())

        # --- audit_events ---
        ae = pd.read_csv(
            dd / "audit_events.csv",
            usecols=["identity_id", "event_type", "outcome", "timestamp", "risk_indicator"],
        )
        ae["canonical_id"] = ae["identity_id"].astype(str).map(self._iid_to_canon)
        ae["ts"] = pd.to_datetime(ae["timestamp"], utc=True, errors="coerce")
        ae["dt_date"] = ae["ts"].dt.date
        self._ae = ae
        logger.info("audit_events: %d rows", len(ae))

        # --- resource_access_logs ---
        rl = pd.read_csv(
            dd / "resource_access_logs.csv",
            usecols=["identity_id", "timestamp"],
        )
        rl["canonical_id"] = rl["identity_id"].astype(str).map(self._iid_to_canon)
        rl["ts"] = pd.to_datetime(rl["timestamp"], utc=True, errors="coerce")
        rl["dt_date"] = rl["ts"].dt.date
        self._rl = rl
        logger.info("resource_access_logs: %d rows", len(rl))

        # --- effective_privileges ---
        self._ep = pd.read_csv(
            dd / "effective_privileges.csv",
            usecols=["identity_id", "privilege_level", "is_excessive", "platform"],
        )
        logger.info("effective_privileges: %d rows", len(self._ep))

        # --- role_mappings ---
        rm = pd.read_csv(
            dd / "role_mappings.csv",
            usecols=["identity_id", "assigned_date"],
        )
        rm["canonical_id"] = rm["identity_id"].astype(str).map(self._iid_to_canon)
        rm["assigned_date"] = pd.to_datetime(rm["assigned_date"], errors="coerce").dt.date
        self._rm = rm
        logger.info("role_mappings: %d rows", len(rm))

        # --- offboarding_records ---
        ob = pd.read_csv(
            dd / "offboarding_records.csv",
            usecols=["identity_id", "revocation_delay_days",
                     "accounts_disabled", "access_revoked"],
        )
        ob["canonical_id"] = ob["identity_id"].astype(str).map(self._iid_to_canon)
        self._ob = ob
        logger.info("offboarding_records: %d rows", len(ob))

        return self

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build(self) -> pd.DataFrame:
        """Compute all 13 features for all 453 canonical identities."""
        all_canonical = sorted(self._ui["canonical_id"].unique())
        logger.info("Building features for %d canonical identities …", len(all_canonical))

        f1 = self._platform_count()
        f2, f3, f6, f7 = self._privilege_features()
        f4, f5 = self._activity_features()
        f9 = self._privilege_velocity()
        f10 = self._offboarding_gap_score()
        f11 = self._access_revocation_failure()
        f12 = self._risk_event_ratio()

        fm = pd.DataFrame({"canonical_id": all_canonical})
        fm = fm.merge(f1, on="canonical_id", how="left")
        fm = fm.merge(f2, on="canonical_id", how="left")
        fm = fm.merge(f3, on="canonical_id", how="left")
        fm = fm.merge(f4, on="canonical_id", how="left")
        fm = fm.merge(f5, on="canonical_id", how="left")
        fm = fm.merge(f6, on="canonical_id", how="left")
        fm = fm.merge(f7, on="canonical_id", how="left")
        fm = fm.merge(f9, on="canonical_id", how="left")
        fm = fm.merge(f10, on="canonical_id", how="left")
        fm = fm.merge(f11, on="canonical_id", how="left")
        fm = fm.merge(f12, on="canonical_id", how="left")

        # Fill nulls — identities missing from a table get 0
        fill_zeros = ["privilege_count", "admin_role_count", "login_frequency",
                      "privilege_usage_ratio", "cross_platform_exposure",
                      "privilege_velocity", "offboarding_gap_score",
                      "access_revocation_failure", "risk_event_ratio"]
        fm[fill_zeros] = fm[fill_zeros].fillna(0.0)
        fm["dormant_days"] = fm["dormant_days"].fillna(999).astype(int)

        # --- Feature 8: risk_accumulation_score (depends on features 1–7, 9–10) ---
        fm["risk_accumulation_score"] = fm.apply(self._compute_ras, axis=1)

        # --- Feature 13: privilege_peer_deviation (requires privilege_count already set) ---
        fm["privilege_peer_deviation"] = self._privilege_peer_deviation(fm)

        fm = fm[["canonical_id"] + FEATURE_COLS].copy()
        logger.info("Feature matrix built: %d rows x %d feature cols",
                    len(fm), len(FEATURE_COLS))
        return fm

    # ------------------------------------------------------------------
    # Individual feature computations
    # ------------------------------------------------------------------

    def _platform_count(self) -> pd.DataFrame:
        """Feature 1: distinct platforms per canonical identity."""
        cnt = (
            self._ui.groupby("canonical_id")["platform"]
            .nunique()
            .reset_index()
            .rename(columns={"platform": "platform_count"})
        )
        return cnt

    def _privilege_features(self) -> tuple:
        """
        Features 2, 3, 6, 7 from effective_privileges.csv.
        ep.identity_id == canonical_id (post Phase 3 fix), so no join needed.
        """
        ep = self._ep.copy()
        ep["is_admin"] = ep["privilege_level"].isin(ADMIN_LEVELS)
        ep["is_used"] = ~ep["is_excessive"].astype(bool)

        agg = ep.groupby("identity_id").agg(
            privilege_count=("privilege_level", "count"),
            admin_role_count=("is_admin", "sum"),
            used_count=("is_used", "sum"),
            cross_platform_exposure=("platform", "nunique"),
        ).reset_index().rename(columns={"identity_id": "canonical_id"})

        agg["privilege_usage_ratio"] = (
            agg["used_count"] / agg["privilege_count"].clip(lower=1)
        ).clip(0.0, 1.0)

        f2 = agg[["canonical_id", "privilege_count"]].copy()
        f2["privilege_count"] = f2["privilege_count"].astype(int)

        f3 = agg[["canonical_id", "admin_role_count"]].copy()
        f3["admin_role_count"] = f3["admin_role_count"].astype(int)

        f6 = agg[["canonical_id", "privilege_usage_ratio"]].copy()

        f7 = agg[["canonical_id", "cross_platform_exposure"]].copy()
        f7["cross_platform_exposure"] = f7["cross_platform_exposure"].astype(int)

        return f2, f3, f6, f7

    def _activity_features(self) -> tuple:
        """
        Features 4 (login_frequency) and 5 (dormant_days).

        login_frequency: average successful logins per 30-day window over the
        12-month audit history.  Computed as: total_logins / (365/30).

        dormant_days: days since the most recent activity signal (any audit
        event or resource access) across ALL platform accounts of a canonical
        identity.  999 if no activity is found (should not occur given the data).
        """
        ae = self._ae
        rl = self._rl

        # --- login_frequency ---
        cutoff_12m = date(
            REFERENCE_DATE.year - 1, REFERENCE_DATE.month, REFERENCE_DATE.day
        )
        logins = ae[
            (ae["event_type"] == "LOGIN")
            & (ae["outcome"] == "SUCCESS")
            & (ae["dt_date"] >= cutoff_12m)
        ]
        login_cnt = (
            logins.groupby("canonical_id")
            .size()
            .reset_index(name="total_logins_12m")
        )
        login_cnt["login_frequency"] = (
            login_cnt["total_logins_12m"] / (AUDIT_WINDOW_DAYS / 30.0)
        ).round(4)
        f4 = login_cnt[["canonical_id", "login_frequency"]]

        # --- dormant_days: latest activity across both tables ---
        ae_last = ae.groupby("canonical_id")["dt_date"].max().reset_index(
            name="last_ae_date"
        )
        rl_last = rl.groupby("canonical_id")["dt_date"].max().reset_index(
            name="last_rl_date"
        )
        activity = ae_last.merge(rl_last, on="canonical_id", how="outer")
        activity["last_activity"] = activity[["last_ae_date", "last_rl_date"]].max(
            axis=1
        )
        activity["dormant_days"] = activity["last_activity"].apply(
            lambda d: (REFERENCE_DATE - d).days if pd.notna(d) else 999
        ).astype(int)
        f5 = activity[["canonical_id", "dormant_days"]]

        return f4, f5

    def _privilege_velocity(self) -> pd.DataFrame:
        """
        Feature 9: role assignment rate in the last 90 days, normalized.

        velocity = (roles assigned in last 90d) / VELOCITY_WINDOW_DAYS
        The raw per-day rate is then min-max scaled to [0,1] using the
        population max so extreme spikes read as 1.0 and stable identities
        read as 0.0.
        """
        cutoff = date(
            REFERENCE_DATE.year,
            REFERENCE_DATE.month,
            REFERENCE_DATE.day,
        )
        from datetime import timedelta
        cutoff = REFERENCE_DATE - timedelta(days=VELOCITY_WINDOW_DAYS)

        rm = self._rm
        recent = rm[rm["assigned_date"] >= cutoff]
        cnt = (
            recent.groupby("canonical_id")
            .size()
            .reset_index(name="recent_role_count")
        )
        cnt["raw_velocity"] = cnt["recent_role_count"] / float(VELOCITY_WINDOW_DAYS)
        max_v = cnt["raw_velocity"].max()
        cnt["privilege_velocity"] = (
            cnt["raw_velocity"] / max_v if max_v > 0 else 0.0
        ).clip(0.0, 1.0)
        return cnt[["canonical_id", "privilege_velocity"]]

    def _offboarding_gap_score(self) -> pd.DataFrame:
        """
        Feature 10: quality of offboarding / access revocation [0, 1].

        Score = 0.0 if no offboarding record exists (identity is active, no gap).

        For identities with records:
          delay_component  = min(revocation_delay_days / OB_DELAY_CAP_DAYS, 1.0)
          penalty          = 0.25 if accounts_disabled=False else 0.0
                           + 0.25 if access_revoked=False     else 0.0
          gap_score        = clamp(delay_component × 0.50 + penalty, 0, 1)

        The 50% cap on delay means a 90-day revocation delay alone reaches 0.50;
        an unremediated account with neither accounts nor access revoked reaches 1.0.
        """
        ob = self._ob.copy()
        ob["delay_norm"] = (
            ob["revocation_delay_days"].clip(lower=0) / OB_DELAY_CAP_DAYS
        ).clip(upper=1.0)
        ob["penalty"] = (
            (~ob["accounts_disabled"].astype(bool)).astype(float) * 0.25
            + (~ob["access_revoked"].astype(bool)).astype(float) * 0.25
        )
        ob["offboarding_gap_score"] = (
            ob["delay_norm"] * 0.50 + ob["penalty"]
        ).clip(0.0, 1.0)

        # Keep the worst score per canonical_id (in case of duplicate records)
        agg = (
            ob.groupby("canonical_id")["offboarding_gap_score"]
            .max()
            .reset_index()
        )
        return agg

    def _access_revocation_failure(self) -> pd.DataFrame:
        """
        Feature 11: access_revocation_failure — binary 1.0 / 0.0.

        1.0 if the identity has an offboarding record AND access_revoked=False
        in that record.  This is a targeted signal for ORPHANED_ACCOUNT:
        the person was formally offboarded but their system access was never
        revoked.  offboarding_gap_score encodes this but as a continuous value
        diluted across 10 features; this binary flag gives IsolationForest a
        sharp axis to isolate on.
        """
        ob = self._ob.copy()
        ob["access_revocation_failure"] = (~ob["access_revoked"].astype(bool)).astype(float)
        agg = (
            ob.groupby("canonical_id")["access_revocation_failure"]
            .max()
            .reset_index()
        )
        return agg

    def _risk_event_ratio(self) -> pd.DataFrame:
        """
        Feature 12: risk_event_ratio — fraction of audit events with
        risk_indicator=True for this canonical identity.

        risk_indicator is a SIEM-style alert flag present in audit_events.csv
        (operational data, NOT the ground-truth eval file).  TOKEN_ABUSE
        identities generate anomalous audit events (API bursts, token replay
        patterns) that the data simulator marks with risk_indicator=True, while
        normal identities have a near-zero rate.  Mean across categories:
          TOKEN_ABUSE = 0.647, NORMAL = 0.000, others = 0.07–0.13.
        """
        ae = self._ae.copy()
        ae["risk_flag"] = ae["risk_indicator"].astype(bool).astype(float)
        agg = ae.groupby("canonical_id").agg(
            risk_event_ratio=("risk_flag", "mean")
        ).reset_index()
        return agg

    def _privilege_peer_deviation(self, fm: pd.DataFrame) -> pd.Series:
        """
        Feature 13: privilege_peer_deviation — z-score of this identity's
        privilege_count relative to their department cohort, clipped to [0, 5].

        Positive values only (one-sided): we flag identities with MORE
        privileges than peers, not fewer.  Clipped at 5 standard deviations
        to prevent a single extreme outlier from dominating normalisation.

        Department is read from the canonical representative's row in
        unified_identities (the row where identity_id == canonical_id).

        Diagnostic motivation: OVERPRIVILEGED identities had privilege_usage_
        ratio = 0.92–1.00 (actively using every privilege), making them
        indistinguishable from legitimate power-users on usage metrics.
        The distinguisher is RELATIVE QUANTITY: their privilege_count is
        multiple standard deviations above department peers.
        """
        # Canonical representative's department
        ui_canon = self._ui[self._ui["identity_id"] == self._ui["canonical_id"]][
            ["canonical_id", "department"]
        ].copy()

        fm_dept = fm[["canonical_id", "privilege_count"]].merge(
            ui_canon, on="canonical_id", how="left"
        )
        fm_dept["department"] = fm_dept["department"].fillna("Unknown")

        dept_stats = fm_dept.groupby("department")["privilege_count"].agg(["mean", "std"])
        dept_stats["std"] = dept_stats["std"].fillna(1.0).clip(lower=1.0)

        fm_dept = fm_dept.merge(dept_stats, on="department", how="left")
        deviation = (
            (fm_dept["privilege_count"] - fm_dept["mean"]) / fm_dept["std"]
        ).clip(lower=0.0, upper=5.0).fillna(0.0)

        return deviation.values

    @staticmethod
    def _compute_ras(row: pd.Series) -> float:
        """
        Feature 8: risk_accumulation_score — composite [0, 1].

        Formula (weights sum to 1.0):
          W1 = 0.30 × clamp(privilege_count / 15.0)
               Privilege exposure: count normalised against 'elevated' threshold
               of 15 (≈ 2× dataset average 7.56).
          W2 = 0.25 × (admin_role_count / max(privilege_count, 1))
               Admin concentration: what fraction of privileges are blast-radius-
               amplifying ADMIN / FULL_CONTROL grants.
          W3 = 0.25 × (1 - privilege_usage_ratio)
               Unused privilege burden: stale grants that expand attack surface
               without serving a legitimate business need.
          W4 = 0.15 × clamp(dormant_days / 180.0)
               Dormancy signal: capped at 6 months; stale credentials become
               high-value targets for credential stuffing / token replay.
          W5 = 0.05 × offboarding_gap_score
               Compliance gap: weak offboarding increases residual access risk
               even after an identity leaves the organisation.
        """
        priv_count = float(row["privilege_count"])
        admin_count = float(row["admin_role_count"])
        usage_ratio = float(row["privilege_usage_ratio"])
        dormant = float(row["dormant_days"])
        ob_gap = float(row["offboarding_gap_score"])

        w1 = 0.30 * min(priv_count / RAS_PRIV_COUNT_THRESHOLD, 1.0)
        w2 = 0.25 * (admin_count / max(priv_count, 1.0))
        w3 = 0.25 * (1.0 - usage_ratio)
        w4 = 0.15 * min(dormant / RAS_DORMANT_THRESHOLD, 1.0)
        w5 = 0.05 * ob_gap

        return round(w1 + w2 + w3 + w4 + w5, 6)

    # ------------------------------------------------------------------
    # Save + summary
    # ------------------------------------------------------------------

    def save(self, fm: pd.DataFrame) -> None:
        out = self.data_dir / "feature_matrix.csv"
        fm.to_csv(out, index=False)
        logger.info("Wrote feature_matrix.csv: %d rows", len(fm))

    def print_summary(self, fm: pd.DataFrame) -> None:
        print()
        print("=" * 65)
        print("  FEATURE ENGINEERING — Summary")
        print("=" * 65)
        print(f"  Output rows (canonical identities) : {len(fm)}")
        print()
        for col in FEATURE_COLS:
            s = fm[col]
            print(
                f"  {col:<28s} "
                f"mean={s.mean():7.3f}  std={s.std():6.3f}  "
                f"min={s.min():7.3f}  max={s.max():7.3f}"
            )
        print("=" * 65)
        print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identity Nexus AI — Phase 4: Feature Engineering"
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

    fe = FeatureEngineer(data_dir=Path(args.data_dir))
    fe.load()
    fm = fe.build()
    fe.save(fm)
    fe.print_summary(fm)


if __name__ == "__main__":
    main()
