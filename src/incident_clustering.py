"""
src/incident_clustering.py
Identity Nexus AI — Phase 4: Incident Clustering

Single responsibility: group high-risk identities with similar anomaly
signatures into typed incidents using DBSCAN, then label each cluster
with an incident type based on centroid feature profiles.

Algorithm
---------
  1. Select all identities where is_anomaly=True OR risk_tier ∈ {CRITICAL, HIGH}.
     These are the "raw alerts" to reduce.

  2. Standardise their 10 feature-matrix features using StandardScaler fitted
     on the full population (not just the flagged set) to preserve relative
     distances.

  3. Run DBSCAN (eps=1.2, min_samples=2) on the standardised vectors.
     DBSCAN naturally identifies dense clusters (similar anomaly profiles) and
     labels outliers as noise (-1).  No k is pre-specified — cluster count
     emerges from the data.

  4. Assign incident_type to each cluster and each noise point by testing the
     cluster centroid against a priority-ordered set of feature rules
     (see _classify_incident_type).

  5. Write one row per flagged identity to incidents.csv with:
       cluster_id   — DBSCAN label (−1 for noise, >=0 for cluster members)
       incident_type — typed from centroid rules
       severity     — mapped from risk_tier
       affected_resources — top-5 EP resource_ids (CRITICAL first)
       contributing_features — top-3 most-deviant features (by z-score)

Reduction metric
----------------
  raw_alerts          = total rows in incidents.csv
  effective_incidents = unique DBSCAN clusters (cluster_id >= 0)
                      + noise points (cluster_id = −1, each is its own alert)
  reduction %         = (raw_alerts − effective_incidents) / raw_alerts × 100
  Target: >= 40 % reduction.

Incident types (7)
------------------
  PRIVILEGE_ABUSE     high admin concentration + low privilege usage
  LATERAL_MOVEMENT    high privilege velocity + multi-platform exposure
  DATA_EXFIL          high cross-platform exposure + recent velocity
  DORMANT_ADMIN       high admin count + high dormant_days
  ORPHANED_ACCOUNT    high offboarding_gap_score
  SOD_VIOLATION       high privilege_count + high admin concentration
  BEHAVIORAL_OUTLIER  catch-all for identities with no dominant feature signal

Severity mapping
----------------
  risk_tier CRITICAL → severity CRITICAL
  risk_tier HIGH     → severity HIGH
  risk_tier MEDIUM   → severity MEDIUM
  risk_tier LOW      → severity LOW

Outputs
-------
  generated_data/incidents.csv

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
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent.parent / "generated_data"

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
    # Phase 4 v2 additions (must match feature_engineering.FEATURE_COLS)
    "access_revocation_failure",
    "risk_event_ratio",
    "privilege_peer_deviation",
]

# DBSCAN parameters
DBSCAN_EPS: float = 1.5
DBSCAN_MIN_SAMPLES: int = 2

# Incident type priority thresholds (centroid-based)
OB_GAP_THRESHOLD: float = 0.25
ADMIN_HIGH_THRESHOLD: float = 5.0
DORMANT_HIGH_THRESHOLD: float = 60.0
VELOCITY_HIGH_THRESHOLD: float = 0.40
USAGE_LOW_THRESHOLD: float = 0.65
PRIV_COUNT_HIGH_THRESHOLD: float = 10.0
CROSS_PLAT_HIGH_THRESHOLD: float = 3.5


# ---------------------------------------------------------------------------
# Incident Clustering
# ---------------------------------------------------------------------------


class IncidentClusterer:
    """
    Groups high-risk identities into typed incidents.

    Usage
    -----
    ic = IncidentClusterer().load()
    incidents = ic.cluster()
    ic.save(incidents)
    ic.print_summary(incidents)
    """

    def __init__(self, data_dir: Path = DATA_DIR) -> None:
        self.data_dir = data_dir
        self._anom: Optional[pd.DataFrame] = None
        self._rs: Optional[pd.DataFrame] = None
        self._fm: Optional[pd.DataFrame] = None
        self._ep_resources: dict[str, list[str]] = {}
        self._canon_platform: dict[str, str] = {}
        self._feature_means: Optional[np.ndarray] = None
        self._feature_stds: Optional[np.ndarray] = None

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load(self) -> "IncidentClusterer":
        dd = self.data_dir

        self._anom = pd.read_csv(
            dd / "anomaly_scores.csv",
            usecols=["canonical_id", "ensemble_anomaly_score", "is_anomaly", "detection_method"],
        )
        logger.info("anomaly_scores.csv: %d rows", len(self._anom))

        self._rs = pd.read_csv(
            dd / "risk_scores.csv",
            usecols=["canonical_id", "final_risk_score", "risk_tier"],
        )
        logger.info("risk_scores.csv: %d rows", len(self._rs))

        self._fm = pd.read_csv(dd / "feature_matrix.csv")
        logger.info("feature_matrix.csv: %d rows", len(self._fm))

        # Pre-compute top-5 resource_ids per canonical_id (CRITICAL first)
        ep = pd.read_csv(
            dd / "effective_privileges.csv",
            usecols=["identity_id", "resource_id", "resource_criticality",
                     "privilege_level"],
        ).rename(columns={"identity_id": "canonical_id"})

        crit_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        priv_order = {"FULL_CONTROL": 0, "ADMIN": 1, "WRITE": 2, "READ": 3, "EXECUTE": 4}
        ep["_c_ord"] = ep["resource_criticality"].map(crit_order).fillna(9)
        ep["_p_ord"] = ep["privilege_level"].map(priv_order).fillna(9)
        ep_sorted = ep.sort_values(["_c_ord", "_p_ord"])

        self._ep_resources = (
            ep_sorted.groupby("canonical_id")["resource_id"]
            .apply(lambda s: list(s.unique()[:5]))
            .to_dict()
        )

        # Primary platform of canonical representative (identity_id == canonical_id)
        ui = pd.read_csv(
            dd / "unified_identities.csv",
            usecols=["identity_id", "canonical_id", "platform"],
        )
        canon_rows = ui[ui["identity_id"] == ui["canonical_id"]]
        self._canon_platform = dict(zip(canon_rows["canonical_id"], canon_rows["platform"]))

        # Population feature stats for z-score computation
        X_pop = self._fm[FEATURE_COLS].values.astype(float)
        self._feature_means = X_pop.mean(axis=0)
        self._feature_stds = X_pop.std(axis=0).clip(min=1e-8)

        return self

    # ------------------------------------------------------------------
    # Cluster
    # ------------------------------------------------------------------

    def cluster(self) -> pd.DataFrame:
        """Cluster high-risk identities and return incidents DataFrame."""
        # --- Select high-risk pool ---
        merged = self._fm.merge(self._anom, on="canonical_id", how="left")
        merged = merged.merge(self._rs, on="canonical_id", how="left")
        merged["is_anomaly"] = merged["is_anomaly"].fillna(False).astype(bool)
        merged["risk_tier"] = merged["risk_tier"].fillna("LOW")
        merged["detection_method"] = merged["detection_method"].fillna("ML_ENSEMBLE")

        flagged = merged[
            merged["is_anomaly"] | merged["risk_tier"].isin({"CRITICAL", "HIGH"})
        ].copy().reset_index(drop=True)

        n_raw = len(flagged)
        logger.info(
            "High-risk pool: %d identities (is_anomaly=True OR CRITICAL/HIGH tier)",
            n_raw,
        )

        if n_raw == 0:
            logger.warning("No high-risk identities found — incidents.csv will be empty.")
            return pd.DataFrame()

        # --- Standardise features using population scaler ---
        scaler = StandardScaler()
        scaler.fit(self._fm[FEATURE_COLS].values.astype(float))
        X = scaler.transform(flagged[FEATURE_COLS].values.astype(float))

        # --- DBSCAN ---
        dbscan = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES, metric="euclidean")
        labels = dbscan.fit_predict(X)
        flagged["cluster_id"] = labels

        n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
        n_noise = (labels == -1).sum()
        logger.info(
            "DBSCAN: %d clusters, %d noise points (eps=%.1f, min_samples=%d)",
            n_clusters, n_noise, DBSCAN_EPS, DBSCAN_MIN_SAMPLES,
        )

        # --- Compute cluster centroids and assign incident types ---
        cluster_types: dict[int, str] = {}
        unique_labels = sorted(set(labels))
        for label in unique_labels:
            mask = labels == label
            centroid = dict(zip(FEATURE_COLS, X[mask].mean(axis=0)))
            # Unscale centroid for interpretable thresholds
            centroid_raw = dict(
                zip(FEATURE_COLS, flagged[FEATURE_COLS].values[mask].mean(axis=0))
            )
            cluster_types[label] = _classify_incident_type(centroid_raw)

        # --- Build ONE output row per DISTINCT incident ---
        # For a cluster (label >= 0): one row representing all members, with the
        # highest-risk-score member as the primary canonical_id and
        # related_canonical_ids listing every member in the cluster.
        # For a noise point (label == -1): one row per identity; each is its
        # own singleton incident with related_canonical_ids = [itself].
        # This implements the correct grain: incidents.csv rows == effective
        # incidents, not raw alert inputs.
        detection_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        rows = []
        X_pop_mean = self._feature_means
        X_pop_std = self._feature_stds

        for label in unique_labels:
            members = flagged[flagged["cluster_id"] == label]

            if label == -1:
                # Each noise point is its own singleton incident.
                # Compute incident_type PER IDENTITY using its own feature vector
                # as the centroid — NOT the aggregate centroid of all noise points.
                for _, row in members.iterrows():
                    canon_id = str(row["canonical_id"])
                    feat_vals = row[FEATURE_COLS].values.astype(float)
                    z_scores = np.abs((feat_vals - X_pop_mean) / X_pop_std)
                    contributing = [FEATURE_COLS[j] for j in np.argsort(z_scores)[::-1][:3]]
                    singleton_centroid = dict(zip(FEATURE_COLS, feat_vals))
                    rows.append({
                        "incident_id": str(uuid.uuid4()),
                        "cluster_id": -1,
                        "canonical_id": canon_id,
                        "member_count": 1,
                        "related_canonical_ids": json.dumps([canon_id]),
                        "incident_type": _classify_incident_type(singleton_centroid),
                        "severity": _tier_to_severity(str(row["risk_tier"])),
                        "detection_method": str(row["detection_method"]),
                        "detection_timestamp": detection_ts,
                        "anomaly_score": round(float(row["ensemble_anomaly_score"]), 6),
                        "risk_score": round(float(row["final_risk_score"]), 2),
                        "affected_resources": json.dumps(self._ep_resources.get(canon_id, [])),
                        "contributing_features": json.dumps(contributing),
                        "status": "OPEN",
                        "platform": self._canon_platform.get(canon_id, "UNKNOWN"),
                        "compliance_tags": json.dumps([]),
                        "llm_narrative": "",
                    })
            else:
                # All members of this cluster → one consolidated incident row
                # Primary actor = member with the highest final_risk_score
                primary = members.nlargest(1, "final_risk_score").iloc[0]
                canon_id = str(primary["canonical_id"])
                all_ids = [str(c) for c in members["canonical_id"].tolist()]

                # Centroid-level contributing features (mean z-score across members)
                feat_matrix = members[FEATURE_COLS].values.astype(float)
                centroid_z = np.abs(
                    (feat_matrix.mean(axis=0) - X_pop_mean) / X_pop_std
                )
                contributing = [FEATURE_COLS[j] for j in np.argsort(centroid_z)[::-1][:3]]

                # Highest severity among cluster members
                sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                severities = members["risk_tier"].map(_tier_to_severity)
                severity = min(severities, key=lambda s: sev_rank.get(s, 9))

                # Combine affected resources across all members (top-5 unique)
                all_resources: list = []
                for cid in all_ids:
                    all_resources.extend(self._ep_resources.get(cid, []))
                seen: set = set()
                unique_resources = [r for r in all_resources
                                    if not (r in seen or seen.add(r))][:5]

                rows.append({
                    "incident_id": str(uuid.uuid4()),
                    "cluster_id": label,
                    "canonical_id": canon_id,
                    "member_count": len(members),
                    "related_canonical_ids": json.dumps(all_ids),
                    "incident_type": cluster_types[label],
                    "severity": severity,
                    "detection_method": str(primary["detection_method"]),
                    "detection_timestamp": detection_ts,
                    "anomaly_score": round(float(members["ensemble_anomaly_score"].max()), 6),
                    "risk_score": round(float(members["final_risk_score"].max()), 2),
                    "affected_resources": json.dumps(unique_resources),
                    "contributing_features": json.dumps(contributing),
                    "status": "OPEN",
                    "platform": self._canon_platform.get(canon_id, "UNKNOWN"),
                    "compliance_tags": json.dumps([]),
                    "llm_narrative": "",
                })

        incidents = pd.DataFrame(rows)

        # --- Compute reduction stats ---
        k_clusters = len([c for c in incidents["cluster_id"].unique() if c >= 0])
        n_noise_pts = (incidents["cluster_id"] == -1).sum()
        effective_incidents = len(incidents)
        reduction_pct = (n_raw - effective_incidents) / n_raw * 100 if n_raw > 0 else 0.0
        logger.info(
            "Alert reduction: %d raw alerts -> %d effective incidents "
            "(%d clusters + %d noise) = %.1f%% reduction",
            n_raw, effective_incidents, k_clusters, n_noise_pts, reduction_pct,
        )

        # Store stats for print_summary
        self._stats = {
            "n_raw": n_raw,
            "k_clusters": k_clusters,
            "n_noise": int(n_noise_pts),
            "effective_incidents": effective_incidents,
            "reduction_pct": reduction_pct,
        }

        return incidents

    # ------------------------------------------------------------------
    # Save + summary
    # ------------------------------------------------------------------

    def save(self, incidents: pd.DataFrame) -> None:
        out = self.data_dir / "incidents.csv"
        incidents.to_csv(out, index=False)
        logger.info("Wrote incidents.csv: %d rows", len(incidents))

    def print_summary(self, incidents: pd.DataFrame) -> None:
        s = getattr(self, "_stats", {})
        n_raw = s.get("n_raw", len(incidents))
        k_cls = s.get("k_clusters", 0)
        n_noise = s.get("n_noise", 0)
        eff = s.get("effective_incidents", len(incidents))
        red = s.get("reduction_pct", 0.0)

        print()
        print("=" * 65)
        print("  INCIDENT CLUSTERING — Summary")
        print("=" * 65)
        print(f"  Raw alerts (flagged identities) : {n_raw}")
        print(f"  DBSCAN clusters found           : {k_cls}")
        print(f"  Noise / singleton alerts        : {n_noise}")
        print(f"  Effective incident count        : {eff}")
        pct_str = f"{red:.1f}%"
        ok = "[OK]" if red >= 40.0 else "[BELOW TARGET]"
        print(f"  Alert reduction                 : {pct_str}  {ok} (target >= 40%)")
        print()
        print("  Incident type distribution:")
        type_counts = incidents["incident_type"].value_counts()
        for itype, cnt in type_counts.items():
            print(f"    {itype:<25s} {cnt:4d}  ({cnt/len(incidents)*100:.1f}%)")
        print()
        print("  Severity distribution:")
        sev_counts = incidents["severity"].value_counts()
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            cnt = sev_counts.get(sev, 0)
            print(f"    {sev:<10s} {cnt:4d}  ({cnt/len(incidents)*100:.1f}%)")
        print()
        print("  Cluster details (multi-member clusters):")
        multi = incidents[incidents["cluster_id"] >= 0].sort_values(
            "member_count", ascending=False
        )
        for _, row in multi.iterrows():
            ids = json.loads(row["related_canonical_ids"])
            preview = ", ".join(ids[:2])
            if len(ids) > 2:
                preview += f" ... (+{len(ids)-2} more)"
            print(
                f"    cluster {int(row['cluster_id']):3d}  "
                f"members={int(row['member_count'])}  "
                f"type={row['incident_type']}"
            )
            print(f"      canonical_ids: {preview}")
        print("=" * 65)
        print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _classify_incident_type(centroid: dict) -> str:
    """
    Assign an incident type from the cluster centroid's raw feature values.
    Rules are checked in priority order so the most specific pattern wins.
    v2: uses access_revocation_failure and risk_event_ratio where available.
    """
    ob = centroid.get("offboarding_gap_score", 0.0)
    arv = centroid.get("access_revocation_failure", 0.0)
    risk_ratio = centroid.get("risk_event_ratio", 0.0)
    admin = centroid.get("admin_role_count", 0.0)
    dormant = centroid.get("dormant_days", 0.0)
    priv_count = centroid.get("privilege_count", 0.0)
    usage_ratio = centroid.get("privilege_usage_ratio", 1.0)
    velocity = centroid.get("privilege_velocity", 0.0)
    cross_plat = centroid.get("cross_platform_exposure", 0.0)
    peer_dev = centroid.get("privilege_peer_deviation", 0.0)

    # Strong binary signal takes top priority
    if arv > 0.5 or ob > OB_GAP_THRESHOLD:
        return "ORPHANED_ACCOUNT"
    # High risk_event_ratio = behavioral anomaly (token/session abuse)
    if risk_ratio > 0.30:
        return "PRIVILEGE_ABUSE"
    if admin > ADMIN_HIGH_THRESHOLD and dormant > DORMANT_HIGH_THRESHOLD:
        return "DORMANT_ADMIN"
    if velocity > VELOCITY_HIGH_THRESHOLD:
        return "LATERAL_MOVEMENT"
    # High peer deviation = over-provisioned relative to department
    if peer_dev > 2.0 and admin > ADMIN_HIGH_THRESHOLD:
        return "SOD_VIOLATION"
    if priv_count > PRIV_COUNT_HIGH_THRESHOLD and admin > ADMIN_HIGH_THRESHOLD:
        return "SOD_VIOLATION"
    if admin > ADMIN_HIGH_THRESHOLD and usage_ratio < USAGE_LOW_THRESHOLD:
        return "PRIVILEGE_ABUSE"
    if cross_plat > CROSS_PLAT_HIGH_THRESHOLD and velocity > 0.2:
        return "DATA_EXFIL"
    if dormant > 90.0:
        return "DORMANT_ADMIN"
    return "BEHAVIORAL_OUTLIER"


def _tier_to_severity(tier: str) -> str:
    mapping = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return mapping.get(tier, "MEDIUM")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identity Nexus AI — Phase 4: Incident Clustering"
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

    ic = IncidentClusterer(data_dir=Path(args.data_dir))
    ic.load()
    incidents = ic.cluster()
    ic.save(incidents)
    ic.print_summary(incidents)


if __name__ == "__main__":
    main()
