"""
src/remediation_engine.py
Identity Nexus AI — Phase 6: Remediation Engine

Single responsibility: generate one prioritised, actionable remediation
recommendation for EVERY identity in risk_scores.csv (all 453 canonical
identities, not just the 20 with attack-path simulations).

ACTION TYPE SELECTION (deterministic, no randomness)
=====================================================
1. If the identity appears in attack_paths.csv (CRITICAL/HIGH tier, BFS
   simulation already run), use the remediation_action already decided
   by AttackPathSimulator — never contradict Phase 5.
2. For remaining CRITICAL identities (should not normally occur; Phase 5
   targets all CRITICAL/HIGH):
     - DOMAIN_RULE in detection_method → DISABLE_ACCOUNT
     - Otherwise → REVOKE_ROLE
3. For HIGH identities not in attack_paths (edge case):
     - excessive_admin_privileges in risk_drivers → REVOKE_ROLE
     - Otherwise → SCOPE_REDUCTION
4. For MEDIUM identities (proportionate, less drastic):
     - mfa_disabled in risk_drivers → ENFORCE_MFA
     - excessive_privileges or high_unused_privilege_ratio → REQUIRE_RECERTIFICATION
     - Default → REQUIRE_RECERTIFICATION
5. For LOW identities (proactive hygiene):
     - mfa_disabled → ENFORCE_MFA
     - Default → REQUIRE_RECERTIFICATION (next-sprint cadence)

PRIORITY MAPPING
================
P1 (act within 4 h)  → CRITICAL tier; also HIGH + DISABLE_ACCOUNT
P2 (act within 24 h) → HIGH tier (other actions); MEDIUM + ENFORCE_MFA
P3 (act within 72 h) → MEDIUM tier (other actions)
P4 (next sprint)     → LOW tier

REDUCTION ESTIMATES
===================
For the 20 identities with attack-path simulations:
    estimated_risk_reduction, blast_radius_reduction → taken directly from
    attack_paths.csv (risk_reduction_pct, blast_radius_reduction_pct).

For all other identities (no BFS simulation performed):
    blast_radius_reduction = 0.0 (no simulation; do not fabricate)
    estimated_risk_reduction = heuristic formula derived from the identity's
    risk score components (documented inline in _estimate_risk_reduction).

OUTPUTS
=======
    generated_data/remediation_actions.csv  — 453 rows, one per canonical identity

MUST NOT read ground_truth_labels.csv.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "generated_data"

# ---------------------------------------------------------------------------
# Lookup tables — placed at module top for auditability
# ---------------------------------------------------------------------------

# Maps risk_tier → P-priority
TIER_PRIORITY: dict[str, str] = {
    "CRITICAL": "P1",
    "HIGH": "P2",
    "MEDIUM": "P3",
    "LOW": "P4",
}

# Human labels for P-priorities (for action_priority column)
PRIORITY_LABEL: dict[str, str] = {
    "P1": "urgent",
    "P2": "high",
    "P3": "medium",
    "P4": "low",
}

# Estimated effort per action type
ACTION_EFFORT: dict[str, str] = {
    "DISABLE_ACCOUNT": "significant",
    "REVOKE_ROLE": "moderate",
    "REMOVE_GROUP": "moderate",
    "SCOPE_REDUCTION": "moderate",
    "ENFORCE_MFA": "quick",
    "REQUIRE_RECERTIFICATION": "quick",
}

# Whether an action requires management/security approval before execution
ACTION_REQUIRES_APPROVAL: dict[str, bool] = {
    "DISABLE_ACCOUNT": True,
    "REVOKE_ROLE": True,
    "REMOVE_GROUP": True,
    "SCOPE_REDUCTION": False,
    "ENFORCE_MFA": False,
    "REQUIRE_RECERTIFICATION": False,
}

# Human-readable labels for risk_driver codes (for justification sentences)
DRIVER_LABELS: dict[str, str] = {
    "excessive_admin_privileges": "excessive administrator-level privileges",
    "high_unused_privilege_ratio": "high proportion of provisioned-but-unused privileges",
    "anomaly_model_flag": "anomaly detection model flagged this identity as a statistical outlier",
    "dormant_account": "extended period of account inactivity",
    "dormant_days": "extended inactivity period",
    "orphaned_account_rule": "deterministic IAM rule: access was not revoked following offboarding",
    "token_abuse_rule": "deterministic IAM rule: elevated ratio of risk-flagged audit events",
    "mfa_disabled": "multi-factor authentication is not enabled",
    "privilege_escalation": "privilege escalation events detected in audit trail",
    "off_hours_access": "anomalous off-hours access pattern",
    "geo_anomaly": "geographic access anomaly (impossible travel or unusual location)",
    "excessive_privileges": "excessive provisioned privileges relative to peer group",
    "compliance_violation": "compliance policy violation in offboarding records",
    "sod_violation": "separation-of-duties conflict detected",
    "data_exfil_indicators": "data exfiltration indicators in access logs",
    "access_revocation_failure": "access revocation failure post-offboarding",
    "risk_event_ratio": "elevated proportion of risk-flagged events",
    "cross_platform_exposure": "elevated cross-platform administrative exposure",
    "admin_role_count": "high count of administrative roles assigned",
    "privilege_peer_deviation": "privilege count deviates significantly from department peers",
}

# Heuristic reduction coefficients per action type.
# Used ONLY for identities without attack-path simulations (no BFS run).
# Computed as fraction of the relevant risk component that the action addresses.
HEURISTIC_REDUCTIONS: dict[str, dict[str, float]] = {
    "DISABLE_ACCOUNT": {
        "privilege_weight": 1.00,  # all privilege risk eliminated
        "behavioural_weight": 0.90,
        "note": "full account lockout",
    },
    "REVOKE_ROLE": {
        "privilege_weight": 0.60,  # removes highest-impact role, others remain
        "behavioural_weight": 0.25,
        "note": "single role revocation",
    },
    "SCOPE_REDUCTION": {
        "privilege_weight": 0.30,
        "behavioural_weight": 0.10,
        "note": "downgrade to read-only",
    },
    "ENFORCE_MFA": {
        "privilege_weight": 0.00,
        "behavioural_weight": 0.15,
        "identity_weight": 0.70,  # main improvement in identity hygiene dimension
        "note": "MFA reduces identity hygiene risk",
    },
    "REQUIRE_RECERTIFICATION": {
        "privilege_weight": 0.20,
        "behavioural_weight": 0.05,
        "note": "certification triggers removal of stale access",
    },
    "REMOVE_GROUP": {
        "privilege_weight": 0.40,
        "behavioural_weight": 0.10,
        "note": "group removal reduces inherited access",
    },
}

# Component weights (mirror RiskScoringEngine formula)
W_PRIV: float = 0.35
W_BEHAV: float = 0.35
W_IDENT: float = 0.20
W_COMP: float = 0.10


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _parse_drivers(raw: Any) -> list[str]:
    """Parse risk_drivers JSON string → list of driver codes."""
    if pd.isna(raw) or not raw:
        return []
    try:
        return json.loads(str(raw)) if str(raw).startswith("[") else [str(raw)]
    except (json.JSONDecodeError, TypeError):
        return []


def _choose_action_type(
    risk_tier: str,
    detection_method: str,
    drivers: list[str],
    ap_action: str | None,
) -> str:
    """
    Select the most appropriate remediation action type.
    Deterministic — same inputs always produce the same output.
    """
    # Rule 1: respect Phase 5 AttackPathSimulator decision for CRITICAL/HIGH
    if ap_action:
        return ap_action

    # Rule 2: CRITICAL — account-level intervention
    if risk_tier == "CRITICAL":
        if "DOMAIN_RULE" in str(detection_method):
            return "DISABLE_ACCOUNT"
        return "REVOKE_ROLE"

    # Rule 3: HIGH — role or scope reduction
    if risk_tier == "HIGH":
        if any(d in drivers for d in ("excessive_admin_privileges", "admin_role_count")):
            return "REVOKE_ROLE"
        return "SCOPE_REDUCTION"

    # Rule 4: MEDIUM — lighter-touch remediation
    if risk_tier == "MEDIUM":
        if "mfa_disabled" in drivers:
            return "ENFORCE_MFA"
        if any(d in drivers for d in (
            "excessive_privileges", "high_unused_privilege_ratio",
            "excessive_admin_privileges", "privilege_peer_deviation",
        )):
            return "REQUIRE_RECERTIFICATION"
        return "REQUIRE_RECERTIFICATION"

    # Rule 5: LOW — proactive hygiene
    if "mfa_disabled" in drivers:
        return "ENFORCE_MFA"
    return "REQUIRE_RECERTIFICATION"


def _choose_priority(risk_tier: str, action_type: str) -> str:
    """Map risk tier (and action type for edge cases) to P-priority."""
    if risk_tier == "CRITICAL":
        return "P1"
    if risk_tier == "HIGH":
        # Disable account on a HIGH-tier identity is still urgent
        return "P1" if action_type == "DISABLE_ACCOUNT" else "P2"
    if risk_tier == "MEDIUM":
        # MFA enforcement is faster and more urgent than recertification
        return "P2" if action_type == "ENFORCE_MFA" else "P3"
    return "P4"


def _build_justification(
    root_cause: str,
    drivers: list[str],
    detection_method: str,
    action_type: str,
    risk_tier: str,
) -> str:
    """
    Build a plain-English, identity-specific justification.
    Prefers root_cause (already computed, specific to this identity).
    Falls back to driver-label sentences if root_cause is absent.
    Never uses generic boilerplate.
    """
    # Use root_cause as primary source if available and meaningful
    if root_cause and isinstance(root_cause, str) and len(root_cause) > 20:
        base = root_cause[:500]
    else:
        # Build from driver labels
        readable = [DRIVER_LABELS.get(d, d) for d in drivers[:4]]
        if readable:
            base = "Key risk factors: " + "; ".join(readable) + "."
        else:
            base = f"Identity at {risk_tier} risk tier requires {action_type} to reduce exposure."

    # Append detection-method attribution for transparency
    dm = str(detection_method)
    if "DOMAIN_RULE" in dm and "ML_ENSEMBLE" not in dm and "IF_PREDICT" not in dm:
        base += " Detection was triggered by a deterministic IAM governance rule (not an ML model)."
    elif "DOMAIN_RULE" in dm:
        base += " Detection involved both ML anomaly scoring and a deterministic IAM rule."

    return base


def _estimate_risk_reduction(
    action_type: str,
    priv_risk: float,
    behav_risk: float,
    ident_risk: float,
    comp_risk: float,
    final_risk: float,
) -> float:
    """
    Heuristic risk reduction estimate for identities without attack-path
    simulations. Uses component weights and action-specific coefficients.

    Formula (for REVOKE_ROLE as example):
        removed_privilege_risk = priv_risk * 0.60
        removed_behavioural    = behav_risk * 0.25
        total_removed          = W_PRIV * removed_privilege_risk
                               + W_BEHAV * removed_behavioural
        pct_reduction          = total_removed / final_risk * 100
    """
    if final_risk <= 0:
        return 0.0
    coeff = HEURISTIC_REDUCTIONS.get(action_type, {})
    pw = coeff.get("privilege_weight", 0.0)
    bw = coeff.get("behavioural_weight", 0.0)
    iw = coeff.get("identity_weight", 0.0)

    removed = (
        W_PRIV * priv_risk * pw
        + W_BEHAV * behav_risk * bw
        + W_IDENT * ident_risk * iw
    )
    return round(min(removed / final_risk * 100.0, 95.0), 2)


# ---------------------------------------------------------------------------
# RemediationEngine class
# ---------------------------------------------------------------------------


class RemediationEngine:
    """
    Generates one prioritised remediation action per canonical identity (453 total).
    Aligns with Phase 5 attack-path simulations for CRITICAL/HIGH identities.
    """

    def __init__(self, data_dir: Path = DATA_DIR) -> None:
        self.data_dir = data_dir
        self._rs: pd.DataFrame | None = None
        self._inc_map: dict[str, dict] = {}     # canonical_id -> best incident
        self._ap_map: dict[str, dict] = {}      # canonical_id -> attack_path row
        self._top_resource_map: dict[str, str] = {}  # canonical_id -> resource_id

    def load(self) -> "RemediationEngine":
        """Load all input data into memory."""
        # Risk scores — one row per canonical identity (453)
        self._rs = pd.read_csv(self.data_dir / "risk_scores.csv")
        logger.info("risk_scores: %d rows loaded", len(self._rs))

        # Incidents — build highest-severity incident per canonical_id
        SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        inc = pd.read_csv(
            self.data_dir / "incidents.csv",
            usecols=["incident_id", "canonical_id", "incident_type", "severity", "platform"],
        )
        inc_sorted = inc.copy()
        inc_sorted["_sev_rank"] = inc_sorted["severity"].map(SEV_ORDER)
        inc_sorted = inc_sorted.sort_values("_sev_rank")
        for _, row in inc_sorted.drop_duplicates("canonical_id").iterrows():
            self._inc_map[row["canonical_id"]] = row.to_dict()
        logger.info("incidents: %d rows, %d unique canonical_ids", len(inc), len(self._inc_map))

        # Attack paths — one row per CRITICAL/HIGH identity
        ap = pd.read_csv(self.data_dir / "attack_paths.csv")
        for _, row in ap.iterrows():
            self._ap_map[row["canonical_id"]] = row.to_dict()
        logger.info("attack_paths: %d rows loaded", len(ap))

        # Effective privileges — find highest-criticality ADMIN resource per identity
        ui = pd.read_csv(
            self.data_dir / "unified_identities.csv",
            usecols=["identity_id", "canonical_id"],
        )
        id_to_can = dict(zip(ui["identity_id"], ui["canonical_id"]))

        ep = pd.read_csv(
            self.data_dir / "effective_privileges.csv",
            usecols=["identity_id", "resource_id", "privilege_level", "resource_criticality"],
        )
        ep_admin = ep[ep["privilege_level"].isin(["ADMIN", "FULL_CONTROL"])].copy()
        ep_admin["canonical_id"] = ep_admin["identity_id"].map(id_to_can)
        CRIT = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        ep_top = (
            ep_admin.sort_values("resource_criticality", key=lambda s: s.map(CRIT))
            .drop_duplicates("canonical_id")
        )
        self._top_resource_map = dict(
            zip(ep_top["canonical_id"], ep_top["resource_id"])
        )
        logger.info(
            "effective_privileges: %d ADMIN/FULL_CONTROL rows; "
            "%d unique canonical_ids with admin access",
            len(ep_admin), len(self._top_resource_map),
        )
        return self

    def run(self) -> pd.DataFrame:
        """Generate one remediation action per identity. Returns DataFrame (453 rows)."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        rows: list[dict] = []

        for _, rs_row in self._rs.iterrows():
            can = rs_row["canonical_id"]
            risk_tier = rs_row["risk_tier"]
            detection_method = str(rs_row.get("detection_method", "ML_ENSEMBLE"))
            drivers = _parse_drivers(rs_row.get("risk_drivers", "[]"))
            root_cause = str(rs_row.get("root_cause", ""))
            final_risk = float(rs_row["final_risk_score"])
            priv_risk = float(rs_row["privilege_risk_component"])
            behav_risk = float(rs_row["behavioural_risk_component"])
            ident_risk = float(rs_row["identity_risk_component"])
            comp_risk = float(rs_row["compliance_risk_component"])

            # Phase 5 alignment: use attack_path data if available
            ap_row = self._ap_map.get(can)
            ap_action = ap_row["remediation_action"] if ap_row else None

            action_type = _choose_action_type(
                risk_tier, detection_method, drivers, ap_action
            )
            priority = _choose_priority(risk_tier, action_type)

            # Blast-radius and risk reduction
            if ap_row:
                # Exact values from Phase 5 BFS simulation
                blast_radius_reduction = float(ap_row["blast_radius_reduction_pct"])
                estimated_risk_reduction = float(ap_row["risk_reduction_pct"])
            else:
                # No simulation — heuristic only; blast radius not computed
                blast_radius_reduction = 0.0
                estimated_risk_reduction = _estimate_risk_reduction(
                    action_type, priv_risk, behav_risk, ident_risk, comp_risk, final_risk
                )

            justification = _build_justification(
                root_cause, drivers, detection_method, action_type, risk_tier
            )

            # Link to best incident (nullable)
            inc_info = self._inc_map.get(can, {})
            incident_id = inc_info.get("incident_id")  # None if no incident

            # Affected resource (for resource-scoped actions)
            if action_type in ("REVOKE_ROLE", "SCOPE_REDUCTION"):
                affected_resource_id = self._top_resource_map.get(can)
            else:
                affected_resource_id = None  # account-level actions

            row = {
                "action_id": str(uuid.uuid4()),
                "incident_id": incident_id if incident_id else "",
                "identity_id": can,  # canonical_id == identity_id post-resolution
                "canonical_id": can,
                "action_type": action_type,
                "recommended_action": action_type,
                "priority": priority,
                "action_priority": PRIORITY_LABEL[priority],
                "affected_resource_id": affected_resource_id if affected_resource_id else "",
                "estimated_risk_reduction": estimated_risk_reduction,
                "blast_radius_reduction": blast_radius_reduction,
                "justification": justification,
                "estimated_effort": ACTION_EFFORT[action_type],
                "requires_approval": ACTION_REQUIRES_APPROVAL[action_type],
                "compliance_frameworks": "[]",   # populated by ComplianceMapper
                "status": "RECOMMENDED",
                "generated_timestamp": ts,
                "llm_rationale": "",             # populated by LLMNarrativeGenerator
            }
            rows.append(row)

        df = pd.DataFrame(rows)
        logger.info(
            "Generated %d remediation actions: %s",
            len(df),
            df["priority"].value_counts().to_dict(),
        )
        return df

    def save(self, df: pd.DataFrame) -> None:
        """Write remediation_actions.csv."""
        out = self.data_dir / "remediation_actions.csv"
        df.to_csv(out, index=False)
        logger.info("Wrote %s (%d rows)", out, len(df))

    def print_summary(self, df: pd.DataFrame) -> None:
        """Print validation output."""
        print()
        print("=" * 70)
        print("  REMEDIATION ENGINE — Summary")
        print("=" * 70)
        print(f"  Total actions generated      : {len(df)}")
        print()
        print("  action_priority breakdown:")
        for label in ["urgent", "high", "medium", "low"]:
            cnt = (df["action_priority"] == label).sum()
            pct = cnt / len(df) * 100
            print(f"    {label:<10} {cnt:>4}  ({pct:.1f}%)")
        print()
        print("  action_type breakdown:")
        for act, cnt in df["action_type"].value_counts().items():
            print(f"    {act:<30} {cnt}")
        print()
        print("  Identities aligned with Phase 5 attack paths :", len(self._ap_map))
        print("  Identities using heuristic reduction estimate :",
              len(df) - len(self._ap_map))
        print()
        print("  estimated_risk_reduction (pct):")
        print(f"    min={df['estimated_risk_reduction'].min():.1f}  "
              f"mean={df['estimated_risk_reduction'].mean():.1f}  "
              f"max={df['estimated_risk_reduction'].max():.1f}")
        print()
        p1 = df[df["priority"] == "P1"].iloc[0]
        print("  Sample P1 (urgent) action:")
        print(f"    canonical_id     : {p1['canonical_id']}")
        print(f"    action_type      : {p1['action_type']}")
        print(f"    justification    : {p1['justification'][:120]}...")
        print(f"    requires_approval: {p1['requires_approval']}")
        print(f"    risk_reduction   : {p1['estimated_risk_reduction']:.1f}%")
        print(f"    blast_reduction  : {p1['blast_radius_reduction']:.1f}%")
        print("=" * 70)
        print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Identity Nexus AI -- Phase 6: Remediation Engine"
    )
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s -- %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )

    engine = RemediationEngine(data_dir=Path(args.data_dir))
    engine.load()
    df = engine.run()
    engine.save(df)
    engine.print_summary(df)


if __name__ == "__main__":
    main()
