"""
src/anomaly_injector.py
Identity Nexus AI — Phase 2: Anomaly Injection Framework

Separated from data_simulator.py so injection logic is independently auditable,
testable, and rate-tunable without touching generation code.

EVALUATION-ONLY CONTRACT
========================
get_ground_truth_df() produces ground_truth_labels.csv.
This file MUST NOT be read by any analytics pipeline module (Phases 3-9):
  identity_resolver, graph_builder, effective_privilege_engine,
  feature_engineering, anomaly_detection, risk_scoring,
  incident_clustering, attack_path_simulator, remediation_engine,
  compliance_mapper, llm_narrative_generator, main, app.

It is consumed ONLY in Phase 10 for precision/recall evaluation.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ── Anomaly type registry ─────────────────────────────────────────────────────

ANOMALY_TYPES: Dict[str, Dict] = {
    "ORPHANED_ACCOUNT": {
        "description": "Offboarded identity; AD/AzureAD disabled but ≥1 other platform still active",
        "true_positive": True,
        "target_rate_key": "orphaned_accounts",
    },
    "OVERPRIVILEGED": {
        "description": "Admin roles assigned on ≥2 platforms simultaneously without justification",
        "true_positive": True,
        "target_rate_key": "overprivileged_users",
    },
    "PRIVILEGE_ESCALATION": {
        "description": "Role escalated within audit window; no ticket_id or approval record",
        "true_positive": True,
        "target_rate_key": "privilege_escalations",
    },
    "TOKEN_ABUSE": {
        "description": "Abnormal API call volume/pattern: burst at off-hours from atypical source IPs",
        "true_positive": True,
        "target_rate_key": "token_abuse",
    },
    "DORMANT_ADMIN": {
        "description": "Privileged role assigned; no login activity in 90+ days",
        "true_positive": True,
        "target_rate_key": "dormant_admins",
    },
    "LEGITIMATE_EXCEPTION": {
        "description": (
            "Looks anomalous (elevated access, off-hours activity) but carries valid "
            "ticket_id/approval_date/expiry_date. False-positive trap for ML models."
        ),
        "true_positive": False,
        "target_rate_key": "legitimate_exceptions",
    },
}

# Ordered assignment sequence — categories are selected from the unassigned pool
# in this order so percentages don't fight each other.
ASSIGNMENT_ORDER = [
    "ORPHANED_ACCOUNT",
    "OVERPRIVILEGED",
    "PRIVILEGE_ESCALATION",
    "TOKEN_ABUSE",
    "DORMANT_ADMIN",
    "LEGITIMATE_EXCEPTION",
]


@dataclass
class AnomalyProfile:
    """Describes one canonical identity's anomaly assignment."""

    identity_id: str
    anomaly_type: Optional[str]   # None → NORMAL (no injected anomaly)
    is_anomalous: bool             # False for NORMAL and LEGITIMATE_EXCEPTION
    subtype: str = ""             # e.g. "cross_platform_admin", "api_token_burst"
    details: Dict = field(default_factory=dict)  # free-form injection details


class AnomalyInjector:
    """
    Manages all anomaly injection categories for Identity Nexus AI Phase 2.

    Usage pattern
    -------------
    1. Instantiate with a seeded RNG and rate config.
    2. Call assign_profiles(person_ids) once after the canonical person list is
       finalised — this partitions identities into anomaly buckets.
    3. Pass the injector instance into each generator (platform accounts, group
       mappings, role mappings, audit events, resource logs, offboarding) so
       each generator can query the profile and skew its output accordingly.
    4. After all data is generated, call get_ground_truth_df() to export labels.

    The injector does NOT modify DataFrames itself — it only answers queries.
    Modification is delegated to the calling generator methods so data
    generation logic stays in data_simulator.py.
    """

    def __init__(self, rng: np.random.Generator, rates: Dict[str, float]) -> None:
        """
        Parameters
        ----------
        rng:   seeded numpy Generator (shared with data_simulator for reproducibility)
        rates: dict mapping rate keys (e.g. "orphaned_accounts") to fractions [0,1]
        """
        self.rng = rng
        self.rates = rates
        self._profiles: Dict[str, AnomalyProfile] = {}

    # ── Assignment ────────────────────────────────────────────────────────────

    def assign_profiles(self, person_ids: List[str]) -> None:
        """
        Partition person_ids into anomaly categories using the configured rates.

        Each person receives at most one primary anomaly type.  Remaining
        persons are labelled NORMAL (anomaly_type=None, is_anomalous=False).

        The assignment is deterministic given the shared RNG seed.
        """
        ids = list(person_ids)
        n = len(ids)
        self.rng.shuffle(ids)          # shuffle so selection isn't positional

        unassigned: List[str] = list(ids)
        assigned: Set[str] = set()

        for atype in ASSIGNMENT_ORDER:
            meta = ANOMALY_TYPES[atype]
            rate = self.rates.get(meta["target_rate_key"], 0.0)
            count = max(1, int(round(n * rate)))
            # take 'count' from the front of unassigned
            cohort = [iid for iid in unassigned if iid not in assigned][:count]

            for iid in cohort:
                self._profiles[iid] = AnomalyProfile(
                    identity_id=iid,
                    anomaly_type=atype,
                    is_anomalous=meta["true_positive"],
                    subtype=self._default_subtype(atype),
                    details={},
                )
                assigned.add(iid)

            logger.debug(
                "Assigned %d identities to anomaly type %s (target rate %.1f%%)",
                len(cohort), atype, rate * 100,
            )

        # all remaining → NORMAL
        for iid in ids:
            if iid not in assigned:
                self._profiles[iid] = AnomalyProfile(
                    identity_id=iid,
                    anomaly_type=None,
                    is_anomalous=False,
                )

        counts = self._count_by_type()
        logger.info(
            "Anomaly assignment complete: %d total | %s",
            n,
            " | ".join(f"{k}={v}" for k, v in counts.items()),
        )

    def _default_subtype(self, atype: str) -> str:
        subtypes = {
            "ORPHANED_ACCOUNT": "active_on_cloud_after_offboard",
            "OVERPRIVILEGED": "cross_platform_admin",
            "PRIVILEGE_ESCALATION": "no_ticket_role_change",
            "TOKEN_ABUSE": "api_token_burst_offhours",
            "DORMANT_ADMIN": "privileged_no_login_90d",
            "LEGITIMATE_EXCEPTION": "authorized_temp_elevated_access",
        }
        return subtypes.get(atype, "")

    # ── Query interface (used by generator methods) ───────────────────────────

    def get_profile(self, identity_id: str) -> AnomalyProfile:
        """Return the AnomalyProfile for a person, defaulting to NORMAL."""
        return self._profiles.get(
            identity_id,
            AnomalyProfile(identity_id=identity_id, anomaly_type=None, is_anomalous=False),
        )

    def is_anomalous(self, identity_id: str) -> bool:
        return self.get_profile(identity_id).is_anomalous

    def anomaly_type(self, identity_id: str) -> Optional[str]:
        return self.get_profile(identity_id).anomaly_type

    def ids_with_type(self, atype: str) -> List[str]:
        return [iid for iid, p in self._profiles.items() if p.anomaly_type == atype]

    def ids_for_types(self, *atypes: str) -> Set[str]:
        return {iid for iid, p in self._profiles.items() if p.anomaly_type in atypes}

    def all_anomalous_ids(self) -> Set[str]:
        return {iid for iid, p in self._profiles.items() if p.is_anomalous}

    # ── Helpers for generators ────────────────────────────────────────────────

    def should_disable_on_platform(self, identity_id: str, platform: str) -> bool:
        """
        For ORPHANED_ACCOUNT: AD and AzureAD accounts are disabled (is_active=False),
        while cloud platform accounts (AWS, Okta, Salesforce) remain active.
        This creates the cross-platform orphan signal.
        """
        if self.anomaly_type(identity_id) != "ORPHANED_ACCOUNT":
            return False
        return platform in ("AD", "AzureAD")

    def should_clear_last_login(self, identity_id: str) -> bool:
        """
        DORMANT_ADMIN identities have no recent login (last_login set to null or
        120-400 days ago during account generation).
        """
        return self.anomaly_type(identity_id) == "DORMANT_ADMIN"

    def needs_extra_admin_roles(self, identity_id: str) -> bool:
        """OVERPRIVILEGED identities receive admin roles on multiple platforms."""
        return self.anomaly_type(identity_id) == "OVERPRIVILEGED"

    def needs_escalation_event(self, identity_id: str) -> bool:
        """PRIVILEGE_ESCALATION identities get a PRIVILEGE_ESCALATION audit event."""
        return self.anomaly_type(identity_id) == "PRIVILEGE_ESCALATION"

    def needs_token_abuse_pattern(self, identity_id: str) -> bool:
        """TOKEN_ABUSE identities get burst resource access at unusual hours."""
        return self.anomaly_type(identity_id) == "TOKEN_ABUSE"

    def needs_offboarding(self, identity_id: str) -> bool:
        """ORPHANED_ACCOUNT identities must have an offboarding record."""
        return self.anomaly_type(identity_id) == "ORPHANED_ACCOUNT"

    def needs_legitimate_exception_ticket(self, identity_id: str) -> bool:
        """
        LEGITIMATE_EXCEPTION identities receive a ticket_id and expiry_date on their
        elevated role assignments — making them look risky but justified.
        """
        return self.anomaly_type(identity_id) == "LEGITIMATE_EXCEPTION"

    # ── Ground-truth export ───────────────────────────────────────────────────

    def get_ground_truth_df(self) -> pd.DataFrame:
        """
        Return a DataFrame of ground-truth anomaly labels for all identities.

        EVALUATION-ONLY — write to generated_data/ground_truth_labels.csv.
        Must never be read by any analytics pipeline module.

        Columns
        -------
        identity_id             : canonical person identity_id
        ground_truth_anomaly_type : ORPHANED_ACCOUNT / OVERPRIVILEGED /
                                    PRIVILEGE_ESCALATION / TOKEN_ABUSE /
                                    DORMANT_ADMIN / LEGITIMATE_EXCEPTION / NORMAL
        ground_truth_is_anomalous : True only for true-positive anomaly types
        anomaly_subtype         : finer-grained label for evaluation slicing
        injection_details       : JSON blob with what was modified
        """
        rows = []
        for iid, p in self._profiles.items():
            rows.append({
                "identity_id": iid,
                "ground_truth_anomaly_type": p.anomaly_type if p.anomaly_type else "NORMAL",
                "ground_truth_is_anomalous": p.is_anomalous,
                "anomaly_subtype": p.subtype,
                "injection_details": json.dumps(p.details),
            })
        return pd.DataFrame(rows)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"NORMAL": 0}
        for atype in ANOMALY_TYPES:
            counts[atype] = 0
        for p in self._profiles.values():
            key = p.anomaly_type if p.anomaly_type else "NORMAL"
            counts[key] = counts.get(key, 0) + 1
        return counts

    def summary(self) -> str:
        """Return a human-readable summary string for logging."""
        total = len(self._profiles)
        lines = [f"Anomaly injection summary ({total} identities):"]
        for atype, meta in ANOMALY_TYPES.items():
            ids = self.ids_with_type(atype)
            pct = len(ids) / total * 100 if total else 0
            true_label = "TRUE POSITIVE" if meta["true_positive"] else "FALSE-POSITIVE TRAP"
            lines.append(f"  {atype:28s} {len(ids):4d} ({pct:5.1f}%)  [{true_label}]")
        normal_n = sum(1 for p in self._profiles.values() if not p.anomaly_type)
        lines.append(f"  {'NORMAL':28s} {normal_n:4d} ({normal_n/total*100:5.1f}%)")
        return "\n".join(lines)
