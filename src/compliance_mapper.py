"""
src/compliance_mapper.py
Identity Nexus AI — Phase 6: Compliance Mapper

Single responsibility: map every incident and remediation action to the
specific control IDs it violates or satisfies across four compliance
frameworks (MITRE ATT&CK, NIST 800-53 Rev 5, CIS Controls v8, GDPR).

DESIGN PRINCIPLE — AUDITABILITY FIRST
======================================
All mapping logic is declared in two lookup tables at the top of this
module (INCIDENT_COMPLIANCE_MAP and REMEDIATION_COMPLIANCE_MAP) so that
the mappings are fully auditable by a compliance officer without reading
code logic. No framework ID is buried in if/else branches.

The mapping is deterministic: same incident_type and action_type always
produce the same set of control IDs.

OUTPUTS
=======
    generated_data/incidents.csv           — in-place update: adds/replaces compliance_tags
    generated_data/remediation_actions.csv — in-place update: adds/replaces compliance_frameworks
    generated_data/compliance_mappings.csv — standalone audit table (new file):
        one row per (incident_id OR action_id) × framework × control_id

MUST NOT read ground_truth_labels.csv.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "generated_data"

# ---------------------------------------------------------------------------
# INCIDENT COMPLIANCE MAP
# ---------------------------------------------------------------------------
# Key: incident_type string
# Value: dict mapping framework abbreviation to list of specific control IDs
#
# MITRE ATT&CK technique IDs  — https://attack.mitre.org
# NIST 800-53 Rev 5 control IDs — https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
# CIS Controls v8 sub-control IDs — https://www.cisecurity.org/controls/v8
# GDPR article references — https://gdpr-info.eu
#
# Rationale for each mapping is documented in the "rationale" list below each
# entry (for compliance-officer review; not written to output).
# ---------------------------------------------------------------------------

INCIDENT_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    "ORPHANED_ACCOUNT": {
        "MITRE": [
            "T1078",        # Valid Accounts — orphaned account still has valid creds
            "T1078.001",    # Default Accounts — often left with default permissions
            "T1098",        # Account Manipulation — stale accounts can be hijacked
        ],
        "NIST": [
            "AC-2",         # Account Management — failure to disable departed user
            "AC-2(1)",      # Automated Account Management — process gap
            "AC-2(3)",      # Disable Inactive Accounts — accounts not terminated
            "IA-4",         # Identifier Management — identity lifecycle failure
            "IA-5(7)",      # Password-Based Authentication — stale credentials
        ],
        "CIS": [
            "5.1",          # Establish & Maintain Inventory of Enterprise Accounts
            "5.3",          # Disable Dormant Accounts — directly applicable
            "6.2",          # Establish an Access Revoking Process
        ],
        "GDPR": [
            "Art.5(1)(e)",  # Storage limitation — data still accessible post-departure
            "Art.32",       # Security of processing — inadequate account controls
        ],
    },

    "DORMANT_ADMIN": {
        "MITRE": [
            "T1078",        # Valid Accounts — dormant admin still has valid session
            "T1078.002",    # Domain Accounts — stale privileged domain account
            "T1098",        # Account Manipulation — dormant accounts targeted by attackers
        ],
        "NIST": [
            "AC-2",         # Account Management
            "AC-2(3)",      # Disable Inactive Accounts — 90+ day inactivity threshold
            "AC-6",         # Least Privilege — dormant admin violates least-privilege
            "IA-5",         # Authenticator Management — stale credential risk
        ],
        "CIS": [
            "5.3",          # Disable Dormant Accounts
            "5.4",          # Restrict Administrator Privileges — dormant admins
            "6.8",          # Define and Maintain Role-Based Access Control
        ],
        "GDPR": [
            "Art.5(1)(f)",  # Integrity and confidentiality — admin access without need
            "Art.32",       # Security of processing
        ],
    },

    "PRIVILEGE_ABUSE": {
        "MITRE": [
            "T1078",        # Valid Accounts
            "T1548",        # Abuse Elevation Control Mechanism
            "T1134",        # Access Token Manipulation
        ],
        "NIST": [
            "AC-6",         # Least Privilege
            "AC-6(1)",      # Authorize Access to Security Functions
            "AC-6(9)",      # Log Use of Privileged Functions
            "AU-2",         # Audit Events — privilege use must be logged
            "AU-12",        # Audit Record Generation
        ],
        "CIS": [
            "5.4",          # Restrict Administrator Privileges
            "6.7",          # Centralize Access Control
            "6.8",          # Role-Based Access Control
            "8.5",          # Collect Detailed Audit Logs
        ],
        "GDPR": [
            "Art.5(1)(f)",  # Integrity and confidentiality
            "Art.32",       # Security of processing
        ],
    },

    "LATERAL_MOVEMENT": {
        "MITRE": [
            "T1550",        # Use Alternate Authentication Material
            "T1021",        # Remote Services
            "T1484",        # Domain Policy Modification
            "T1563",        # Remote Service Session Hijacking
        ],
        "NIST": [
            "AC-4",         # Information Flow Enforcement
            "AC-17",        # Remote Access
            "SC-7",         # Boundary Protection
            "SI-4",         # System Monitoring — detect movement
        ],
        "CIS": [
            "4.1",          # Establish and Maintain Secure Configuration
            "12.1",         # Ensure Network Infrastructure Is Up-to-Date
            "13.1",         # Centralise Security Event Alerting
        ],
        "GDPR": [
            "Art.32",       # Security of processing
            "Art.33",       # Notification of breach to supervisory authority
        ],
    },

    "DATA_EXFIL": {
        "MITRE": [
            "T1567",        # Exfiltration Over Web Service
            "T1048",        # Exfiltration Over Alternative Protocol
            "T1530",        # Data from Cloud Storage Object
            "T1020",        # Automated Exfiltration
        ],
        "NIST": [
            "AC-4",         # Information Flow Enforcement
            "AU-12",        # Audit Record Generation
            "SC-7",         # Boundary Protection
            "SI-4",         # System Monitoring
        ],
        "CIS": [
            "3.1",          # Establish and Maintain Data Management Process
            "3.6",          # Encrypt Data on End-User Devices
            "13.1",         # Centralise Security Event Alerting
            "13.6",         # Collect Network Traffic Flow Logs
        ],
        "GDPR": [
            "Art.5(1)(f)",  # Integrity and confidentiality
            "Art.32",       # Security of processing
            "Art.33",       # Notification of breach to supervisory authority
            "Art.34",       # Communication of breach to data subjects
        ],
    },

    "SOD_VIOLATION": {
        "MITRE": [
            "T1078",        # Valid Accounts — dual-role abuse
            "T1548.002",    # Bypass User Account Control
        ],
        "NIST": [
            "AC-5",         # Separation of Duties — direct control violation
            "AC-6",         # Least Privilege
            "AC-2",         # Account Management — provisioning control failure
        ],
        "CIS": [
            "5.4",          # Restrict Administrator Privileges
            "6.8",          # Role-Based Access Control
            "14.6",         # Protect Information Through Access Control Lists
        ],
        "GDPR": [
            "Art.5(1)(f)",  # Integrity and confidentiality
            "Art.32",       # Security of processing
        ],
    },

    "BEHAVIORAL_OUTLIER": {
        "MITRE": [
            "T1078",        # Valid Accounts — statistical outlier with no dominant pattern
            "T1133",        # External Remote Services
            "T1110",        # Brute Force — outlier may indicate credential anomaly
        ],
        "NIST": [
            "AC-17",        # Remote Access
            "IA-3",         # Device Identification and Authentication
            "SI-4",         # System Monitoring
        ],
        "CIS": [
            "6.3",          # Require MFA for all user accounts
            "12.6",         # Use of Secure Network Management and Communication Protocols
            "13.1",         # Centralise Security Event Alerting
        ],
        "GDPR": [
            "Art.32",       # Security of processing
        ],
    },
}

# ---------------------------------------------------------------------------
# REMEDIATION ACTION COMPLIANCE MAP
# ---------------------------------------------------------------------------
# Key: action_type string
# Value: list of framework control IDs this action satisfies (i.e. brings
#        the organisation into compliance with these controls).
# Format: "<FRAMEWORK>-<CONTROL_ID>" for unambiguous identification
# ---------------------------------------------------------------------------

REMEDIATION_COMPLIANCE_MAP: dict[str, list[str]] = {
    "REVOKE_ROLE": [
        "NIST-AC-6",         # Least Privilege — role revocation enforces it
        "NIST-AC-6(1)",      # Authorize Access to Security Functions
        "CIS-5.4",           # Restrict Administrator Privileges
        "CIS-6.8",           # Role-Based Access Control
        "ISO-A.9.2.2",       # User Access Provisioning (ISO 27001:2013)
        "ISO-A.9.2.5",       # Review of User Access Rights
        "SOX-ITGC-AC",       # SOX IT General Controls — Access Control
    ],
    "DISABLE_ACCOUNT": [
        "NIST-AC-2",         # Account Management — terminate orphaned accounts
        "NIST-AC-2(3)",      # Disable Inactive Accounts
        "NIST-IA-4",         # Identifier Management
        "CIS-5.1",           # Establish Account Inventory
        "CIS-5.3",           # Disable Dormant Accounts
        "CIS-6.2",           # Establish Access Revoking Process
        "ISO-A.9.2.6",       # Removal or Adjustment of Access Rights
        "SOX-ITGC-AC",       # SOX IT General Controls — Access Control
    ],
    "ENFORCE_MFA": [
        "NIST-IA-2",         # Identification and Authentication — MFA requirement
        "NIST-IA-2(1)",      # Multi-Factor Authentication (Privileged Accounts)
        "NIST-IA-2(2)",      # Multi-Factor Authentication (Non-Privileged)
        "CIS-6.3",           # Require MFA for All User Accounts
        "ISO-A.9.4.2",       # Secure Log-on Procedures
        "SOC2-CC6.1",        # Logical and Physical Access Controls
    ],
    "REMOVE_GROUP": [
        "NIST-AC-6",         # Least Privilege — remove unneeded group membership
        "NIST-AC-6(1)",      # Authorize Access to Security Functions
        "CIS-5.4",           # Restrict Administrator Privileges
        "CIS-6.8",           # Role-Based Access Control
        "ISO-A.9.2.2",       # User Access Provisioning
    ],
    "SCOPE_REDUCTION": [
        "NIST-AC-6",         # Least Privilege — downgrade from ADMIN to READ
        "NIST-AC-6(1)",      # Authorize Access to Security Functions
        "CIS-5.4",           # Restrict Administrator Privileges
        "ISO-A.9.2.5",       # Review of User Access Rights
        "SOX-ITGC-AC",       # SOX IT General Controls — Access Control
    ],
    "REQUIRE_RECERTIFICATION": [
        "NIST-AC-2(9)",      # Account Management — Periodic Review
        "NIST-AC-5",         # Separation of Duties — certification validates segregation
        "CIS-5.1",           # Establish Account Inventory
        "CIS-6.1",           # Establish Access Granting Process
        "ISO-A.9.2.5",       # Review of User Access Rights
        "SOC2-CC6.3",        # Internal Control over Access — periodic review
    ],
}

# ---------------------------------------------------------------------------
# ComplianceMapper class
# ---------------------------------------------------------------------------


class ComplianceMapper:
    """
    Maps incidents and remediation actions to compliance control IDs.
    Enriches incidents.csv and remediation_actions.csv in-place.
    Also writes compliance_mappings.csv as a standalone audit table.
    """

    def __init__(self, data_dir: Path = DATA_DIR) -> None:
        self.data_dir = data_dir
        self._inc: pd.DataFrame | None = None
        self._act: pd.DataFrame | None = None

    def load(self) -> "ComplianceMapper":
        """Load incidents and remediation actions."""
        self._inc = pd.read_csv(self.data_dir / "incidents.csv")
        self._act = pd.read_csv(self.data_dir / "remediation_actions.csv")
        logger.info(
            "Loaded: incidents=%d rows, remediation_actions=%d rows",
            len(self._inc), len(self._act),
        )
        return self

    def _map_incident(self, incident_type: str) -> list[str]:
        """
        Return compliance tag list for a given incident_type.
        Format: "<FRAMEWORK>:<CONTROL_ID>" — unambiguous in UI and exports.
        """
        mapping = INCIDENT_COMPLIANCE_MAP.get(incident_type, {})
        tags: list[str] = []
        for framework, controls in mapping.items():
            for ctrl in controls:
                tags.append(f"{framework}:{ctrl}")
        return tags

    def _map_action(self, action_type: str) -> list[str]:
        """Return compliance framework list for a given action_type."""
        return REMEDIATION_COMPLIANCE_MAP.get(action_type, [])

    def run(self) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Enrich incidents and remediation actions with compliance mappings.
        Returns (incidents_df, actions_df, audit_table_df).
        """
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        audit_rows: list[dict] = []

        # --- Enrich incidents ---
        inc_tags: list[str] = []
        for _, row in self._inc.iterrows():
            tags = self._map_incident(row["incident_type"])
            inc_tags.append(json.dumps(tags))
            for tag in tags:
                framework, ctrl = tag.split(":", 1)
                audit_rows.append({
                    "mapping_id": str(uuid.uuid4()),
                    "source_type": "INCIDENT",
                    "source_id": row["incident_id"],
                    "canonical_id": row.get("canonical_id", ""),
                    "incident_type": row["incident_type"],
                    "action_type": "",
                    "framework": framework,
                    "control_id": ctrl,
                    "tag": tag,
                    "mapped_timestamp": ts,
                })

        self._inc = self._inc.copy()
        self._inc["compliance_tags"] = inc_tags

        # --- Enrich remediation actions ---
        act_frameworks: list[str] = []
        for _, row in self._act.iterrows():
            frameworks = self._map_action(row["action_type"])
            act_frameworks.append(json.dumps(frameworks))
            for fw in frameworks:
                parts = fw.split("-", 1)
                framework = parts[0] if parts else fw
                ctrl = parts[1] if len(parts) > 1 else fw
                audit_rows.append({
                    "mapping_id": str(uuid.uuid4()),
                    "source_type": "ACTION",
                    "source_id": row["action_id"],
                    "canonical_id": row.get("canonical_id", ""),
                    "incident_type": "",
                    "action_type": row["action_type"],
                    "framework": framework,
                    "control_id": ctrl,
                    "tag": fw,
                    "mapped_timestamp": ts,
                })

        self._act = self._act.copy()
        self._act["compliance_frameworks"] = act_frameworks

        audit_df = pd.DataFrame(audit_rows)
        logger.info(
            "Compliance mappings: %d incident tags, %d action framework entries, "
            "%d audit rows total",
            self._inc["compliance_tags"].apply(lambda x: len(json.loads(x))).sum(),
            self._act["compliance_frameworks"].apply(lambda x: len(json.loads(x))).sum(),
            len(audit_df),
        )
        return self._inc, self._act, audit_df

    def save(
        self,
        inc_df: pd.DataFrame,
        act_df: pd.DataFrame,
        audit_df: pd.DataFrame,
    ) -> None:
        """Write all three outputs."""
        inc_path = self.data_dir / "incidents.csv"
        inc_df.to_csv(inc_path, index=False)
        logger.info("Updated incidents.csv (%d rows)", len(inc_df))

        act_path = self.data_dir / "remediation_actions.csv"
        act_df.to_csv(act_path, index=False)
        logger.info("Updated remediation_actions.csv (%d rows)", len(act_df))

        audit_path = self.data_dir / "compliance_mappings.csv"
        audit_df.to_csv(audit_path, index=False)
        logger.info("Wrote compliance_mappings.csv (%d rows)", len(audit_df))

    def print_summary(
        self,
        inc_df: pd.DataFrame,
        act_df: pd.DataFrame,
        audit_df: pd.DataFrame,
    ) -> None:
        """Print validation output."""
        # Count findings with at least one mapping
        inc_mapped = (
            inc_df["compliance_tags"]
            .apply(lambda x: len(json.loads(x)) > 0)
            .sum()
        )
        act_mapped = (
            act_df["compliance_frameworks"]
            .apply(lambda x: len(json.loads(x)) > 0)
            .sum()
        )

        print()
        print("=" * 70)
        print("  COMPLIANCE MAPPER — Summary")
        print("=" * 70)
        print(f"  Incidents with >= 1 mapping  : {inc_mapped}/{len(inc_df)}")
        print(f"  Actions with >= 1 framework  : {act_mapped}/{len(act_df)}")
        print(f"  Total audit rows             : {len(audit_df)}")
        print()
        print("  Audit rows by framework:")
        for fw, cnt in audit_df["framework"].value_counts().items():
            print(f"    {fw:<8} {cnt}")
        print()

        # Show 2 full example incident mappings
        print("  EXAMPLE MAPPING 1 — ORPHANED_ACCOUNT incident:")
        orphan = inc_df[inc_df["incident_type"] == "ORPHANED_ACCOUNT"]
        if not orphan.empty:
            row = orphan.iloc[0]
            tags = json.loads(row["compliance_tags"])
            print(f"    canonical_id   : {row['canonical_id']}")
            print(f"    incident_type  : {row['incident_type']}")
            print(f"    detection_method: {row['detection_method']}")
            print(f"    compliance_tags: {tags}")
        print()

        dormant = inc_df[inc_df["incident_type"] == "DORMANT_ADMIN"]
        if not dormant.empty:
            row = dormant.iloc[0]
            tags = json.loads(row["compliance_tags"])
            print("  EXAMPLE MAPPING 2 — DORMANT_ADMIN incident:")
            print(f"    canonical_id   : {row['canonical_id']}")
            print(f"    incident_type  : {row['incident_type']}")
            print(f"    detection_method: {row['detection_method']}")
            print(f"    compliance_tags: {tags}")
        print("=" * 70)
        print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Identity Nexus AI -- Phase 6: Compliance Mapper"
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

    mapper = ComplianceMapper(data_dir=Path(args.data_dir))
    mapper.load()
    inc_df, act_df, audit_df = mapper.run()
    mapper.save(inc_df, act_df, audit_df)
    mapper.print_summary(inc_df, act_df, audit_df)


if __name__ == "__main__":
    main()
