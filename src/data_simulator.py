"""
src/data_simulator.py
Identity Nexus AI — Phase 2: Synthetic Data Simulator

Generates all raw foundational CSVs consumed by the downstream pipeline.
Strictly conforms to schemas in architecture.md and data_dictionary.md.

Implementation notes (spec gaps resolved — see data_dictionary.md for updates):
  1. Platform set: AD, AzureAD, AWS, Okta, Salesforce (5 per Phase 2 task,
     superseding the 6-platform list in architecture.md §1 for this phase).
  2. Per-platform raw CSVs (ad_identities.csv etc.) are written alongside
     unified_identities.csv so IdentityResolver (Phase 3) has real fuzzy-
     matching work. Not in Phase 1 spec — Phase 2 artefacts.
  3. Supplementary reference files added (needed by GraphBuilder, Phase 4):
       generated_data/group_definitions.csv — group catalog + nesting hierarchy
       generated_data/role_definitions.csv  — role catalog + permission scope
  4. Schema extensions (documented in data_dictionary.md §Updates):
       role_mappings.csv  → + ticket_id, + approval_date, + approver_id
       audit_events.csv   → + ticket_id
     These exist in ALL rows; populated only for LEGITIMATE_EXCEPTION and
     some authorised elevated assignments.
  5. unified_identities.csv at Phase 2 has one row per platform account.
     canonical_id = identity_id (pre-resolution). IdentityResolver updates
     canonical_id to group matched accounts in Phase 3.
  6. Ground-truth labels are in ground_truth_labels.csv ONLY — never read by
     the analytics pipeline (evaluation use in Phase 10 only).

Run:
    python src/data_simulator.py
    python src/data_simulator.py --n_identities 300 --seed 7 --output_dir ./generated_data
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random as _stdlib_random
import sys
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd
from faker import Faker

# Module-level seeded PRNG for deterministic ID generation.
# Seeded in DataSimulator.__init__ before any uid/gid/rid/res_id calls.
# Must be module-level so the standalone helper functions can access it.
_uuid_rng = _stdlib_random.Random()

# ── Path bootstrap so anomaly_injector can be imported from same dir ──────────
_SRC_DIR = Path(__file__).parent
sys.path.insert(0, str(_SRC_DIR))
from anomaly_injector import AnomalyInjector  # noqa: E402

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("data_simulator")

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — all tunable parameters; override via CLI or direct edit
# ──────────────────────────────────────────────────────────────────────────────
CONFIG: Dict[str, Any] = {
    "seed": 42,
    "n_identities": 400,          # canonical human identities to generate
    "n_service_accounts": 55,     # service/machine accounts (added on top of humans)
    "output_dir": str(Path(__file__).parent.parent / "generated_data"),
    "reference_date": date(2026, 6, 20),   # simulation "today"
    "audit_window_months": 12,             # audit events span this far back
    "org_domain": "corp.nexusai.com",
    "aws_account_id": "123456789012",
    "sf_org_id": "00D000000000001EAA",
    "okta_domain": "nexusai.okta.com",
    "ad_domain": "corp.nexusai.com",
    "ad_domain_dn": "DC=corp,DC=nexusai,DC=com",
    "azure_tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "platform_coverage": {   # probability each human gets an account here
        "AD":         0.92,
        "AzureAD":    0.87,
        "AWS":        0.40,
        "Okta":       0.76,
        "Salesforce": 0.30,
    },
    "anomaly_rates": {
        "orphaned_accounts":     0.12,
        "overprivileged_users":  0.10,
        "privilege_escalations": 0.06,
        "token_abuse":           0.04,
        "dormant_admins":        0.07,
        "legitimate_exceptions": 0.17,
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# STATIC CATALOGS
# ──────────────────────────────────────────────────────────────────────────────

DEPARTMENTS = [
    "Engineering", "Finance", "HR", "Legal", "Marketing",
    "Operations", "Security", "Sales", "IT-Operations", "Executive",
]

JOB_TITLES: Dict[str, List[str]] = {
    "Engineering":    ["Software Engineer", "Senior Software Engineer", "Principal Engineer",
                       "Engineering Manager", "DevOps Engineer", "Data Engineer", "QA Engineer"],
    "Finance":        ["Financial Analyst", "Senior Financial Analyst", "Finance Manager",
                       "Controller", "Accountant", "Treasury Analyst"],
    "HR":             ["HR Specialist", "HR Business Partner", "HR Manager",
                       "Talent Acquisition Specialist", "Compensation Analyst"],
    "Legal":          ["Legal Counsel", "Senior Legal Counsel", "Paralegal",
                       "Compliance Officer", "Contract Specialist"],
    "Marketing":      ["Marketing Analyst", "Content Strategist", "Marketing Manager",
                       "Demand Generation Manager", "Brand Specialist"],
    "Operations":     ["Operations Analyst", "Process Engineer", "Operations Manager",
                       "Supply Chain Analyst", "Business Operations Specialist"],
    "Security":       ["Security Analyst", "Senior Security Analyst", "Security Engineer",
                       "IAM Engineer", "Threat Intelligence Analyst", "Incident Responder"],
    "Sales":          ["Account Executive", "Sales Development Rep", "Sales Manager",
                       "Enterprise Account Executive", "Regional Sales Director"],
    "IT-Operations":  ["IT Support Specialist", "Systems Administrator", "Network Engineer",
                       "IT Manager", "Infrastructure Engineer", "Cloud Engineer"],
    "Executive":      ["CEO", "CTO", "CFO", "CISO", "COO", "VP Engineering",
                       "SVP Finance", "VP Sales"],
}

GEO_LOCATIONS = ["US-East", "US-West", "EU-West", "EU-Central", "APAC", "LATAM"]

GEO_IP_RANGES: Dict[str, str] = {
    "US-East":   "10.10",
    "US-West":   "10.11",
    "EU-West":   "10.20",
    "EU-Central":"10.21",
    "APAC":      "10.30",
    "LATAM":     "10.40",
}

ANOMALOUS_IPS = [
    "185.220.101", "94.102.49", "45.142.212",
    "185.156.73",  "176.10.104", "92.118.160",
]

RESOURCE_CATALOG: List[Dict] = [
    # AWS
    {"name": "prod-s3-finance",          "type": "S3_BUCKET",   "criticality": "CRITICAL", "platform": "AWS"},
    {"name": "prod-s3-engineering",      "type": "S3_BUCKET",   "criticality": "HIGH",     "platform": "AWS"},
    {"name": "prod-s3-hr",               "type": "S3_BUCKET",   "criticality": "CRITICAL", "platform": "AWS"},
    {"name": "dev-s3-sandbox",           "type": "S3_BUCKET",   "criticality": "LOW",      "platform": "AWS"},
    {"name": "backup-s3-all",            "type": "S3_BUCKET",   "criticality": "HIGH",     "platform": "AWS"},
    {"name": "prod-rds-finance",         "type": "DATABASE",    "criticality": "CRITICAL", "platform": "AWS"},
    {"name": "prod-rds-customers",       "type": "DATABASE",    "criticality": "CRITICAL", "platform": "AWS"},
    {"name": "dev-rds-engineering",      "type": "DATABASE",    "criticality": "MEDIUM",   "platform": "AWS"},
    {"name": "prod-ec2-webserver",       "type": "COMPUTE",     "criticality": "HIGH",     "platform": "AWS"},
    {"name": "prod-ec2-appserver",       "type": "COMPUTE",     "criticality": "HIGH",     "platform": "AWS"},
    {"name": "dev-ec2-sandbox",          "type": "COMPUTE",     "criticality": "LOW",      "platform": "AWS"},
    {"name": "aws-secrets-prod-keys",    "type": "SECRET",      "criticality": "CRITICAL", "platform": "AWS"},
    {"name": "aws-secrets-api-tokens",   "type": "SECRET",      "criticality": "CRITICAL", "platform": "AWS"},
    {"name": "aws-api-finance",          "type": "API",         "criticality": "HIGH",     "platform": "AWS"},
    {"name": "aws-api-users",            "type": "API",         "criticality": "MEDIUM",   "platform": "AWS"},
    # AzureAD
    {"name": "azure-sharepoint-finance", "type": "APPLICATION", "criticality": "HIGH",     "platform": "AzureAD"},
    {"name": "azure-sharepoint-hr",      "type": "APPLICATION", "criticality": "CRITICAL", "platform": "AzureAD"},
    {"name": "azure-keyvault-prod",      "type": "SECRET",      "criticality": "CRITICAL", "platform": "AzureAD"},
    {"name": "azure-sql-crm",            "type": "DATABASE",    "criticality": "HIGH",     "platform": "AzureAD"},
    {"name": "azure-api-mgmt-gateway",   "type": "API",         "criticality": "HIGH",     "platform": "AzureAD"},
    # AD
    {"name": "ad-fileserver-finance",    "type": "APPLICATION", "criticality": "HIGH",     "platform": "AD"},
    {"name": "ad-dc-primary",            "type": "COMPUTE",     "criticality": "CRITICAL", "platform": "AD"},
    {"name": "ad-fileserver-engineering","type": "APPLICATION", "criticality": "MEDIUM",   "platform": "AD"},
    {"name": "ad-print-server",          "type": "APPLICATION", "criticality": "LOW",      "platform": "AD"},
    # Salesforce
    {"name": "sf-accounts-data",         "type": "APPLICATION", "criticality": "HIGH",     "platform": "Salesforce"},
    {"name": "sf-opportunities",         "type": "APPLICATION", "criticality": "MEDIUM",   "platform": "Salesforce"},
    {"name": "sf-reports-financial",     "type": "APPLICATION", "criticality": "CRITICAL", "platform": "Salesforce"},
    {"name": "sf-campaigns",             "type": "APPLICATION", "criticality": "LOW",      "platform": "Salesforce"},
    # Okta
    {"name": "okta-saml-integration",   "type": "API",         "criticality": "CRITICAL", "platform": "Okta"},
    {"name": "okta-provisioning-api",   "type": "API",         "criticality": "HIGH",     "platform": "Okta"},
    {"name": "okta-audit-logs-api",     "type": "API",         "criticality": "MEDIUM",   "platform": "Okta"},
]

# group_name → {platform, parent (None=root), is_privileged}
GROUP_CATALOG: List[Dict] = [
    # AD — 3 levels of nesting
    {"name": "AD-Domain-Admins",         "platform": "AD",         "parent": None,                   "privileged": True},
    {"name": "AD-IT-Operations",         "platform": "AD",         "parent": None,                   "privileged": False},
    {"name": "AD-Helpdesk",              "platform": "AD",         "parent": "AD-IT-Operations",     "privileged": False},
    {"name": "AD-Finance",               "platform": "AD",         "parent": None,                   "privileged": False},
    {"name": "AD-Finance-Controllers",   "platform": "AD",         "parent": "AD-Finance",           "privileged": False},
    {"name": "AD-Finance-Analysts",      "platform": "AD",         "parent": "AD-Finance",           "privileged": False},
    {"name": "AD-Engineering",           "platform": "AD",         "parent": None,                   "privileged": False},
    {"name": "AD-Engineering-Backend",   "platform": "AD",         "parent": "AD-Engineering",       "privileged": False},
    {"name": "AD-Engineering-Frontend",  "platform": "AD",         "parent": "AD-Engineering",       "privileged": False},
    {"name": "AD-HR",                    "platform": "AD",         "parent": None,                   "privileged": False},
    {"name": "AD-Security",              "platform": "AD",         "parent": None,                   "privileged": True},
    {"name": "AD-All-Users",             "platform": "AD",         "parent": None,                   "privileged": False},
    # AzureAD — nested security ops
    {"name": "AzureAD-Global-Admins",   "platform": "AzureAD",    "parent": None,                   "privileged": True},
    {"name": "AzureAD-Security-Ops",    "platform": "AzureAD",    "parent": None,                   "privileged": True},
    {"name": "AzureAD-SOC-Analysts",    "platform": "AzureAD",    "parent": "AzureAD-Security-Ops", "privileged": False},
    {"name": "AzureAD-All-Users",       "platform": "AzureAD",    "parent": None,                   "privileged": False},
    {"name": "AzureAD-M365-E3",         "platform": "AzureAD",    "parent": "AzureAD-All-Users",    "privileged": False},
    # AWS — nested power users
    {"name": "AWS-Admin-Global",         "platform": "AWS",        "parent": None,                   "privileged": True},
    {"name": "AWS-IAM-Admins",           "platform": "AWS",        "parent": "AWS-Admin-Global",     "privileged": True},
    {"name": "AWS-PowerUsers",           "platform": "AWS",        "parent": None,                   "privileged": False},
    {"name": "AWS-DevOps",               "platform": "AWS",        "parent": "AWS-PowerUsers",       "privileged": False},
    {"name": "AWS-DataEngineers",        "platform": "AWS",        "parent": "AWS-PowerUsers",       "privileged": False},
    {"name": "AWS-Finance-DataAccess",   "platform": "AWS",        "parent": None,                   "privileged": False},
    {"name": "AWS-ReadOnly",             "platform": "AWS",        "parent": None,                   "privileged": False},
    # Okta — nested app admins
    {"name": "Okta-Super-Admins",        "platform": "Okta",       "parent": None,                   "privileged": True},
    {"name": "Okta-AppAdmins",           "platform": "Okta",       "parent": None,                   "privileged": False},
    {"name": "Okta-SalesforceAdmins",    "platform": "Okta",       "parent": "Okta-AppAdmins",       "privileged": False},
    {"name": "Okta-AWSAdmins",           "platform": "Okta",       "parent": "Okta-AppAdmins",       "privileged": False},
    {"name": "Okta-All-Users",           "platform": "Okta",       "parent": None,                   "privileged": False},
    # Salesforce — nested sales ops
    {"name": "SF-System-Admins",         "platform": "Salesforce", "parent": None,                   "privileged": True},
    {"name": "SF-Sales-Operations",      "platform": "Salesforce", "parent": None,                   "privileged": False},
    {"name": "SF-Sales-Managers",        "platform": "Salesforce", "parent": "SF-Sales-Operations",  "privileged": False},
    {"name": "SF-Sales-Reps",            "platform": "Salesforce", "parent": "SF-Sales-Operations",  "privileged": False},
    {"name": "SF-Standard-Users",        "platform": "Salesforce", "parent": None,                   "privileged": False},
]

# role_name → {platform, permission_scope, is_privileged, resources (list of resource names)}
ROLE_CATALOG: List[Dict] = [
    # AD
    {"name": "AD-Domain-Admins",        "platform": "AD",         "scope": "global",    "privileged": True,
     "resources": ["ad-dc-primary", "ad-fileserver-finance", "ad-fileserver-engineering", "ad-print-server"]},
    {"name": "AD-Account-Operators",    "platform": "AD",         "scope": "user_mgmt", "privileged": True,
     "resources": ["ad-dc-primary"]},
    {"name": "AD-Standard-User",        "platform": "AD",         "scope": "read",      "privileged": False,
     "resources": ["ad-fileserver-finance", "ad-fileserver-engineering", "ad-print-server"]},
    {"name": "AD-Read-Only",            "platform": "AD",         "scope": "read-only", "privileged": False,
     "resources": ["ad-fileserver-engineering"]},
    # AzureAD
    {"name": "AzureAD-Global-Admin",    "platform": "AzureAD",   "scope": "global",    "privileged": True,
     "resources": ["azure-sharepoint-finance", "azure-sharepoint-hr", "azure-keyvault-prod", "azure-sql-crm", "azure-api-mgmt-gateway"]},
    {"name": "AzureAD-User-Admin",      "platform": "AzureAD",   "scope": "user_mgmt", "privileged": True,
     "resources": ["azure-sharepoint-hr", "azure-sharepoint-finance"]},
    {"name": "AzureAD-Security-Reader", "platform": "AzureAD",   "scope": "read-only", "privileged": False,
     "resources": ["azure-sharepoint-finance", "azure-sharepoint-hr"]},
    {"name": "AzureAD-Standard-User",   "platform": "AzureAD",   "scope": "standard",  "privileged": False,
     "resources": ["azure-sharepoint-finance"]},
    # AWS
    {"name": "AWS-AdministratorAccess", "platform": "AWS",        "scope": "global",    "privileged": True,
     "resources": ["prod-s3-finance", "prod-s3-engineering", "prod-s3-hr", "dev-s3-sandbox",
                   "backup-s3-all", "prod-rds-finance", "prod-rds-customers", "dev-rds-engineering",
                   "prod-ec2-webserver", "prod-ec2-appserver", "dev-ec2-sandbox",
                   "aws-secrets-prod-keys", "aws-secrets-api-tokens", "aws-api-finance", "aws-api-users"]},
    {"name": "AWS-PowerUserAccess",     "platform": "AWS",        "scope": "power",     "privileged": False,
     "resources": ["prod-s3-engineering", "dev-s3-sandbox", "dev-rds-engineering",
                   "prod-ec2-webserver", "prod-ec2-appserver", "dev-ec2-sandbox", "aws-api-users"]},
    {"name": "AWS-ReadOnlyAccess",      "platform": "AWS",        "scope": "read-only", "privileged": False,
     "resources": ["prod-s3-engineering", "dev-s3-sandbox", "aws-api-users"]},
    {"name": "AWS-FinanceDataAccess",   "platform": "AWS",        "scope": "finance",   "privileged": False,
     "resources": ["prod-s3-finance", "prod-rds-finance", "aws-api-finance"]},
    {"name": "AWS-IAMFullAccess",       "platform": "AWS",        "scope": "iam",       "privileged": True,
     "resources": ["aws-api-users"]},
    # Okta
    {"name": "Okta-Super-Admin",        "platform": "Okta",       "scope": "global",    "privileged": True,
     "resources": ["okta-saml-integration", "okta-provisioning-api", "okta-audit-logs-api"]},
    {"name": "Okta-Org-Admin",          "platform": "Okta",       "scope": "org_mgmt",  "privileged": True,
     "resources": ["okta-provisioning-api", "okta-audit-logs-api"]},
    {"name": "Okta-Read-Only-Admin",    "platform": "Okta",       "scope": "read-only", "privileged": False,
     "resources": ["okta-audit-logs-api"]},
    {"name": "Okta-Standard-User",      "platform": "Okta",       "scope": "standard",  "privileged": False,
     "resources": []},
    # Salesforce
    {"name": "SF-System-Admin",         "platform": "Salesforce", "scope": "global",    "privileged": True,
     "resources": ["sf-accounts-data", "sf-opportunities", "sf-reports-financial", "sf-campaigns"]},
    {"name": "SF-Standard-User",        "platform": "Salesforce", "scope": "standard",  "privileged": False,
     "resources": ["sf-accounts-data", "sf-opportunities", "sf-campaigns"]},
    {"name": "SF-Marketing-User",       "platform": "Salesforce", "scope": "marketing", "privileged": False,
     "resources": ["sf-campaigns", "sf-accounts-data"]},
    {"name": "SF-Contract-Manager",     "platform": "Salesforce", "scope": "contracts", "privileged": False,
     "resources": ["sf-opportunities", "sf-reports-financial"]},
]

# Dept → which AD group leaf to assign by default
DEPT_TO_GROUP: Dict[str, Dict[str, str]] = {
    "Engineering":   {"AD": "AD-Engineering-Backend",  "AzureAD": "AzureAD-All-Users",
                      "AWS": "AWS-DevOps",              "Okta": "Okta-All-Users",    "Salesforce": "SF-Standard-Users"},
    "Finance":       {"AD": "AD-Finance-Analysts",      "AzureAD": "AzureAD-M365-E3",
                      "AWS": "AWS-Finance-DataAccess",  "Okta": "Okta-All-Users",    "Salesforce": "SF-Contract-Manager"},
    "HR":            {"AD": "AD-HR",                    "AzureAD": "AzureAD-M365-E3",
                      "AWS": "AWS-ReadOnly",            "Okta": "Okta-All-Users",    "Salesforce": "SF-Standard-Users"},
    "Legal":         {"AD": "AD-Finance-Analysts",      "AzureAD": "AzureAD-M365-E3",
                      "AWS": "AWS-ReadOnly",            "Okta": "Okta-All-Users",    "Salesforce": "SF-Standard-Users"},
    "Marketing":     {"AD": "AD-Engineering-Frontend",  "AzureAD": "AzureAD-M365-E3",
                      "AWS": "AWS-ReadOnly",            "Okta": "Okta-All-Users",    "Salesforce": "SF-Marketing-User"},
    "Operations":    {"AD": "AD-Finance-Analysts",      "AzureAD": "AzureAD-M365-E3",
                      "AWS": "AWS-ReadOnly",            "Okta": "Okta-All-Users",    "Salesforce": "SF-Standard-Users"},
    "Security":      {"AD": "AD-Security",              "AzureAD": "AzureAD-SOC-Analysts",
                      "AWS": "AWS-PowerUsers",          "Okta": "Okta-AppAdmins",   "Salesforce": "SF-Standard-Users"},
    "Sales":         {"AD": "AD-Finance-Analysts",      "AzureAD": "AzureAD-M365-E3",
                      "AWS": "AWS-ReadOnly",            "Okta": "Okta-All-Users",    "Salesforce": "SF-Sales-Reps"},
    "IT-Operations": {"AD": "AD-Helpdesk",              "AzureAD": "AzureAD-Security-Ops",
                      "AWS": "AWS-PowerUsers",          "Okta": "Okta-AppAdmins",   "Salesforce": "SF-Standard-Users"},
    "Executive":     {"AD": "AD-IT-Operations",         "AzureAD": "AzureAD-All-Users",
                      "AWS": "AWS-ReadOnly",            "Okta": "Okta-All-Users",    "Salesforce": "SF-Sales-Managers"},
}

DEPT_TO_ROLE: Dict[str, Dict[str, str]] = {
    "Engineering":   {"AD": "AD-Standard-User",       "AzureAD": "AzureAD-Standard-User",
                      "AWS": "AWS-PowerUserAccess",   "Okta": "Okta-Standard-User",  "Salesforce": "SF-Standard-User"},
    "Finance":       {"AD": "AD-Standard-User",       "AzureAD": "AzureAD-Standard-User",
                      "AWS": "AWS-FinanceDataAccess", "Okta": "Okta-Standard-User",  "Salesforce": "SF-Contract-Manager"},
    "HR":            {"AD": "AD-Standard-User",       "AzureAD": "AzureAD-Standard-User",
                      "AWS": "AWS-ReadOnlyAccess",    "Okta": "Okta-Standard-User",  "Salesforce": "SF-Standard-User"},
    "Legal":         {"AD": "AD-Standard-User",       "AzureAD": "AzureAD-Standard-User",
                      "AWS": "AWS-ReadOnlyAccess",    "Okta": "Okta-Standard-User",  "Salesforce": "SF-Standard-User"},
    "Marketing":     {"AD": "AD-Standard-User",       "AzureAD": "AzureAD-Standard-User",
                      "AWS": "AWS-ReadOnlyAccess",    "Okta": "Okta-Standard-User",  "Salesforce": "SF-Marketing-User"},
    "Operations":    {"AD": "AD-Standard-User",       "AzureAD": "AzureAD-Standard-User",
                      "AWS": "AWS-ReadOnlyAccess",    "Okta": "Okta-Standard-User",  "Salesforce": "SF-Standard-User"},
    "Security":      {"AD": "AD-Standard-User",       "AzureAD": "AzureAD-Security-Reader",
                      "AWS": "AWS-PowerUserAccess",   "Okta": "Okta-Read-Only-Admin","Salesforce": "SF-Standard-User"},
    "Sales":         {"AD": "AD-Standard-User",       "AzureAD": "AzureAD-Standard-User",
                      "AWS": "AWS-ReadOnlyAccess",    "Okta": "Okta-Standard-User",  "Salesforce": "SF-Standard-User"},
    "IT-Operations": {"AD": "AD-Account-Operators",   "AzureAD": "AzureAD-User-Admin",
                      "AWS": "AWS-PowerUserAccess",   "Okta": "Okta-Org-Admin",     "Salesforce": "SF-Standard-User"},
    "Executive":     {"AD": "AD-Standard-User",       "AzureAD": "AzureAD-Standard-User",
                      "AWS": "AWS-ReadOnlyAccess",    "Okta": "Okta-Standard-User",  "Salesforce": "SF-Standard-User"},
}


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _seeded_uuid() -> uuid.UUID:
    """Generate a UUID from the module-level seeded PRNG (deterministic)."""
    return uuid.UUID(int=_uuid_rng.getrandbits(128))


def uid() -> str:
    """Return a deterministic UUID string (seeded via _uuid_rng)."""
    return str(_seeded_uuid())


def gid() -> str:
    """Return a deterministic GRP-prefixed UUID string."""
    return f"GRP-{_seeded_uuid()}"


def rid() -> str:
    """Return a deterministic ROLE-prefixed UUID string."""
    return f"ROLE-{_seeded_uuid()}"


def res_id() -> str:
    """Return a deterministic RES-prefixed UUID string."""
    return f"RES-{_seeded_uuid()}"


def fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def fmt_date(d: date) -> str:
    return d.strftime("%Y-%m-%d")


def rdt(start: datetime, end: datetime, rng: np.random.Generator) -> datetime:
    """Random UTC datetime in [start, end]."""
    delta = int((end - start).total_seconds())
    if delta <= 0:
        return start
    return start + timedelta(seconds=int(rng.integers(0, delta)))


def rdate(start: date, end: date, rng: np.random.Generator) -> date:
    """Random date in [start, end]."""
    delta = (end - start).days
    if delta <= 0:
        return start
    return start + timedelta(days=int(rng.integers(0, delta + 1)))


def rand_ip(geo: str, rng: np.random.Generator) -> str:
    """Generate a plausible internal IP for a given geography."""
    prefix = GEO_IP_RANGES.get(geo, "10.99")
    return f"{prefix}.{rng.integers(1,255)}.{rng.integers(1,254)}"


def anomalous_ip(rng: np.random.Generator) -> str:
    """Generate an external/anomalous IP (different geo pattern)."""
    prefix = ANOMALOUS_IPS[rng.integers(0, len(ANOMALOUS_IPS))]
    return f"{prefix}.{rng.integers(1,254)}"


def ticket_id(rng: np.random.Generator, ref: date) -> str:
    """Generate a realistic IT ticket ID."""
    return f"TKT-{ref.strftime('%Y%m')}-{rng.integers(10000,99999)}"


# ──────────────────────────────────────────────────────────────────────────────
# DATACLASSES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Person:
    """Canonical human identity, platform-agnostic."""
    idx: int
    first_name: str
    last_name: str
    email: str                    # corp email (primary correlation key)
    department: str
    job_title: str
    geo_location: str
    hire_date: date
    is_executive: bool
    manager_idx: Optional[int]    # index into persons list
    # Filled after platform account generation:
    account_ids: Dict[str, str] = field(default_factory=dict)  # platform → identity_id
    # Filled after anomaly assignment:
    anomaly_type: Optional[str] = None


@dataclass
class Resource:
    resource_id: str
    name: str
    res_type: str
    criticality: str
    platform: str


@dataclass
class Group:
    group_id: str
    name: str
    platform: str
    parent_name: Optional[str]
    parent_id: Optional[str]
    nesting_depth: int
    is_privileged: bool


@dataclass
class Role:
    role_id: str
    name: str
    platform: str
    permission_scope: str
    is_privileged: bool
    resource_names: List[str]


# ──────────────────────────────────────────────────────────────────────────────
# DATA SIMULATOR
# ──────────────────────────────────────────────────────────────────────────────

class DataSimulator:
    """
    Orchestrates all synthetic data generation for Identity Nexus AI Phase 2.

    Call run() to execute the full pipeline and write all output CSVs.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.cfg = config
        # Seed the module-level UUID PRNG FIRST so uid()/gid()/rid()/res_id()
        # are deterministic before any catalog builder is called.
        _uuid_rng.seed(config["seed"])
        self.rng = np.random.default_rng(config["seed"])
        Faker.seed(config["seed"])
        self.fake = Faker()
        self.ref_date: date = config["reference_date"]
        self.ref_dt: datetime = datetime(self.ref_date.year, self.ref_date.month, self.ref_date.day)
        self.audit_start: datetime = self.ref_dt - timedelta(days=config["audit_window_months"] * 30)
        self.out_dir = Path(config["output_dir"])
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.injector = AnomalyInjector(self.rng, config["anomaly_rates"])
        # Built during run():
        self.resources: List[Resource] = []
        self.groups: List[Group] = []
        self.roles: List[Role] = []
        self.persons: List[Person] = []
        self.name_index: Set[str] = set()   # tracks used emails to deduplicate

    # ── Catalog builders ──────────────────────────────────────────────────────

    def _build_resources(self) -> None:
        """Materialise RESOURCE_CATALOG into Resource objects with stable RES-UUIDs."""
        for r in RESOURCE_CATALOG:
            self.resources.append(Resource(
                resource_id=res_id(),
                name=r["name"],
                res_type=r["type"],
                criticality=r["criticality"],
                platform=r["platform"],
            ))
        logger.info("Built resource catalog: %d resources", len(self.resources))

    def _res_by_name(self) -> Dict[str, Resource]:
        return {r.name: r for r in self.resources}

    def _build_groups(self) -> None:
        """Materialise GROUP_CATALOG into Group objects, resolving parent IDs."""
        name_to_id: Dict[str, str] = {}
        # first pass — assign IDs
        for g in GROUP_CATALOG:
            name_to_id[g["name"]] = gid()
        # second pass — build Group objects with resolved parent_id
        for g in GROUP_CATALOG:
            parent_name = g["parent"]
            parent_id = name_to_id.get(parent_name) if parent_name else None
            depth = 0 if not parent_name else 1
            # calculate actual depth (handle 2-level nesting)
            if parent_name:
                parent_def = next((x for x in GROUP_CATALOG if x["name"] == parent_name), None)
                if parent_def and parent_def.get("parent"):
                    depth = 2
            self.groups.append(Group(
                group_id=name_to_id[g["name"]],
                name=g["name"],
                platform=g["platform"],
                parent_name=parent_name,
                parent_id=parent_id,
                nesting_depth=depth,
                is_privileged=g["privileged"],
            ))
        logger.info("Built group catalog: %d groups", len(self.groups))

    def _grp_by_name(self) -> Dict[str, Group]:
        return {g.name: g for g in self.groups}

    def _build_roles(self) -> None:
        """Materialise ROLE_CATALOG into Role objects with stable ROLE-UUIDs."""
        for r in ROLE_CATALOG:
            self.roles.append(Role(
                role_id=rid(),
                name=r["name"],
                platform=r["platform"],
                permission_scope=r["scope"],
                is_privileged=r["privileged"],
                resource_names=r["resources"],
            ))
        logger.info("Built role catalog: %d roles", len(self.roles))

    def _role_by_name(self) -> Dict[str, Role]:
        return {r.name: r for r in self.roles}

    # ── People ────────────────────────────────────────────────────────────────

    def _generate_persons(self) -> None:
        """Create canonical human identities (persons)."""
        n = self.cfg["n_identities"]
        # Determine manager structure: first 8 are executives (no manager)
        n_execs = min(8, n // 10)
        persons: List[Person] = []

        for i in range(n):
            dept = DEPARTMENTS[int(self.rng.integers(0, len(DEPARTMENTS)))]
            if i < n_execs:
                dept = "Executive"
                is_exec = True
            else:
                is_exec = False

            first = self.fake.first_name()
            last = self.fake.last_name()
            base_email = f"{first.lower()}.{last.lower()}@{self.cfg['org_domain']}"
            # deduplicate email
            email = base_email
            suffix = 2
            while email in self.name_index:
                email = f"{first.lower()}.{last.lower()}{suffix}@{self.cfg['org_domain']}"
                suffix += 1
            self.name_index.add(email)

            titles = JOB_TITLES.get(dept, ["Specialist"])
            job_title = titles[int(self.rng.integers(0, len(titles)))]
            geo = GEO_LOCATIONS[int(self.rng.integers(0, len(GEO_LOCATIONS)))]

            # hire date: 1-6 years ago
            days_back = int(self.rng.integers(365, 365 * 6))
            hire_date = self.ref_date - timedelta(days=days_back)

            # manager: execs have None; others get a random exec/senior
            if is_exec or i < n_execs:
                mgr_idx = None
            else:
                mgr_idx = int(self.rng.integers(0, max(1, i // 5)))

            persons.append(Person(
                idx=i,
                first_name=first,
                last_name=last,
                email=email,
                department=dept,
                job_title=job_title,
                geo_location=geo,
                hire_date=hire_date,
                is_executive=is_exec,
                manager_idx=mgr_idx,
            ))

        self.persons = persons
        logger.info("Generated %d canonical persons", len(persons))

    def _assign_anomaly_profiles(self) -> None:
        """Assign anomaly types to the canonical person pool."""
        person_ids = [p.email for p in self.persons]  # use email as stable key
        self.injector.assign_profiles(person_ids)
        for p in self.persons:
            p.anomaly_type = self.injector.anomaly_type(p.email)
        logger.info(self.injector.summary())

    # ── Platform account generators ───────────────────────────────────────────

    def _make_ad_account(self, p: Person, identity_id: str) -> Dict:
        """Generate an Active Directory account row with AD-specific quirks."""
        sam = f"{p.first_name[0].lower()}{p.last_name.lower()}"
        # AD SAM names are short (≤20 chars), no spaces, may collide → accepted for sim
        upn = p.email
        ou_map = {
            "Engineering": "OU=Engineering", "Finance": "OU=Finance",
            "HR": "OU=HR", "IT-Operations": "OU=IT", "Security": "OU=Security",
            "Executive": "OU=Executives",
        }
        ou = ou_map.get(p.department, "OU=Staff")
        dn = f"CN={p.first_name} {p.last_name},{ou},{self.cfg['ad_domain_dn']}"

        is_active = not self.injector.should_disable_on_platform(p.email, "AD")
        uac = 512 if is_active else 514  # 512=NORMAL_ACCOUNT, 514=DISABLED

        last_logon = self._last_login_dt(p, is_active)
        pwd_last_set = rdt(
            datetime(p.hire_date.year, p.hire_date.month, p.hire_date.day),
            self.ref_dt - timedelta(days=30),
            self.rng,
        )

        return {
            "ad_object_guid": identity_id,
            "sam_account_name": sam,
            "user_principal_name": upn,
            "distinguished_name": dn,
            "display_name": f"{p.first_name} {p.last_name}",
            "given_name": p.first_name,
            "surname": p.last_name,
            "email": p.email,
            "department": p.department,
            "job_title": p.job_title,
            "manager_dn": "",   # resolved post-generation to avoid circular dep
            "account_enabled": is_active,
            "user_account_control": uac,
            "password_last_set": fmt_dt(pwd_last_set),
            "last_logon": fmt_dt(last_logon) if last_logon else "",
            "account_created": fmt_date(p.hire_date),
            "ou": ou,
        }

    def _make_azuread_account(self, p: Person, identity_id: str) -> Dict:
        """Generate an Azure AD account row with AzureAD-specific quirks."""
        # ~30% of AzureAD accounts use a @tenant.onmicrosoft.com UPN (cloud-only)
        use_onmicrosoft = self.rng.random() < 0.30
        upn = (
            f"{p.first_name.lower()}.{p.last_name.lower()}@nexusai.onmicrosoft.com"
            if use_onmicrosoft else p.email
        )
        is_active = not self.injector.should_disable_on_platform(p.email, "AzureAD")
        last_sign_in = self._last_login_dt(p, is_active)
        mfa = self.rng.random() > 0.15  # 85% have MFA

        return {
            "aad_object_id": identity_id,
            "user_principal_name": upn,
            "display_name": f"{p.first_name} {p.last_name}",
            "given_name": p.first_name,
            "surname": p.last_name,
            "email": p.email,          # mail attribute — reliable correlation field
            "department": p.department,
            "job_title": p.job_title,
            "account_enabled": is_active,
            "last_sign_in": fmt_dt(last_sign_in) if last_sign_in else "",
            "created_date_time": fmt_date(p.hire_date),
            "on_premises_sync_enabled": self.rng.random() < 0.75,  # 75% synced from AD
            "on_premises_sam_account_name": (
                f"{p.first_name[0].lower()}{p.last_name.lower()}"
                if self.rng.random() < 0.75 else ""
            ),
            "assigned_licenses": json.dumps(["ENTERPRISEPACK"]),
            "mfa_registered": mfa,
            "tenant_id": self.cfg["azure_tenant_id"],
        }

    def _make_aws_account(self, p: Person, identity_id: str) -> Dict:
        """
        Generate an AWS IAM account row.
        AWS does not have an email attribute natively — it's stored as a tag.
        Username format varies (dots, hyphens) — fuzzy-matching challenge.
        """
        # Intentionally vary username format to create resolver challenge
        style = int(self.rng.integers(0, 3))
        if style == 0:
            username = f"{p.first_name[0].lower()}.{p.last_name.lower()}"
        elif style == 1:
            username = f"{p.first_name.lower()}-{p.last_name.lower()}"
        else:
            username = f"{p.first_name.lower()}{p.last_name[0].lower()}"

        arn = (
            f"arn:aws:iam::{self.cfg['aws_account_id']}:user/{username}"
        )
        path_map = {
            "Engineering": "/engineering/",
            "Finance": "/finance/",
            "Security": "/security/",
            "IT-Operations": "/it/",
        }
        path = path_map.get(p.department, "/")
        is_active = True  # AWS accounts stay active unless explicitly disabled
        last_login = self._last_login_dt(p, is_active)

        return {
            "arn": arn,
            "username": username,
            "user_id": f"AIDA{self.fake.lexify('?????????????????', letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')}",
            "account_id": self.cfg["aws_account_id"],
            "path": path,
            # email stored only in tags — deliberately absent from the main field
            "email_tag": p.email if self.rng.random() < 0.70 else "",  # 30% missing
            "created_date": fmt_date(p.hire_date),
            "password_last_used": fmt_dt(last_login) if last_login else "",
            "access_key_last_used": fmt_dt(last_login) if last_login else "",
            "account_type": "human",
            "has_console_access": True,
            "has_programmatic_access": p.department in ("Engineering", "IT-Operations", "Security"),
            "tags": json.dumps({"Department": p.department, "Email": p.email,
                                "CostCenter": p.department}),
        }

    def _make_okta_account(self, p: Person, identity_id: str) -> Dict:
        """
        Generate an Okta account row.
        Okta login is email-based — highest correlation fidelity across platforms.
        """
        is_active = True
        last_login = self._last_login_dt(p, is_active)
        status = "ACTIVE" if is_active else "DEPROVISIONED"
        mfa = self.rng.random() > 0.12
        activated = datetime(p.hire_date.year, p.hire_date.month, p.hire_date.day) + timedelta(days=1)

        return {
            "okta_id": f"00u{self.fake.lexify('???????????????', letters='abcdefghijklmnopqrstuvwxyz0123456789')}",
            "login": p.email,             # primary correlation key — same as corp email
            "email": p.email,
            "first_name": p.first_name,
            "last_name": p.last_name,
            "display_name": f"{p.first_name} {p.last_name}",
            "department": p.department,
            "title": p.job_title,
            "status": status,
            "activated": fmt_dt(activated),
            "last_login": fmt_dt(last_login) if last_login else "",
            "last_updated": fmt_dt(self.ref_dt - timedelta(days=int(self.rng.integers(1, 60)))),
            "mfa_enrolled": mfa,
            "external_id": identity_id,   # stores the AD objectGUID for linked accounts
            "user_type": "regular",
        }

    def _make_salesforce_account(self, p: Person, identity_id: str) -> Dict:
        """
        Generate a Salesforce account row.
        SF usernames use a different domain (@org.salesforce.com) — fuzzy-match challenge.
        """
        # Salesforce username deliberately uses a different domain
        sf_username = f"{p.email.split('@')[0]}@nexusai.salesforce.com"
        alias = f"{p.first_name[0].lower()}{p.last_name[:7].lower()}"  # max 8 chars
        is_active = True
        last_login = self._last_login_dt(p, is_active)
        sf_id = f"005{self.fake.lexify('???????????????', letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}"

        profile_map = {
            "Sales": "Standard User",
            "Finance": "Standard User",
            "Marketing": "Marketing User",
            "Executive": "Standard User",
            "IT-Operations": "System Administrator",
            "Security": "Standard User",
        }
        profile = profile_map.get(p.department, "Chatter Free User")

        return {
            "sf_user_id": sf_id,
            "username": sf_username,          # different domain — resolver challenge
            "email": p.email,                 # personal email stored separately
            "first_name": p.first_name,
            "last_name": p.last_name,
            "alias": alias,
            "profile_name": profile,
            "department": p.department,
            "title": p.job_title,
            "is_active": is_active,
            "created_date": fmt_date(p.hire_date),
            "last_login_date": fmt_dt(last_login) if last_login else "",
            "federation_id": p.email,         # SAML federation uses corp email
            "user_role": p.department,
            "org_id": self.cfg["sf_org_id"],
        }

    def _last_login_dt(self, p: Person, is_active: bool) -> Optional[datetime]:
        """Compute last_login based on anomaly type and account state."""
        if not is_active:
            return None
        atype = p.anomaly_type
        if atype == "DORMANT_ADMIN":
            # no login in 120-400 days
            days_ago = int(self.rng.integers(120, 400))
            return self.ref_dt - timedelta(days=days_ago)
        if atype == "ORPHANED_ACCOUNT":
            # last login was just before/around offboarding date (6-18 months ago)
            days_ago = int(self.rng.integers(180, 540))
            return self.ref_dt - timedelta(days=days_ago)
        if atype is None or atype in ("OVERPRIVILEGED", "TOKEN_ABUSE",
                                       "PRIVILEGE_ESCALATION", "LEGITIMATE_EXCEPTION"):
            days_ago = int(self.rng.integers(0, 14))
            return self.ref_dt - timedelta(days=days_ago)
        days_ago = int(self.rng.integers(0, 30))
        return self.ref_dt - timedelta(days=days_ago)

    # ── Unified identity assembly ──────────────────────────────────────────────

    def _generate_platform_accounts(self) -> Tuple[Dict[str, pd.DataFrame], pd.DataFrame]:
        """
        Generate per-platform raw DataFrames and the unified_identities DataFrame.

        Returns (platform_dfs, unified_df) where platform_dfs is a dict
        mapping platform name → raw platform DataFrame.
        """
        platform_dfs: Dict[str, List[Dict]] = {p: [] for p in self.cfg["platform_coverage"]}
        unified_rows: List[Dict] = []

        for p in self.persons:
            atype = p.anomaly_type
            for platform, coverage in self.cfg["platform_coverage"].items():
                # Orphaned account anomaly: always get AD + AzureAD accounts
                if atype == "ORPHANED_ACCOUNT" and platform in ("AD", "AzureAD", "Okta"):
                    has_account = True
                elif self.rng.random() >= coverage:
                    has_account = False
                else:
                    has_account = True

                if not has_account:
                    continue

                identity_id = uid()
                p.account_ids[platform] = identity_id

                # Generate platform-specific raw record
                if platform == "AD":
                    raw = self._make_ad_account(p, identity_id)
                elif platform == "AzureAD":
                    raw = self._make_azuread_account(p, identity_id)
                elif platform == "AWS":
                    raw = self._make_aws_account(p, identity_id)
                elif platform == "Okta":
                    raw = self._make_okta_account(p, identity_id)
                else:
                    raw = self._make_salesforce_account(p, identity_id)

                platform_dfs[platform].append(raw)

                # Build unified row
                is_active = not self.injector.should_disable_on_platform(p.email, platform)
                last_login_dt = self._last_login_dt(p, is_active)
                is_privileged = atype in ("OVERPRIVILEGED", "DORMANT_ADMIN")
                mfa_on = self.rng.random() > 0.15

                unified_rows.append({
                    "identity_id": identity_id,
                    "display_name": f"{p.first_name} {p.last_name}",
                    "email": p.email,
                    "username": self._derive_username(p, platform, raw),
                    "platform": platform,
                    "account_type": "human",
                    "department": p.department,
                    "job_title": p.job_title,
                    "manager_id": "",   # filled in second pass
                    "created_date": fmt_date(p.hire_date),
                    "last_login": fmt_dt(last_login_dt) if last_login_dt else "",
                    "is_active": is_active,
                    "is_privileged": is_privileged,
                    "mfa_enabled": mfa_on,
                    "geo_location": p.geo_location,
                    "canonical_id": identity_id,  # pre-resolution: same as identity_id
                })

        # Add service accounts
        unified_rows += self._generate_service_accounts(platform_dfs)

        unified_df = pd.DataFrame(unified_rows)

        # Second pass: fill manager_id (use primary platform account of manager)
        email_to_primary_id = self._build_primary_id_map()
        for i, p in enumerate(self.persons):
            mgr = self.persons[p.manager_idx] if p.manager_idx is not None and p.manager_idx < len(self.persons) else None
            mgr_id = email_to_primary_id.get(mgr.email, "") if mgr else ""
            mask = unified_df["email"] == p.email
            unified_df.loc[mask, "manager_id"] = mgr_id

        return (
            {k: pd.DataFrame(v) for k, v in platform_dfs.items()},
            unified_df,
        )

    def _derive_username(self, p: Person, platform: str, raw: Dict) -> str:
        """Extract the platform-canonical username from a raw account dict."""
        if platform == "AD":
            return raw["sam_account_name"]
        if platform == "AzureAD":
            return raw["user_principal_name"]
        if platform == "AWS":
            return raw["username"]
        if platform == "Okta":
            return raw["login"]
        return raw["username"]   # Salesforce

    def _build_primary_id_map(self) -> Dict[str, str]:
        """Map person email → their primary identity_id (AD preferred)."""
        result: Dict[str, str] = {}
        for p in self.persons:
            for platform in ["AD", "AzureAD", "Okta", "AWS", "Salesforce"]:
                if platform in p.account_ids:
                    result[p.email] = p.account_ids[platform]
                    break
        return result

    def _generate_service_accounts(self, platform_dfs: Dict[str, List[Dict]]) -> List[Dict]:
        """Generate service/machine accounts and add them to platform_dfs."""
        rows: List[Dict] = []
        platforms = list(self.cfg["platform_coverage"].keys())
        for i in range(self.cfg["n_service_accounts"]):
            platform = platforms[i % len(platforms)]
            identity_id = uid()
            svc_name = f"svc-{self.fake.word()}-{self.fake.word()}"
            dept = DEPARTMENTS[int(self.rng.integers(0, len(DEPARTMENTS)))]
            acct_type = "service" if i < self.cfg["n_service_accounts"] - 5 else "machine"

            if platform == "AWS":
                raw = {
                    "arn": f"arn:aws:iam::{self.cfg['aws_account_id']}:user/{svc_name}",
                    "username": svc_name,
                    "user_id": f"AIDA{self.fake.lexify('?????????????????', letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')}",
                    "account_id": self.cfg["aws_account_id"],
                    "path": "/service/",
                    "email_tag": f"{svc_name}@{self.cfg['org_domain']}",
                    "created_date": fmt_date(rdate(date(2021, 1, 1), self.ref_date, self.rng)),
                    "password_last_used": "",
                    "access_key_last_used": fmt_dt(self.ref_dt - timedelta(days=int(self.rng.integers(0, 3)))),
                    "account_type": acct_type,
                    "has_console_access": False,
                    "has_programmatic_access": True,
                    "tags": json.dumps({"Department": dept}),
                }
                platform_dfs["AWS"].append(raw)
            rows.append({
                "identity_id": identity_id,
                "display_name": svc_name,
                "email": f"{svc_name}@{self.cfg['org_domain']}",
                "username": svc_name,
                "platform": platform,
                "account_type": acct_type,
                "department": dept,
                "job_title": "Service Account",
                "manager_id": "",
                "created_date": fmt_date(rdate(date(2021, 1, 1), self.ref_date, self.rng)),
                "last_login": "",
                "is_active": True,
                "is_privileged": False,
                "mfa_enabled": False,
                "geo_location": "US-East",
                "canonical_id": identity_id,
            })
        return rows

    # ── Group mappings ────────────────────────────────────────────────────────

    def _generate_group_mappings(self, unified_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build group_mappings.csv with both direct and inherited (nested) rows.

        For each identity, assign a leaf group; then walk the parent chain to
        generate inherited membership rows for every ancestor group.
        """
        grp_by_name = self._grp_by_name()
        rows: List[Dict] = []

        # Build parent chain map: group_name → list[Group] from leaf to root
        def ancestors(leaf_name: str) -> List[Group]:
            chain: List[Group] = []
            current = grp_by_name.get(leaf_name)
            seen = set()
            while current and current.parent_name and current.parent_name not in seen:
                chain.append(grp_by_name[current.parent_name])
                seen.add(current.parent_name)
                current = grp_by_name.get(current.parent_name)
            return chain

        # Overprivileged identities get admin group assignments on ALL platforms
        overprivileged_emails = self.injector.ids_with_type("OVERPRIVILEGED")
        # Legitimate exception identities get a time-limited privileged group on one platform
        legit_exception_emails = self.injector.ids_with_type("LEGITIMATE_EXCEPTION")

        for _, row in unified_df.iterrows():
            iid = row["identity_id"]
            platform = row["platform"]
            dept = row["department"]
            email = row["email"]
            acct_type = row["account_type"]

            if acct_type != "human":
                # Service accounts → ReadOnly or PowerUsers group
                svc_grp_map = {
                    "AD": "AD-All-Users", "AzureAD": "AzureAD-All-Users",
                    "AWS": "AWS-ReadOnly", "Okta": "Okta-All-Users",
                    "Salesforce": "SF-Standard-Users",
                }
                leaf_name = svc_grp_map.get(platform)
            elif email in overprivileged_emails:
                # Overprivileged → admin group on every platform they have an account on
                admin_grp = {
                    "AD": "AD-Domain-Admins", "AzureAD": "AzureAD-Global-Admins",
                    "AWS": "AWS-Admin-Global", "Okta": "Okta-Super-Admins",
                    "Salesforce": "SF-System-Admins",
                }
                leaf_name = admin_grp.get(platform, DEPT_TO_GROUP.get(dept, {}).get(platform))
            elif email in legit_exception_emails:
                # Legitimate exception → temporarily in a privileged group
                priv_grp = {
                    "AD": "AD-Security", "AzureAD": "AzureAD-Security-Ops",
                    "AWS": "AWS-PowerUsers", "Okta": "Okta-AppAdmins",
                    "Salesforce": "SF-Sales-Managers",
                }
                leaf_name = priv_grp.get(platform, DEPT_TO_GROUP.get(dept, {}).get(platform))
            else:
                leaf_name = DEPT_TO_GROUP.get(dept, {}).get(platform)

            if not leaf_name or leaf_name not in grp_by_name:
                continue

            leaf_grp = grp_by_name[leaf_name]
            assign_date = fmt_date(rdate(
                date(2022, 1, 1), self.ref_date - timedelta(days=30), self.rng
            ))

            # Direct membership row
            rows.append({
                "mapping_id": uid(),
                "identity_id": iid,
                "group_id": leaf_grp.group_id,
                "group_name": leaf_grp.name,
                "platform": platform,
                "is_nested": False,
                "parent_group_id": "",
                "assigned_date": assign_date,
            })

            # Inherited membership rows for each ancestor
            direct_parent_id = leaf_grp.group_id
            for ancestor in ancestors(leaf_name):
                rows.append({
                    "mapping_id": uid(),
                    "identity_id": iid,
                    "group_id": ancestor.group_id,
                    "group_name": ancestor.name,
                    "platform": platform,
                    "is_nested": True,
                    "parent_group_id": direct_parent_id,
                    "assigned_date": assign_date,
                })
                direct_parent_id = ancestor.group_id   # walk up

        logger.info("Generated %d group mapping rows", len(rows))
        return pd.DataFrame(rows)

    # ── Role mappings ─────────────────────────────────────────────────────────

    def _generate_role_mappings(
        self,
        unified_df: pd.DataFrame,
        admin_identity_ids: List[str],
    ) -> pd.DataFrame:
        """
        Build role_mappings.csv.

        Columns (spec-conformant + Phase 2 additions):
          mapping_id, identity_id, role_id, role_name, platform,
          assignment_type, assigned_by, assigned_date, expiry_date,
          ticket_id (NEW), approval_date (NEW), approver_id (NEW)

        The ticket_id / approval_date / approver_id columns are populated only
        for LEGITIMATE_EXCEPTION identities (and some normal elevated roles).
        """
        role_by_name = self._role_by_name()
        overprivileged = self.injector.ids_with_type("OVERPRIVILEGED")
        escalation = self.injector.ids_with_type("PRIVILEGE_ESCALATION")
        legit_exc = self.injector.ids_with_type("LEGITIMATE_EXCEPTION")
        dormant_adm = self.injector.ids_with_type("DORMANT_ADMIN")

        # Build email→identity_id lookup for humans
        email_to_ids: Dict[str, List[str]] = {}
        for _, row in unified_df.iterrows():
            if row["account_type"] == "human":
                email_to_ids.setdefault(row["email"], []).append(row["identity_id"])

        rows: List[Dict] = []
        approver_pool = admin_identity_ids[:20] if admin_identity_ids else [uid()]

        for _, row in unified_df.iterrows():
            iid = row["identity_id"]
            platform = row["platform"]
            dept = row["department"]
            email = row["email"]
            acct_type = row["account_type"]

            if acct_type != "human":
                role_name = (
                    "AWS-ReadOnlyAccess" if platform == "AWS"
                    else {"AD": "AD-Read-Only", "AzureAD": "AzureAD-Standard-User",
                          "Okta": "Okta-Standard-User",
                          "Salesforce": "SF-Standard-User"}.get(platform, "AD-Read-Only")
                )
            elif email in overprivileged:
                admin_role = {
                    "AD": "AD-Domain-Admins", "AzureAD": "AzureAD-Global-Admin",
                    "AWS": "AWS-AdministratorAccess", "Okta": "Okta-Super-Admin",
                    "Salesforce": "SF-System-Admin",
                }
                role_name = admin_role.get(platform, DEPT_TO_ROLE.get(dept, {}).get(platform, "AD-Standard-User"))
            elif email in dormant_adm:
                # Admin role but no login
                priv_role = {
                    "AD": "AD-Domain-Admins", "AzureAD": "AzureAD-User-Admin",
                    "AWS": "AWS-AdministratorAccess", "Okta": "Okta-Org-Admin",
                    "Salesforce": "SF-System-Admin",
                }
                role_name = priv_role.get(platform, DEPT_TO_ROLE.get(dept, {}).get(platform, "AD-Standard-User"))
            else:
                role_name = DEPT_TO_ROLE.get(dept, {}).get(platform, "AD-Standard-User")

            role = role_by_name.get(role_name)
            if not role:
                continue

            assigned_date = rdate(p_hire_date(unified_df, iid, self.persons),
                                  self.ref_date - timedelta(days=10), self.rng)
            assigned_by = approver_pool[int(self.rng.integers(0, len(approver_pool)))]

            # Expiry date for legitimate exceptions (time-limited role)
            expiry = ""
            tkt = ""
            approval_dt = ""
            approver_id = ""

            if email in legit_exc:
                # legitimate exception: temporary elevated role with ticket
                expiry = fmt_date(self.ref_date + timedelta(days=int(self.rng.integers(30, 180))))
                tkt = ticket_id(self.rng, self.ref_date)
                approval_dt = fmt_date(rdate(
                    assigned_date, self.ref_date, self.rng
                ))
                approver_id = approver_pool[int(self.rng.integers(0, len(approver_pool)))]

            elif email in escalation:
                # privilege escalation: original lower role stays; escalated admin row
                # added in audit events. No ticket on the escalated role.
                pass

            rows.append({
                "mapping_id": uid(),
                "identity_id": iid,
                "role_id": role.role_id,
                "role_name": role.name,
                "platform": platform,
                "assignment_type": "direct",
                "assigned_by": assigned_by,
                "assigned_date": fmt_date(assigned_date),
                "expiry_date": expiry,
                "ticket_id": tkt,
                "approval_date": approval_dt,
                "approver_id": approver_id,
            })

            # Privilege escalation: add a second admin role mid-year (no ticket)
            if email in escalation:
                escalation_role_map = {
                    "AD": "AD-Domain-Admins", "AzureAD": "AzureAD-User-Admin",
                    "AWS": "AWS-AdministratorAccess", "Okta": "Okta-Org-Admin",
                    "Salesforce": "SF-System-Admin",
                }
                esc_role_name = escalation_role_map.get(platform)
                esc_role = role_by_name.get(esc_role_name or "")
                if esc_role and esc_role_name != role_name:
                    esc_date = rdate(
                        self.ref_date - timedelta(days=270),
                        self.ref_date - timedelta(days=30),
                        self.rng,
                    )
                    rows.append({
                        "mapping_id": uid(),
                        "identity_id": iid,
                        "role_id": esc_role.role_id,
                        "role_name": esc_role.name,
                        "platform": platform,
                        "assignment_type": "direct",
                        "assigned_by": assigned_by,
                        "assigned_date": fmt_date(esc_date),
                        "expiry_date": "",
                        "ticket_id": "",        # NO ticket — anomaly signal
                        "approval_date": "",
                        "approver_id": "",
                    })

        logger.info("Generated %d role mapping rows", len(rows))
        return pd.DataFrame(rows)

    # ── Audit events ──────────────────────────────────────────────────────────

    def _generate_audit_events(
        self,
        unified_df: pd.DataFrame,
        resources: List[Resource],
    ) -> pd.DataFrame:
        """
        Generate audit_events.csv spanning cfg['audit_window_months'] months.

        Each identity gets a mix of LOGIN, ACCESS, LOGOUT events; anomalous
        identities receive additional injected events.
        """
        res_by_platform: Dict[str, List[Resource]] = {}
        for r in resources:
            res_by_platform.setdefault(r.platform, []).append(r)

        token_abuse_emails = self.injector.ids_with_type("TOKEN_ABUSE")
        escalation_emails = self.injector.ids_with_type("PRIVILEGE_ESCALATION")
        legit_exc_emails = self.injector.ids_with_type("LEGITIMATE_EXCEPTION")

        rows: List[Dict] = []

        for _, row in unified_df.iterrows():
            iid = row["identity_id"]
            platform = row["platform"]
            email = row["email"]
            is_active = row["is_active"]
            acct_type = row["account_type"]
            geo = row["geo_location"]

            if not is_active and acct_type == "human":
                continue  # disabled accounts generate no recent events

            atype = self.injector.anomaly_type(email) if acct_type == "human" else None

            if atype == "DORMANT_ADMIN":
                # Zero events in last 90 days; a few old events before that
                n_events = int(self.rng.integers(2, 8))
                time_range = (
                    self.ref_dt - timedelta(days=365),
                    self.ref_dt - timedelta(days=120),
                )
            elif acct_type != "human":
                n_events = int(self.rng.integers(20, 80))
                time_range = (self.audit_start, self.ref_dt)
            elif atype in ("TOKEN_ABUSE",):
                n_events = int(self.rng.integers(30, 60))
                time_range = (self.audit_start, self.ref_dt)
            elif atype in ("OVERPRIVILEGED", "PRIVILEGE_ESCALATION"):
                n_events = int(self.rng.integers(30, 80))
                time_range = (self.audit_start, self.ref_dt)
            else:
                n_events = int(self.rng.integers(10, 40))
                time_range = (self.audit_start, self.ref_dt)

            plat_resources = res_by_platform.get(platform, [])

            for _ in range(n_events):
                ts = rdt(time_range[0], time_range[1], self.rng)
                session = uid()
                event_type, action, resource, risk_flag = self._pick_event(
                    acct_type, atype, plat_resources
                )
                rname = resource.name if resource else ""
                rid_val = resource.resource_id if resource else ""
                src_ip = rand_ip(geo, self.rng)

                rows.append(self._audit_row(
                    iid, ts, event_type, platform, rid_val, rname,
                    action, src_ip, geo, risk_flag, session, "",
                ))

            # --- Anomaly-specific injection ---

            # PRIVILEGE_ESCALATION: inject one escalation event
            if atype == "PRIVILEGE_ESCALATION":
                ts = rdt(
                    self.ref_dt - timedelta(days=200),
                    self.ref_dt - timedelta(days=60),
                    self.rng,
                )
                rows.append(self._audit_row(
                    iid, ts, "PRIVILEGE_ESCALATION", platform, "", "",
                    "ADMIN", rand_ip(geo, self.rng), geo, True, uid(), "",
                ))

            # TOKEN_ABUSE: burst of ACCESS events at off-hours from anomalous IP
            if atype == "TOKEN_ABUSE":
                burst_start = rdt(
                    self.ref_dt - timedelta(days=60),
                    self.ref_dt - timedelta(days=7),
                    self.rng,
                )
                burst_start = burst_start.replace(hour=int(self.rng.integers(1, 5)))
                bad_ip = anomalous_ip(self.rng)
                for j in range(int(self.rng.integers(40, 100))):
                    bt = burst_start + timedelta(seconds=int(j * self.rng.integers(10, 60)))
                    res = plat_resources[int(self.rng.integers(0, len(plat_resources)))] if plat_resources else None
                    rows.append(self._audit_row(
                        iid, bt, "ACCESS", platform,
                        res.resource_id if res else "",
                        res.name if res else "",
                        "EXECUTE", bad_ip, "UNKNOWN", True, uid(), "",
                    ))

            # LEGITIMATE_EXCEPTION: elevated admin events with ticket reference
            if atype == "LEGITIMATE_EXCEPTION":
                tkt = ticket_id(self.rng, self.ref_date)
                for _ in range(int(self.rng.integers(5, 15))):
                    ts = rdt(self.audit_start, self.ref_dt, self.rng)
                    # off-hours but legitimate (on-call)
                    ts = ts.replace(hour=int(self.rng.integers(0, 6)))
                    rows.append(self._audit_row(
                        iid, ts, "ADMIN_ACTION", platform, "", "",
                        "ADMIN", rand_ip(geo, self.rng), geo, False, uid(), tkt,
                    ))

        logger.info("Generated %d audit event rows", len(rows))
        return pd.DataFrame(rows)

    def _pick_event(
        self,
        acct_type: str,
        atype: Optional[str],
        resources: List[Resource],
    ) -> Tuple[str, str, Optional[Resource], bool]:
        """Choose an event_type, action, and optional resource for one event."""
        if acct_type != "human":
            event_type = self.rng.choice(["ACCESS", "ACCESS", "ACCESS", "ADMIN_ACTION"])
            action = self.rng.choice(["READ", "EXECUTE", "READ", "WRITE"])
            res = resources[int(self.rng.integers(0, len(resources)))] if resources else None
            return event_type, action, res, False

        r = self.rng.random()
        if r < 0.40:
            return "LOGIN", "READ", None, False
        if r < 0.55:
            return "LOGOUT", "READ", None, False
        if r < 0.80:
            res = resources[int(self.rng.integers(0, len(resources)))] if resources else None
            return "ACCESS", self.rng.choice(["READ", "READ", "WRITE"]), res, False
        if r < 0.90:
            return "CONFIG_CHANGE", "WRITE", None, False
        if r < 0.95:
            res = resources[int(self.rng.integers(0, len(resources)))] if resources else None
            return "EXPORT", "READ", res, atype is not None
        return "ADMIN_ACTION", "ADMIN", None, atype is not None

    def _audit_row(
        self, iid: str, ts: datetime, event_type: str, platform: str,
        resource_id: str, resource_name: str, action: str,
        source_ip: str, geo: str, risk_indicator: bool,
        session_id: str, tkt: str,
    ) -> Dict:
        outcome = "SUCCESS" if self.rng.random() > 0.05 else "FAILURE"
        return {
            "event_id": uid(),
            "timestamp": fmt_dt(ts),
            "identity_id": iid,
            "event_type": event_type,
            "platform": platform,
            "resource_id": resource_id,
            "resource_name": resource_name,
            "action": action,
            "outcome": outcome,
            "source_ip": source_ip,
            "geo_location": geo,
            "risk_indicator": risk_indicator,
            "session_id": session_id,
            "ticket_id": tkt,   # Phase 2 extension column
        }

    # ── Resource access logs ──────────────────────────────────────────────────

    def _generate_resource_access_logs(
        self,
        unified_df: pd.DataFrame,
        resources: List[Resource],
    ) -> pd.DataFrame:
        """
        Generate resource_access_logs.csv.

        TOKEN_ABUSE identities get burst patterns (many EXECUTE calls, high bytes,
        off-hours, different IPs). DORMANT_ADMIN identities have no recent accesses.
        """
        token_abuse_emails = self.injector.ids_with_type("TOKEN_ABUSE")
        dormant_emails = self.injector.ids_with_type("DORMANT_ADMIN")

        res_by_platform: Dict[str, List[Resource]] = {}
        for r in resources:
            res_by_platform.setdefault(r.platform, []).append(r)

        rows: List[Dict] = []

        for _, row in unified_df.iterrows():
            iid = row["identity_id"]
            platform = row["platform"]
            email = row["email"]
            geo = row["geo_location"]
            acct_type = row["account_type"]
            atype = self.injector.anomaly_type(email) if acct_type == "human" else None

            plat_resources = res_by_platform.get(platform, [])
            if not plat_resources:
                continue

            if atype == "DORMANT_ADMIN":
                # Only old accesses (>120 days ago)
                n_accesses = int(self.rng.integers(1, 5))
                time_range = (
                    self.ref_dt - timedelta(days=365),
                    self.ref_dt - timedelta(days=120),
                )
            elif atype == "TOKEN_ABUSE":
                # Normal accesses + burst injection below
                n_accesses = int(self.rng.integers(15, 40))
                time_range = (self.audit_start, self.ref_dt)
            elif acct_type != "human":
                n_accesses = int(self.rng.integers(30, 120))
                time_range = (self.audit_start, self.ref_dt)
            else:
                n_accesses = int(self.rng.integers(5, 30))
                time_range = (self.audit_start, self.ref_dt)

            for _ in range(n_accesses):
                ts = rdt(time_range[0], time_range[1], self.rng)
                res = plat_resources[int(self.rng.integers(0, len(plat_resources)))]
                access_type = self.rng.choice(["READ", "READ", "WRITE", "EXECUTE"])
                duration = int(self.rng.integers(5, 3600))
                bytes_tx = (
                    int(self.rng.integers(1024, 10 * 1024 * 1024))
                    if access_type in ("READ", "WRITE")
                    else None
                )
                rows.append({
                    "log_id": uid(),
                    "resource_id": res.resource_id,
                    "resource_name": res.name,
                    "resource_type": res.res_type,
                    "resource_criticality": res.criticality,
                    "platform": platform,
                    "identity_id": iid,
                    "access_type": access_type,
                    "timestamp": fmt_dt(ts),
                    "duration_seconds": duration,
                    "bytes_transferred": bytes_tx if bytes_tx is not None else "",
                    "outcome": "SUCCESS" if self.rng.random() > 0.03 else "FAILURE",
                })

            # TOKEN_ABUSE burst injection
            if atype == "TOKEN_ABUSE":
                burst_start = rdt(
                    self.ref_dt - timedelta(days=45),
                    self.ref_dt - timedelta(days=3),
                    self.rng,
                )
                burst_start = burst_start.replace(hour=int(self.rng.integers(1, 4)))
                bad_ip_suffix = int(self.rng.integers(1, 254))
                burst_count = int(self.rng.integers(150, 400))
                for j in range(burst_count):
                    bt = burst_start + timedelta(seconds=j * int(self.rng.integers(5, 30)))
                    res = plat_resources[int(self.rng.integers(0, len(plat_resources)))]
                    rows.append({
                        "log_id": uid(),
                        "resource_id": res.resource_id,
                        "resource_name": res.name,
                        "resource_type": res.res_type,
                        "resource_criticality": res.criticality,
                        "platform": platform,
                        "identity_id": iid,
                        "access_type": "EXECUTE",
                        "timestamp": fmt_dt(bt),
                        "duration_seconds": int(self.rng.integers(1, 10)),
                        "bytes_transferred": int(self.rng.integers(100, 512)),
                        "outcome": "SUCCESS",
                    })

        logger.info("Generated %d resource access log rows", len(rows))
        return pd.DataFrame(rows)

    # ── Offboarding records ───────────────────────────────────────────────────

    def _generate_offboarding_records(
        self,
        unified_df: pd.DataFrame,
        admin_identity_ids: List[str],
    ) -> pd.DataFrame:
        """
        Generate offboarding_records.csv.

        ~20% of human identities are offboarded. ORPHANED_ACCOUNT anomalies
        are always included with NON_COMPLIANT status and high revocation_delay_days.
        """
        orphaned_emails = set(self.injector.ids_with_type("ORPHANED_ACCOUNT"))
        all_human_emails = [
            r["email"] for _, r in unified_df.iterrows()
            if r["account_type"] == "human"
        ]
        # Unique human emails
        seen_emails: Set[str] = set()
        unique_humans: List[Dict] = []
        for _, r in unified_df.iterrows():
            if r["account_type"] == "human" and r["email"] not in seen_emails:
                unique_humans.append(r.to_dict())
                seen_emails.add(r["email"])

        target_offboarded = int(len(unique_humans) * 0.20)
        # Ensure all orphaned accounts are in the offboarded pool
        offboard_pool_emails = list(orphaned_emails)
        remaining = [h for h in unique_humans if h["email"] not in orphaned_emails]
        self.rng.shuffle(remaining)
        for h in remaining:
            if len(offboard_pool_emails) >= target_offboarded:
                break
            offboard_pool_emails.append(h["email"])

        email_to_unified = {h["email"]: h for h in unique_humans}
        reviewer_pool = admin_identity_ids[:15] if admin_identity_ids else [uid()]

        rows: List[Dict] = []
        offboarding_types = ["RESIGNED", "TERMINATED", "CONTRACTOR_END", "TRANSFER"]

        for email in offboard_pool_emails:
            h = email_to_unified.get(email)
            if not h:
                continue
            iid = h["identity_id"]
            is_orphaned = email in orphaned_emails

            off_date = rdate(
                self.ref_date - timedelta(days=540),
                self.ref_date - timedelta(days=60),
                self.rng,
            )

            if is_orphaned:
                # Accounts partially disabled — orphan signal
                accts_disabled = False
                access_revoked = False
                delay = int(self.rng.integers(45, 200))
                compliance = "NON_COMPLIANT"
            else:
                accts_disabled = True
                access_revoked = self.rng.random() > 0.05
                delay = 0 if access_revoked else int(self.rng.integers(1, 10))
                compliance = "COMPLIANT" if access_revoked else "PENDING"

            rows.append({
                "record_id": uid(),
                "identity_id": iid,
                "offboarding_date": fmt_date(off_date),
                "offboarding_type": offboarding_types[
                    int(self.rng.integers(0, len(offboarding_types)))
                ],
                "accounts_disabled": accts_disabled,
                "access_revoked": access_revoked,
                "data_retained": self.rng.random() < 0.30,
                "revocation_delay_days": delay,
                "reviewed_by": reviewer_pool[int(self.rng.integers(0, len(reviewer_pool)))],
                "compliance_status": compliance,
            })

        logger.info("Generated %d offboarding records (%d orphaned)",
                    len(rows), len(orphaned_emails))
        return pd.DataFrame(rows)

    # ── Reference table writers ───────────────────────────────────────────────

    def _build_group_definitions_df(self) -> pd.DataFrame:
        """Write supplementary group_definitions.csv for GraphBuilder (Phase 4)."""
        rows = [{
            "group_id": g.group_id,
            "group_name": g.name,
            "platform": g.platform,
            "parent_group_id": g.parent_id if g.parent_id else "",
            "parent_group_name": g.parent_name if g.parent_name else "",
            "nesting_depth": g.nesting_depth,
            "is_privileged": g.is_privileged,
        } for g in self.groups]
        return pd.DataFrame(rows)

    def _build_role_definitions_df(self) -> pd.DataFrame:
        """Write supplementary role_definitions.csv for GraphBuilder (Phase 4)."""
        res_by_name = self._res_by_name()
        rows = []
        for r in self.roles:
            resource_ids = [
                res_by_name[rn].resource_id
                for rn in r.resource_names
                if rn in res_by_name
            ]
            rows.append({
                "role_id": r.role_id,
                "role_name": r.name,
                "platform": r.platform,
                "permission_scope": r.permission_scope,
                "is_privileged": r.is_privileged,
                "resource_ids": json.dumps(resource_ids),
                "resource_names": json.dumps(r.resource_names),
            })
        return pd.DataFrame(rows)

    def _build_resource_catalog_df(self) -> pd.DataFrame:
        """Write resource_catalog.csv (supplementary — full resource registry)."""
        rows = [{
            "resource_id": r.resource_id,
            "resource_name": r.name,
            "resource_type": r.res_type,
            "resource_criticality": r.criticality,
            "platform": r.platform,
        } for r in self.resources]
        return pd.DataFrame(rows)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _admin_identity_ids(self, unified_df: pd.DataFrame) -> List[str]:
        """Return a pool of IT-Operations identity_ids to use as provisioners."""
        ids = unified_df.loc[
            unified_df["department"].isin(["IT-Operations", "Security", "Executive"]),
            "identity_id",
        ].tolist()
        return ids if ids else unified_df["identity_id"].tolist()[:10]

    # ── Main orchestrator ─────────────────────────────────────────────────────

    def run(self) -> Dict[str, int]:
        """
        Execute the full data generation pipeline.

        Returns a dict of {filename: row_count} for all written files.
        """
        logger.info("=" * 60)
        logger.info("Identity Nexus AI — Data Simulator Phase 2")
        logger.info("Config: n_identities=%d  seed=%d  output=%s",
                    self.cfg["n_identities"], self.cfg["seed"], self.out_dir)
        logger.info("=" * 60)

        # 1. Build static catalogs
        self._build_resources()
        self._build_groups()
        self._build_roles()

        # 2. Generate people and anomaly profiles
        self._generate_persons()
        self._assign_anomaly_profiles()

        # 3. Generate platform accounts and unified identities
        logger.info("Generating platform accounts…")
        platform_dfs, unified_df = self._generate_platform_accounts()

        # 4. Admin pool for FK references
        admin_ids = self._admin_identity_ids(unified_df)

        # 5. Group mappings
        logger.info("Generating group mappings…")
        group_mappings_df = self._generate_group_mappings(unified_df)

        # 6. Role mappings
        logger.info("Generating role mappings…")
        role_mappings_df = self._generate_role_mappings(unified_df, admin_ids)

        # 7. Audit events
        logger.info("Generating audit events…")
        audit_df = self._generate_audit_events(unified_df, self.resources)

        # 8. Resource access logs
        logger.info("Generating resource access logs…")
        resource_logs_df = self._generate_resource_access_logs(unified_df, self.resources)

        # 9. Offboarding records
        logger.info("Generating offboarding records…")
        offboarding_df = self._generate_offboarding_records(unified_df, admin_ids)

        # 10. Reference tables
        group_defs_df = self._build_group_definitions_df()
        role_defs_df = self._build_role_definitions_df()
        resource_catalog_df = self._build_resource_catalog_df()

        # 11. Ground truth labels (EVALUATION ONLY)
        ground_truth_df = self.injector.get_ground_truth_df()

        # 12. Write all files
        written: Dict[str, int] = {}

        def save(df: pd.DataFrame, fname: str) -> None:
            path = self.out_dir / fname
            df.to_csv(path, index=False)
            written[fname] = len(df)
            logger.info("  ✓ %-45s  %6d rows", fname, len(df))

        logger.info("Writing output files to %s …", self.out_dir)

        # Per-platform raw CSVs
        for platform, df in platform_dfs.items():
            save(df, f"{platform.lower()}_identities.csv")

        # Core pipeline files (Phase 1 spec)
        save(unified_df,       "unified_identities.csv")
        save(group_mappings_df,"group_mappings.csv")
        save(role_mappings_df, "role_mappings.csv")
        save(audit_df,         "audit_events.csv")
        save(offboarding_df,   "offboarding_records.csv")
        save(resource_logs_df, "resource_access_logs.csv")

        # Supplementary reference files (Phase 2 additions)
        save(group_defs_df,      "group_definitions.csv")
        save(role_defs_df,       "role_definitions.csv")
        save(resource_catalog_df,"resource_catalog.csv")

        # Evaluation-only ground truth (never read by analytics pipeline)
        save(ground_truth_df,  "ground_truth_labels.csv")

        return written

    # ── Summary report ────────────────────────────────────────────────────────

    def print_summary(self, written: Dict[str, int]) -> None:
        """Print a structured summary report to stdout."""
        total_accts = sum(
            n for fname, n in written.items()
            if fname.endswith("_identities.csv") and fname != "unified_identities.csv"
        )
        print("\n" + "=" * 65)
        print("  IDENTITY NEXUS AI — Phase 2 Data Simulator Summary")
        print("=" * 65)
        print(f"\n  Canonical human identities  : {self.cfg['n_identities']}")
        print(f"  Service / machine accounts  : {self.cfg['n_service_accounts']}")
        print(f"  Random seed                 : {self.cfg['seed']}")
        print(f"  Reference date              : {self.ref_date}")
        print(f"  Audit window                : {self.cfg['audit_window_months']} months")

        print("\n  Platform account distribution:")
        for plat in self.cfg["platform_coverage"]:
            fname = f"{plat.lower()}_identities.csv"
            n = written.get(fname, 0)
            print(f"    {plat:<14} {n:5d} accounts")
        print(f"    {'TOTAL':<14} {written.get('unified_identities.csv',0):5d} rows in unified_identities.csv")

        print("\n  Anomaly injection summary:")
        from anomaly_injector import ANOMALY_TYPES
        total_people = self.cfg["n_identities"]
        for atype, meta in ANOMALY_TYPES.items():
            ids = self.injector.ids_with_type(atype)
            pct = len(ids) / total_people * 100
            label = "(true positive)" if meta["true_positive"] else "(false-positive trap)"
            print(f"    {atype:<28} {len(ids):4d}  ({pct:5.1f}%)  {label}")
        normal_n = sum(1 for p in self.persons if p.anomaly_type is None)
        print(f"    {'NORMAL':<28} {normal_n:4d}  ({normal_n/total_people*100:5.1f}%)")

        print("\n  Output files written:")
        for fname, nrows in sorted(written.items()):
            marker = "  [EVAL ONLY]" if "ground_truth" in fname else ""
            print(f"    {fname:<48} {nrows:6d} rows{marker}")

        print("\n" + "=" * 65 + "\n")


# ──────────────────────────────────────────────────────────────────────────────
# HELPER: hire-date lookup used by role mapping generator
# ──────────────────────────────────────────────────────────────────────────────

def p_hire_date(unified_df: pd.DataFrame, iid: str, persons: List[Person]) -> date:
    """Return the hire date for a given identity_id (fallback: 3 years ago)."""
    rows = unified_df.loc[unified_df["identity_id"] == iid, "created_date"]
    if not rows.empty:
        try:
            return date.fromisoformat(rows.iloc[0])
        except Exception:
            pass
    return date(2022, 1, 1)


# ──────────────────────────────────────────────────────────────────────────────
# CLI ENTRYPOINT
# ──────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Identity Nexus AI — Phase 2 Synthetic Data Simulator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--n_identities",  type=int, default=CONFIG["n_identities"],
                        help="Number of canonical human identities to generate")
    parser.add_argument("--seed",          type=int, default=CONFIG["seed"],
                        help="Random seed for reproducibility")
    parser.add_argument("--output_dir",    type=str, default=CONFIG["output_dir"],
                        help="Directory to write generated CSVs")
    parser.add_argument("--log_level",     type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING"],
                        help="Logging verbosity")
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint — run the full data simulator pipeline."""
    args = _parse_args()
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    cfg = dict(CONFIG)
    cfg["n_identities"] = args.n_identities
    cfg["seed"] = args.seed
    cfg["output_dir"] = args.output_dir

    sim = DataSimulator(cfg)
    written = sim.run()
    sim.print_summary(written)


if __name__ == "__main__":
    main()
