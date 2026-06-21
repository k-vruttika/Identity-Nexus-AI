"""
src/identity_resolver.py
Identity Nexus AI — Phase 3: Cross-Platform Identity Resolution

Single responsibility: correlate and deduplicate the 1,377 per-platform account
rows in unified_identities.csv into ~453 canonical identities using a three-stage
matching strategy:
  1. Exact normalised-email match          (confidence 100, method exact_email)
  2. Fuzzy display-name match via RapidFuzz (confidence = score, method fuzzy_name)
  3. Unresolved fallback                   (confidence 0, method unresolved)

Output
------
generated_data/unified_identities.csv  — overwritten; canonical_id column updated
generated_data/resolution_report.csv   — per-row match metadata + source IDs list

Contract
--------
MUST NOT read ground_truth_labels.csv.
MUST NOT import from any later-phase module.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

import pandas as pd
from rapidfuzz import fuzz

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent.parent / "generated_data"

# Platform priority for canonical ID selection.
# The account whose platform appears earliest in this list becomes the canonical
# representative for a resolved group.
PLATFORM_PRIORITY: List[str] = ["AD", "AzureAD", "Okta", "AWS", "Salesforce"]

# Minimum fuzzy score (0–100) required to accept a name-based merge.
# Below this threshold the record is flagged "unresolved" and its canonical_id
# stays equal to its own identity_id.
FUZZY_THRESHOLD: int = 85


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _norm_email(email: object) -> str:
    """Return lowercase-stripped email, or '' if null/non-string."""
    if pd.isna(email) or not isinstance(email, str):
        return ""
    return email.strip().lower()


def _norm_name(name: object) -> str:
    """Return normalised display name for fuzzy comparison."""
    if pd.isna(name) or not isinstance(name, str):
        return ""
    return " ".join(name.strip().lower().split())


# ---------------------------------------------------------------------------
# Main resolver class
# ---------------------------------------------------------------------------

class IdentityResolver:
    """
    Reads unified_identities.csv (pre-resolution, canonical_id == identity_id)
    and assigns a shared canonical_id to all rows that represent the same
    real-world person or service account.

    The canonical_id chosen for a resolution group is the identity_id of
    whichever row has the highest-priority platform (AD > AzureAD > Okta >
    AWS > Salesforce).  This is deterministic across runs.
    """

    def __init__(
        self,
        data_dir: Path = DATA_DIR,
        fuzzy_threshold: int = FUZZY_THRESHOLD,
    ) -> None:
        self.data_dir = data_dir
        self.fuzzy_threshold = fuzzy_threshold

        self._df: Optional[pd.DataFrame] = None
        # identity_id → canonical_id
        self._canonical: Dict[str, str] = {}
        # identity_id → match_method string
        self._method: Dict[str, str] = {}
        # identity_id → match_confidence int
        self._confidence: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> "IdentityResolver":
        """Load unified_identities.csv from disk."""
        path = self.data_dir / "unified_identities.csv"
        self._df = pd.read_csv(path, dtype=str)
        # Normalise boolean columns that were written as True/False strings
        for col in ("is_active", "is_privileged", "mfa_enabled"):
            if col in self._df.columns:
                self._df[col] = self._df[col].map(
                    {"True": True, "False": False, True: True, False: False}
                )
        logger.info("Loaded unified_identities.csv: %d rows", len(self._df))
        return self

    def resolve(self) -> "IdentityResolver":
        """
        Run the three-stage resolution pipeline and populate the internal
        canonical / method / confidence maps.
        """
        df = self._df
        assigned: Set[str] = set()

        # ---- Stage 1: Exact email match ----------------------------------
        df["_email_norm"] = df["email"].apply(_norm_email)

        email_groups = (
            df[df["_email_norm"] != ""]
            .groupby("_email_norm", sort=False)
        )

        exact_groups = 0
        for email, group in email_groups:
            canonical_id = self._pick_canonical(group)
            for iid in group["identity_id"]:
                self._canonical[iid] = canonical_id
                self._method[iid] = "exact_email"
                self._confidence[iid] = 100
                assigned.add(iid)
            exact_groups += 1

        logger.info(
            "Stage 1 (exact_email): %d email groups -> %d rows resolved",
            exact_groups, len(assigned),
        )

        # ---- Stage 2: Fuzzy display-name match for any remainders --------
        unassigned = df[~df["identity_id"].isin(assigned)]

        if not unassigned.empty:
            logger.info(
                "Stage 2 (fuzzy_name): %d rows need fuzzy matching",
                len(unassigned),
            )
            # Build name → canonical_id lookup from already-resolved rows
            name_to_canonical: Dict[str, str] = {}
            for iid, canonical_id in self._canonical.items():
                row = df.loc[df["identity_id"] == iid].iloc[0]
                name_key = _norm_name(row["display_name"])
                if name_key and canonical_id not in name_to_canonical.values():
                    name_to_canonical[name_key] = canonical_id

            fuzzy_resolved = 0
            for _, row in unassigned.iterrows():
                iid = row["identity_id"]
                candidate_name = _norm_name(row["display_name"])

                best_score = 0
                best_canonical: Optional[str] = None

                for known_name, cid in name_to_canonical.items():
                    score = fuzz.token_sort_ratio(candidate_name, known_name)
                    if score > best_score:
                        best_score = score
                        best_canonical = cid

                if best_score >= self.fuzzy_threshold and best_canonical:
                    self._canonical[iid] = best_canonical
                    self._method[iid] = "fuzzy_name"
                    self._confidence[iid] = best_score
                    assigned.add(iid)
                    fuzzy_resolved += 1
                    logger.debug(
                        "Fuzzy match: %s → %s (score=%d)", iid, best_canonical, best_score
                    )
                else:
                    self._canonical[iid] = iid  # unresolved: self-referential
                    self._method[iid] = "unresolved"
                    self._confidence[iid] = best_score
                    assigned.add(iid)
                    logger.debug(
                        "Unresolved: %s (best_score=%d)", iid, best_score
                    )

            logger.info(
                "Stage 2 (fuzzy_name): %d resolved, %d left unresolved",
                fuzzy_resolved, len(unassigned) - fuzzy_resolved,
            )

        # ---- Stage 3: Safety net — any row not yet processed ---------------
        for iid in df["identity_id"]:
            if iid not in self._canonical:
                self._canonical[iid] = iid
                self._method[iid] = "unresolved"
                self._confidence[iid] = 0
                logger.warning("Safety-net fallback for identity_id=%s", iid)

        return self

    def save(self) -> None:
        """
        Overwrite unified_identities.csv with updated canonical_id values.
        Write resolution_report.csv with per-row match metadata.
        """
        df = self._df.copy()

        # Apply resolution
        df["canonical_id"] = df["identity_id"].map(self._canonical)

        # Drop the internal working column
        df = df.drop(columns=["_email_norm"], errors="ignore")

        # Restore original boolean formatting
        for col in ("is_active", "is_privileged", "mfa_enabled"):
            if col in df.columns:
                df[col] = df[col].map({True: "True", False: "False"}).fillna(df[col])

        out_path = self.data_dir / "unified_identities.csv"
        df.to_csv(out_path, index=False)
        logger.info("Overwrote unified_identities.csv: %d rows", len(df))

        # Build resolution report
        report_rows: List[dict] = []
        # For traceability: canonical_id → list of all identity_ids merged into it
        canonical_to_sources: Dict[str, List[str]] = defaultdict(list)
        for iid, cid in self._canonical.items():
            canonical_to_sources[cid].append(iid)

        for _, row in df.iterrows():
            iid = row["identity_id"]
            cid = self._canonical[iid]
            report_rows.append({
                "identity_id": iid,
                "canonical_id": cid,
                "platform": row["platform"],
                "account_type": row["account_type"],
                "email": row["email"],
                "display_name": row["display_name"],
                "match_method": self._method[iid],
                "match_confidence": self._confidence[iid],
                "is_canonical_representative": iid == cid,
                "merged_source_ids": json.dumps(
                    canonical_to_sources.get(cid, [iid])
                ),
            })

        report_df = pd.DataFrame(report_rows)
        report_path = self.data_dir / "resolution_report.csv"
        report_df.to_csv(report_path, index=False)
        logger.info("Wrote resolution_report.csv: %d rows", len(report_df))

    def print_summary(self) -> None:
        """Print a structured resolution summary to stdout."""
        if not self._canonical:
            print("Resolver has not been run yet.")
            return

        total_rows = len(self._canonical)
        canonical_ids: Set[str] = set(self._canonical.values())
        n_canonical = len(canonical_ids)

        method_counts: Dict[str, int] = defaultdict(int)
        for m in self._method.values():
            method_counts[m] += 1

        # Identities that were merged (canonical_id ≠ identity_id)
        merged_rows = sum(
            1 for iid, cid in self._canonical.items() if iid != cid
        )

        # Orphan platform records (unresolved)
        unresolved = method_counts.get("unresolved", 0)

        print("=" * 60)
        print("  IDENTITY RESOLVER — Summary")
        print("=" * 60)
        print(f"  Total platform account rows   : {total_rows}")
        print(f"  Canonical identities resolved  : {n_canonical}")
        print(f"  Rows merged (canonical_id!=self): {merged_rows}")
        print(f"  Unresolved (orphan records)    : {unresolved}")
        print()
        print("  Match method breakdown:")
        for method, count in sorted(method_counts.items()):
            pct = count / total_rows * 100
            print(f"    {method:25s}: {count:5d}  ({pct:5.1f}%)")
        print()
        # Platform breakdown per canonical identity
        df = self._df.copy()
        df["canonical_id"] = df["identity_id"].map(self._canonical)
        platform_dist = df.groupby("canonical_id")["platform"].apply(list)
        from collections import Counter
        platform_count_dist: Counter = Counter(
            len(v) for v in platform_dist
        )
        print("  Platforms per canonical identity:")
        for n_plat in sorted(platform_count_dist.keys()):
            print(
                f"    {n_plat} platform(s): "
                f"{platform_count_dist[n_plat]:4d} canonical identities"
            )
        print("=" * 60)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _pick_canonical(self, group: pd.DataFrame) -> str:
        """
        Return the identity_id of the row with highest platform priority.
        Tie-break: first occurrence in the dataframe.
        """
        for platform in PLATFORM_PRIORITY:
            mask = group["platform"] == platform
            if mask.any():
                return group.loc[mask[mask].index[0], "identity_id"]
        # Fallback: first row
        return group.iloc[0]["identity_id"]


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identity Nexus AI — Phase 3: Identity Resolver"
    )
    parser.add_argument(
        "--data-dir",
        default=str(DATA_DIR),
        help="Path to generated_data/ directory (default: %(default)s)",
    )
    parser.add_argument(
        "--fuzzy-threshold",
        type=int,
        default=FUZZY_THRESHOLD,
        help="Minimum RapidFuzz score for fuzzy name merge (default: %(default)d)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: %(default)s)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )

    resolver = IdentityResolver(
        data_dir=Path(args.data_dir),
        fuzzy_threshold=args.fuzzy_threshold,
    )
    resolver.load().resolve().save()
    resolver.print_summary()


if __name__ == "__main__":
    main()
