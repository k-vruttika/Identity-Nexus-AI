"""
src/effective_privilege_engine.py
Identity Nexus AI — Phase 3: Effective Privilege Engine

Single responsibility: traverse the identity graph via BFS for every Identity
node to materialise the complete set of resources each identity can effectively
reach, resolving nested group chains and avoiding cycles.

BFS edge traversal order (per architecture.md §6):
  MEMBER_OF  → continue (Group node)
  NESTED_IN  → continue (parent Group node)
  HAS_ROLE   → continue (Role node)
  GRANTS_ACCESS → record effective privilege (Resource node)
  FEDERATES_TO  → NOT followed during privilege computation

Deduplication: if the same (identity_id, resource_id) pair is reachable via
multiple paths, the row with the highest privilege_level is kept and all
grant_paths are concatenated with ';'.

Privilege level ordering (ascending):
  READ < WRITE < EXECUTE < ADMIN < FULL_CONTROL

Flags:
  is_excessive  — provisioned but NEVER accessed (no entry in resource_access_logs)
  is_dormant    — not accessed in the last 90 days
  last_used     — most recent access date from resource_access_logs

Contract
--------
Reads  : models/identity_graph.gpickle
         generated_data/resource_access_logs.csv
Writes : generated_data/effective_privileges.csv
MUST NOT read ground_truth_labels.csv or import later-phase modules.
"""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from collections import deque
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx
import pandas as pd

# Import GraphBuilder only for its load_graph() classmethod; no circular risk
# because graph_builder.py has no imports from other src/ modules.
from graph_builder import GraphBuilder

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent.parent / "generated_data"
MODELS_DIR = Path(__file__).parent.parent / "models"

REFERENCE_DATE: date = date(2026, 6, 21)   # same as Phase 2 reference
DORMANT_DAYS: int = 90

# Privilege level ordering for deduplication (higher index = higher privilege)
PRIVILEGE_RANK: Dict[str, int] = {
    "READ": 1,
    "WRITE": 2,
    "EXECUTE": 3,
    "ADMIN": 4,
    "FULL_CONTROL": 5,
}


# ---------------------------------------------------------------------------
# Effective Privilege Engine
# ---------------------------------------------------------------------------

class EffectivePrivilegeEngine:
    """
    Materialises effective_privileges.csv by performing per-identity BFS over
    the identity graph.

    Usage
    -----
    engine = EffectivePrivilegeEngine().load()
    df = engine.run()
    engine.save(df)
    engine.print_summary(df)
    """

    def __init__(
        self,
        data_dir: Path = DATA_DIR,
        models_dir: Path = MODELS_DIR,
        reference_date: date = REFERENCE_DATE,
        dormant_days: int = DORMANT_DAYS,
    ) -> None:
        self.data_dir = data_dir
        self.models_dir = models_dir
        self.reference_date = reference_date
        self.dormant_days = dormant_days

        self._graph: Optional[nx.MultiDiGraph] = None
        # (identity_id, resource_id) → most recent access date (or None)
        self._last_access: Dict[Tuple[str, str], date] = {}
        self._dormant_cutoff: date = date(
            reference_date.year,
            reference_date.month,
            reference_date.day,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> "EffectivePrivilegeEngine":
        """Load the identity graph and pre-compute the access-date lookup."""
        graph_path = self.models_dir / "identity_graph.gpickle"
        self._graph = GraphBuilder.load_graph(graph_path)
        logger.info(
            "Loaded graph: %d nodes, %d edges",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
        )

        # Build identity_id → canonical_id lookup from unified_identities.csv.
        # resource_access_logs.csv stores per-platform identity_ids, but the
        # graph now has one canonical Identity node per person.  We must
        # aggregate last-access dates under the canonical_id so that
        # is_excessive / is_dormant reflect the person's aggregate activity.
        ui_path = self.data_dir / "unified_identities.csv"
        ui = pd.read_csv(ui_path, usecols=["identity_id", "canonical_id"])
        iid_to_canon: Dict[str, str] = dict(zip(ui["identity_id"].astype(str),
                                                 ui["canonical_id"].astype(str)))
        logger.info("Loaded identity_id->canonical_id map: %d entries", len(iid_to_canon))

        rl_path = self.data_dir / "resource_access_logs.csv"
        rl = pd.read_csv(rl_path, usecols=["identity_id", "resource_id", "timestamp"])
        logger.info("Loaded resource_access_logs.csv: %d rows", len(rl))

        # Parse timestamps once; keep only the date portion
        rl["_date"] = pd.to_datetime(rl["timestamp"], errors="coerce").dt.date

        # Build (canonical_id, resource_id) → most recent access date.
        # Aggregate over all platform accounts so that any access by any of a
        # person's accounts counts toward is_dormant / is_excessive.
        for _, row in rl.iterrows():
            raw_iid = str(row["identity_id"])
            canon_id = iid_to_canon.get(raw_iid, raw_iid)
            key = (canon_id, str(row["resource_id"]))
            d = row["_date"]
            if d is None or (isinstance(d, float)):
                continue
            existing = self._last_access.get(key)
            if existing is None or d > existing:
                self._last_access[key] = d

        logger.info(
            "Access lookup built: %d unique (canonical_id, resource) pairs",
            len(self._last_access),
        )
        return self

    def run(self) -> pd.DataFrame:
        """
        Compute effective privileges for every Identity node in the graph.
        Returns a DataFrame conforming to the effective_privileges.csv schema.
        """
        G = self._graph
        identity_nodes = [
            n for n, d in G.nodes(data=True) if d.get("type") == "Identity"
        ]
        logger.info(
            "Computing effective privileges for %d Identity nodes …",
            len(identity_nodes),
        )

        all_rows: List[dict] = []
        computed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        for idx, identity_id in enumerate(identity_nodes):
            raw_privs = self._bfs_privileges(identity_id)
            for resource_id, priv_data in raw_privs.items():
                row = self._build_row(
                    identity_id=identity_id,
                    resource_id=resource_id,
                    privilege_level=priv_data["privilege_level"],
                    grant_paths=priv_data["grant_paths"],
                    computed_at=computed_at,
                )
                all_rows.append(row)

            if (idx + 1) % 200 == 0:
                logger.info(
                    "  Progress: %d / %d identities processed",
                    idx + 1, len(identity_nodes),
                )

        df = pd.DataFrame(all_rows)
        logger.info(
            "Effective privilege computation complete: %d rows", len(df)
        )
        return df

    def save(self, df: pd.DataFrame) -> None:
        """Write effective_privileges.csv to the data directory."""
        out = self.data_dir / "effective_privileges.csv"
        df.to_csv(out, index=False)
        logger.info("Wrote effective_privileges.csv: %d rows", len(df))

    def print_summary(self, df: pd.DataFrame) -> None:
        """Print summary statistics to stdout."""
        if df.empty:
            print("No effective privilege rows computed.")
            return

        n_rows = len(df)
        n_identities = df["identity_id"].nunique()
        avg_privs = n_rows / n_identities if n_identities else 0.0
        n_excessive = df["is_excessive"].sum()
        n_dormant = df["is_dormant"].sum()

        top5 = (
            df.groupby("identity_id")
            .size()
            .sort_values(ascending=False)
            .head(5)
        )

        print()
        print("=" * 65)
        print("  EFFECTIVE PRIVILEGE ENGINE — Summary")
        print("=" * 65)
        print(f"  Total privilege rows       : {n_rows:,}")
        print(f"  Unique identities          : {n_identities:,}")
        print(f"  Avg privileges per identity: {avg_privs:.1f}")
        print(f"  Excessive (never used)     : {n_excessive:,}  "
              f"({n_excessive/n_rows*100:.1f}%)")
        print(f"  Dormant (>90d no use)      : {n_dormant:,}  "
              f"({n_dormant/n_rows*100:.1f}%)")

        # Privilege level breakdown
        lev_counts = df["privilege_level"].value_counts()
        print("\n  Privilege level distribution:")
        for lev, cnt in lev_counts.items():
            print(f"    {lev:<15s}: {cnt:6,}  ({cnt/n_rows*100:.1f}%)")

        print("\n  Top 5 identities by effective privilege count:")
        for iid, cnt in top5.items():
            node_data = self._graph.nodes.get(iid, {})
            label = node_data.get("display_name", iid[:16])
            plat = node_data.get("platform", "?")
            print(f"    {iid[:36]}  {cnt:4d} privs  [{plat}] {label}")

        # Side validation hint (does NOT use ground_truth_labels.csv)
        print("\n  [INFO] High privilege counts above may correlate with")
        print("  OVERPRIVILEGED / DORMANT_ADMIN anomaly categories — validate")
        print("  against Phase 2 anomaly injection after Phase 10 evaluation.")
        print("=" * 65)
        print()

    # ------------------------------------------------------------------
    # BFS core
    # ------------------------------------------------------------------

    def _bfs_privileges(
        self, identity_id: str
    ) -> Dict[str, Dict]:
        """
        BFS from identity_id following MEMBER_OF, NESTED_IN, HAS_ROLE,
        GRANTS_ACCESS edges.  Returns a dict:
            resource_id → {privilege_level, grant_paths: List[str]}

        Cycle protection: visited set prevents any Group/Role node from being
        expanded more than once per identity traversal.

        Path tracking: each queue item carries the path_description accumulated
        to reach the current node, enabling grant_path construction per spec.
        """
        G = self._graph

        # (node_id, path_description_to_reach_this_node)
        queue: deque = deque([(identity_id, "DIRECT")])
        visited: Set[str] = {identity_id}

        # resource_id → {"privilege_level": str, "grant_paths": List[str]}
        privileges: Dict[str, dict] = {}

        while queue:
            current, path = queue.popleft()
            current_type = G.nodes[current].get("type", "")

            for _, neighbor, edge_data in G.out_edges(current, data=True):
                edge_type = edge_data.get("edge_type", "")

                if edge_type == "GRANTS_ACCESS" and current_type == "Role":
                    # Neighbor is a Resource — record the privilege
                    res_id = neighbor
                    priv_level = edge_data.get("privilege_level", "READ")
                    self._record_privilege(privileges, res_id, priv_level, path)

                elif edge_type == "HAS_ROLE":
                    # Neighbor is a Role node
                    if neighbor not in visited:
                        visited.add(neighbor)
                        role_name = G.nodes[neighbor].get("role_name", neighbor)
                        assignment_type = edge_data.get("assignment_type", "direct")
                        if path == "DIRECT":
                            new_path = f"ROLE:{role_name}"
                        else:
                            # Arrived at this role via a group chain
                            new_path = f"{path}→ROLE:{role_name}"
                        queue.append((neighbor, new_path))

                elif edge_type == "MEMBER_OF":
                    # Neighbor is a Group node
                    if neighbor not in visited:
                        visited.add(neighbor)
                        group_name = G.nodes[neighbor].get("group_name", neighbor)
                        new_path = f"GROUP:{group_name}"
                        queue.append((neighbor, new_path))

                elif edge_type == "NESTED_IN":
                    # Neighbor is a parent Group node
                    if neighbor not in visited:
                        visited.add(neighbor)
                        parent_name = G.nodes[neighbor].get("group_name", neighbor)
                        # Build nested chain string
                        if path.startswith("NESTED:"):
                            chain = path[len("NESTED:"):]
                            new_path = f"NESTED:{chain}→{parent_name}"
                        elif path.startswith("GROUP:"):
                            child_name = path[len("GROUP:"):]
                            new_path = f"NESTED:{child_name}→{parent_name}"
                        else:
                            new_path = f"NESTED:{parent_name}"
                        queue.append((neighbor, new_path))

                # FEDERATES_TO and Platform edges are NOT followed here
                # (per architecture spec §6 BFS pseudocode)

        return privileges

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _record_privilege(
        privileges: Dict[str, dict],
        resource_id: str,
        privilege_level: str,
        grant_path: str,
    ) -> None:
        """
        Update the privileges dict for resource_id.
        Keep the highest privilege_level; accumulate distinct grant_paths.
        """
        if resource_id not in privileges:
            privileges[resource_id] = {
                "privilege_level": privilege_level,
                "grant_paths": [grant_path],
            }
        else:
            existing = privileges[resource_id]
            # Promote if new privilege is higher
            if PRIVILEGE_RANK.get(privilege_level, 0) > PRIVILEGE_RANK.get(
                existing["privilege_level"], 0
            ):
                existing["privilege_level"] = privilege_level
            # Append distinct grant_paths
            if grant_path not in existing["grant_paths"]:
                existing["grant_paths"].append(grant_path)

    def _build_row(
        self,
        identity_id: str,
        resource_id: str,
        privilege_level: str,
        grant_paths: List[str],
        computed_at: str,
    ) -> dict:
        """Build one effective_privileges.csv row."""
        G = self._graph
        res_attrs = G.nodes.get(resource_id, {})

        last_access = self._last_access.get((identity_id, resource_id))

        is_excessive: bool = last_access is None

        if last_access is None:
            is_dormant = True
        else:
            days_since = (self.reference_date - last_access).days
            is_dormant = days_since >= self.dormant_days

        last_used_str = last_access.isoformat() if last_access else ""
        combined_path = ";".join(grant_paths)

        return {
            "privilege_id": str(uuid.uuid4()),
            "identity_id": identity_id,
            "resource_id": resource_id,
            "resource_name": res_attrs.get("resource_name", ""),
            "resource_type": res_attrs.get("resource_type", ""),
            "resource_criticality": res_attrs.get("resource_criticality", ""),
            "platform": res_attrs.get("platform", ""),
            "privilege_level": privilege_level,
            "grant_path": combined_path,
            "is_excessive": is_excessive,
            "is_dormant": is_dormant,
            "last_used": last_used_str,
            "computed_date": computed_at,
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identity Nexus AI — Phase 3: Effective Privilege Engine"
    )
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--models-dir", default=str(MODELS_DIR))
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

    engine = EffectivePrivilegeEngine(
        data_dir=Path(args.data_dir),
        models_dir=Path(args.models_dir),
    )
    engine.load()
    df = engine.run()
    engine.save(df)
    engine.print_summary(df)


if __name__ == "__main__":
    main()
