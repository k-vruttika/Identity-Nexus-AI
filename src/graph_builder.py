"""
src/graph_builder.py
Identity Nexus AI — Phase 3: Identity Graph Builder

Single responsibility: construct a NetworkX MultiDiGraph from the resolved
identity, group, role, and resource data, then serialise it to
models/identity_graph.gpickle for all downstream consumers.

Node types  : Identity (453 canonical), Group, Role, Resource, Platform
Edge types  : MEMBER_OF, HAS_ROLE, GRANTS_ACCESS, NESTED_IN

Serialisation: Python pickle (NetworkX 3.x removed nx.write_gpickle).
               Downstream modules load via GraphBuilder.load_graph().

Contract
--------
Reads  : generated_data/unified_identities.csv (post-resolution)
         generated_data/group_mappings.csv
         generated_data/role_mappings.csv
         generated_data/group_definitions.csv
         generated_data/role_definitions.csv
         generated_data/resource_catalog.csv
Writes : models/identity_graph.gpickle
MUST NOT read ground_truth_labels.csv or import later-phase modules.
"""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import sys
from pathlib import Path
from typing import Dict, Optional

import networkx as nx
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent.parent / "generated_data"
MODELS_DIR = Path(__file__).parent.parent / "models"

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

# Maps a role's permission_scope → privilege_level for GRANTS_ACCESS edges.
# Actual values observed in role_definitions.csv are confirmed below.
SCOPE_TO_PRIVILEGE: Dict[str, str] = {
    "global": "FULL_CONTROL",
    "user_mgmt": "ADMIN",
    "iam": "ADMIN",
    "org_mgmt": "ADMIN",
    "standard": "WRITE",
    "finance": "WRITE",
    "power": "WRITE",
    "schema": "WRITE",
    "read-only": "READ",
    "read": "READ",        # AD-Standard-User uses "read" (not "read-only")
    "marketing": "READ",
    "contracts": "READ",
}

# Federation protocol for FEDERATES_TO edges between platforms.
FEDERATION_PROTOCOL: Dict[tuple, str] = {
    ("AD", "AzureAD"): "LDAP_SYNC",
    ("AzureAD", "AD"): "LDAP_SYNC",
    ("AD", "Okta"): "SAML",
    ("AzureAD", "Okta"): "OIDC",
    ("Okta", "AD"): "SAML",
    ("Okta", "AzureAD"): "OIDC",
    ("AD", "AWS"): "SAML",
    ("AzureAD", "AWS"): "SAML",
    ("Okta", "AWS"): "SAML",
    ("AWS", "AD"): "SAML",
    ("AWS", "AzureAD"): "SAML",
    ("AWS", "Okta"): "SAML",
    ("AD", "Salesforce"): "SAML",
    ("AzureAD", "Salesforce"): "SAML",
    ("Okta", "Salesforce"): "SAML",
    ("Salesforce", "AD"): "SAML",
    ("Salesforce", "AzureAD"): "SAML",
    ("Salesforce", "Okta"): "SAML",
}

PLATFORM_FEDERATION_PROTOCOL: Dict[str, str] = {
    "AD": "LDAP",
    "AzureAD": "OIDC",
    "AWS": "SAML",
    "Okta": "SAML",
    "Salesforce": "SAML",
}


# ---------------------------------------------------------------------------
# GraphBuilder
# ---------------------------------------------------------------------------

class GraphBuilder:
    """
    Assembles the Identity Nexus AI MultiDiGraph from Phase 2/3 CSVs.

    Usage
    -----
    builder = GraphBuilder().build()
    builder.print_summary()
    builder.save()

    Later phases load the graph with:
    G = GraphBuilder.load_graph()
    """

    def __init__(
        self,
        data_dir: Path = DATA_DIR,
        models_dir: Path = MODELS_DIR,
    ) -> None:
        self.data_dir = data_dir
        self.models_dir = models_dir
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()
        self._iid_to_canon: dict = {}  # filled by _add_identity_nodes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self) -> "GraphBuilder":
        """Load all CSVs and assemble the graph."""
        dfs = self._load_data()

        logger.info("Adding nodes …")
        self._add_identity_nodes(dfs["unified_identities"])
        self._add_group_nodes(dfs["group_definitions"])
        self._add_role_nodes(dfs["role_definitions"])
        self._add_resource_nodes(dfs["resource_catalog"])
        self._add_platform_nodes(dfs["unified_identities"])

        logger.info("Adding edges …")
        self._add_member_of_edges(dfs["group_mappings"])
        self._add_nested_in_edges(dfs["group_definitions"])
        self._add_has_role_edges(dfs["role_mappings"])
        self._add_grants_access_edges(dfs["role_definitions"])
        # FEDERATES_TO removed: graph now has one canonical node per person,
        # so there are no cross-platform account pairs to link.

        logger.info(
            "Graph built: %d nodes, %d edges",
            self.G.number_of_nodes(),
            self.G.number_of_edges(),
        )
        return self

    def save(self, path: Optional[Path] = None) -> Path:
        """Serialise the graph to .gpickle using Python pickle."""
        out = path or (self.models_dir / "identity_graph.gpickle")
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f:
            pickle.dump(self.G, f, pickle.HIGHEST_PROTOCOL)
        logger.info("Graph serialised -> %s", out)
        return out

    @classmethod
    def load_graph(cls, path: Optional[Path] = None) -> nx.MultiDiGraph:
        """Load and return a previously serialised graph."""
        p = path or (Path(__file__).parent.parent / "models" / "identity_graph.gpickle")
        with open(p, "rb") as f:
            return pickle.load(f)

    def print_summary(self) -> None:
        """Print node/edge counts and basic connectivity statistics."""
        G = self.G

        # Node counts by type
        type_counts: Dict[str, int] = {}
        for _, data in G.nodes(data=True):
            t = data.get("type", "Unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        # Edge counts by edge_type attribute
        edge_counts: Dict[str, int] = {}
        for _, _, data in G.edges(data=True):
            t = data.get("edge_type", "Unknown")
            edge_counts[t] = edge_counts.get(t, 0) + 1

        # Degree statistics
        degrees = [d for _, d in G.degree()]
        avg_deg = sum(degrees) / len(degrees) if degrees else 0.0
        max_deg = max(degrees) if degrees else 0

        # Connectivity
        n_wcc = nx.number_weakly_connected_components(G)

        print()
        print("=" * 65)
        print("  IDENTITY NEXUS AI — Graph Summary")
        print("=" * 65)
        print(f"\n  Total nodes : {G.number_of_nodes():,}")
        for node_type, cnt in sorted(type_counts.items()):
            print(f"    {node_type:<20s} {cnt:6,}")
        print(f"\n  Total edges : {G.number_of_edges():,}")
        for edge_type, cnt in sorted(edge_counts.items()):
            print(f"    {edge_type:<25s} {cnt:6,}")
        print(f"\n  Avg node degree              : {avg_deg:.2f}")
        print(f"  Max node degree              : {max_deg}")
        print(f"  Weakly connected components  : {n_wcc:,}")
        print("=" * 65)
        print()

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_data(self) -> Dict[str, pd.DataFrame]:
        names = [
            "unified_identities",
            "group_mappings",
            "role_mappings",
            "group_definitions",
            "role_definitions",
            "resource_catalog",
        ]
        dfs: Dict[str, pd.DataFrame] = {}
        for name in names:
            p = self.data_dir / f"{name}.csv"
            dfs[name] = pd.read_csv(p)
            logger.info("  %-30s %d rows", name + ".csv", len(dfs[name]))
        return dfs

    # ------------------------------------------------------------------
    # Node builders
    # ------------------------------------------------------------------

    def _add_identity_nodes(self, ui: pd.DataFrame) -> None:
        """
        Create ONE Identity node per canonical person (453 nodes).

        Node ID = canonical_id, which is identical to the identity_id of the
        canonical representative row (the highest-priority platform account as
        selected by IdentityResolver).  Attributes come from that representative
        row.  All platform accounts for the same person collapse into this single
        node; per-platform membership and role edges are still preserved by
        mapping identity_id -> canonical_id in the edge builders below.
        """
        # Build identity_id -> canonical_id lookup for edge builders to use.
        self._iid_to_canon: dict = dict(zip(ui["identity_id"], ui["canonical_id"]))

        count = 0
        for _, row in ui.iterrows():
            canon_id = str(row["canonical_id"])
            # Only materialise the node for the canonical representative
            if str(row["identity_id"]) != canon_id:
                continue
            self.G.add_node(
                canon_id,
                type="Identity",
                display_name=str(row["display_name"]),
                email=str(row["email"]),
                account_type=str(row["account_type"]),
                platform=str(row["platform"]),
                is_active=bool(row["is_active"]) if pd.notna(row["is_active"]) else True,
                is_privileged=bool(row["is_privileged"]) if pd.notna(row["is_privileged"]) else False,
                risk_score=0.0,
                department=str(row.get("department", "")) if pd.notna(row.get("department")) else "",
                canonical_id=canon_id,
            )
            count += 1
        logger.info("Added %d Identity nodes (canonical, one per person)", count)

    def _add_group_nodes(self, gd: pd.DataFrame) -> None:
        for _, row in gd.iterrows():
            self.G.add_node(
                str(row["group_id"]),
                type="Group",
                group_name=str(row["group_name"]),
                platform=str(row["platform"]),
                member_count=0,          # filled after MEMBER_OF edges
                is_privileged=bool(row["is_privileged"]),
                nesting_depth=int(row["nesting_depth"]),
            )
        logger.info("Added %d Group nodes", len(gd))

    def _add_role_nodes(self, rd: pd.DataFrame) -> None:
        for _, row in rd.iterrows():
            self.G.add_node(
                str(row["role_id"]),
                type="Role",
                role_name=str(row["role_name"]),
                platform=str(row["platform"]),
                permission_scope=str(row["permission_scope"]),
                is_privileged=bool(row["is_privileged"]),
            )
        logger.info("Added %d Role nodes", len(rd))

    def _add_resource_nodes(self, rc: pd.DataFrame) -> None:
        for _, row in rc.iterrows():
            self.G.add_node(
                str(row["resource_id"]),
                type="Resource",
                resource_name=str(row["resource_name"]),
                resource_type=str(row["resource_type"]),
                resource_criticality=str(row["resource_criticality"]),
                platform=str(row["platform"]),
            )
        logger.info("Added %d Resource nodes", len(rc))

    def _add_platform_nodes(self, ui: pd.DataFrame) -> None:
        platforms = ui["platform"].unique()
        for plat in platforms:
            node_id = f"PLAT-{plat}"
            self.G.add_node(
                node_id,
                type="Platform",
                platform_name=str(plat),
                federation_protocol=PLATFORM_FEDERATION_PROTOCOL.get(str(plat), "UNKNOWN"),
            )
        logger.info("Added %d Platform nodes", len(platforms))

    # ------------------------------------------------------------------
    # Edge builders
    # ------------------------------------------------------------------

    def _add_member_of_edges(self, gm: pd.DataFrame) -> None:
        """
        MEMBER_OF  Identity → Group

        Only direct memberships (is_nested=False) are added as graph edges.
        The is_nested=True rows in group_mappings are pre-computed transitive
        memberships and are redundant given the NESTED_IN edges from
        group_definitions; including them would cause BFS double-counting.
        """
        direct = gm[gm["is_nested"] == False]
        added = skipped = 0
        member_counts: Dict[str, int] = {}

        for _, row in direct.iterrows():
            iid = str(row["identity_id"])
            # Translate per-platform identity_id to canonical node ID
            canon_id = self._iid_to_canon.get(iid, iid)
            gid = str(row["group_id"])
            if canon_id not in self.G or gid not in self.G:
                skipped += 1
                continue
            self.G.add_edge(
                canon_id, gid,
                key=f"MEMBER_OF_{iid[:8]}",
                edge_type="MEMBER_OF",
                assigned_date=str(row["assigned_date"]),
                is_nested=False,
            )
            member_counts[gid] = member_counts.get(gid, 0) + 1
            added += 1

        # Update member_count on Group nodes
        for gid, cnt in member_counts.items():
            if gid in self.G:
                self.G.nodes[gid]["member_count"] = cnt

        logger.info(
            "Added %d MEMBER_OF edges (skipped %d — unknown node IDs)",
            added, skipped,
        )

    def _add_nested_in_edges(self, gd: pd.DataFrame) -> None:
        """
        NESTED_IN  ChildGroup → ParentGroup

        Sourced from group_definitions where parent_group_id is non-null.
        These 14 edges represent the true group hierarchy and allow the
        EffectivePrivilegeEngine to traverse nested group chains.
        """
        nested = gd[gd["parent_group_id"].notna()]
        added = skipped = 0
        for _, row in nested.iterrows():
            child_gid = str(row["group_id"])
            parent_gid = str(row["parent_group_id"])
            if child_gid not in self.G or parent_gid not in self.G:
                skipped += 1
                continue
            self.G.add_edge(
                child_gid, parent_gid,
                key="NESTED_IN",
                edge_type="NESTED_IN",
                nesting_depth=int(row["nesting_depth"]),
                platform=str(row["platform"]),
            )
            added += 1
        logger.info(
            "Added %d NESTED_IN edges (skipped %d — unknown node IDs)",
            added, skipped,
        )

    def _add_has_role_edges(self, rm: pd.DataFrame) -> None:
        """
        HAS_ROLE  Identity → Role

        All 1,451 role_mappings rows are "direct" assignment_type in Phase 2
        data.  Each row gets its own unique edge key (mapping_id prefix) so
        the MultiDiGraph can store multiple HAS_ROLE edges from the same
        identity (e.g. AD-Standard-User AND AD-Account-Operators).
        """
        added = skipped = 0
        for _, row in rm.iterrows():
            iid = str(row["identity_id"])
            # Translate per-platform identity_id to canonical node ID
            canon_id = self._iid_to_canon.get(iid, iid)
            rid = str(row["role_id"])
            if canon_id not in self.G or rid not in self.G:
                skipped += 1
                continue
            expiry = str(row["expiry_date"]) if pd.notna(row.get("expiry_date")) else ""
            edge_key = f"HAS_ROLE_{str(row['mapping_id'])[:8]}"
            self.G.add_edge(
                canon_id, rid,
                key=edge_key,
                edge_type="HAS_ROLE",
                assigned_date=str(row["assigned_date"]),
                assignment_type=str(row["assignment_type"]),
                expiry_date=expiry,
            )
            added += 1
        logger.info(
            "Added %d HAS_ROLE edges (skipped %d — unknown node IDs)",
            added, skipped,
        )

    def _add_grants_access_edges(self, rd: pd.DataFrame) -> None:
        """
        GRANTS_ACCESS  Role → Resource

        Privilege level is derived from the role's permission_scope via
        SCOPE_TO_PRIVILEGE.  Roles with is_privileged=True that map to "READ"
        are promoted to "WRITE" as a minimum.
        Roles with empty resource_ids lists (e.g. Okta-Standard-User) produce
        no GRANTS_ACCESS edges.
        """
        added = skipped = 0
        for _, row in rd.iterrows():
            role_id = str(row["role_id"])
            if role_id not in self.G:
                skipped += 1
                continue

            scope = str(row["permission_scope"])
            is_privileged = bool(row["is_privileged"])
            privilege_level = SCOPE_TO_PRIVILEGE.get(scope, "READ")
            # Privileged roles should not fall below WRITE
            if is_privileged and privilege_level == "READ":
                privilege_level = "WRITE"

            try:
                resource_ids = json.loads(str(row["resource_ids"]))
            except (json.JSONDecodeError, TypeError, ValueError):
                resource_ids = []

            if not resource_ids:
                logger.debug("Role %s has no resource_ids — no GRANTS_ACCESS edges", row["role_name"])
                continue

            for res_id in resource_ids:
                res_id = str(res_id)
                if res_id not in self.G:
                    skipped += 1
                    continue
                self.G.add_edge(
                    role_id, res_id,
                    key="GRANTS_ACCESS",
                    edge_type="GRANTS_ACCESS",
                    privilege_level=privilege_level,
                    platform=str(row["platform"]),
                    grant_mechanism="RBAC",
                )
                added += 1
        logger.info(
            "Added %d GRANTS_ACCESS edges (skipped %d — unknown node IDs / empty lists)",
            added, skipped,
        )

    def _add_federates_to_edges(self, ui: pd.DataFrame) -> None:
        """
        FEDERATES_TO  Identity → Identity

        Links every pair of platform accounts that share the same canonical_id
        (i.e. the same real-world person), bridging cross-platform identity
        nodes.  Used by AttackPathSimulator to extend blast-radius through
        federated platforms.

        Not followed during EffectivePrivilegeEngine BFS (per architecture spec).
        """
        if "canonical_id" not in ui.columns:
            logger.warning("canonical_id column missing; skipping FEDERATES_TO edges")
            return

        # Group by canonical_id; only groups with ≥2 accounts need edges
        groups = ui.groupby("canonical_id")
        added = 0

        for canonical_id, group in groups:
            if len(group) < 2:
                continue
            rows = group.to_dict("records")
            for i, src in enumerate(rows):
                for tgt in rows[i + 1:]:
                    src_id = str(src["identity_id"])
                    tgt_id = str(tgt["identity_id"])
                    if src_id not in self.G or tgt_id not in self.G:
                        continue
                    src_plat = str(src["platform"])
                    tgt_plat = str(tgt["platform"])
                    protocol = FEDERATION_PROTOCOL.get(
                        (src_plat, tgt_plat),
                        FEDERATION_PROTOCOL.get((tgt_plat, src_plat), "SAML"),
                    )
                    # Add both directions so Phase 7 attack simulation can pivot
                    # from any platform account (e.g. compromised AWS) to all
                    # federated peers including higher-priority platforms (AD).
                    self.G.add_edge(
                        src_id, tgt_id,
                        key=f"FED_{tgt_id[:8]}",
                        edge_type="FEDERATES_TO",
                        federation_protocol=protocol,
                        source_platform=src_plat,
                        target_platform=tgt_plat,
                    )
                    self.G.add_edge(
                        tgt_id, src_id,
                        key=f"FED_{src_id[:8]}",
                        edge_type="FEDERATES_TO",
                        federation_protocol=protocol,
                        source_platform=tgt_plat,
                        target_platform=src_plat,
                    )
                    added += 2

        logger.info("Added %d FEDERATES_TO edges (bidirectional)", added)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identity Nexus AI — Phase 3: Graph Builder"
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

    builder = GraphBuilder(
        data_dir=Path(args.data_dir),
        models_dir=Path(args.models_dir),
    )
    builder.build()
    builder.save()
    builder.print_summary()


if __name__ == "__main__":
    main()
