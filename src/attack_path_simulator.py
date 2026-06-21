"""
src/attack_path_simulator.py
Identity Nexus AI - Phase 5: Attack Path Simulator

Single responsibility: for every CRITICAL and HIGH risk identity, simulate
adversarial lateral movement from that identity across the identity graph to
enumerate all reachable resources (blast radius), then simulate a targeted
remediation and quantify the reduction.

This is the platform's flagship demo feature: "If this identity's credentials
were compromised, what can an attacker reach -- and how much does one
remediation action reduce that exposure?"

=============================================================================
TRAVERSAL ALGORITHM
=============================================================================
BFS from the Identity node (keyed by canonical_id), following only these
edge types (edge_type attribute):

    MEMBER_OF     Identity  -> Group   (direct group membership)
    NESTED_IN     Group     -> Group   (group inherits parent group's access)
    HAS_ROLE      Identity  -> Role    (also Group -> Role if graph contains it)
    GRANTS_ACCESS Role      -> Resource
    FEDERATES_TO  Identity  -> Identity (cross-platform federation; bridging)

Cycle safety: a single visited set prevents any non-Resource node from being
expanded more than once per simulation. Resource nodes are leaf nodes: they
are recorded but never expanded.

=============================================================================
BLAST RADIUS SCORE (BRS) FORMULA
=============================================================================
Criticality weights (from architecture.md §7.1):
    CRITICAL -> 4    HIGH -> 3    MEDIUM -> 2    LOW -> 1

    weighted_reachable = sum(weight(r) for r in reachable_resources)
    max_possible       = sum(weight(r) for r in ALL resources in catalog)
                       = 11*4 + 11*3 + 5*2 + 4*1 = 91

    BRS = (weighted_reachable / max_possible) * 100  -> [0, 100]

=============================================================================
REMEDIATION SELECTION LOGIC
=============================================================================
One remediation action is chosen per target identity based on risk profile:

  DISABLE_ACCOUNT
    Trigger: detection_method contains DOMAIN_RULE AND risk_tier == CRITICAL
    Rationale: orphaned/token-abuse identities at CRITICAL risk should be
    fully deactivated (account should not exist / access fully revoked).
    Surgery: remove ALL outgoing edges from identity node in graph copy.

  REVOKE_ROLE (highest-impact HAS_ROLE edge)
    Trigger: all other CRITICAL and all HIGH identities.
    Surgery: identify the direct HAS_ROLE edge from the identity to the role
    whose GRANTS_ACCESS resources have the highest combined criticality weight.
    Remove that single HAS_ROLE edge from the graph copy.
    If no direct HAS_ROLE edges exist, fall back to DISABLE_ACCOUNT.

=============================================================================
RISK REDUCTION ESTIMATION
=============================================================================
Blast Radius Reduction % is exact: recomputed via BFS on the modified graph.

Risk Reduction % is estimated analytically (RemediationEngine in Phase 6
will compute the precise value using the full scoring formula):

    DISABLE_ACCOUNT:
        remediated_risk = W_IDENT * identity_risk + W_COMP * compliance_risk
        (privilege_risk and behavioural_risk -> 0 when account is disabled)

    REVOKE_ROLE:
        brs_prop = blast_radius_reduction_pct / 100.0
        new_priv  = privilege_risk  * (1 - brs_prop)
        new_behav = behavioural_risk * (1 - 0.40 * brs_prop)
        remediated_risk = W_PRIV*new_priv + W_BEHAV*new_behav
                        + W_IDENT*identity_risk + W_COMP*compliance_risk

    W_PRIV=0.35, W_BEHAV=0.35, W_IDENT=0.20, W_COMP=0.10
    (mirrors RiskScoringEngine formula from Phase 4)

=============================================================================
OUTPUTS
=============================================================================
    generated_data/attack_paths.csv       -- one row per simulated identity
    generated_data/attack_paths_detail.json -- full graph-level detail for Phase 8

MUST NOT read ground_truth_labels.csv.
MUST NOT import later-phase src/ modules.
"""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import sys
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent.parent / "generated_data"
MODELS_DIR = Path(__file__).parent.parent / "models"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRIT_WEIGHTS: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

TRAVERSABLE_EDGE_TYPES: frozenset[str] = frozenset(
    {"MEMBER_OF", "NESTED_IN", "HAS_ROLE", "GRANTS_ACCESS", "FEDERATES_TO"}
)

# Ensemble weights mirror RiskScoringEngine (Phase 4)
W_PRIV: float = 0.35
W_BEHAV: float = 0.35
W_IDENT: float = 0.20
W_COMP: float = 0.10

# Behavioural risk decay coefficient when a role is revoked.
# Conservative: only 40% of the behavioural risk is attributable to the
# specific privilege path being revoked (historical audit trail remains).
BEHAV_DECAY_COEFF: float = 0.40

# Risk tiers that are simulated
TARGET_TIERS: frozenset[str] = frozenset({"CRITICAL", "HIGH"})


# ---------------------------------------------------------------------------
# Graph utilities
# ---------------------------------------------------------------------------


def load_graph(models_dir: Path = MODELS_DIR):
    """Load the identity graph from pickle. Returns a NetworkX MultiDiGraph."""
    import networkx as nx  # local import to keep module import-time light

    path = models_dir / "identity_graph.gpickle"
    if not path.exists():
        raise FileNotFoundError(
            f"identity_graph.gpickle not found at {path}. "
            "Run src/graph_builder.py first."
        )
    with open(path, "rb") as fh:
        G = pickle.load(fh)
    logger.info(
        "Loaded identity graph: %d nodes, %d edges",
        G.number_of_nodes(),
        G.number_of_edges(),
    )
    # Confirm Identity node count
    n_identity = sum(1 for _, d in G.nodes(data=True) if d.get("type") == "Identity")
    n_resource = sum(1 for _, d in G.nodes(data=True) if d.get("type") == "Resource")
    logger.info("  Identity nodes: %d  |  Resource nodes: %d", n_identity, n_resource)
    return G


# ---------------------------------------------------------------------------
# BFS traversal
# ---------------------------------------------------------------------------


def bfs_blast_radius(
    G,
    src: str,
) -> dict[str, dict[str, Any]]:
    """
    BFS from `src` Identity node through TRAVERSABLE_EDGE_TYPES to enumerate
    all reachable Resource nodes and the shortest path to each.

    Parameters
    ----------
    G   : NetworkX MultiDiGraph — the identity graph (read-only)
    src : canonical_id of the compromised identity

    Returns
    -------
    dict[resource_id -> {
        criticality, resource_name, resource_type, platform,
        path_nodes: list[str],   # ordered node IDs from src to resource
        path_edges: list[str],   # ordered edge types (len = len(path_nodes) - 1)
    }]

    Guarantees: first arrival = shortest path (BFS property).
    Cycle safety: visited set prevents re-expanding any node.
    """
    if src not in G:
        logger.warning("Source node %s not in graph — no paths simulated.", src)
        return {}

    visited: set[str] = set()
    # queue items: (current_node, path_nodes_so_far, path_edges_so_far)
    queue: deque[tuple[str, list[str], list[str]]] = deque(
        [(src, [src], [])]
    )
    reachable: dict[str, dict[str, Any]] = {}

    while queue:
        node, path_nodes, path_edges = queue.popleft()
        if node in visited:
            continue
        visited.add(node)

        node_type = G.nodes[node].get("type", "")

        if node_type == "Resource":
            # Record on first arrival (shortest path); do not expand
            if node not in reachable:
                reachable[node] = {
                    "criticality": G.nodes[node].get("resource_criticality", "LOW"),
                    "resource_name": G.nodes[node].get("resource_name", ""),
                    "resource_type": G.nodes[node].get("resource_type", ""),
                    "platform": G.nodes[node].get("platform", ""),
                    "path_nodes": path_nodes,
                    "path_edges": path_edges,
                }
            continue  # Resource nodes are leaf nodes -- never expand

        # Expand Identity, Group, Role nodes via traversable edges
        for _, nbr, edata in G.out_edges(node, data=True):
            etype = edata.get("edge_type", "")
            if etype not in TRAVERSABLE_EDGE_TYPES:
                continue
            if nbr not in visited:
                queue.append(
                    (nbr, path_nodes + [nbr], path_edges + [etype])
                )

    return reachable


def compute_brs(
    reachable: dict[str, dict[str, Any]],
    max_possible: int,
) -> float:
    """
    Blast Radius Score = (weighted_reachable / max_possible) * 100.

    Capped at 100 to guard against floating-point edge cases.
    """
    if max_possible == 0:
        return 0.0
    weighted = sum(
        CRIT_WEIGHTS.get(v["criticality"], 1) for v in reachable.values()
    )
    return round(min(weighted / max_possible * 100.0, 100.0), 4)


# ---------------------------------------------------------------------------
# Remediation helpers
# ---------------------------------------------------------------------------


def _role_weighted_reach(G, role_id: str) -> int:
    """Sum of criticality weights of resources reachable via GRANTS_ACCESS from role_id."""
    total = 0
    for _, res_id, edata in G.out_edges(role_id, data=True):
        if edata.get("edge_type") == "GRANTS_ACCESS":
            crit = G.nodes[res_id].get("resource_criticality", "LOW")
            total += CRIT_WEIGHTS.get(crit, 1)
    return total


def choose_remediation(
    G,
    src: str,
    risk_tier: str,
    detection_method: str,
) -> tuple[str, Any, str]:
    """
    Choose and apply a remediation action for `src`, returning a modified graph copy.

    Parameters
    ----------
    G               : original graph (NOT mutated)
    src             : canonical_id of the target identity
    risk_tier       : 'CRITICAL' or 'HIGH'
    detection_method: value from risk_scores.csv detection_method column

    Returns
    -------
    (action_type: str, G_copy: MultiDiGraph, scenario_desc: str)
    """
    import copy as _copy

    is_domain_rule = "DOMAIN_RULE" in str(detection_method)

    # DISABLE_ACCOUNT: CRITICAL identities detected by domain rule
    # (these are orphaned/token-abuse accounts that should not exist)
    if risk_tier == "CRITICAL" and is_domain_rule:
        G_copy = _copy.deepcopy(G)
        out_edges = list(G_copy.out_edges(src, keys=True))
        n_removed = len(out_edges)
        for u, v, k in out_edges:
            G_copy.remove_edge(u, v, k)
        scenario_desc = (
            f"DISABLE_ACCOUNT: removed all {n_removed} outgoing edges from identity node. "
            f"Full account lockout simulated (rule-based detection: "
            f"orphaned/token-abuse identity at CRITICAL risk tier)."
        )
        return "DISABLE_ACCOUNT", G_copy, scenario_desc

    # REVOKE_ROLE: find the direct HAS_ROLE edge with highest weighted blast-radius
    # contribution and remove just that edge
    has_role_edges = [
        (v, k, d)
        for _, v, k, d in G.out_edges(src, data=True, keys=True)
        if d.get("edge_type") == "HAS_ROLE"
    ]

    if has_role_edges:
        # Score each role by weighted resource reach (GRANTS_ACCESS from that role)
        scored = [
            (role_id, key, edata, _role_weighted_reach(G, role_id))
            for role_id, key, edata in has_role_edges
        ]
        # Pick highest-scoring role; tie-break by role_id for determinism
        scored.sort(key=lambda x: (-x[3], x[0]))
        best_role_id, best_key, best_edata, best_score = scored[0]
        role_name = G.nodes[best_role_id].get("role_name", best_role_id[:24])
        role_platform = best_edata.get("platform", G.nodes[best_role_id].get("platform", "?"))
        role_resource_count = sum(
            1 for _, _, d in G.out_edges(best_role_id, data=True)
            if d.get("edge_type") == "GRANTS_ACCESS"
        )
        crit_count = sum(
            1 for _, res_id, d in G.out_edges(best_role_id, data=True)
            if d.get("edge_type") == "GRANTS_ACCESS"
            and G.nodes[res_id].get("resource_criticality") == "CRITICAL"
        )

        G_copy = _copy.deepcopy(G)
        # Remove ALL HAS_ROLE edges from src to best_role_id (MultiDiGraph can have
        # multiple edges between the same pair)
        edges_to_remove = [
            (u, v, k)
            for u, v, k, d in G_copy.out_edges(src, data=True, keys=True)
            if v == best_role_id and d.get("edge_type") == "HAS_ROLE"
        ]
        for u, v, k in edges_to_remove:
            G_copy.remove_edge(u, v, k)

        scenario_desc = (
            f"REVOKE_ROLE: removed HAS_ROLE edge to role '{role_name}' "
            f"(platform={role_platform}, weighted_blast_contribution={best_score}). "
            f"This role granted access to {role_resource_count} resources "
            f"({crit_count} CRITICAL)."
        )
        return "REVOKE_ROLE", G_copy, scenario_desc

    # Fallback: DISABLE_ACCOUNT if identity has no direct HAS_ROLE edges
    import copy as _copy
    G_copy = _copy.deepcopy(G)
    out_edges = list(G_copy.out_edges(src, keys=True))
    for u, v, k in out_edges:
        G_copy.remove_edge(u, v, k)
    scenario_desc = (
        "DISABLE_ACCOUNT: no direct HAS_ROLE edges found -- "
        "full account lockout simulated as fallback remediation."
    )
    return "DISABLE_ACCOUNT", G_copy, scenario_desc


def estimate_remediated_risk(
    action_type: str,
    privilege_risk: float,
    behavioural_risk: float,
    identity_risk: float,
    compliance_risk: float,
    brs_reduction_pct: float,
) -> float:
    """
    Estimate risk score after remediation.

    DISABLE_ACCOUNT: privilege and behavioural risk go to 0. Only identity hygiene
    and compliance components remain.

    REVOKE_ROLE: privilege and behavioural risk are reduced proportional to the
    blast-radius reduction achieved. Behavioural risk decays at 40% of the BRS
    reduction rate (historical audit trail remains even after role revocation).

    Returns clamped [0, 100].
    """
    if action_type == "DISABLE_ACCOUNT":
        remediated = W_IDENT * identity_risk + W_COMP * compliance_risk
    else:  # REVOKE_ROLE
        brs_prop = brs_reduction_pct / 100.0
        new_priv = privilege_risk * (1.0 - brs_prop)
        new_behav = behavioural_risk * (1.0 - BEHAV_DECAY_COEFF * brs_prop)
        remediated = (
            W_PRIV * new_priv
            + W_BEHAV * new_behav
            + W_IDENT * identity_risk
            + W_COMP * compliance_risk
        )
    return round(max(0.0, min(100.0, remediated)), 2)


# ---------------------------------------------------------------------------
# Path sequence formatter
# ---------------------------------------------------------------------------


def _format_path_sequence(
    G,
    src: str,
    src_display: str,
    reachable: dict[str, dict[str, Any]],
) -> str:
    """
    Build a human-readable path string to the highest-criticality, shortest path
    among all reachable resources.

    Format:
        <display_name> -HAS_ROLE-> <Role[role_name]> -GRANTS_ACCESS-> <res_name[CRIT]>

    Falls back to first reachable resource if no CRITICAL resource exists.
    """
    if not reachable:
        return f"{src_display} -> (no resources reachable)"

    priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    # Pick the shortest path to the highest-criticality resource
    best_res_id = min(
        reachable,
        key=lambda r: (
            priority.get(reachable[r]["criticality"], 9),
            len(reachable[r]["path_edges"]),
        ),
    )
    info = reachable[best_res_id]
    nodes = info["path_nodes"]
    edges = info["path_edges"]
    res_name = info["resource_name"]
    crit = info["criticality"]

    parts = [f"{src_display}"]
    for i, etype in enumerate(edges):
        target_id = nodes[i + 1]
        target_data = G.nodes[target_id]
        target_type = target_data.get("type", "?")
        if target_type == "Role":
            label = f"Role[{target_data.get('role_name', target_id[:16])}]"
        elif target_type == "Group":
            label = f"Group[{target_data.get('group_name', target_id[:16])}]"
        elif target_type == "Resource":
            label = f"Resource[{res_name}:{crit}]"
        elif target_type == "Identity":
            label = f"Identity[{target_data.get('display_name', target_id[:16])}]"
        else:
            label = target_id[:20]
        parts.append(f"-{etype}-> {label}")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# JSON detail builder for Phase 8 Plotly
# ---------------------------------------------------------------------------


def _build_detail_entry(
    G,
    src: str,
    display_name: str,
    risk_tier: str,
    final_risk_score: float,
    detection_method: str,
    action_type: str,
    scenario_desc: str,
    current_reachable: dict[str, dict[str, Any]],
    post_reachable: dict[str, dict[str, Any]],
    current_brs: float,
    post_brs: float,
    brs_reduction_pct: float,
    risk_reduction_pct: float,
) -> dict[str, Any]:
    """
    Build the per-identity JSON entry for attack_paths_detail.json.

    The structure gives Phase 8's Plotly renderer:
      - all_nodes: every node encountered in any path (src + intermediaries + resources)
      - all_edges: every directed edge traversed (deduplicated)
      - paths: per-resource shortest-path detail
    """

    def _serialise_scenario(
        reachable: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        all_nodes: list[dict] = []
        all_edges: list[dict] = []
        seen_nodes: set[str] = set()
        seen_edges: set[tuple] = set()
        paths_detail: list[dict] = []

        for res_id, info in reachable.items():
            pnodes = info["path_nodes"]
            pedges = info["path_edges"]

            for nid in pnodes:
                if nid not in seen_nodes:
                    seen_nodes.add(nid)
                    ndata = G.nodes[nid]
                    node_entry: dict = {"id": nid, "type": ndata.get("type", "?")}
                    if ndata.get("type") == "Identity":
                        node_entry["display_name"] = ndata.get("display_name", "")
                        node_entry["canonical_id"] = ndata.get("canonical_id", nid)
                        node_entry["is_privileged"] = ndata.get("is_privileged", False)
                    elif ndata.get("type") == "Role":
                        node_entry["role_name"] = ndata.get("role_name", "")
                        node_entry["platform"] = ndata.get("platform", "")
                    elif ndata.get("type") == "Group":
                        node_entry["group_name"] = ndata.get("group_name", "")
                        node_entry["platform"] = ndata.get("platform", "")
                    elif ndata.get("type") == "Resource":
                        node_entry["resource_name"] = ndata.get("resource_name", "")
                        node_entry["resource_criticality"] = ndata.get(
                            "resource_criticality", "LOW"
                        )
                        node_entry["resource_type"] = ndata.get("resource_type", "")
                        node_entry["platform"] = ndata.get("platform", "")
                    all_nodes.append(node_entry)

            for i, etype in enumerate(pedges):
                edge_key = (pnodes[i], pnodes[i + 1], etype)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    all_edges.append(
                        {
                            "source": pnodes[i],
                            "target": pnodes[i + 1],
                            "edge_type": etype,
                        }
                    )

            paths_detail.append(
                {
                    "resource_id": res_id,
                    "resource_name": info["resource_name"],
                    "resource_criticality": info["criticality"],
                    "resource_type": info["resource_type"],
                    "platform": info["platform"],
                    "path_nodes": pnodes,
                    "path_edges": pedges,
                    "path_length": len(pedges),
                }
            )

        # Sort paths: CRITICAL first, then by path length
        crit_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        paths_detail.sort(
            key=lambda p: (crit_order.get(p["resource_criticality"], 9), p["path_length"])
        )

        return {
            "blast_radius_score": round(
                sum(
                    CRIT_WEIGHTS.get(v["criticality"], 1) for v in reachable.values()
                )
                / 91.0  # max_possible = 91 for this dataset
                * 100.0,
                4,
            ),
            "reachable_count": len(reachable),
            "critical_count": sum(
                1 for v in reachable.values() if v["criticality"] == "CRITICAL"
            ),
            "all_nodes": all_nodes,
            "all_edges": all_edges,
            "paths": paths_detail,
        }

    return {
        "canonical_id": src,
        "display_name": display_name,
        "risk_tier": risk_tier,
        "final_risk_score": final_risk_score,
        "detection_method": detection_method,
        "remediation_action": action_type,
        "remediation_scenario": scenario_desc,
        "blast_radius_reduction_pct": brs_reduction_pct,
        "risk_reduction_pct": risk_reduction_pct,
        "current_state": _serialise_scenario(current_reachable),
        "post_remediation": _serialise_scenario(post_reachable),
    }


# ---------------------------------------------------------------------------
# Main simulator class
# ---------------------------------------------------------------------------


class AttackPathSimulator:
    """
    Runs blast-radius simulations for every CRITICAL and HIGH risk identity.

    Usage
    -----
    sim = AttackPathSimulator().load()
    df, detail = sim.run()
    sim.save(df, detail)
    sim.print_summary(df)
    """

    def __init__(
        self,
        data_dir: Path = DATA_DIR,
        models_dir: Path = MODELS_DIR,
    ) -> None:
        self.data_dir = data_dir
        self.models_dir = models_dir
        self._G = None
        self._original_edge_count: int = 0
        self._rs: pd.DataFrame | None = None
        self._ui_map: dict[str, str] = {}  # canonical_id -> display_name
        self._max_possible: int = 0

    def load(self) -> "AttackPathSimulator":
        """Load graph, risk scores, resource catalog, and identity display names."""
        self._G = load_graph(self.models_dir)
        self._original_edge_count = self._G.number_of_edges()

        self._rs = pd.read_csv(
            self.data_dir / "risk_scores.csv",
            usecols=[
                "canonical_id",
                "risk_tier",
                "final_risk_score",
                "privilege_risk_component",
                "behavioural_risk_component",
                "identity_risk_component",
                "compliance_risk_component",
                "detection_method",
                "risk_drivers",
                "root_cause",
            ],
        )
        targets = self._rs[self._rs["risk_tier"].isin(TARGET_TIERS)].copy()
        targets = targets.sort_values("final_risk_score", ascending=False).reset_index(
            drop=True
        )
        self._targets = targets
        logger.info(
            "Target identities: %d (%s)",
            len(targets),
            targets["risk_tier"].value_counts().to_dict(),
        )

        # Resource catalog -> max possible BRS weight
        rc = pd.read_csv(
            self.data_dir / "resource_catalog.csv",
            usecols=["resource_id", "resource_criticality"],
        )
        self._max_possible = sum(
            CRIT_WEIGHTS.get(c, 1) for c in rc["resource_criticality"]
        )
        logger.info(
            "Resource catalog: %d resources, max BRS weight = %d",
            len(rc),
            self._max_possible,
        )

        # Display name map: canonical_id -> display_name (first row per canonical)
        ui = pd.read_csv(
            self.data_dir / "unified_identities.csv",
            usecols=["canonical_id", "display_name"],
        ).drop_duplicates("canonical_id")
        self._ui_map = dict(zip(ui["canonical_id"], ui["display_name"]))

        return self

    def run(self) -> tuple[pd.DataFrame, list[dict]]:
        """
        Simulate current-state and post-remediation blast radius for every target.

        Returns
        -------
        (summary_df: pd.DataFrame, detail: list[dict])
        summary_df has one row per simulated identity.
        detail is the JSON structure for attack_paths_detail.json.
        """
        sim_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        rows: list[dict] = []
        detail: list[dict] = []

        for _, risk_row in self._targets.iterrows():
            src = risk_row["canonical_id"]
            display = self._ui_map.get(src, src[:24])
            tier = risk_row["risk_tier"]
            detection_method = str(risk_row.get("detection_method", "ML_ENSEMBLE"))
            final_risk = float(risk_row["final_risk_score"])
            priv_risk = float(risk_row["privilege_risk_component"])
            behav_risk = float(risk_row["behavioural_risk_component"])
            ident_risk = float(risk_row["identity_risk_component"])
            comp_risk = float(risk_row["compliance_risk_component"])

            # --- CURRENT STATE ---
            current_reachable = bfs_blast_radius(self._G, src)
            current_brs = compute_brs(current_reachable, self._max_possible)
            current_count = len(current_reachable)
            critical_exposure = sum(
                1 for v in current_reachable.values() if v["criticality"] == "CRITICAL"
            )
            impacted_assets = sorted(current_reachable.keys())
            impacted_platforms = sorted(
                {v["platform"] for v in current_reachable.values() if v["platform"]}
            )

            # --- REMEDIATION ---
            action_type, G_copy, scenario_desc = choose_remediation(
                self._G, src, tier, detection_method
            )

            # Confirm original graph was NOT mutated by choose_remediation
            assert self._G.number_of_edges() == self._original_edge_count, (
                f"Graph mutation detected after remediation for {src}! "
                f"Expected {self._original_edge_count} edges, "
                f"got {self._G.number_of_edges()}."
            )

            # --- POST-REMEDIATION ---
            post_reachable = bfs_blast_radius(G_copy, src)
            post_brs = compute_brs(post_reachable, self._max_possible)
            post_count = len(post_reachable)

            # Reduction percentages (guard division by zero)
            if current_brs > 0:
                brs_reduction_pct = round(
                    (current_brs - post_brs) / current_brs * 100.0, 2
                )
            else:
                brs_reduction_pct = 0.0

            remediated_risk = estimate_remediated_risk(
                action_type, priv_risk, behav_risk, ident_risk, comp_risk,
                brs_reduction_pct,
            )

            if final_risk > 0:
                risk_reduction_pct = round(
                    (final_risk - remediated_risk) / final_risk * 100.0, 2
                )
            else:
                risk_reduction_pct = 0.0

            # Highest-criticality shortest path sequence
            path_seq = _format_path_sequence(self._G, src, display, current_reachable)

            row = {
                "path_id": str(uuid.uuid4()),
                "canonical_id": src,
                "display_name": display,
                "risk_tier": tier,
                "final_risk_score": round(final_risk, 2),
                "detection_method": detection_method,
                "path_sequence": path_seq,
                "current_blast_radius": current_brs,
                "current_risk": round(final_risk, 2),
                "remediation_action": action_type,
                "remediation_scenario": scenario_desc,
                "remediated_blast_radius": post_brs,
                "remediated_risk": remediated_risk,
                "blast_radius_reduction_pct": brs_reduction_pct,
                "risk_reduction_pct": risk_reduction_pct,
                "reachable_node_count": current_count,
                "reachable_node_count_post": post_count,
                "impacted_assets": json.dumps(impacted_assets),
                "impacted_platforms": json.dumps(impacted_platforms),
                "critical_resource_exposure": critical_exposure,
                "simulation_timestamp": sim_ts,
            }
            rows.append(row)

            # Full detail for Phase 8
            detail.append(
                _build_detail_entry(
                    self._G, src, display, tier, final_risk,
                    detection_method, action_type, scenario_desc,
                    current_reachable, post_reachable,
                    current_brs, post_brs,
                    brs_reduction_pct, risk_reduction_pct,
                )
            )

            logger.info(
                "Simulated %-36s  tier=%-8s  BRS_curr=%-6.1f  BRS_post=%-6.1f  "
                "BRS_red=%-5.1f%%  risk_red=%-5.1f%%  action=%s",
                src, tier, current_brs, post_brs,
                brs_reduction_pct, risk_reduction_pct, action_type,
            )

        # Final mutation guard across the full run
        assert self._G.number_of_edges() == self._original_edge_count, (
            "Graph was mutated during simulation run! "
            f"Expected {self._original_edge_count}, "
            f"got {self._G.number_of_edges()} edges."
        )
        logger.info(
            "Mutation guard passed: graph still has %d edges after all simulations.",
            self._original_edge_count,
        )

        df = pd.DataFrame(rows)
        return df, detail

    def save(self, df: pd.DataFrame, detail: list[dict]) -> None:
        """Write attack_paths.csv and attack_paths_detail.json."""
        csv_path = self.data_dir / "attack_paths.csv"
        df.to_csv(csv_path, index=False)
        logger.info("Wrote attack_paths.csv: %d rows", len(df))

        json_path = self.data_dir / "attack_paths_detail.json"
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(detail, fh, indent=2, ensure_ascii=False)
        logger.info("Wrote attack_paths_detail.json: %d identities", len(detail))

    def print_summary(self, df: pd.DataFrame) -> None:
        """Print validation output to stdout."""
        if df.empty:
            print("No simulations produced.")
            return

        n = len(df)
        print()
        print("=" * 70)
        print("  ATTACK PATH SIMULATOR -- Summary")
        print("=" * 70)
        print(f"  Total identities simulated    : {n}")
        tier_counts = df["risk_tier"].value_counts().to_dict()
        for t in ["CRITICAL", "HIGH"]:
            print(f"    {t:<10} {tier_counts.get(t, 0)}")
        print()

        # Action type breakdown
        action_counts = df["remediation_action"].value_counts().to_dict()
        print("  Remediation action distribution:")
        for action, cnt in sorted(action_counts.items()):
            print(f"    {action:<25} {cnt}")
        print()

        # BRS distribution
        brs = df["current_blast_radius"]
        print(f"  Blast Radius Score (current)  : min={brs.min():.2f}  "
              f"mean={brs.mean():.2f}  max={brs.max():.2f}")
        brs_red = df["blast_radius_reduction_pct"]
        print(f"  BRS Reduction %               : min={brs_red.min():.1f}  "
              f"mean={brs_red.mean():.1f}  max={brs_red.max():.1f}")
        risk_red = df["risk_reduction_pct"]
        print(f"  Risk Reduction %              : min={risk_red.min():.1f}  "
              f"mean={risk_red.mean():.1f}  max={risk_red.max():.1f}")
        print()

        # Confirm no remediated BRS > current BRS
        invalid = (df["remediated_blast_radius"] > df["current_blast_radius"]).sum()
        check = "[OK]" if invalid == 0 else f"[FAIL] {invalid} rows violated"
        print(f"  remediated_brs <= current_brs : {check}")
        print()

        # Highest current BRS identity -- full detail
        top_row = df.nlargest(1, "current_blast_radius").iloc[0]
        print("  HIGHEST BLAST RADIUS IDENTITY:")
        print(f"    canonical_id              : {top_row['canonical_id']}")
        print(f"    display_name              : {top_row['display_name']}")
        print(f"    risk_tier                 : {top_row['risk_tier']}")
        print(f"    detection_method          : {top_row['detection_method']}")
        print(f"    path_sequence             : {top_row['path_sequence']}")
        print(f"    current_blast_radius      : {top_row['current_blast_radius']:.2f}")
        print(f"    current_risk              : {top_row['current_risk']:.2f}")
        print(f"    remediation_action        : {top_row['remediation_action']}")
        print(f"    remediation_scenario      : {top_row['remediation_scenario']}")
        print(f"    remediated_blast_radius   : {top_row['remediated_blast_radius']:.2f}")
        print(f"    remediated_risk           : {top_row['remediated_risk']:.2f}")
        print(f"    blast_radius_reduction_pct: {top_row['blast_radius_reduction_pct']:.1f}%")
        print(f"    risk_reduction_pct        : {top_row['risk_reduction_pct']:.1f}%")
        print(f"    reachable_node_count      : {top_row['reachable_node_count']}")
        print(f"    reachable_node_count_post : {top_row['reachable_node_count_post']}")
        print(f"    critical_resource_exposure: {top_row['critical_resource_exposure']}")
        assets = json.loads(top_row["impacted_assets"])
        print(f"    impacted_assets (count)   : {len(assets)}")
        print(f"    impacted_platforms        : {top_row['impacted_platforms']}")
        print("=" * 70)
        print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identity Nexus AI -- Phase 5: Attack Path Simulator"
    )
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--models-dir", default=str(MODELS_DIR))
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s -- %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )

    sim = AttackPathSimulator(
        data_dir=Path(args.data_dir),
        models_dir=Path(args.models_dir),
    )
    sim.load()
    df, detail = sim.run()
    sim.save(df, detail)
    sim.print_summary(df)


if __name__ == "__main__":
    main()
