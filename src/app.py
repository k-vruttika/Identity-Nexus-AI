"""
src/app.py
Identity Nexus AI — Phase 8: Streamlit SOC Dashboard

Dark, futuristic SOC platform with glassmorphism panels, Plotly charts,
and detection-method visual distinction (ML vs rule-based badges).

Run:  streamlit run src/app.py
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SRC_DIR = Path(__file__).parent
DATA_DIR = SRC_DIR.parent / "generated_data"

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------
C_TEAL   = "#00F5D4"
C_BLUE   = "#00B4FF"
C_PURPLE = "#7B61FF"
C_RED    = "#FF4D6D"
C_AMBER  = "#F5A623"
C_BG     = "#080d1a"
C_CARD   = "rgba(255,255,255,0.05)"
C_BORDER = "rgba(255,255,255,0.10)"

TIER_COLORS = {
    "CRITICAL": C_RED,
    "HIGH": C_AMBER,
    "MEDIUM": C_PURPLE,
    "LOW": "#4a9eff",
}

CRIT_COLORS = {
    "CRITICAL": C_RED,
    "HIGH": C_AMBER,
    "MEDIUM": C_PURPLE,
    "LOW": "#6b7280",
}

NODE_TYPE_COLORS = {
    "Identity": C_TEAL,
    "Role": C_BLUE,
    "Group": "#a78bfa",
    "Resource": None,   # overridden by criticality
    "Platform": "#6b7280",
}

# ---------------------------------------------------------------------------
# Page config (must be first Streamlit call)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Identity Nexus AI",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Global CSS injection
# ---------------------------------------------------------------------------
st.markdown(
    f"""
<style>
/* === Base dark background === */
[data-testid="stApp"] {{
    background-color: {C_BG};
    color: #e2e8f0;
    font-family: 'Inter', 'Segoe UI', sans-serif;
}}
[data-testid="stSidebar"] {{
    background: rgba(8,13,26,0.95) !important;
    border-right: 1px solid {C_BORDER};
}}
[data-testid="stSidebar"] * {{
    color: #cbd5e1 !important;
}}
/* === Glassmorphism card === */
.glass-card {{
    background: {C_CARD};
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid {C_BORDER};
    border-radius: 14px;
    padding: 20px 24px;
    margin-bottom: 16px;
}}
/* === KPI card === */
.kpi-card {{
    background: {C_CARD};
    backdrop-filter: blur(12px);
    border: 1px solid {C_BORDER};
    border-radius: 14px;
    padding: 18px 16px;
    text-align: center;
    height: 110px;
    display: flex;
    flex-direction: column;
    justify-content: center;
}}
.kpi-value {{
    font-size: 2.2rem;
    font-weight: 800;
    line-height: 1.1;
    letter-spacing: -0.5px;
}}
.kpi-sub {{
    font-size: 0.72rem;
    color: #94a3b8;
    margin-top: 4px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}}
/* === Detection method badges === */
.badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.04em;
    margin-right: 4px;
    white-space: nowrap;
}}
.badge-ml {{
    background: {C_BLUE};
    color: #000;
}}
.badge-rule {{
    background: {C_AMBER};
    color: #000;
}}
.badge-none {{
    background: #374151;
    color: #9ca3af;
}}
/* === Risk tier pills === */
.tier-CRITICAL {{ color: {C_RED}; font-weight: 700; }}
.tier-HIGH {{ color: {C_AMBER}; font-weight: 700; }}
.tier-MEDIUM {{ color: {C_PURPLE}; font-weight: 700; }}
.tier-LOW {{ color: #4a9eff; font-weight: 700; }}
/* === Section headings === */
.section-header {{
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #64748b;
    margin-bottom: 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid {C_BORDER};
}}
/* === Path breadcrumb === */
.path-step {{
    display: inline-block;
    background: rgba(0,180,255,0.15);
    border: 1px solid rgba(0,180,255,0.3);
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 12px;
    font-family: monospace;
    color: {C_BLUE};
    margin: 2px;
}}
.path-arrow {{
    color: #475569;
    margin: 0 4px;
    font-size: 12px;
}}
/* === Metric delta === */
.delta-positive {{
    color: {C_TEAL};
    font-weight: 700;
}}
.delta-negative {{
    color: {C_RED};
    font-weight: 700;
}}
/* === Streamlit overrides === */
div[data-testid="stMetricValue"] > div {{
    color: {C_TEAL} !important;
    font-size: 2rem !important;
    font-weight: 800 !important;
}}
div[data-testid="metric-container"] {{
    background: {C_CARD};
    backdrop-filter: blur(12px);
    border: 1px solid {C_BORDER};
    border-radius: 14px;
    padding: 16px;
}}
h1, h2, h3 {{
    color: #f1f5f9 !important;
}}
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Helper: detection method badges (HTML)
# ---------------------------------------------------------------------------

def detection_badge_html(detection_method: str) -> str:
    """
    Return HTML badge(s) for a detection_method string.
    DOMAIN_RULE  → amber 'Rule-based' badge
    ML_ENSEMBLE / IF_PREDICT → blue 'ML Ensemble' badge
    """
    if not detection_method or str(detection_method).strip() in ("", "nan", "NONE"):
        return '<span class="badge badge-none">— None</span>'

    parts = [p.strip() for p in str(detection_method).split("|")]
    badges = []
    has_rule = "DOMAIN_RULE" in parts
    has_ml   = "ML_ENSEMBLE" in parts or "IF_PREDICT" in parts

    if has_ml:
        badges.append('<span class="badge badge-ml">&#129302; ML Ensemble</span>')
    if has_rule:
        badges.append('<span class="badge badge-rule">&#9881; Rule-based</span>')
    if not badges:
        badges.append('<span class="badge badge-none">— None</span>')

    return " ".join(badges)


def tier_badge_html(tier: str) -> str:
    colors = {"CRITICAL": C_RED, "HIGH": C_AMBER, "MEDIUM": C_PURPLE, "LOW": "#4a9eff"}
    c = colors.get(tier, "#6b7280")
    return (
        f'<span style="background:rgba({_hex_to_rgb(c)},0.15);'
        f'border:1px solid {c};color:{c};padding:2px 10px;'
        f'border-radius:20px;font-size:11px;font-weight:700;">{tier}</span>'
    )


def _hex_to_rgb(h: str) -> str:
    h = h.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"{r},{g},{b}"


def _safe_num(val, default: float = 0.0) -> float:
    try:
        v = float(val)
        return v if not (v != v) else default  # NaN check
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Data loading (all cached)
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner=False)
def load_risk_scores() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "risk_scores.csv")


@st.cache_data(show_spinner=False)
def load_anomaly_scores() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "anomaly_scores.csv")


@st.cache_data(show_spinner=False)
def load_incidents() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "incidents.csv")


@st.cache_data(show_spinner=False)
def load_attack_paths() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "attack_paths.csv")


@st.cache_data(show_spinner=False)
def load_attack_paths_detail() -> list[dict]:
    p = DATA_DIR / "attack_paths_detail.json"
    if not p.exists():
        return []
    with open(p, encoding="utf-8") as f:
        return json.load(f)


@st.cache_data(show_spinner=False)
def load_remediation_actions() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "remediation_actions.csv")


@st.cache_data(show_spinner=False)
def load_compliance_mappings() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "compliance_mappings.csv")


@st.cache_data(show_spinner=False)
def load_unified_identities() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "unified_identities.csv")


@st.cache_data(show_spinner=False)
def load_effective_privileges() -> pd.DataFrame:
    ep = pd.read_csv(DATA_DIR / "effective_privileges.csv")
    ui = pd.read_csv(DATA_DIR / "unified_identities.csv", usecols=["identity_id", "canonical_id"])
    return ep.merge(ui[["identity_id", "canonical_id"]].drop_duplicates(), on="identity_id", how="left")


@st.cache_data(show_spinner=False)
def load_narratives() -> list[dict] | None:
    p = DATA_DIR / "narratives.json"
    if not p.exists():
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


@st.cache_data(show_spinner=False)
def load_identity_explorer() -> pd.DataFrame:
    rs = pd.read_csv(DATA_DIR / "risk_scores.csv")
    ui = pd.read_csv(DATA_DIR / "unified_identities.csv")
    ui_agg = (
        ui.groupby("canonical_id")
        .agg(
            display_name=("display_name", "first"),
            email=("email", "first"),
            department=("department", "first"),
            job_title=("job_title", "first"),
            account_type=("account_type", "first"),
            platforms=("platform", lambda x: ", ".join(sorted(x.unique()))),
            platform_count=("platform", "nunique"),
            mfa_enabled=("mfa_enabled", "first"),
            is_active=("is_active", "first"),
            is_privileged=("is_privileged", "first"),
            geo_location=("geo_location", "first"),
        )
        .reset_index()
    )
    return rs.merge(ui_agg, on="canonical_id", how="left")


# ---------------------------------------------------------------------------
# Plotly theming helper
# ---------------------------------------------------------------------------

PLOTLY_DARK = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(8,13,26,0.6)",
    font=dict(color="#e2e8f0", family="Inter, Segoe UI, sans-serif", size=12),
    margin=dict(l=0, r=0, t=30, b=0),
    xaxis=dict(gridcolor="rgba(255,255,255,0.06)", linecolor="rgba(255,255,255,0.1)"),
    yaxis=dict(gridcolor="rgba(255,255,255,0.06)", linecolor="rgba(255,255,255,0.1)"),
    legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#94a3b8")),
)


def _layout(**overrides) -> dict:
    """Return PLOTLY_DARK merged with per-chart overrides (explicit kwargs always win).
    Use **_layout(key=val) instead of **PLOTLY_DARK, key=val to avoid Python's
    'multiple values for keyword argument' error when a key appears in both."""
    return {**PLOTLY_DARK, **overrides}


def dark_fig(fig: go.Figure, height: int = 350) -> go.Figure:
    fig.update_layout(**_layout(height=height))
    return fig


# ---------------------------------------------------------------------------
# Network graph helpers (for identity graph and attack path)
# ---------------------------------------------------------------------------

def _hierarchical_positions(nodes: list[dict]) -> dict[str, tuple[float, float]]:
    """Layer layout: Identity → Roles/Groups → Resources."""
    identities = [n for n in nodes if n.get("type") == "Identity"]
    roles      = [n for n in nodes if n.get("type") in ("Role", "Group")]
    resources  = [n for n in nodes if n.get("type") == "Resource"]

    pos: dict[str, tuple[float, float]] = {}

    def _spread(items, y, spacing=2.5):
        n = len(items)
        for i, item in enumerate(items):
            pos[item["id"]] = ((i - (n - 1) / 2) * spacing, y)

    _spread(identities, y=2.0, spacing=3.0)
    _spread(roles,      y=1.0, spacing=2.5)

    # Two-row layout for many resources
    n_res = len(resources)
    cols  = max(1, math.ceil(math.sqrt(n_res * 2)))
    for i, n in enumerate(resources):
        row = i // cols
        col = i % cols
        row_size = min(cols, n_res - row * cols)
        x = (col - (row_size - 1) / 2) * 1.8
        pos[n["id"]] = (x, -row * 0.9)

    return pos


def _node_color(node: dict) -> str:
    ntype = node.get("type", "")
    if ntype in NODE_TYPE_COLORS and NODE_TYPE_COLORS[ntype] is not None:
        return NODE_TYPE_COLORS[ntype]
    if ntype == "Resource":
        return CRIT_COLORS.get(node.get("resource_criticality", "LOW"), "#6b7280")
    return "#6b7280"


def _node_label(node: dict) -> str:
    ntype = node.get("type", "")
    raw = (
        node.get("display_name")
        or node.get("role_name")
        or node.get("resource_name")
        or node.get("id", "")[:10]
    )
    return (raw[:18] + "…") if len(raw) > 18 else raw


def _node_size(node: dict) -> int:
    t = node.get("type", "")
    return 28 if t == "Identity" else 20 if t in ("Role", "Group") else 16


def build_attack_graph(
    nodes: list[dict],
    edges: list[dict],
    title: str = "",
    removed_node_ids: set | None = None,
) -> go.Figure:
    """Build a Plotly figure for an attack path subgraph."""
    removed_node_ids = removed_node_ids or set()
    pos = _hierarchical_positions(nodes)

    # --- Edge traces ---
    ex, ey, etxt = [], [], []
    for edge in edges:
        s, t = edge.get("source", ""), edge.get("target", "")
        if s in pos and t in pos:
            x0, y0 = pos[s]
            x1, y1 = pos[t]
            ex += [x0, x1, None]
            ey += [y0, y1, None]
            mid = ((x0 + x1) / 2, (y0 + y1) / 2)
            etxt.append(edge.get("edge_type", ""))

    edge_trace = go.Scatter(
        x=ex, y=ey,
        mode="lines",
        line=dict(width=1.5, color="rgba(148,163,184,0.25)"),
        hoverinfo="none",
        showlegend=False,
    )

    # --- Node traces grouped by type for legend ---
    type_groups: dict[str, list] = {}
    for node in nodes:
        t = node.get("type", "Other")
        type_groups.setdefault(t, []).append(node)

    traces = [edge_trace]
    for ntype, group in type_groups.items():
        nx_vals, ny_vals, colors, labels, sizes, hovers = [], [], [], [], [], []
        for node in group:
            nid = node["id"]
            if nid not in pos:
                continue
            x, y = pos[nid]
            nx_vals.append(x)
            ny_vals.append(y)
            is_removed = nid in removed_node_ids
            color = "#374151" if is_removed else _node_color(node)
            colors.append(color)
            lbl = _node_label(node)
            labels.append(f"<s>{lbl}</s>" if is_removed else lbl)
            sizes.append(_node_size(node))
            crit = node.get("resource_criticality", "")
            hover = f"<b>{node.get('type')}</b>: {lbl}"
            if crit:
                hover += f"<br>Criticality: {crit}"
            if is_removed:
                hover += "<br><i>Removed by remediation</i>"
            hovers.append(hover)

        traces.append(go.Scatter(
            x=nx_vals, y=ny_vals,
            mode="markers+text",
            name=ntype,
            marker=dict(
                size=sizes,
                color=colors,
                line=dict(width=1.5, color="rgba(255,255,255,0.2)"),
            ),
            text=labels,
            textposition="bottom center",
            textfont=dict(size=8, color="rgba(226,232,240,0.9)"),
            hovertext=hovers,
            hoverinfo="text",
        ))

    fig = go.Figure(data=traces)
    fig.update_layout(
        title=dict(text=title, font=dict(size=13, color="#94a3b8")),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, visible=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, visible=False),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(8,13,26,0.6)",
        font=dict(color="#e2e8f0", family="Inter, sans-serif"),
        margin=dict(l=10, r=10, t=40, b=10),
        height=420,
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(size=10, color="#94a3b8"),
            orientation="h",
            y=-0.02,
        ),
        showlegend=True,
    )
    return fig


# ---------------------------------------------------------------------------
# Page 1 — Executive Overview
# ---------------------------------------------------------------------------

def page_executive_overview() -> None:
    st.markdown("## 🛡 Executive Overview")
    st.markdown('<p style="color:#64748b;font-size:13px;">Real-time identity risk intelligence across all platforms</p>', unsafe_allow_html=True)

    rs   = load_risk_scores()
    anom = load_anomaly_scores()
    inc  = load_incidents()
    ap   = load_attack_paths()

    total_ids      = len(rs)
    anomaly_count  = int(anom["is_anomaly"].sum()) if "is_anomaly" in anom.columns else 0
    crit_high      = int(rs["risk_tier"].isin(["CRITICAL", "HIGH"]).sum())
    incident_count = len(inc)
    alert_count    = anomaly_count
    reduction_pct  = round((1 - incident_count / alert_count) * 100, 1) if alert_count > 0 else 0.0
    avg_br_red     = round(ap["blast_radius_reduction_pct"].mean(), 1) if "blast_radius_reduction_pct" in ap.columns else 0.0

    # --- KPI row ---
    c1, c2, c3, c4, c5 = st.columns(5)
    kpis = [
        (c1, total_ids,      C_TEAL,   "Total Identities",        ""),
        (c2, anomaly_count,  C_AMBER,  "Anomalies Flagged",       ""),
        (c3, crit_high,      C_RED,    "Critical / High Risk",    ""),
        (c4, incident_count, C_PURPLE, "Incidents",               f"▼ {reduction_pct}% alert reduction"),
        (c5, f"{avg_br_red}%", C_BLUE, "Avg Blast Radius ↓",     "post-remediation"),
    ]
    for col, val, color, label, sub in kpis:
        with col:
            st.markdown(
                f'<div class="kpi-card">'
                f'<div class="kpi-value" style="color:{color}">{val}</div>'
                f'<div class="kpi-sub">{label}</div>'
                f'{"<div style=color:#64748b;font-size:11px>" + sub + "</div>" if sub else ""}'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    col_a, col_b, col_c = st.columns([2, 2, 2])

    with col_a:
        # Risk tier donut
        tier_counts = rs["risk_tier"].value_counts().reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"], fill_value=0)
        fig_tier = go.Figure(go.Pie(
            labels=tier_counts.index.tolist(),
            values=tier_counts.values.tolist(),
            hole=0.55,
            marker=dict(
                colors=[TIER_COLORS.get(t, "#888") for t in tier_counts.index],
                line=dict(color=C_BG, width=2),
            ),
            textfont=dict(size=11),
            insidetextorientation="radial",
        ))
        fig_tier.update_layout(**_layout(
            title="Risk Tier Distribution",
            legend=dict(orientation="h", y=-0.15, font=dict(size=10), bgcolor="rgba(0,0,0,0)"),
            height=300,
        ))
        st.plotly_chart(fig_tier, use_container_width=True, key="exec_tier_pie")

    with col_b:
        # Detection method breakdown
        def _det_category(dm: str) -> str:
            dm = str(dm)
            has_rule = "DOMAIN_RULE" in dm
            has_ml   = "ML_ENSEMBLE" in dm or "IF_PREDICT" in dm
            if has_ml and has_rule:
                return "ML + Rule"
            if has_ml:
                return "ML Ensemble"
            if has_rule:
                return "Rule-based"
            return "None"

        rs_copy = rs.copy()
        rs_copy["det_category"] = rs_copy["detection_method"].apply(_det_category)
        det_counts = rs_copy["det_category"].value_counts()
        det_colors = {
            "ML Ensemble": C_BLUE,
            "Rule-based":  C_AMBER,
            "ML + Rule":   C_PURPLE,
            "None":        "#374151",
        }
        fig_det = go.Figure(go.Bar(
            x=det_counts.index.tolist(),
            y=det_counts.values.tolist(),
            marker_color=[det_colors.get(k, "#888") for k in det_counts.index],
            text=det_counts.values.tolist(),
            textposition="outside",
            textfont=dict(size=11, color="#e2e8f0"),
        ))
        fig_det.update_layout(**_layout(
            title="Detection Method Breakdown",
            height=300,
            xaxis_title=None,
            yaxis_title="Identities",
        ))
        st.plotly_chart(fig_det, use_container_width=True, key="exec_det_bar")

    with col_c:
        # Incident type breakdown
        inc_counts = inc["incident_type"].value_counts()
        fig_inc = go.Figure(go.Bar(
            y=inc_counts.index.tolist(),
            x=inc_counts.values.tolist(),
            orientation="h",
            marker_color=C_PURPLE,
            text=inc_counts.values.tolist(),
            textposition="outside",
            textfont=dict(size=10, color="#e2e8f0"),
        ))
        fig_inc.update_layout(**_layout(
            title="Incidents by Type",
            height=300,
            xaxis_title="Count",
            yaxis=dict(gridcolor="rgba(255,255,255,0.06)", autorange="reversed"),
        ))
        st.plotly_chart(fig_inc, use_container_width=True, key="exec_inc_bar")

    # --- Top 15 risk identities chart ---
    st.markdown('<div class="section-header">TOP 15 HIGHEST-RISK IDENTITIES</div>', unsafe_allow_html=True)
    top15 = rs.nlargest(15, "final_risk_score")[["canonical_id", "final_risk_score", "risk_tier", "detection_method"]]
    # Try to get display_name
    try:
        ui_names = pd.read_csv(DATA_DIR / "unified_identities.csv", usecols=["canonical_id", "display_name"]).drop_duplicates("canonical_id")
        top15 = top15.merge(ui_names, on="canonical_id", how="left")
    except Exception:
        top15["display_name"] = top15["canonical_id"].str[:12]

    top15["label"] = top15["display_name"].fillna(top15["canonical_id"].str[:12])
    fig_top = go.Figure(go.Bar(
        x=top15["final_risk_score"].tolist(),
        y=top15["label"].tolist(),
        orientation="h",
        marker_color=[TIER_COLORS.get(t, "#888") for t in top15["risk_tier"]],
        text=[f"{v:.1f}" for v in top15["final_risk_score"]],
        textposition="outside",
        textfont=dict(size=10, color="#e2e8f0"),
    ))
    fig_top.update_layout(**_layout(
        height=380,
        xaxis=dict(range=[0, 110], gridcolor="rgba(255,255,255,0.06)"),
        yaxis=dict(autorange="reversed", gridcolor="rgba(255,255,255,0.06)"),
        margin=dict(l=0, r=60, t=10, b=0),
    ))
    st.plotly_chart(fig_top, use_container_width=True, key="exec_top15")


# ---------------------------------------------------------------------------
# Page 2 — Identity Explorer
# ---------------------------------------------------------------------------

def page_identity_explorer() -> None:
    st.markdown("## 🔎 Identity Explorer")
    st.markdown('<p style="color:#64748b;font-size:13px;">Browse and investigate all 453 canonical identities</p>', unsafe_allow_html=True)

    df = load_identity_explorer()

    # --- Filters ---
    f1, f2, f3 = st.columns(3)
    with f1:
        tier_opts = ["All"] + sorted(df["risk_tier"].dropna().unique().tolist(),
                                     key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x))
        sel_tier = st.selectbox("Risk Tier", tier_opts)
    with f2:
        all_plats: set[str] = set()
        for val in df["platforms"].dropna():
            for p in str(val).split(","):
                all_plats.add(p.strip())
        plat_opts = ["All"] + sorted(all_plats)
        sel_plat = st.selectbox("Platform", plat_opts)
    with f3:
        det_opts = ["All", "ML Ensemble", "Rule-based", "ML + Rule", "None"]
        sel_det = st.selectbox("Detection Method", det_opts)

    filtered = df.copy()
    if sel_tier != "All":
        filtered = filtered[filtered["risk_tier"] == sel_tier]
    if sel_plat != "All":
        filtered = filtered[filtered["platforms"].str.contains(sel_plat, na=False)]
    if sel_det == "ML Ensemble":
        filtered = filtered[filtered["detection_method"].str.contains("ML_ENSEMBLE|IF_PREDICT", na=False)]
        filtered = filtered[~filtered["detection_method"].str.contains("DOMAIN_RULE", na=False)]
    elif sel_det == "Rule-based":
        filtered = filtered[filtered["detection_method"].str.contains("DOMAIN_RULE", na=False)]
        filtered = filtered[~filtered["detection_method"].str.contains("ML_ENSEMBLE|IF_PREDICT", na=False)]
    elif sel_det == "ML + Rule":
        filtered = filtered[filtered["detection_method"].str.contains("DOMAIN_RULE", na=False)]
        filtered = filtered[filtered["detection_method"].str.contains("ML_ENSEMBLE|IF_PREDICT", na=False)]
    elif sel_det == "None":
        filtered = filtered[
            ~filtered["detection_method"].str.contains("ML_ENSEMBLE|IF_PREDICT|DOMAIN_RULE", na=False)
        ]

    st.markdown(f'<p style="color:#64748b;font-size:12px;">{len(filtered)} identities</p>', unsafe_allow_html=True)

    # Display table (show_index=False, select mode)
    display_cols = ["display_name", "email", "department", "platforms", "risk_tier", "final_risk_score", "detection_method"]
    available = [c for c in display_cols if c in filtered.columns]
    table_df = filtered[available + ["canonical_id"]].copy()

    event = st.dataframe(
        table_df.drop(columns=["canonical_id"]).rename(columns={
            "display_name": "Name",
            "email": "Email",
            "department": "Dept",
            "platforms": "Platforms",
            "risk_tier": "Tier",
            "final_risk_score": "Risk Score",
            "detection_method": "Detection Method",
        }),
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%.1f"),
        },
        key="identity_table",
        height=320,
    )

    # --- Identity Detail Panel ---
    st.markdown('<div class="section-header">IDENTITY DETAIL</div>', unsafe_allow_html=True)

    selected_rows = event.selection.rows if hasattr(event, "selection") else []
    if selected_rows:
        idx = table_df.index[selected_rows[0]]
        sel_row = df.loc[idx]
        sel_cid = sel_row["canonical_id"]
    else:
        # Default to highest-risk identity
        sel_cid = df.nlargest(1, "final_risk_score").iloc[0]["canonical_id"]
        sel_row = df[df["canonical_id"] == sel_cid].iloc[0]
        st.caption("↑ Click a row above to inspect — showing highest-risk identity by default")

    _render_identity_detail(sel_row, sel_cid)


def _render_identity_detail(row: pd.Series, cid: str) -> None:
    d1, d2 = st.columns([1.4, 1])

    with d1:
        tier = str(row.get("risk_tier", ""))
        dm   = str(row.get("detection_method", ""))
        st.markdown(
            f'<div class="glass-card">'
            f'<h3 style="margin:0 0 8px 0">{row.get("display_name","–")}</h3>'
            f'<p style="color:#94a3b8;font-size:13px;margin:0 0 12px 0">'
            f'{row.get("email","–")} · {row.get("department","–")} · {row.get("job_title","–")}</p>'
            f'{tier_badge_html(tier)} &nbsp; {detection_badge_html(dm)}'
            f'<hr style="border-color:{C_BORDER};margin:14px 0">'
            f'<div style="font-size:12px;color:#94a3b8"><b>Platforms:</b> {row.get("platforms","–")}</div>'
            f'<div style="font-size:12px;color:#94a3b8;margin-top:4px">'
            f'MFA: {"✅" if row.get("mfa_enabled") else "❌"} &nbsp; '
            f'Active: {"✅" if row.get("is_active") else "❌"} &nbsp; '
            f'Privileged: {"✅" if row.get("is_privileged") else "❌"}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # Risk score gauge
        score = float(row.get("final_risk_score", 0))
        fig_g = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            gauge=dict(
                axis=dict(range=[0, 100], tickcolor="#475569"),
                bar=dict(color=TIER_COLORS.get(tier, C_BLUE)),
                bgcolor="rgba(0,0,0,0)",
                bordercolor=C_BORDER,
                steps=[
                    dict(range=[0, 40],  color="rgba(74,158,255,0.1)"),
                    dict(range=[40, 60], color="rgba(123,97,255,0.1)"),
                    dict(range=[60, 80], color="rgba(245,166,35,0.1)"),
                    dict(range=[80, 100],color="rgba(255,77,109,0.1)"),
                ],
                threshold=dict(line=dict(color=TIER_COLORS.get(tier, C_RED), width=3), thickness=0.8, value=score),
            ),
            number=dict(font=dict(size=36, color=TIER_COLORS.get(tier, C_BLUE)), suffix="/100"),
        ))
        fig_g.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            height=200,
            margin=dict(l=30, r=30, t=20, b=10),
        )
        st.plotly_chart(fig_g, use_container_width=True, key=f"gauge_{cid[:8]}")

        # Evidence / root cause / business impact
        for label, key in [("Evidence", "evidence"), ("Root Cause", "root_cause"), ("Business Impact", "business_impact")]:
            val = str(row.get(key, "")) if pd.notna(row.get(key, "")) else ""
            if val:
                st.markdown(
                    f'<div style="background:rgba(0,0,0,0.3);border-left:3px solid {C_BLUE};'
                    f'padding:10px 14px;border-radius:0 8px 8px 0;margin-bottom:8px;font-size:12px;">'
                    f'<b style="color:{C_BLUE}">{label}</b><br>{val}</div>',
                    unsafe_allow_html=True,
                )

    with d2:
        # Effective privileges table
        st.markdown('<div class="section-header">EFFECTIVE PRIVILEGES</div>', unsafe_allow_html=True)
        ep = load_effective_privileges()
        ep_cid = ep[ep["canonical_id"] == cid][
            ["resource_name", "resource_type", "resource_criticality", "privilege_level",
             "is_excessive", "is_dormant"]
        ].copy()
        if ep_cid.empty:
            st.caption("No effective privileges found for this identity.")
        else:
            st.dataframe(
                ep_cid.rename(columns={
                    "resource_name":        "Resource",
                    "resource_type":        "Type",
                    "resource_criticality": "Criticality",
                    "privilege_level":      "Level",
                    "is_excessive":         "Excessive",
                    "is_dormant":           "Dormant",
                }),
                use_container_width=True,
                hide_index=True,
                height=260,
            )

        # Remediation action
        st.markdown('<div class="section-header" style="margin-top:16px">REMEDIATION</div>', unsafe_allow_html=True)
        ra = load_remediation_actions()
        ra_row = ra[ra["canonical_id"] == cid]
        if not ra_row.empty:
            r = ra_row.iloc[0]
            st.markdown(
                f'<div class="glass-card" style="padding:12px 16px">'
                f'<b style="color:{C_TEAL}">{r.get("action_type","")}</b> · {r.get("priority","")}<br>'
                f'<span style="font-size:11px;color:#94a3b8">{str(r.get("recommended_action",""))[:160]}</span><br>'
                f'<span style="font-size:11px;color:#64748b">Est. risk ↓ {_safe_num(r.get("estimated_risk_reduction")):.0f}%'
                f' · Blast radius ↓ {_safe_num(r.get("blast_radius_reduction")):.0f}%</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            st.caption("No remediation action found.")


# ---------------------------------------------------------------------------
# Page 3 — Risk Register
# ---------------------------------------------------------------------------

def page_risk_register() -> None:
    st.markdown("## 📋 Risk Register")
    rs = load_risk_scores()

    f1, f2 = st.columns(2)
    with f1:
        tier_opts = ["All"] + ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sel_tier = st.selectbox("Risk Tier", tier_opts, key="rr_tier")
    with f2:
        det_opts = ["All", "ML Ensemble", "Rule-based", "ML + Rule", "None"]
        sel_det  = st.selectbox("Detection Method", det_opts, key="rr_det")

    filtered = rs.copy()
    if sel_tier != "All":
        filtered = filtered[filtered["risk_tier"] == sel_tier]

    def _det_cat(dm):
        dm = str(dm)
        has_rule = "DOMAIN_RULE" in dm
        has_ml   = "ML_ENSEMBLE" in dm or "IF_PREDICT" in dm
        if has_ml and has_rule: return "ML + Rule"
        if has_ml: return "ML Ensemble"
        if has_rule: return "Rule-based"
        return "None"

    filtered = filtered.copy()
    filtered["det_category"] = filtered["detection_method"].apply(_det_cat)
    if sel_det != "All":
        filtered = filtered[filtered["det_category"] == sel_det]

    st.markdown(f'<p style="color:#64748b;font-size:12px;">{len(filtered)} records</p>', unsafe_allow_html=True)

    # Color-coded risk register table
    show_cols = [
        "canonical_id", "risk_tier", "final_risk_score",
        "privilege_risk_component", "behavioural_risk_component",
        "identity_risk_component", "compliance_risk_component",
        "det_category", "evidence",
    ]
    available = [c for c in show_cols if c in filtered.columns]
    display = filtered[available].sort_values("final_risk_score", ascending=False)

    st.dataframe(
        display.rename(columns={
            "canonical_id":               "Canonical ID",
            "risk_tier":                  "Tier",
            "final_risk_score":           "Risk Score",
            "privilege_risk_component":   "Privilege",
            "behavioural_risk_component": "Behavioural",
            "identity_risk_component":    "Identity",
            "compliance_risk_component":  "Compliance",
            "det_category":               "Detection",
            "evidence":                   "Evidence",
        }),
        use_container_width=True,
        hide_index=True,
        height=500,
        column_config={
            "Risk Score":   st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%.1f"),
            "Privilege":    st.column_config.NumberColumn("Privilege",    format="%.1f"),
            "Behavioural":  st.column_config.NumberColumn("Behavioural",  format="%.1f"),
            "Identity":     st.column_config.NumberColumn("Identity",     format="%.1f"),
            "Compliance":   st.column_config.NumberColumn("Compliance",   format="%.1f"),
            "Canonical ID": st.column_config.TextColumn("Canonical ID", width="small"),
        },
    )

    # Risk score distribution histogram
    st.markdown("<br>", unsafe_allow_html=True)
    fig_hist = go.Figure(go.Histogram(
        x=filtered["final_risk_score"],
        nbinsx=30,
        marker_color=C_PURPLE,
        marker_line=dict(color=C_BG, width=0.5),
        opacity=0.8,
    ))
    fig_hist.update_layout(**_layout(
        title="Risk Score Distribution",
        xaxis_title="Final Risk Score",
        yaxis_title="Count",
        height=250,
    ))
    for t, c in TIER_COLORS.items():
        thresholds = {"CRITICAL": 80, "HIGH": 60, "MEDIUM": 40}
        if t in thresholds:
            fig_hist.add_vline(x=thresholds[t], line_dash="dot", line_color=c,
                               annotation_text=t, annotation_font_color=c, annotation_font_size=10)
    st.plotly_chart(fig_hist, use_container_width=True, key="rr_hist")


# ---------------------------------------------------------------------------
# Page 4 — Incident Explorer
# ---------------------------------------------------------------------------

def page_incident_explorer() -> None:
    st.markdown("## 🚨 Incident Explorer")
    inc = load_incidents()

    f1, f2 = st.columns(2)
    with f1:
        itype_opts = ["All"] + sorted(inc["incident_type"].dropna().unique().tolist())
        sel_type = st.selectbox("Incident Type", itype_opts, key="ie_type")
    with f2:
        sev_opts = ["All"] + ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sel_sev  = st.selectbox("Severity", sev_opts, key="ie_sev")

    filtered = inc.copy()
    if sel_type != "All":
        filtered = filtered[filtered["incident_type"] == sel_type]
    if sel_sev != "All":
        filtered = filtered[filtered["severity"] == sel_sev]

    st.markdown(f'<p style="color:#64748b;font-size:12px;">{len(filtered)} incidents</p>', unsafe_allow_html=True)

    # Severity breakdown mini-chart
    sev_counts = filtered["severity"].value_counts().reindex(["CRITICAL","HIGH","MEDIUM","LOW"], fill_value=0)
    col_chart, col_type = st.columns([1, 2])
    with col_chart:
        fig_sev = go.Figure(go.Bar(
            x=sev_counts.index.tolist(),
            y=sev_counts.values.tolist(),
            marker_color=[TIER_COLORS.get(s, "#888") for s in sev_counts.index],
            text=sev_counts.values.tolist(),
            textposition="outside",
            textfont=dict(color="#e2e8f0", size=11),
        ))
        fig_sev.update_layout(**_layout(height=220, margin=dict(l=0, r=0, t=10, b=0), title="By Severity"))
        st.plotly_chart(fig_sev, use_container_width=True, key="ie_sev_chart")
    with col_type:
        type_counts = filtered["incident_type"].value_counts()
        fig_type = go.Figure(go.Bar(
            y=type_counts.index.tolist(),
            x=type_counts.values.tolist(),
            orientation="h",
            marker_color=C_PURPLE,
            text=type_counts.values.tolist(),
            textposition="outside",
            textfont=dict(color="#e2e8f0", size=10),
        ))
        fig_type.update_layout(**_layout(
            height=220, margin=dict(l=0, r=10, t=10, b=0), title="By Type",
            yaxis=dict(autorange="reversed", gridcolor="rgba(255,255,255,0.06)"),
        ))
        st.plotly_chart(fig_type, use_container_width=True, key="ie_type_chart")

    # --- Incident cards ---
    st.markdown('<div class="section-header">INCIDENTS</div>', unsafe_allow_html=True)
    for _, row in filtered.iterrows():
        sev     = str(row.get("severity", ""))
        itype   = str(row.get("incident_type", ""))
        dm      = str(row.get("detection_method", ""))
        rscore  = float(row.get("risk_score", 0) or 0)
        ascore  = float(row.get("anomaly_score", 0) or 0)
        mc      = int(row.get("member_count", 1) or 1)
        narrative = str(row.get("llm_narrative", ""))
        narrative_display = (narrative[:250] + "…") if len(narrative) > 250 else narrative
        has_narr = narrative and narrative not in ("nan", "", "NaN")

        sev_color = TIER_COLORS.get(sev, "#888")

        st.markdown(
            f'<div class="glass-card" style="border-left:3px solid {sev_color}">'
            f'<div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;">'
            f'<div>'
            f'  <b style="font-size:14px">{itype}</b> &nbsp; {tier_badge_html(sev)} &nbsp; {detection_badge_html(dm)}'
            f'  <div style="font-size:11px;color:#64748b;margin-top:4px">'
            f'    {str(row.get("incident_id",""))[:20]} · {str(row.get("detection_timestamp","")[:16])}'
            f'  </div>'
            f'</div>'
            f'<div style="text-align:right;font-size:12px;color:#94a3b8">'
            f'  Risk: <b style="color:{sev_color}">{rscore:.1f}</b> &nbsp; '
            f'  Anomaly: <b>{ascore:.3f}</b><br>'
            f'  Identities: <b style="color:{C_TEAL}">{mc}</b>'
            f'</div>'
            f'</div>'
            f'<div style="font-size:11px;color:#64748b;margin-top:8px">'
            f'Platform: {row.get("platform","–")} · Status: {row.get("status","–")}'
            f'</div>'
            f'{f"""<div style="font-size:11px;color:#94a3b8;margin-top:8px;line-height:1.5">{narrative_display}</div>""" if has_narr else ""}'
            f'</div>',
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Page 5 — Identity Graph
# ---------------------------------------------------------------------------

def page_identity_graph() -> None:
    st.markdown("## 🕸 Identity Graph")
    st.markdown(
        '<p style="color:#64748b;font-size:13px;">Privilege paths for CRITICAL / HIGH identities — '
        'select an identity to visualise its current access subgraph</p>',
        unsafe_allow_html=True,
    )

    detail = load_attack_paths_detail()
    if not detail:
        st.warning("attack_paths_detail.json not found. Run the pipeline first.")
        return

    options = {f"{d['display_name']} ({d['risk_tier']})": i for i, d in enumerate(detail)}
    sel_name = st.selectbox("Select Identity", list(options.keys()), key="ig_identity")
    sel_idx  = options[sel_name]
    d        = detail[sel_idx]

    # Stats bar
    cs = d.get("current_state", {})
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f'<div class="kpi-card"><div class="kpi-value" style="color:{TIER_COLORS.get(d["risk_tier"],C_BLUE)}">'
            f'{d["risk_tier"]}</div><div class="kpi-sub">Risk Tier</div></div>',
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f'<div class="kpi-card"><div class="kpi-value" style="color:{C_RED}">'
            f'{cs.get("reachable_count",0)}</div><div class="kpi-sub">Reachable Resources</div></div>',
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f'<div class="kpi-card"><div class="kpi-value" style="color:{C_AMBER}">'
            f'{cs.get("critical_count",0)}</div><div class="kpi-sub">Critical Resources</div></div>',
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f'<div class="kpi-card"><div class="kpi-value" style="color:{C_TEAL}">'
            f'{cs.get("blast_radius_score",0):.1f}%</div><div class="kpi-sub">Blast Radius Score</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    nodes = cs.get("all_nodes", [])
    edges = cs.get("all_edges", [])
    fig   = build_attack_graph(nodes, edges, title=f"Access Subgraph — {d['display_name']}")
    st.plotly_chart(fig, use_container_width=True, key="ig_graph")

    # Legend
    st.markdown(
        f'<div style="font-size:11px;color:#64748b;display:flex;gap:16px;flex-wrap:wrap;">'
        f'<span>● <span style="color:{C_TEAL}">Identity</span></span>'
        f'<span>● <span style="color:{C_BLUE}">Role</span></span>'
        f'<span>● <span style="color:{C_RED}">CRITICAL Resource</span></span>'
        f'<span>● <span style="color:{C_AMBER}">HIGH Resource</span></span>'
        f'<span>● <span style="color:{C_PURPLE}">MEDIUM Resource</span></span>'
        f'<span>● <span style="color:#6b7280">LOW Resource</span></span>'
        f'</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Page 6 — Attack Path Simulator
# ---------------------------------------------------------------------------

def page_attack_path_simulator() -> None:
    st.markdown("## ⚡ Attack Path Simulator")
    st.markdown(
        '<p style="color:#64748b;font-size:13px;">Before / after remediation blast-radius comparison '
        'for each CRITICAL and HIGH identity</p>',
        unsafe_allow_html=True,
    )

    detail = load_attack_paths_detail()
    ap     = load_attack_paths()
    if not detail:
        st.warning("attack_paths_detail.json not found. Run the pipeline first.")
        return

    # Identity selector
    options = {f"[{d['risk_tier']}] {d['display_name']} — Risk {d['final_risk_score']:.1f}": i
               for i, d in enumerate(detail)}
    sel_name = st.selectbox("Select Identity to Simulate", list(options.keys()), key="aps_identity")
    sel_idx  = options[sel_name]
    d        = detail[sel_idx]

    cs = d.get("current_state", {})
    pr = d.get("post_remediation", {})

    brs_current = float(cs.get("blast_radius_score", 0))
    brs_post    = float(pr.get("blast_radius_score", 0))
    br_red_pct  = float(d.get("blast_radius_reduction_pct", 0))
    risk_red_pct= float(d.get("risk_reduction_pct", 0))

    # --- Headline KPIs ---
    k1, k2, k3, k4, k5 = st.columns(5)
    kpis_ap = [
        (k1, f"{brs_current:.1f}%",     C_RED,   "Blast Radius (Current)", ""),
        (k2, f"{brs_post:.1f}%",        C_TEAL,  "Blast Radius (Post)",    "after remediation"),
        (k3, f"▼ {br_red_pct:.1f}%",   C_AMBER, "Blast Reduction",         ""),
        (k4, f"▼ {risk_red_pct:.1f}%", C_BLUE,  "Risk Reduction",          ""),
        (k5, d.get("remediation_action","–"), C_PURPLE, "Recommended Action", ""),
    ]
    for col, val, color, label, sub in kpis_ap:
        with col:
            st.markdown(
                f'<div class="kpi-card">'
                f'<div class="kpi-value" style="color:{color};font-size:1.7rem">{val}</div>'
                f'<div class="kpi-sub">{label}</div>'
                f'{"<div style=color:#64748b;font-size:11px>" + sub + "</div>" if sub else ""}'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Reduction bar comparison ---
    fig_compare = go.Figure()
    fig_compare.add_trace(go.Bar(
        x=["Blast Radius Score", "Reachable Resources", "Critical Resources"],
        y=[brs_current, cs.get("reachable_count",0), cs.get("critical_count",0)],
        name="Current State",
        marker_color=C_RED,
        opacity=0.85,
    ))
    fig_compare.add_trace(go.Bar(
        x=["Blast Radius Score", "Reachable Resources", "Critical Resources"],
        y=[brs_post, pr.get("reachable_count",0), pr.get("critical_count",0)],
        name="Post Remediation",
        marker_color=C_TEAL,
        opacity=0.85,
    ))
    fig_compare.update_layout(**_layout(
        barmode="group",
        title=f"Before vs After Remediation — {d['display_name']}",
        legend=dict(orientation="h", y=1.1, font=dict(color="#94a3b8"), bgcolor="rgba(0,0,0,0)"),
        height=300,
    ))
    st.plotly_chart(fig_compare, use_container_width=True, key="aps_compare")

    # --- Side-by-side graphs ---
    g_left, g_right = st.columns(2)

    with g_left:
        st.markdown(f'<div style="text-align:center;color:{C_RED};font-weight:600;font-size:13px;margin-bottom:6px">⚠ CURRENT STATE — {cs.get("reachable_count",0)} resources reachable</div>', unsafe_allow_html=True)
        nodes_c = cs.get("all_nodes", [])
        edges_c = cs.get("all_edges", [])
        fig_c   = build_attack_graph(nodes_c, edges_c, title="")
        st.plotly_chart(fig_c, use_container_width=True, key="aps_graph_current")

    with g_right:
        st.markdown(f'<div style="text-align:center;color:{C_TEAL};font-weight:600;font-size:13px;margin-bottom:6px">✅ POST REMEDIATION — {pr.get("reachable_count",0)} resources reachable</div>', unsafe_allow_html=True)
        nodes_p = pr.get("all_nodes", [])
        edges_p = pr.get("all_edges", [])
        # Find nodes that were removed
        current_ids = {n["id"] for n in nodes_c}
        post_ids    = {n["id"] for n in nodes_p}
        removed_ids = current_ids - post_ids
        # Show full current graph with removed nodes greyed out for visual impact
        fig_p = build_attack_graph(nodes_c, edges_p, title="", removed_node_ids=removed_ids)
        st.plotly_chart(fig_p, use_container_width=True, key="aps_graph_post")

    # --- Path sequence breadcrumb ---
    ap_row = ap[ap["canonical_id"] == d["canonical_id"]]
    if not ap_row.empty:
        path_seq = str(ap_row.iloc[0].get("path_sequence", ""))
        if path_seq:
            st.markdown('<div class="section-header">ATTACK PATH SEQUENCE (example path)</div>', unsafe_allow_html=True)
            # Parse: "Name -EDGE-> Node -EDGE-> Node"
            parts = path_seq.replace(" -", "|-").replace("-> ", "|").split("|")
            breadcrumb_html = ""
            for i, part in enumerate(parts):
                part = part.strip()
                if "-" in part and not part.startswith("-"):
                    # It's a node
                    breadcrumb_html += f'<span class="path-step">{part}</span>'
                elif part.startswith("-"):
                    edge = part.strip("- >")
                    breadcrumb_html += f'<span class="path-arrow">—{edge}—›</span>'
                else:
                    breadcrumb_html += f'<span class="path-step">{part}</span>'
            st.markdown(f'<div style="margin:8px 0;flex-wrap:wrap;">{breadcrumb_html}</div>', unsafe_allow_html=True)

    # --- Remediation scenario ---
    remediation_scenario = d.get("remediation_scenario", "")
    if remediation_scenario:
        st.markdown('<div class="section-header">REMEDIATION SCENARIO</div>', unsafe_allow_html=True)
        st.markdown(
            f'<div style="background:rgba(0,245,212,0.05);border:1px solid rgba(0,245,212,0.2);'
            f'border-radius:8px;padding:12px 16px;font-size:12px;color:#94a3b8;line-height:1.6">'
            f'{remediation_scenario}</div>',
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Page 7 — Compliance Dashboard
# ---------------------------------------------------------------------------

def page_compliance_dashboard() -> None:
    st.markdown("## 📊 Compliance Dashboard")

    cm = load_compliance_mappings()

    if cm.empty:
        st.warning("compliance_mappings.csv is empty.")
        return

    # Framework summary
    fw_counts = cm["framework"].value_counts()
    fw_colors = {
        "MITRE": C_RED,
        "NIST":  C_BLUE,
        "CIS":   C_TEAL,
        "GDPR":  C_AMBER,
        "ISO":   C_PURPLE,
        "SOC2":  "#34d399",
        "SOX":   "#fb923c",
    }

    col_pie, col_bar = st.columns(2)
    with col_pie:
        fig_fw = go.Figure(go.Pie(
            labels=fw_counts.index.tolist(),
            values=fw_counts.values.tolist(),
            hole=0.5,
            marker=dict(
                colors=[fw_colors.get(f, "#888") for f in fw_counts.index],
                line=dict(color=C_BG, width=2),
            ),
            textfont=dict(size=11),
        ))
        fig_fw.update_layout(**_layout(
            title="Audit Rows by Framework",
            legend=dict(orientation="h", y=-0.15, font=dict(size=10), bgcolor="rgba(0,0,0,0)"),
            height=310,
        ))
        st.plotly_chart(fig_fw, use_container_width=True, key="comp_fw_pie")

    with col_bar:
        # Incidents per framework
        inc_fw = cm[cm["source_type"] == "INCIDENT"]["framework"].value_counts()
        fig_inc = go.Figure(go.Bar(
            x=inc_fw.index.tolist(),
            y=inc_fw.values.tolist(),
            marker_color=[fw_colors.get(f, "#888") for f in inc_fw.index],
            text=inc_fw.values.tolist(),
            textposition="outside",
            textfont=dict(color="#e2e8f0", size=11),
        ))
        fig_inc.update_layout(**_layout(
            title="Incident Mappings by Framework",
            height=310,
            xaxis_title=None,
            yaxis_title="Mapping count",
        ))
        st.plotly_chart(fig_inc, use_container_width=True, key="comp_inc_fw")

    # Top violated controls per framework
    st.markdown('<div class="section-header">TOP VIOLATED CONTROLS</div>', unsafe_allow_html=True)

    frameworks_available = cm["framework"].dropna().unique().tolist()
    sel_fw = st.selectbox("Framework", sorted(frameworks_available), key="comp_fw_sel")

    fw_df = cm[(cm["framework"] == sel_fw) & (cm["source_type"] == "INCIDENT")]
    if fw_df.empty:
        st.caption(f"No incident mappings for {sel_fw}.")
    else:
        top_ctrl = fw_df["control_id"].value_counts().head(15)
        fig_ctrl = go.Figure(go.Bar(
            y=top_ctrl.index.tolist(),
            x=top_ctrl.values.tolist(),
            orientation="h",
            marker_color=fw_colors.get(sel_fw, C_BLUE),
            text=top_ctrl.values.tolist(),
            textposition="outside",
            textfont=dict(color="#e2e8f0", size=10),
        ))
        fig_ctrl.update_layout(**_layout(
            title=f"Top Controls — {sel_fw}",
            height=360,
            yaxis=dict(autorange="reversed", gridcolor="rgba(255,255,255,0.06)"),
            xaxis_title="Incident count",
        ))
        st.plotly_chart(fig_ctrl, use_container_width=True, key="comp_ctrl_bar")

    # Compliance coverage table
    st.markdown('<div class="section-header" style="margin-top:8px">REMEDIATION COVERAGE BY FRAMEWORK</div>', unsafe_allow_html=True)
    act_fw = cm[cm["source_type"] == "ACTION"]["framework"].value_counts().rename("Remediation Actions")
    inc_fw2 = cm[cm["source_type"] == "INCIDENT"]["framework"].value_counts().rename("Incidents")
    cov = pd.concat([inc_fw2, act_fw], axis=1).fillna(0).astype(int).reset_index()
    cov.columns = ["Framework", "Incident Mappings", "Action Mappings"]
    st.dataframe(cov, use_container_width=True, hide_index=True, height=240)


# ---------------------------------------------------------------------------
# Page 8 — Narratives
# ---------------------------------------------------------------------------

def page_narratives() -> None:
    st.markdown("## 📝 AI-Generated Narratives")

    narratives = load_narratives()
    if narratives is None:
        st.markdown(
            '<div class="glass-card">'
            '<h3 style="color:#F5A623">⚠ Narratives Not Available</h3>'
            '<p style="color:#94a3b8">Run the full pipeline with LLM enabled to populate this view:</p>'
            '<code style="color:#00F5D4">python src/main.py</code>'
            '<p style="color:#64748b;font-size:12px;margin-top:8px">'
            'With <code>--skip-llm</code>, template narratives are written to incidents.csv and '
            'remediation_actions.csv but narratives.json is not produced.</p>'
            '</div>',
            unsafe_allow_html=True,
        )
        # Still show incident narratives from incidents.csv if available
        inc = load_incidents()
        has_narr = inc["llm_narrative"].notna() & (inc["llm_narrative"].astype(str).str.len() > 10)
        if has_narr.any():
            st.markdown('<div class="section-header">NARRATIVES FROM INCIDENTS.CSV</div>', unsafe_allow_html=True)
            st.caption(f"{has_narr.sum()} incidents have template narratives in incidents.csv")
            for _, row in inc[has_narr].head(10).iterrows():
                _render_narrative_card(
                    display_name=str(row.get("canonical_id",""))[:12],
                    risk_tier=str(row.get("severity","")),
                    detection_method=str(row.get("detection_method","")),
                    narrative_text=str(row.get("llm_narrative","")),
                    narrative_type="TEMPLATE (incidents.csv)",
                    rationale_text="",
                )
        return

    st.markdown(
        f'<p style="color:#64748b;font-size:13px;">{len(narratives)} narratives for CRITICAL / HIGH identities</p>',
        unsafe_allow_html=True,
    )

    # Filter by tier
    tier_filter = st.radio("Filter", ["All", "CRITICAL", "HIGH"], horizontal=True, key="narr_tier_filter")
    if tier_filter != "All":
        narratives = [n for n in narratives if n.get("risk_tier") == tier_filter]

    for n in narratives:
        _render_narrative_card(
            display_name=n.get("display_name","–"),
            risk_tier=n.get("risk_tier",""),
            detection_method=n.get("detection_method",""),
            narrative_text=n.get("narrative_text",""),
            narrative_type=n.get("narrative_type",""),
            rationale_text=n.get("rationale_text",""),
        )


def _render_narrative_card(
    display_name: str,
    risk_tier: str,
    detection_method: str,
    narrative_text: str,
    narrative_type: str,
    rationale_text: str,
) -> None:
    tier_color = TIER_COLORS.get(risk_tier, C_BLUE)
    type_color = C_TEAL if "LLM" in str(narrative_type) else "#64748b"
    type_icon  = "🤖" if "LLM" in str(narrative_type) else "📄"

    st.markdown(
        f'<div class="glass-card" style="border-left:3px solid {tier_color};margin-bottom:12px">'
        f'<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;">'
        f'  <div>'
        f'    <b style="font-size:15px">{display_name}</b> &nbsp; {tier_badge_html(risk_tier)}'
        f'    <br><span style="font-size:11px;color:#64748b;margin-top:4px;display:block">'
        f'      {detection_badge_html(detection_method)}'
        f'    </span>'
        f'  </div>'
        f'  <span style="font-size:11px;color:{type_color};font-weight:600">'
        f'    {type_icon} {narrative_type}'
        f'  </span>'
        f'</div>'
        f'<div style="font-size:12px;line-height:1.7;color:#cbd5e1;margin-top:12px">'
        f'{narrative_text}'
        f'</div>'
        f'{"<div style=margin-top:10px;padding-top:10px;border-top:1px solid rgba(255,255,255,0.08)>" if rationale_text else ""}'
        f'{"<b style=font-size:11px;color:#64748b>REMEDIATION RATIONALE</b><br>" if rationale_text else ""}'
        f'{"<span style=font-size:11px;color:#94a3b8>" + rationale_text[:300] + "</span>" if rationale_text else ""}'
        f'{"</div>" if rationale_text else ""}'
        f'</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Sidebar + main routing
# ---------------------------------------------------------------------------

PAGES = {
    "🛡 Executive Overview":      page_executive_overview,
    "🔎 Identity Explorer":       page_identity_explorer,
    "📋 Risk Register":            page_risk_register,
    "🚨 Incident Explorer":        page_incident_explorer,
    "🕸 Identity Graph":           page_identity_graph,
    "⚡ Attack Path Simulator":    page_attack_path_simulator,
    "📊 Compliance Dashboard":     page_compliance_dashboard,
    "📝 Narratives":               page_narratives,
}


def main() -> None:
    # Sidebar branding
    with st.sidebar:
        st.markdown(
            f'<div style="padding:16px 0 24px 0">'
            f'<div style="font-size:22px;font-weight:800;letter-spacing:-0.5px">'
            f'<span style="color:{C_TEAL}">Identity</span>'
            f'<span style="color:{C_BLUE}"> Nexus</span>'
            f'<span style="color:{C_PURPLE}"> AI</span>'
            f'</div>'
            f'<div style="font-size:11px;color:#475569;letter-spacing:0.08em;text-transform:uppercase;margin-top:2px">'
            f'SOC Intelligence Platform</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        st.markdown('<div class="section-header">NAVIGATION</div>', unsafe_allow_html=True)
        page = st.radio("", list(PAGES.keys()), key="nav_page", label_visibility="collapsed")

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-header">DETECTION LEGEND</div>', unsafe_allow_html=True)
        st.markdown(
            f'<span class="badge badge-ml">&#129302; ML Ensemble</span><br>'
            f'<div style="font-size:10px;color:#475569;margin:3px 0 10px 4px">'
            f'IsolationForest + LOF + Autoencoder<br>weighted ensemble score</div>'
            f'<span class="badge badge-rule">&#9881; Rule-based</span><br>'
            f'<div style="font-size:10px;color:#475569;margin:3px 0 0 4px">'
            f'Deterministic IAM governance rules<br>ORPHANED_ACCOUNT · TOKEN_ABUSE</div>',
            unsafe_allow_html=True,
        )

        st.markdown("<br>", unsafe_allow_html=True)
        try:
            rs = load_risk_scores()
            inc = load_incidents()
            n_crit = int((rs["risk_tier"] == "CRITICAL").sum())
            n_open = int((inc["status"] == "OPEN").sum())
            st.markdown(
                f'<div style="background:rgba(255,77,109,0.1);border:1px solid rgba(255,77,109,0.3);'
                f'border-radius:8px;padding:10px 12px;font-size:12px;">'
                f'<b style="color:{C_RED}">LIVE STATUS</b><br>'
                f'<span style="color:#94a3b8">Critical: <b style="color:{C_RED}">{n_crit}</b></span><br>'
                f'<span style="color:#94a3b8">Open incidents: <b style="color:{C_AMBER}">{n_open}</b></span>'
                f'</div>',
                unsafe_allow_html=True,
            )
        except Exception:
            pass

    # Render selected page
    PAGES[page]()


if __name__ == "__main__":
    main()
