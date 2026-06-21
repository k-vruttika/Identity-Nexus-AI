"""
src/llm_narrative_generator.py
Identity Nexus AI — Phase 6: LLM Narrative Generator

Single responsibility: call the Anthropic Claude API to produce one concise
executive-ready investigative narrative (<= 200 words) for each CRITICAL and
HIGH risk identity (the 20 from attack_paths.csv), then populate the
llm_narrative and llm_rationale columns in incidents.csv and
remediation_actions.csv in-place. All remaining incidents and actions receive
a deterministic templated narrative (not a placeholder — fully usable text).

=============================================================================
API KEY CONFIGURATION
=============================================================================
Set the environment variable ANTHROPIC_API_KEY before running:

    export ANTHROPIC_API_KEY="sk-ant-..."   # Linux / macOS
    $env:ANTHROPIC_API_KEY = "sk-ant-..."   # PowerShell

If ANTHROPIC_API_KEY is not set:
    - The generator logs a clear warning with instructions.
    - ALL narratives fall back to the deterministic template.
    - The pipeline does NOT crash.
    - The output files are fully written with template narratives.
    - narratives.json documents narrative_type = "TEMPLATE" for every entry.

=============================================================================
DETECTION METHOD ATTRIBUTION — CRITICAL INVARIANT
=============================================================================
The system prompt and every user prompt EXPLICITLY instruct the LLM:

  DOMAIN_RULE findings (ORPHANED_ACCOUNT, TOKEN_ABUSE):
    --> "identified via deterministic IAM governance rule"
    --> "flagged by automated access lifecycle policy"
    --> NEVER: "the AI identified", "the model detected", "ML-flagged"

  ML_ENSEMBLE / IF_PREDICT findings:
    --> "flagged by the ensemble anomaly detection model"
    --> "identified by the anomaly detection model as a statistical outlier"
    --> Standard ML language is appropriate

  Combined (DOMAIN_RULE + ML):
    --> Describe BOTH layers separately and explicitly

This constraint is enforced at the prompt level (LLM instruction) and at
the template level (deterministic text uses correct attribution). The LLM
cannot override this instruction without producing an off-topic response.

=============================================================================
DETERMINISM NOTE
=============================================================================
This module is deterministic EXCEPT for the LLM API call itself.
  - Data loading, priority selection, template generation: fully deterministic.
  - LLM API call: non-deterministic (temperature=0.3 minimises variation but
    does not eliminate it; different API call timestamps may yield slightly
    different phrasing).
  - Retry logic uses exponential backoff: 2s, 4s, 8s before fallback.

=============================================================================
RETRY AND FALLBACK POLICY
=============================================================================
For each LLM API call:
  Attempt 1: immediate
  Attempt 2: after 2s sleep (if Attempt 1 fails)
  Attempt 3: after 4s sleep (if Attempt 2 fails)
  Fallback:  deterministic template narrative (if all 3 attempts fail)
             narrative_type in narratives.json = "TEMPLATE_FALLBACK"

The pipeline NEVER crashes on an API error. A failed LLM call produces a
template narrative indistinguishable in schema from an LLM narrative.

=============================================================================
OUTPUTS
=============================================================================
    generated_data/incidents.csv           — in-place: llm_narrative populated
    generated_data/remediation_actions.csv — in-place: llm_rationale populated
    generated_data/narratives.json         — 20 entries (one per CRITICAL/HIGH identity)

MUST NOT read ground_truth_labels.csv.
MUST NOT import later-phase src/ modules.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "generated_data"
MODEL_ID = "claude-sonnet-4-6"
MAX_NARRATIVE_WORDS = 200
MAX_RETRIES = 3
RETRY_DELAYS = [2, 4, 8]  # seconds between retries

# ---------------------------------------------------------------------------
# System prompt (shared across all narrative calls)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert Identity and Access Management (IAM) security analyst at a \
financial services firm. Your role is to write concise, factual investigative \
narratives for security incidents, suitable for a CISO or senior executive audience.

=== CRITICAL ATTRIBUTION RULES ===
You MUST follow these rules about detection attribution — they are non-negotiable:

1. DOMAIN_RULE detection (orphaned accounts, token abuse via IAM rules):
   - ALWAYS describe as: "identified via deterministic IAM governance rule",
     "flagged by automated access lifecycle policy", or
     "detected by IAM access control rule"
   - NEVER use: "the AI identified", "the model flagged", "AI-detected",
     "machine learning detected", or any similar phrase implying AI/ML detection

2. ML_ENSEMBLE or IF_PREDICT detection (anomaly model):
   - APPROPRIATE: "flagged by the ensemble anomaly detection model",
     "identified by the anomaly detection model as a statistical outlier",
     "the ML anomaly model detected unusual behaviour"
   - Standard ML attribution language is correct for these findings

3. Combined detection (DOMAIN_RULE + ML components):
   - Describe BOTH layers explicitly and separately
   - e.g. "This identity was flagged independently by both the ensemble \
anomaly detection model and a deterministic IAM rule..."

=== WRITING STYLE ===
- Under 200 words, maximum
- Factual and evidence-based — use only the data provided
- No speculation, no invented details
- Open with the severity and core risk
- State the business impact
- Recommend the specific action
- Quantify the risk reduction where data is available
- Past tense for observations, present tense for recommendations
"""

# ---------------------------------------------------------------------------
# Template narrative functions (deterministic fallback — not placeholders)
# ---------------------------------------------------------------------------


def _detection_attribution(detection_method: str) -> str:
    """
    Return the correct detection attribution phrase for a given detection_method.
    This ensures DOMAIN_RULE incidents are never described as AI/ML-detected.
    """
    dm = str(detection_method)
    has_domain_rule = "DOMAIN_RULE" in dm
    has_ml = "ML_ENSEMBLE" in dm or "IF_PREDICT" in dm

    if has_domain_rule and not has_ml:
        return "identified via a deterministic IAM governance rule"
    if has_domain_rule and has_ml:
        return (
            "independently flagged by both the ensemble anomaly detection model "
            "and a deterministic IAM governance rule"
        )
    return "flagged by the ensemble anomaly detection model as a statistical outlier"


def _template_incident_narrative(
    inc_row: dict,
    rs_row: dict | None,
    ap_row: dict | None,
) -> str:
    """
    Deterministic template narrative for an incident.
    Used when: (a) the identity is not in the CRITICAL/HIGH attack-path set,
               (b) the API key is missing,
               (c) all LLM retries have failed (TEMPLATE_FALLBACK).
    This is a fully usable narrative, not a placeholder.
    """
    display = rs_row.get("display_name", "") if rs_row else ""
    canonical = inc_row.get("canonical_id", "")[:12]
    inc_type = inc_row.get("incident_type", "UNKNOWN").replace("_", " ").title()
    severity = inc_row.get("severity", "MEDIUM")
    risk_score = inc_row.get("risk_score", 0)
    detection_method = inc_row.get("detection_method", "ML_ENSEMBLE")
    attribution = _detection_attribution(detection_method)
    platform = inc_row.get("platform", "multiple platforms")

    try:
        features = json.loads(inc_row.get("contributing_features", "[]") or "[]")
        feature_text = ", ".join(f.replace("_", " ") for f in features[:3]) if features else "elevated risk indicators"
    except (json.JSONDecodeError, TypeError):
        feature_text = "elevated risk indicators"

    name_or_id = display if display else f"identity {canonical}..."

    lines = [
        f"[{severity}] {inc_type} incident detected for {name_or_id} on {platform}.",
        f"This identity was {attribution}, with a risk score of {risk_score:.1f}/100.",
        f"Key contributing factors include: {feature_text}.",
    ]

    if ap_row:
        brs = ap_row.get("current_blast_radius", 0)
        brs_post = ap_row.get("remediated_blast_radius", 0)
        brs_red = ap_row.get("blast_radius_reduction_pct", 0)
        action = ap_row.get("remediation_scenario", "the recommended remediation")
        lines.append(
            f"Attack path analysis shows a blast radius score of {brs:.1f}/100, "
            f"spanning {ap_row.get('reachable_node_count', 0)} reachable resources. "
            f"Applying {ap_row.get('remediation_action', 'the recommended action')} "
            f"would reduce blast radius to {brs_post:.1f} ({brs_red:.1f}% reduction)."
        )
    else:
        lines.append(
            "Immediate review and access right recertification is recommended "
            "to reduce exposure and meet least-privilege requirements."
        )

    root_cause = rs_row.get("root_cause", "") if rs_row else ""
    if root_cause and isinstance(root_cause, str) and len(root_cause) > 20:
        lines.append(f"Root cause: {root_cause[:200]}")

    return " ".join(lines)


def _template_remediation_rationale(
    act_row: dict,
    rs_row: dict | None,
    inc_row: dict | None,
) -> str:
    """
    Deterministic template rationale for a remediation action.
    Used under the same fallback conditions as _template_incident_narrative.
    """
    action_type = act_row.get("action_type", "REQUIRE_RECERTIFICATION")
    priority = act_row.get("action_priority", "medium")
    risk_red = act_row.get("estimated_risk_reduction", 0)
    brs_red = act_row.get("blast_radius_reduction", 0)
    effort = act_row.get("estimated_effort", "moderate")
    justification = act_row.get("justification", "")

    action_descriptions = {
        "DISABLE_ACCOUNT": (
            "Disabling this account immediately removes all active access paths "
            "and eliminates the threat vector. This is the most effective remediation "
            "for identities identified as orphaned or exhibiting rule-based IAM violations."
        ),
        "REVOKE_ROLE": (
            "Revoking the highest-privilege role reduces administrative access to only "
            "what is required for the identity's current business function, directly "
            "enforcing least-privilege principles."
        ),
        "ENFORCE_MFA": (
            "Enabling multi-factor authentication adds a critical second factor to "
            "authentication, significantly reducing the risk of credential-based "
            "attacks and satisfying NIST IA-2 and CIS Control 6.3 requirements."
        ),
        "SCOPE_REDUCTION": (
            "Reducing the privilege scope to the minimum required access level "
            "limits potential blast radius without disrupting business operations, "
            "addressing least-privilege gaps progressively."
        ),
        "REQUIRE_RECERTIFICATION": (
            "Requiring access recertification ensures the identity's current "
            "privilege set is reviewed by the business owner, enabling targeted "
            "removal of stale or excessive permissions within normal change-management cadence."
        ),
        "REMOVE_GROUP": (
            "Removing the identity from the specified group eliminates inherited "
            "access rights granted through group membership, reducing the effective "
            "privilege set without modifying the group's policy for other members."
        ),
    }

    description = action_descriptions.get(action_type, f"Applying {action_type}")
    approval = "requires management approval" if act_row.get("requires_approval") else "can be self-service"

    parts = [
        f"Recommended action: {action_type} (priority: {priority}, effort: {effort}). ",
        description,
        f" Estimated risk reduction: {risk_red:.1f}%.",
    ]
    if brs_red > 0:
        parts.append(f" Blast radius reduction: {brs_red:.1f}%.")
    parts.append(f" This action {approval}.")
    if justification and len(justification) > 20:
        parts.append(f" Basis: {justification[:200]}")

    return "".join(parts)


# ---------------------------------------------------------------------------
# LLM prompt builders
# ---------------------------------------------------------------------------


def _build_incident_prompt(
    inc_row: dict,
    rs_row: dict,
    ap_row: dict | None,
) -> str:
    """Build the user prompt for an incident narrative."""
    display = rs_row.get("display_name", rs_row.get("canonical_id", "")[:24])
    detection_method = inc_row.get("detection_method", "ML_ENSEMBLE")
    dm = str(detection_method)

    # Compose detection attribution instruction specific to this identity
    if "DOMAIN_RULE" in dm and "ML_ENSEMBLE" not in dm and "IF_PREDICT" not in dm:
        dm_instruction = (
            "DETECTION METHOD: DOMAIN_RULE only. "
            "Describe detection as rule-based and deterministic. "
            "Do NOT use AI/ML language for this finding."
        )
    elif "DOMAIN_RULE" in dm:
        dm_instruction = (
            "DETECTION METHOD: Both ML anomaly model AND deterministic IAM rule fired. "
            "Describe BOTH layers explicitly. Clearly separate the rule-based component."
        )
    else:
        dm_instruction = (
            "DETECTION METHOD: ML anomaly model only. "
            "Standard ML attribution language is appropriate."
        )

    try:
        features = json.loads(inc_row.get("contributing_features", "[]") or "[]")
        feature_str = ", ".join(features[:5]) if features else "see evidence below"
    except (json.JSONDecodeError, TypeError):
        feature_str = "see evidence below"

    try:
        resources = json.loads(inc_row.get("affected_resources", "[]") or "[]")
        resource_count = len(resources)
    except (json.JSONDecodeError, TypeError):
        resource_count = 0

    prompt_parts = [
        f"Generate an investigative narrative for this security incident.\n",
        f"\n{dm_instruction}\n",
        f"\nIDENTITY: {display}",
        f"\nRISK TIER: {rs_row.get('risk_tier', 'UNKNOWN')}",
        f"\nRISK SCORE: {rs_row.get('final_risk_score', 0):.1f}/100",
        f"\nINCIDENT TYPE: {inc_row.get('incident_type', 'UNKNOWN')}",
        f"\nSEVERITY: {inc_row.get('severity', 'UNKNOWN')}",
        f"\nPLATFORM: {inc_row.get('platform', 'unknown')}",
        f"\nDETECTION METHOD VALUE: {detection_method}",
        f"\nAFFECTED RESOURCES: {resource_count} resources",
        f"\nCONTRIBUTING FEATURES: {feature_str}",
        f"\n\nEVIDENCE:\n{rs_row.get('evidence', 'No evidence text available.')[:600]}",
        f"\n\nROOT CAUSE:\n{rs_row.get('root_cause', 'No root cause text available.')[:400]}",
        f"\n\nBUSINESS IMPACT:\n{rs_row.get('business_impact', 'No business impact text available.')[:400]}",
    ]

    if ap_row:
        prompt_parts += [
            f"\n\nATTACK PATH ANALYSIS:",
            f"\n  Current blast radius score: {ap_row.get('current_blast_radius', 0):.1f}/100",
            f"\n  Reachable resources (current): {ap_row.get('reachable_node_count', 0)}",
            f"\n  Reachable resources (post-remediation): {ap_row.get('reachable_node_count_post', 0)}",
            f"\n  Impacted platforms: {ap_row.get('impacted_platforms', '[]')}",
            f"\n  Critical resource exposure: {ap_row.get('critical_resource_exposure', 0)} CRITICAL resources",
            f"\n  Recommended remediation: {ap_row.get('remediation_scenario', 'see action board')}",
            f"\n  Blast radius reduction if applied: {ap_row.get('blast_radius_reduction_pct', 0):.1f}%",
            f"\n  Risk score reduction if applied: {ap_row.get('risk_reduction_pct', 0):.1f}%",
        ]

    prompt_parts.append(
        "\n\nWrite a concise executive narrative (maximum 200 words) that:\n"
        "1. Opens with the severity and the single most important risk fact\n"
        "2. Describes HOW the detection occurred (using correct attribution per detection method)\n"
        "3. States the specific business impact using the data above\n"
        "4. Recommends the specific action with its expected reduction\n"
        "5. Ends with an urgency statement appropriate to the risk tier\n"
        "Do not use bullet points. Write as continuous prose."
    )

    return "".join(prompt_parts)


def _build_remediation_prompt(
    act_row: dict,
    rs_row: dict,
    inc_row: dict | None,
) -> str:
    """Build the user prompt for a remediation action rationale."""
    display = rs_row.get("display_name", rs_row.get("canonical_id", "")[:24])
    detection_method = str(rs_row.get("detection_method", "ML_ENSEMBLE"))

    if "DOMAIN_RULE" in detection_method and "ML_ENSEMBLE" not in detection_method and "IF_PREDICT" not in detection_method:
        dm_note = "Note: This identity was detected via a DETERMINISTIC IAM RULE. Any reference to detection in the rationale must NOT use AI/ML language."
    elif "DOMAIN_RULE" in detection_method:
        dm_note = "Note: Detection involved BOTH ML anomaly model AND a deterministic IAM rule. Reference both if relevant."
    else:
        dm_note = "Note: Detection was by the ML anomaly model. Standard ML attribution is appropriate."

    prompt = (
        f"Write a remediation rationale for this security action.\n\n"
        f"{dm_note}\n\n"
        f"IDENTITY: {display}\n"
        f"ACTION TYPE: {act_row.get('action_type', 'UNKNOWN')}\n"
        f"PRIORITY: {act_row.get('action_priority', 'unknown')} ({act_row.get('priority', '?')})\n"
        f"ESTIMATED EFFORT: {act_row.get('estimated_effort', 'unknown')}\n"
        f"REQUIRES APPROVAL: {act_row.get('requires_approval', False)}\n"
        f"ESTIMATED RISK REDUCTION: {act_row.get('estimated_risk_reduction', 0):.1f}%\n"
        f"BLAST RADIUS REDUCTION: {act_row.get('blast_radius_reduction', 0):.1f}%\n"
        f"DETECTION METHOD: {detection_method}\n\n"
        f"JUSTIFICATION (from risk analysis):\n{act_row.get('justification', 'No justification text.')[:500]}\n\n"
        f"ROOT CAUSE:\n{rs_row.get('root_cause', 'No root cause available.')[:400]}\n\n"
    )
    if inc_row:
        prompt += (
            f"ASSOCIATED INCIDENT TYPE: {inc_row.get('incident_type', 'UNKNOWN')}\n"
            f"INCIDENT SEVERITY: {inc_row.get('severity', 'UNKNOWN')}\n\n"
        )

    prompt += (
        "Write a concise plain-English rationale (maximum 150 words) for why this specific "
        "action is recommended for this specific identity. Reference the evidence and expected "
        "outcomes. Appropriate for inclusion in a ticketing system or change-management record. "
        "Do not use bullet points."
    )
    return prompt


# ---------------------------------------------------------------------------
# LLM API caller with retry logic
# ---------------------------------------------------------------------------


def _call_anthropic_api(
    client: Any,
    prompt: str,
    max_tokens: int = 450,
    context_label: str = "",
) -> tuple[str, str]:
    """
    Call the Anthropic API with retry logic.

    Returns (narrative_text: str, narrative_type: str)
    narrative_type is one of: "LLM", "TEMPLATE_FALLBACK"

    Never raises — on all failures, returns a template_fallback signal.
    """
    last_error = ""
    for attempt, delay in enumerate(RETRY_DELAYS, start=1):
        try:
            response = client.messages.create(
                model=MODEL_ID,
                max_tokens=max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
            )
            text = response.content[0].text.strip()
            logger.info("LLM call succeeded (attempt %d) for: %s", attempt, context_label)
            return text, "LLM"
        except Exception as exc:
            last_error = str(exc)
            logger.warning(
                "LLM call failed (attempt %d/%d) for %s: %s",
                attempt, len(RETRY_DELAYS), context_label, last_error,
            )
            if attempt < len(RETRY_DELAYS):
                time.sleep(delay)

    logger.error(
        "All %d LLM attempts failed for %s. Using template fallback. Last error: %s",
        len(RETRY_DELAYS), context_label, last_error,
    )
    return "", "TEMPLATE_FALLBACK"


# ---------------------------------------------------------------------------
# LLMNarrativeGenerator class
# ---------------------------------------------------------------------------


class LLMNarrativeGenerator:
    """
    Generates executive narratives for CRITICAL/HIGH risk identities via Claude API.
    Falls back to deterministic templates for all other identities and on API failure.
    """

    def __init__(self, data_dir: Path = DATA_DIR) -> None:
        self.data_dir = data_dir
        self._api_key_present: bool = False
        self._client: Any = None
        self._inc: pd.DataFrame | None = None
        self._act: pd.DataFrame | None = None
        self._rs_map: dict[str, dict] = {}    # canonical_id -> risk_score row
        self._ap_map: dict[str, dict] = {}    # canonical_id -> attack_path row
        self._ap_canonical_ids: set[str] = set()

    def load(self) -> "LLMNarrativeGenerator":
        """Load all inputs and initialise Anthropic client if API key is present."""
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            logger.warning(
                "ANTHROPIC_API_KEY environment variable is not set. "
                "All narratives will use the deterministic template fallback. "
                "To enable LLM narrative generation, set ANTHROPIC_API_KEY to your "
                "Anthropic API key (format: sk-ant-...)."
            )
            self._api_key_present = False
        else:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=api_key)
                self._api_key_present = True
                logger.info("Anthropic client initialised. Model: %s", MODEL_ID)
            except ImportError:
                logger.error(
                    "anthropic package not installed. "
                    "Run: pip install anthropic. Using template fallback."
                )
                self._api_key_present = False

        self._inc = pd.read_csv(self.data_dir / "incidents.csv")
        self._act = pd.read_csv(self.data_dir / "remediation_actions.csv")
        logger.info("incidents: %d rows | remediation_actions: %d rows",
                    len(self._inc), len(self._act))

        rs = pd.read_csv(self.data_dir / "risk_scores.csv")
        for _, row in rs.iterrows():
            self._rs_map[row["canonical_id"]] = row.to_dict()
        logger.info("risk_scores: %d identities loaded", len(self._rs_map))

        # Load display_names from unified_identities into rs_map
        ui = pd.read_csv(
            self.data_dir / "unified_identities.csv",
            usecols=["canonical_id", "display_name"],
        ).drop_duplicates("canonical_id")
        for _, row in ui.iterrows():
            if row["canonical_id"] in self._rs_map:
                self._rs_map[row["canonical_id"]]["display_name"] = row["display_name"]

        ap = pd.read_csv(self.data_dir / "attack_paths.csv")
        for _, row in ap.iterrows():
            self._ap_map[row["canonical_id"]] = row.to_dict()
        self._ap_canonical_ids = set(self._ap_map.keys())
        logger.info("attack_paths: %d CRITICAL/HIGH identities", len(self._ap_map))

        return self

    def run(self) -> tuple[pd.DataFrame, pd.DataFrame, list[dict]]:
        """
        Generate narratives for all incidents and actions.
        LLM is used only for the 20 CRITICAL/HIGH attack-path identities.
        All others use deterministic templates.

        Returns (updated_inc_df, updated_act_df, narratives_json_list)
        narratives_json_list has exactly 20 entries (one per attack-path identity).
        """
        ts_start = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        # Build canonical_id -> incident map (best incident per identity)
        SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        inc_sorted = self._inc.copy()
        inc_sorted["_sev_rank"] = inc_sorted["severity"].map(SEV_ORDER).fillna(9)
        inc_sorted = inc_sorted.sort_values("_sev_rank")
        canonical_to_best_inc: dict[str, dict] = {}
        for _, row in inc_sorted.drop_duplicates("canonical_id").iterrows():
            canonical_to_best_inc[row["canonical_id"]] = row.to_dict()

        # Build canonical_id -> action map (best/first action per identity)
        canonical_to_best_act: dict[str, dict] = {}
        for _, row in self._act.iterrows():
            can = row.get("canonical_id", row.get("identity_id", ""))
            if can not in canonical_to_best_act:
                canonical_to_best_act[can] = row.to_dict()

        # --- Phase 1: Narratives for the 20 CRITICAL/HIGH attack-path identities ---
        narratives_json: list[dict] = []
        # Store canonical_id -> narrative so we can update all their incidents
        identity_narrative_cache: dict[str, str] = {}
        identity_rationale_cache: dict[str, str] = {}

        for can in sorted(self._ap_canonical_ids):  # sorted for deterministic ordering
            rs_row = self._rs_map.get(can, {})
            ap_row = self._ap_map.get(can)
            inc_row = canonical_to_best_inc.get(can)
            act_row = canonical_to_best_act.get(can)
            ts_gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            # --- Incident narrative ---
            if inc_row and self._api_key_present:
                prompt = _build_incident_prompt(
                    inc_row, rs_row, ap_row
                )
                narrative_text, nt = _call_anthropic_api(
                    self._client, prompt,
                    max_tokens=500,
                    context_label=f"incident/{can[:12]}",
                )
                if nt == "TEMPLATE_FALLBACK" or not narrative_text:
                    narrative_text = _template_incident_narrative(inc_row, rs_row, ap_row)
                    nt = "TEMPLATE_FALLBACK"
            elif inc_row:
                narrative_text = _template_incident_narrative(inc_row, rs_row, ap_row)
                nt = "TEMPLATE" if not self._api_key_present else "TEMPLATE_FALLBACK"
            else:
                # No incident for this CRITICAL/HIGH identity — narrative from risk data
                rs_as_inc = {
                    "canonical_id": can,
                    "incident_type": "PRIVILEGE_ABUSE",  # best guess from tier
                    "severity": rs_row.get("risk_tier", "HIGH"),
                    "detection_method": rs_row.get("detection_method", "ML_ENSEMBLE"),
                    "contributing_features": rs_row.get("risk_drivers", "[]"),
                    "affected_resources": "[]",
                    "platform": "multiple",
                    "risk_score": rs_row.get("final_risk_score", 0),
                }
                if self._api_key_present:
                    prompt = _build_incident_prompt(rs_as_inc, rs_row, ap_row)
                    narrative_text, nt = _call_anthropic_api(
                        self._client, prompt,
                        max_tokens=500,
                        context_label=f"no-incident/{can[:12]}",
                    )
                    if nt == "TEMPLATE_FALLBACK" or not narrative_text:
                        narrative_text = _template_incident_narrative(rs_as_inc, rs_row, ap_row)
                        nt = "TEMPLATE_FALLBACK"
                else:
                    narrative_text = _template_incident_narrative(rs_as_inc, rs_row, ap_row)
                    nt = "TEMPLATE"

            identity_narrative_cache[can] = narrative_text

            # --- Remediation rationale ---
            if act_row and self._api_key_present:
                prompt_r = _build_remediation_prompt(act_row, rs_row, inc_row)
                rationale_text, rt = _call_anthropic_api(
                    self._client, prompt_r,
                    max_tokens=350,
                    context_label=f"action/{can[:12]}",
                )
                if rt == "TEMPLATE_FALLBACK" or not rationale_text:
                    rationale_text = _template_remediation_rationale(act_row, rs_row, inc_row)
                    rt = "TEMPLATE_FALLBACK"
            elif act_row:
                rationale_text = _template_remediation_rationale(act_row, rs_row, inc_row)
                rt = "TEMPLATE" if not self._api_key_present else "TEMPLATE_FALLBACK"
            else:
                rationale_text = ""
                rt = "NONE"

            identity_rationale_cache[can] = rationale_text

            narratives_json.append({
                "canonical_id": can,
                "display_name": rs_row.get("display_name", ""),
                "risk_tier": rs_row.get("risk_tier", ""),
                "detection_method": rs_row.get("detection_method", ""),
                "narrative_text": narrative_text,
                "narrative_type": nt,
                "rationale_text": rationale_text,
                "rationale_type": rt,
                "generated_timestamp": ts_gen,
            })
            logger.info(
                "Generated narrative for %s (%s/%s) type=%s",
                can[:12], rs_row.get("risk_tier", "?"), rs_row.get("detection_method", "?"), nt,
            )

        # --- Phase 2: Populate llm_narrative in incidents.csv ---
        inc_df = self._inc.copy()
        inc_df["llm_narrative"] = inc_df["llm_narrative"].fillna("").astype(str)

        for idx, row in inc_df.iterrows():
            can = row.get("canonical_id", "")
            if can in self._ap_canonical_ids:
                # Use the LLM or fallback narrative cached for this identity
                inc_df.at[idx, "llm_narrative"] = identity_narrative_cache.get(can, "")
            else:
                # Template fallback for non-attack-path incidents
                rs_row = self._rs_map.get(can, {})
                inc_df.at[idx, "llm_narrative"] = _template_incident_narrative(
                    row.to_dict(), rs_row, None
                )

        # --- Phase 3: Populate llm_rationale in remediation_actions.csv ---
        act_df = self._act.copy()
        act_df["llm_rationale"] = act_df["llm_rationale"].fillna("").astype(str)

        for idx, row in act_df.iterrows():
            can = row.get("canonical_id", row.get("identity_id", ""))
            if can in self._ap_canonical_ids:
                act_df.at[idx, "llm_rationale"] = identity_rationale_cache.get(can, "")
            else:
                rs_row = self._rs_map.get(can, {})
                inc_row = canonical_to_best_inc.get(can)
                act_df.at[idx, "llm_rationale"] = _template_remediation_rationale(
                    row.to_dict(), rs_row, inc_row
                )

        llm_count = sum(1 for n in narratives_json if n["narrative_type"] == "LLM")
        tmpl_count = len(narratives_json) - llm_count
        logger.info(
            "Narratives complete: %d LLM, %d template, %d total in JSON",
            llm_count, tmpl_count, len(narratives_json),
        )
        return inc_df, act_df, narratives_json

    def save(
        self,
        inc_df: pd.DataFrame,
        act_df: pd.DataFrame,
        narratives: list[dict],
    ) -> None:
        """Write updated incidents, remediation_actions, and narratives.json."""
        inc_df.to_csv(self.data_dir / "incidents.csv", index=False)
        logger.info("Updated incidents.csv (%d rows)", len(inc_df))

        act_df.to_csv(self.data_dir / "remediation_actions.csv", index=False)
        logger.info("Updated remediation_actions.csv (%d rows)", len(act_df))

        narratives_path = self.data_dir / "narratives.json"
        with open(narratives_path, "w", encoding="utf-8") as fh:
            json.dump(narratives, fh, indent=2, ensure_ascii=False)
        logger.info("Wrote narratives.json (%d entries)", len(narratives))

    def print_summary(self, narratives: list[dict]) -> None:
        """Print validation output including 2 full example narratives."""
        print()
        print("=" * 70)
        print("  LLM NARRATIVE GENERATOR — Summary")
        print("=" * 70)
        print(f"  Narratives in JSON (CRITICAL/HIGH): {len(narratives)}")
        llm_n = [n for n in narratives if n["narrative_type"] == "LLM"]
        tmpl_n = [n for n in narratives if "TEMPLATE" in n["narrative_type"]]
        print(f"    LLM-generated   : {len(llm_n)}")
        print(f"    Template/fallback: {len(tmpl_n)}")
        print()
        api_flag = "YES" if self._api_key_present else "NO (using templates only)"
        print(f"  ANTHROPIC_API_KEY present: {api_flag}")
        print()

        # Find one DOMAIN_RULE and one ML_ENSEMBLE example
        domain_rule_ex = next(
            (n for n in narratives if "DOMAIN_RULE" in n.get("detection_method", "")
             and "ML_ENSEMBLE" not in n.get("detection_method", "")
             and "IF_PREDICT" not in n.get("detection_method", "")),
            None,
        )
        ml_only_ex = next(
            (n for n in narratives if "DOMAIN_RULE" not in n.get("detection_method", "")),
            None,
        )
        mixed_ex = next(
            (n for n in narratives if "DOMAIN_RULE" in n.get("detection_method", "")
             and ("ML_ENSEMBLE" in n.get("detection_method", "")
                  or "IF_PREDICT" in n.get("detection_method", ""))),
            None,
        )

        print("  EXAMPLE 1 — DOMAIN_RULE detection (rule-based language expected):")
        ex = domain_rule_ex or mixed_ex
        if ex:
            print(f"    canonical_id     : {ex['canonical_id']}")
            print(f"    detection_method : {ex['detection_method']}")
            print(f"    narrative_type   : {ex['narrative_type']}")
            print(f"    narrative_text   :")
            # Print the narrative wrapped at 68 chars
            text = ex["narrative_text"]
            for i in range(0, len(text), 68):
                print(f"      {text[i:i+68]}")
        else:
            print("    (no pure DOMAIN_RULE identity in attack paths for this dataset)")
        print()

        print("  EXAMPLE 2 — ML_ENSEMBLE detection (model language expected):")
        ex2 = ml_only_ex
        if ex2:
            print(f"    canonical_id     : {ex2['canonical_id']}")
            print(f"    detection_method : {ex2['detection_method']}")
            print(f"    narrative_type   : {ex2['narrative_type']}")
            print(f"    narrative_text   :")
            text2 = ex2["narrative_text"]
            for i in range(0, len(text2), 68):
                print(f"      {text2[i:i+68]}")
        else:
            print("    (no pure ML_ENSEMBLE identity in attack paths)")
        print("=" * 70)
        print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Identity Nexus AI -- Phase 6: LLM Narrative Generator"
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

    gen = LLMNarrativeGenerator(data_dir=Path(args.data_dir))
    gen.load()
    inc_df, act_df, narratives = gen.run()
    gen.save(inc_df, act_df, narratives)
    gen.print_summary(narratives)


if __name__ == "__main__":
    main()
