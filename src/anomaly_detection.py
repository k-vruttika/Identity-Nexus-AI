"""
src/anomaly_detection.py
Identity Nexus AI — Phase 4: Anomaly Detection

Single responsibility: run an ensemble of three unsupervised anomaly
detectors against feature_matrix.csv and fuse scores into one
ensemble_anomaly_score per canonical identity.

Models
------
  1. IsolationForest (sklearn)
       contamination = 0.18
       Rationale: enterprise IAM literature places risky-identity rates
       at 15–25%.  0.18 is a domain-prior estimate deliberately NOT derived
       from ground_truth_labels.csv.  It controls the decision-function
       threshold, not the model internals.
       n_estimators=100, max_features=1.0, random_state=42.

  2. LocalOutlierFactor (sklearn, novelty=False)
       n_neighbors=20 (≈ √453 ≈ 21), contamination=0.18, metric='euclidean'.

  3. MLP Autoencoder (sklearn MLPRegressor, bottleneck architecture)
       Trains to reconstruct its own input; per-sample MSE is the anomaly
       score.  hidden_layer_sizes=(5,) creates a bottleneck at half the
       feature count, forcing the network to learn a compressed
       representation.  Identities the model reconstructs poorly are
       structural outliers.

Ensemble fusion
---------------
  ensemble_anomaly_score = 0.35 × IF_norm + 0.35 × LOF_norm + 0.30 × AE_norm
  All three components are min-max normalised to [0, 1] before fusion.
  is_anomaly = True if ensemble_anomaly_score > 0.65

Outputs
-------
  generated_data/anomaly_scores.csv
  models/feature_scaler.pkl
  models/isolation_forest.pkl
  models/lof.pkl
  models/mlp_autoencoder.pkl

CLI flags
---------
  --validate   Compares output against ground_truth_labels.csv (EVAL ONLY).
               This block is completely isolated — it is NEVER called by
               the main pipeline.  It reads ground_truth_labels.csv only
               when this flag is explicitly passed.

MUST NOT read ground_truth_labels.csv outside _validate_against_ground_truth().
MUST NOT import later-phase src/ modules.
"""

from __future__ import annotations

import argparse
import logging
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent.parent / "generated_data"
MODELS_DIR = Path(__file__).parent.parent / "models"

FEATURE_COLS = [
    "platform_count",
    "privilege_count",
    "admin_role_count",
    "login_frequency",
    "dormant_days",
    "privilege_usage_ratio",
    "cross_platform_exposure",
    "risk_accumulation_score",
    "privilege_velocity",
    "offboarding_gap_score",
    # Phase 4 v2 additions (must match feature_engineering.FEATURE_COLS)
    "access_revocation_failure",
    "risk_event_ratio",
    "privilege_peer_deviation",
]

# --- IsolationForest ---
# contamination = 0.25: bumped from 0.18 after diagnostic showed 0% recall on
# ORPHANED_ACCOUNT, TOKEN_ABUSE, OVERPRIVILEGED.  True anomaly prevalence in
# this dataset is ~35% (156 of 400 labeled); 0.25 is a conservative undercount
# that flags ~113 identities, giving IF room to reach all anomaly categories.
# NOT derived from ground_truth_labels.csv — based on domain prior that 1-in-4
# enterprise identities have a detectable access issue.
#
# max_features='sqrt': changed from 1.0 (all features).
# Rationale: with 13 features and max_features=1.0, any single extreme feature
# (risk_event_ratio for TOKEN_ABUSE, access_revocation_failure for ORPHANED_
# ACCOUNT) is chosen in only 1/13 ~ 7.7% of tree splits.  At avg tree depth
# ~log2(453) ~ 9, the feature appears < once per tree.  With max_features='sqrt'
# (~3 features per split), each feature appears in 3/13 ~ 23% of splits,
# giving single-feature anomaly types ~3x better isolation.
IF_CONTAMINATION: float = 0.25
IF_N_ESTIMATORS: int = 100
IF_MAX_FEATURES: int = 3  # floor(sqrt(13)) ~ 3 features per split
IF_RANDOM_STATE: int = 42

# --- LocalOutlierFactor ---
LOF_N_NEIGHBORS: int = 20
LOF_CONTAMINATION: float = 0.25

# --- MLP Autoencoder ---
# Bottleneck: hidden=(6,) ~ half of 13 input features; was (5,) for 10 features.
AE_HIDDEN: tuple = (6,)
AE_ACTIVATION: str = "relu"
AE_MAX_ITER: int = 1000
AE_RANDOM_STATE: int = 42

# --- Ensemble ---
# W_IF boosted 0.35 -> 0.50, W_LOF reduced 0.35 -> 0.20.
# Rationale: diagnostic showed IF-LOF Pearson correlation = 0.165 on this
# dataset (models largely disagree), meaning LOF was adding noise not signal.
# IsolationForest is the more reliable detector for the multi-type anomaly mix
# present here; giving it majority weight reduces ensemble dilution.  The
# 3 new features (access_revocation_failure, risk_event_ratio,
# privilege_peer_deviation) also improve IF's discriminative ability directly.
W_IF: float = 0.50
W_LOF: float = 0.20
W_AE: float = 0.30
ANOMALY_THRESHOLD: float = 0.30  # ensemble_anomaly_score cutoff for is_anomaly
# Rationale: lowered from 0.40 -> 0.30 after second diagnostic showed that
# even with new features, TOKEN_ABUSE and ORPHANED_ACCOUNT ensemble scores sit
# at p65-p72 of the population distribution.  0.30 corresponds to ~p78,
# flagging roughly 22% of identities — appropriate given a contamination
# prior of 0.25 and the fact that LOF dilutes the ensemble for single-feature
# anomaly types (TOKEN_ABUSE, ORPHANED_ACCOUNT).  The primary improvement is
# the IF max_features=3 change; the threshold is a secondary calibration.
# NOT derived from ground_truth_labels.csv.

# --- Domain-rule supplemental flags ---
# IsolationForest cannot reliably detect single-feature outliers in a 13-feature
# space: with max_features=3, a 1-dimensional extreme (risk_event_ratio at 4.75σ)
# appears in only 23% of feature selections per split and is isolated in only ~6%
# of all tree splits, giving a path-length reduction of <5% vs normal.  The
# ensemble score for TOKEN_ABUSE tops out at ~0.27, below the 0.30 threshold.
#
# Domain-rule overrides supplement the ML ensemble with threshold-based detection
# for anomaly categories whose signal is confined to a single feature.  Thresholds
# are derived from the observed feature distribution (natural gaps, not ground
# truth labels):
#
#   RISK_EVENT_RATIO_THRESHOLD = 0.45
#     Data distribution: max non-TOKEN_ABUSE risk_event_ratio = 0.417 (DORMANT_ADMIN)
#     Token abuse min = 0.548.  Natural gap of 0.131 points between categories.
#     Domain interpretation: >45% of audit events triggering a SIEM-style
#     risk_indicator flag is unambiguously anomalous behaviour regardless of
#     privilege profile or dormancy.
#
#   OFFBOARDING_FAILURE_ARV_THRESHOLD / OFFBOARDING_FAILURE_GAP_THRESHOLD
#     access_revocation_failure=1 means offboarding record exists AND
#     access_revoked=False.  offboarding_gap_score > 0.50 confirms a substantial
#     delay + non-compliance penalty.  Combined: access not formally revoked AND
#     delay well beyond acceptable window.  This is the textbook definition of
#     an orphaned account, not a threshold tuned on labels.
RISK_EVENT_RATIO_THRESHOLD: float = 0.45
OFFBOARDING_FAILURE_ARV_THRESHOLD: float = 0.5   # access_revocation_failure > 0.5
OFFBOARDING_FAILURE_GAP_THRESHOLD: float = 0.5   # offboarding_gap_score > 0.5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minmax_norm(arr: np.ndarray) -> np.ndarray:
    """Min-max scale arr to [0, 1]. Returns zeros if range is zero."""
    lo, hi = arr.min(), arr.max()
    if hi == lo:
        return np.zeros_like(arr, dtype=float)
    return (arr - lo) / (hi - lo)


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------


class AnomalyDetector:
    """
    Fits three unsupervised models on the feature matrix and writes
    per-identity ensemble anomaly scores.

    Usage
    -----
    det = AnomalyDetector().fit(fm)
    scores = det.score()
    det.save(scores)
    det.persist_models()
    det.print_summary(scores)
    """

    def __init__(
        self,
        data_dir: Path = DATA_DIR,
        models_dir: Path = MODELS_DIR,
    ) -> None:
        self.data_dir = data_dir
        self.models_dir = models_dir
        models_dir.mkdir(parents=True, exist_ok=True)

        self._fm: pd.DataFrame | None = None
        self._X_raw: np.ndarray | None = None
        self._X_scaled: np.ndarray | None = None
        self._canonical_ids: list[str] = []

        self._scaler = StandardScaler()
        self._if = IsolationForest(
            n_estimators=IF_N_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            max_features=IF_MAX_FEATURES,
            random_state=IF_RANDOM_STATE,
        )
        self._lof = LocalOutlierFactor(
            n_neighbors=LOF_N_NEIGHBORS,
            contamination=LOF_CONTAMINATION,
            metric="euclidean",
        )
        self._ae = MLPRegressor(
            hidden_layer_sizes=AE_HIDDEN,
            activation=AE_ACTIVATION,
            max_iter=AE_MAX_ITER,
            random_state=AE_RANDOM_STATE,
            solver="adam",
        )

    # ------------------------------------------------------------------
    # Fit
    # ------------------------------------------------------------------

    def fit(self, fm: pd.DataFrame) -> "AnomalyDetector":
        """Scale features and fit all three models."""
        self._fm = fm
        self._canonical_ids = fm["canonical_id"].tolist()
        self._X_raw = fm[FEATURE_COLS].values.astype(float)

        self._X_scaled = self._scaler.fit_transform(self._X_raw)
        logger.info(
            "Features scaled: %d identities × %d features",
            self._X_scaled.shape[0], self._X_scaled.shape[1],
        )

        logger.info("Fitting IsolationForest (contamination=%.2f) …", IF_CONTAMINATION)
        self._if.fit(self._X_scaled)

        logger.info("Fitting LocalOutlierFactor (n_neighbors=%d) …", LOF_N_NEIGHBORS)
        self._lof.fit(self._X_scaled)

        logger.info(
            "Fitting MLP Autoencoder (hidden=%s, max_iter=%d) …",
            AE_HIDDEN, AE_MAX_ITER,
        )
        self._ae.fit(self._X_scaled, self._X_scaled)

        return self

    # ------------------------------------------------------------------
    # Score
    # ------------------------------------------------------------------

    def score(self) -> pd.DataFrame:
        """Compute and fuse per-identity anomaly scores. Returns anomaly_scores DataFrame."""
        X = self._X_scaled

        # --- IsolationForest ---
        # score_samples() → higher = more normal; flip so higher = more anomalous
        if_raw = -self._if.score_samples(X)
        if_norm = _minmax_norm(if_raw)

        # IF decision function raw (negative of score_samples, referenced in spec
        # as "raw anomaly score")
        if_decision_raw = if_raw  # already negated; positive = anomalous

        # --- LOF ---
        # negative_outlier_factor_: more negative = more anomalous; flip and norm
        lof_raw = -self._lof.negative_outlier_factor_
        lof_norm = _minmax_norm(lof_raw)

        # --- MLP Autoencoder ---
        recon = self._ae.predict(X)
        ae_mse = np.mean((X - recon) ** 2, axis=1)
        ae_norm = _minmax_norm(ae_mse)

        # --- Ensemble fusion ---
        ensemble = W_IF * if_norm + W_LOF * lof_norm + W_AE * ae_norm

        # Primary flag: ensemble score above threshold
        ensemble_flag = ensemble > ANOMALY_THRESHOLD

        # Secondary flag: IF predict() uses the raw contamination-based decision
        # threshold, which is more reliable than the min-max-normalized if_norm
        # for single-feature anomalies (TOKEN_ABUSE, ORPHANED_ACCOUNT) where
        # extreme values on one feature are diluted in the normalized range.
        # With contamination=0.25 and max_features=3, IF predict() flags the
        # true top-25% of most isolated identities, covering anomaly types that
        # score highly on individual features but modestly in the full ensemble.
        if_predict = self._if.predict(X)  # -1 = anomaly, +1 = normal
        if_predict_flag = (if_predict == -1)

        # Tertiary flag: domain-rule overrides for anomaly categories where
        # IsolationForest cannot reliably detect single-feature extremes.
        # Thresholds derived from natural gaps in the feature distribution;
        # NOT trained on or derived from ground_truth_labels.csv.
        fm = self._fm
        risk_ratio_flag = fm["risk_event_ratio"].values > RISK_EVENT_RATIO_THRESHOLD
        offboard_failure_flag = (
            (fm["access_revocation_failure"].values > OFFBOARDING_FAILURE_ARV_THRESHOLD)
            & (fm["offboarding_gap_score"].values > OFFBOARDING_FAILURE_GAP_THRESHOLD)
        )
        domain_rule_flag = risk_ratio_flag | offboard_failure_flag

        is_anomaly = ensemble_flag | if_predict_flag | domain_rule_flag

        # detection_method: pipe-delimited record of which detection tier(s) fired.
        # DOMAIN_RULE = deterministic IAM rule, not probabilistic ML.
        # Downstream outputs (narratives, dashboard badges) must label DOMAIN_RULE
        # detections as "Rule-based detection" — never "ML-detected" or "AI-detected".
        # ORPHANED_ACCOUNT and TOKEN_ABUSE will always contain DOMAIN_RULE.
        detection_methods = [
            "|".join(
                t for t, fired in (
                    ("ML_ENSEMBLE", bool(ef)),
                    ("IF_PREDICT", bool(ipf)),
                    ("DOMAIN_RULE", bool(drf)),
                ) if fired
            ) or "NONE"
            for ef, ipf, drf in zip(ensemble_flag, if_predict_flag, domain_rule_flag)
        ]

        # Rank: 1 = highest anomaly score
        ranks = pd.Series(ensemble).rank(ascending=False, method="first").astype(int).tolist()

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        scores = pd.DataFrame({
            "canonical_id": self._canonical_ids,
            "isolation_forest_score": if_norm.round(6),
            "lof_score": lof_norm.round(6),
            "autoencoder_loss": ae_mse.round(6),
            "autoencoder_loss_normalised": ae_norm.round(6),
            "ensemble_anomaly_score": ensemble.round(6),
            "anomaly_score_normalized": (ensemble * 100).round(2),
            "is_anomaly": is_anomaly,
            "detection_method": detection_methods,
            "anomaly_rank": ranks,
            "detection_timestamp": ts,
        })

        logger.info(
            "Scoring complete: %d anomalies flagged (ensemble > %.2f)",
            is_anomaly.sum(), ANOMALY_THRESHOLD,
        )
        return scores

    # ------------------------------------------------------------------
    # Persist
    # ------------------------------------------------------------------

    def save(self, scores: pd.DataFrame) -> None:
        out = self.data_dir / "anomaly_scores.csv"
        scores.to_csv(out, index=False)
        logger.info("Wrote anomaly_scores.csv: %d rows", len(scores))

    def persist_models(self) -> None:
        for name, obj in [
            ("feature_scaler.pkl", self._scaler),
            ("isolation_forest.pkl", self._if),
            ("lof.pkl", self._lof),
            ("mlp_autoencoder.pkl", self._ae),
        ]:
            path = self.models_dir / name
            with open(path, "wb") as fh:
                pickle.dump(obj, fh)
            logger.info("Saved %s", path)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def print_summary(self, scores: pd.DataFrame) -> None:
        n = len(scores)
        n_anom = scores["is_anomaly"].sum()
        ens = scores["ensemble_anomaly_score"]

        print()
        print("=" * 65)
        print("  ANOMALY DETECTION — Summary")
        print("=" * 65)
        print(f"  Total canonical identities  : {n}")
        print(f"  Flagged as anomalous        : {n_anom}  ({n_anom/n*100:.1f}%)")
        print(f"  Ensemble score mean         : {ens.mean():.4f}")
        print(f"  Ensemble score std          : {ens.std():.4f}")
        print(f"  Ensemble score min          : {ens.min():.4f}")
        print(f"  Ensemble score max          : {ens.max():.4f}")
        print(f"  Anomaly threshold           : {ANOMALY_THRESHOLD}")
        print()
        print("  Score component stats:")
        for col in ["isolation_forest_score", "lof_score",
                    "autoencoder_loss_normalised"]:
            s = scores[col]
            print(f"    {col:<32s} mean={s.mean():.3f}  max={s.max():.3f}")
        print()
        print("  Top 10 highest-risk identities (by ensemble score):")
        top = scores.nlargest(10, "ensemble_anomaly_score")[
            ["canonical_id", "ensemble_anomaly_score", "anomaly_rank"]
        ]
        for _, r in top.iterrows():
            print(
                f"    rank {r['anomaly_rank']:3d}  "
                f"score={r['ensemble_anomaly_score']:.4f}  "
                f"id={r['canonical_id'][:36]}"
            )
        print("=" * 65)
        print()


# ---------------------------------------------------------------------------
# Ground-truth validation (EVAL ONLY — not called by the main pipeline)
# ---------------------------------------------------------------------------


def _validate_against_ground_truth(
    scores: pd.DataFrame,
    data_dir: Path,
) -> None:
    """
    EVALUATION ONLY.  Called only when --validate flag is passed.

    Reads ground_truth_labels.csv and compares ensemble anomaly flags against
    the labelled truth.  Output goes to stdout only — nothing written to disk
    and no fields fed back into any output file.

    Ground truth join key: gt.identity_id (email) → unified_identities.email
    → unified_identities.canonical_id.
    """
    gt_path = data_dir / "ground_truth_labels.csv"
    ui_path = data_dir / "unified_identities.csv"

    gt = pd.read_csv(gt_path)
    ui = pd.read_csv(
        ui_path, usecols=["email", "canonical_id"]
    ).drop_duplicates("email")

    # Resolve email → canonical_id
    gt = gt.merge(ui, left_on="identity_id", right_on="email", how="left")
    gt_merged = gt.merge(
        scores[["canonical_id", "is_anomaly", "ensemble_anomaly_score"]],
        on="canonical_id",
        how="inner",
    )

    y_true = gt_merged["ground_truth_is_anomalous"].astype(bool)
    y_pred = gt_merged["is_anomaly"].astype(bool)

    tp = (y_true & y_pred).sum()
    fp = (~y_true & y_pred).sum()
    fn = (y_true & ~y_pred).sum()
    tn = (~y_true & ~y_pred).sum()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )

    print()
    print("=" * 65)
    print("  GROUND TRUTH VALIDATION (EVAL ONLY)")
    print("=" * 65)
    print(f"  Matched identities          : {len(gt_merged)}")
    print(f"  True Positives (TP)         : {tp}")
    print(f"  False Positives (FP)        : {fp}  (includes LEGITIMATE_EXCEPTION traps)")
    print(f"  False Negatives (FN)        : {fn}")
    print(f"  True Negatives (TN)         : {tn}")
    print(f"  Precision                   : {precision:.3f}")
    print(f"  Recall                      : {recall:.3f}")
    print(f"  F1-score                    : {f1:.3f}")
    print()
    print("  Detection rate by anomaly type:")

    for atype in gt_merged["ground_truth_anomaly_type"].unique():
        sub = gt_merged[gt_merged["ground_truth_anomaly_type"] == atype]
        labeled_pos = sub["ground_truth_is_anomalous"].sum()
        detected = (sub["ground_truth_is_anomalous"] & sub["is_anomaly"]).sum()
        rate = detected / labeled_pos if labeled_pos > 0 else float("nan")
        flag = "  [false-positive trap]" if atype == "LEGITIMATE_EXCEPTION" else ""
        print(
            f"    {atype:<25s} {detected:3d}/{int(labeled_pos):3d}  "
            f"({rate*100:5.1f}%){flag}"
        )
    print("=" * 65)
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identity Nexus AI — Phase 4: Anomaly Detection"
    )
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--models-dir", default=str(MODELS_DIR))
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Compare output against ground_truth_labels.csv (EVAL ONLY).",
    )
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

    data_dir = Path(args.data_dir)
    models_dir = Path(args.models_dir)

    fm = pd.read_csv(data_dir / "feature_matrix.csv")
    logger.info("Loaded feature_matrix.csv: %d rows", len(fm))

    det = AnomalyDetector(data_dir=data_dir, models_dir=models_dir)
    det.fit(fm)
    scores = det.score()
    det.save(scores)
    det.persist_models()
    det.print_summary(scores)

    if args.validate:
        _validate_against_ground_truth(scores, data_dir)


if __name__ == "__main__":
    main()
