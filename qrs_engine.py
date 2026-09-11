"""
modules/qrs_engine.py
QRS (Quantum Risk Scoring) engine for the PQC Transition Toolkit.
Implements Birgin & Celiktas (2026), IEEE Access — DOI: 10.1109/ACCESS.2026.3669437

By: Muhammad Ahmad
Course: Information Security | UMT Lahore | Spring 2026
"""

import json
import datetime

# ── AHP Weights (Equation 1, paper p.33544) ───────────────────────────────────
AHP_WEIGHTS = {
    "dl": 0.30,   # Data Longevity
    "av": 0.25,   # Algorithm Vulnerability
    "ke": 0.25,   # Key Exposure
    "sd": 0.20,   # System Dependence
}

# ── Policy Thresholds (paper p.33546) ─────────────────────────────────────────
THRESHOLDS = {
    "MIGRATE": 8.0,
    "HYBRID":  7.0,
    "MONITOR": 6.0,
    # below 6.0 → DEFER
}

# ── Paper Assets — Table 8 reproduction (Birgin & Celiktas, 2026) ─────────────
PAPER_ASSETS = [
    {
        "id": "A1",
        "name": "PKI Root CA",
        "algorithm": "RSA-4096",
        "sector": "Government",
        "dl": 10, "av": 10, "ke": 8, "sd": 10,
    },
    {
        "id": "A2",
        "name": "TLS Web Gateway",
        "algorithm": "ECDHE-RSA-2048",
        "sector": "Government",
        "dl": 7, "av": 9, "ke": 9, "sd": 8,
    },
    {
        "id": "A3",
        "name": "VPN Infrastructure",
        "algorithm": "DH-2048, AES-256",
        "sector": "Government",
        "dl": 6, "av": 8, "ke": 7, "sd": 8,
    },
    {
        "id": "A4",
        "name": "Code Signing Service",
        "algorithm": "ECDSA-P256",
        "sector": "Government",
        "dl": 5, "av": 7, "ke": 6, "sd": 7,
    },
    {
        "id": "A5",
        "name": "Email Encryption (S/MIME)",
        "algorithm": "RSA-2048",
        "sector": "Government",
        "dl": 5, "av": 7, "ke": 5, "sd": 5,
    },
    {
        "id": "A6",
        "name": "Document Archive Signing",
        "algorithm": "RSA-2048, SHA-256",
        "sector": "Government",
        "dl": 8, "av": 6, "ke": 4, "sd": 4,
    },
]

# ── Extended Assets — New Contribution ────────────────────────────────────────
# Intentionally empty: this dataset is now populated live, from the app's
# "Custom Asset Assessment" page, with real/test data entered by the user —
# no fictional entries are pre-seeded here.
EXTENDED_ASSETS = []


# ── Core QRS computation ───────────────────────────────────────────────────────

def compute_qrs(dl: int, av: int, ke: int, sd: int) -> float:
    """
    QRS = (0.30 × DL) + (0.25 × AV) + (0.25 × KE) + (0.20 × SD)
    Equation 1, Birgin & Celiktas (2026), p.33544
    """
    score = (
        AHP_WEIGHTS["dl"] * dl +
        AHP_WEIGHTS["av"] * av +
        AHP_WEIGHTS["ke"] * ke +
        AHP_WEIGHTS["sd"] * sd
    )
    return round(score, 3)


def assign_policy(qrs_score: float) -> str:
    """Map QRS score to policy state per paper thresholds (p.33546)."""
    if qrs_score >= THRESHOLDS["MIGRATE"]:
        return "MIGRATE"
    elif qrs_score >= THRESHOLDS["HYBRID"]:
        return "HYBRID"
    elif qrs_score >= THRESHOLDS["MONITOR"]:
        return "MONITOR"
    else:
        return "DEFER"


def evaluate_assets(assets: list) -> list:
    """
    Score a list of asset dicts and return enriched results.
    Each input dict must have keys: id, name, algorithm, sector, dl, av, ke, sd.
    Returns list of dicts with added qrs_score and policy fields.
    """
    results = []
    for asset in assets:
        qrs = compute_qrs(asset["dl"], asset["av"], asset["ke"], asset["sd"])
        policy = assign_policy(qrs)
        results.append({
            "id":        asset["id"],
            "name":      asset["name"],
            "algorithm": asset["algorithm"],
            "sector":    asset.get("sector", "Unknown"),
            "dl":        asset["dl"],
            "av":        asset["av"],
            "ke":        asset["ke"],
            "sd":        asset["sd"],
            "qrs_score": qrs,
            "policy":    policy,
        })
    return results


def evaluate_custom(
    name: str, algorithm: str,
    dl: int, av: int, ke: int, sd: int,
    sector: str = "Other"
) -> dict:
    """Score a single custom asset entered by the user."""
    qrs = compute_qrs(dl, av, ke, sd)
    policy = assign_policy(qrs)
    return {
        "id":        "CUSTOM",
        "name":      name,
        "algorithm": algorithm,
        "sector":    sector,
        "dl": dl, "av": av, "ke": ke, "sd": sd,
        "qrs_score": qrs,
        "policy":    policy,
    }


# ── CI/CD Gate (Algorithm 1, paper p.33542) ───────────────────────────────────

def cicd_gate(results: list) -> dict:
    """
    Crypto-Aware CI/CD Validation Gate.
    Returns an audit artifact dict with decision ALLOW / RESTRICT / BLOCK.
    """
    findings = []
    migrate_count = 0
    hybrid_count  = 0
    monitor_count = 0
    defer_count   = 0

    for r in results:
        policy = r["policy"]
        violations = []

        if policy == "MIGRATE":
            migrate_count += 1
            violations.append(
                f"Asset '{r['name']}' uses {r['algorithm']} — QRS {r['qrs_score']} exceeds MIGRATE "
                f"threshold (≥{THRESHOLDS['MIGRATE']}). Immediate PQC migration required (ML-KEM / ML-DSA)."
            )
        elif policy == "HYBRID":
            hybrid_count += 1
            violations.append(
                f"Asset '{r['name']}' — QRS {r['qrs_score']} requires hybrid classical+PQC controls. "
                f"Deploy Kyber-768 or Dilithium-3 alongside existing {r['algorithm']}."
            )
        elif policy == "MONITOR":
            monitor_count += 1
        else:
            defer_count += 1

        if violations:
            findings.append({
                "asset_id":   r["id"],
                "asset_name": r["name"],
                "qrs_score":  r["qrs_score"],
                "policy":     policy,
                "violations": violations,
            })

    # Gate decision logic
    if migrate_count > 0:
        decision = "BLOCK"
    elif hybrid_count > 0:
        decision = "RESTRICT"
    else:
        decision = "ALLOW"

    audit = {
        "gate":          "Crypto-Aware CI/CD Validation Gate",
        "reference":     "Algorithm 1, Birgin & Celiktas (2026), p.33542",
        "timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
        "decision":      decision,
        "migrate_count": migrate_count,
        "hybrid_count":  hybrid_count,
        "monitor_count": monitor_count,
        "defer_count":   defer_count,
        "total_assets":  len(results),
        "findings":      findings,
    }
    return audit


# ── JSON artifact export (Phase P3) ───────────────────────────────────────────

def generate_qrs_json(results: list, output_path: str = None) -> dict:
    """
    Generate a QRS results artifact dict (and optionally save to file).
    Corresponds to qrs_results.json evidence artifact, Table 10.
    """
    artifact = {
        "artifact":   "qrs_results.json",
        "phase":      "P3 — Risk Modeling",
        "reference":  "Birgin & Celiktas (2026), Table 10, p.33547",
        "generated":  datetime.datetime.utcnow().isoformat() + "Z",
        "ahp_weights": AHP_WEIGHTS,
        "thresholds":  THRESHOLDS,
        "results":    results,
    }
    if output_path:
        import os
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(artifact, f, indent=2)
    return artifact
