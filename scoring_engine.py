"""
QShield Scoring Engine (QARS & HNDL)
Implements Mosca's Theorem for cryptographic shelf life.
"""
import logging
from typing import Dict, Any

logger = logging.getLogger("qshield.scoring")

DATA_TIERS = {
    "transaction": {"shelf_life_years": 7},
    "authentication": {"shelf_life_years": 1},
    "static": {"shelf_life_years": 0}
}
CRQC_YEAR = 2030  
CURRENT_YEAR = 2026

def calculate_hndL_deadline(shelf_life: int, migration_time: int = 1) -> str:
    """Mosca's Theorem: X + Y > Z ? Act Now : Safe"""
    years_to_crqc = CRQC_YEAR - CURRENT_YEAR
    danger_point = shelf_life + migration_time
    
    if danger_point > years_to_crqc:
        return "ACT NOW (Harvest Now Decrypt Later risk)"
    else:
        return f"Safe until {CRQC_YEAR - danger_point}"

def calculate_qars(summary: Dict[str, Any], tier: str = "transaction") -> Dict[str, Any]:
    """Calculate Quantum-Adjusted Risk Score (0-100) using a weighted rubric."""
    score = 100.0

    if not summary:
        return {
            "qars_score": 0,
            "risk_level": "UNKNOWN",
            "hndl_status": "Unknown",
            "data_tier": tier,
            "rubric": {},
        }

    def _safe_ratio(numerator: float, denominator: float) -> float:
        return (numerator / denominator) if denominator else 0.0

    vulnerable_assets = float(summary.get("quantum_vulnerable_assets", 0))
    total_assets = float(summary.get("total_assets", 0))
    weak_endpoints = float(summary.get("endpoints_with_weak_crypto", 0))
    total_endpoints = float(summary.get("total_endpoints", 0))
    pqc_ready_endpoints = float(summary.get("endpoints_pqc_ready", 0))
    forward_secrecy_endpoints = float(summary.get("endpoints_with_forward_secrecy", 0))

    strength_counts = summary.get("assets_by_strength", {}) or {}
    weak_assets = float(strength_counts.get("weak", 0) + strength_counts.get("broken", 0))

    vuln_ratio = _safe_ratio(vulnerable_assets, total_assets)
    weak_assets_ratio = _safe_ratio(weak_assets, total_assets)
    weak_endpoints_ratio = _safe_ratio(weak_endpoints, total_endpoints)
    pqc_ready_ratio = _safe_ratio(pqc_ready_endpoints, total_endpoints)
    forward_secrecy_ratio = _safe_ratio(forward_secrecy_endpoints, total_endpoints)

    weights = {
        "vulnerable_assets": 40.0,
        "weak_assets": 10.0,
        "weak_endpoints": 20.0,
        "pqc_ready": 15.0,
        "forward_secrecy": 5.0,
        "hndl_act_now": 10.0,
    }

    penalty_vuln = weights["vulnerable_assets"] * vuln_ratio
    penalty_weak_assets = weights["weak_assets"] * weak_assets_ratio
    penalty_weak_endpoints = weights["weak_endpoints"] * weak_endpoints_ratio
    bonus_pqc = weights["pqc_ready"] * pqc_ready_ratio
    bonus_forward_secrecy = weights["forward_secrecy"] * forward_secrecy_ratio

    score = score - penalty_vuln - penalty_weak_assets - penalty_weak_endpoints + bonus_pqc + bonus_forward_secrecy

    shelf_life = DATA_TIERS.get(tier, DATA_TIERS["transaction"])["shelf_life_years"]
    hndl_status = calculate_hndL_deadline(shelf_life)

    hndl_penalty = 0.0
    if "ACT NOW" in hndl_status and vulnerable_assets > 0:
        hndl_penalty = weights["hndl_act_now"]
        score -= hndl_penalty

    score = max(0.0, min(100.0, score))

    if score >= 85:
        risk = "LOW"
    elif score >= 65:
        risk = "MEDIUM"
    elif score >= 45:
        risk = "HIGH"
    else:
        risk = "CRITICAL"

    rubric = {
        "weights": weights,
        "inputs": {
            "vulnerable_assets": int(vulnerable_assets),
            "total_assets": int(total_assets),
            "weak_assets": int(weak_assets),
            "weak_endpoints": int(weak_endpoints),
            "total_endpoints": int(total_endpoints),
            "pqc_ready_endpoints": int(pqc_ready_endpoints),
            "forward_secrecy_endpoints": int(forward_secrecy_endpoints),
        },
        "ratios": {
            "vulnerable_assets_ratio": round(vuln_ratio, 4),
            "weak_assets_ratio": round(weak_assets_ratio, 4),
            "weak_endpoints_ratio": round(weak_endpoints_ratio, 4),
            "pqc_ready_ratio": round(pqc_ready_ratio, 4),
            "forward_secrecy_ratio": round(forward_secrecy_ratio, 4),
        },
        "penalties": {
            "vulnerable_assets": round(penalty_vuln, 2),
            "weak_assets": round(penalty_weak_assets, 2),
            "weak_endpoints": round(penalty_weak_endpoints, 2),
            "hndl_act_now": round(hndl_penalty, 2),
        },
        "bonuses": {
            "pqc_ready": round(bonus_pqc, 2),
            "forward_secrecy": round(bonus_forward_secrecy, 2),
        },
    }

    return {
        "qars_score": round(score, 1),
        "risk_level": risk,
        "hndl_status": hndl_status,
        "data_tier": tier,
        "rubric": rubric,
    }
