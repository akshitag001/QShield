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
    """Calculate Quantum-Adjusted Risk Score (0-100)"""
    score = 100.0
    
    if not summary:
        return {"qars_score": 0, "risk_level": "UNKNOWN", "hndl_status": "Unknown", "data_tier": tier}
        
    vulnerable = summary.get("quantum_vulnerable_assets", 0)
    total = summary.get("total_assets", 1)
    weak_crypto = summary.get("endpoints_with_weak_crypto", 0)
    
    if weak_crypto > 0:
        score -= 30
        
    if total > 0:
        vuln_ratio = vulnerable / total
        score -= (40 * vuln_ratio)
        
    shelf_life = DATA_TIERS.get(tier, DATA_TIERS["transaction"])["shelf_life_years"]
    hndl_status = calculate_hndL_deadline(shelf_life)
    
    if "ACT NOW" in hndl_status and vulnerable > 0:
        score -= 20
        
    score = max(0.0, min(100.0, score))
    
    if score >= 80: risk = "LOW"
    elif score >= 50: risk = "MEDIUM"
    else: risk = "HIGH (CRITICAL)"
    
    return {
        "qars_score": round(score, 1),
        "risk_level": risk,
        "hndl_status": hndl_status,
        "data_tier": tier
    }
