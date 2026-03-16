from __future__ import annotations

from typing import Iterable


IMPACT_WEIGHTS = {
    "critical": 15,
    "serious": 9,
    "moderate": 5,
    "minor": 2,
}


def compliance_score(impacts: Iterable[str]) -> int:
    penalty = sum(IMPACT_WEIGHTS.get(impact, 3) for impact in impacts)
    return max(0, 100 - penalty)


def pour_breakdown(score: int) -> dict:
    return {
        "perceivable": max(0, score - 2),
        "operable": max(0, score - 5),
        "understandable": max(0, score - 3),
        "robust": max(0, score - 4),
    }
