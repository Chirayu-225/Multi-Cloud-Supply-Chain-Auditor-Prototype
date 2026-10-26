"""
Turns individual findings into one 0-100 risk score.

Plain addition overstated risk (three medium signals could exceed 100).
Here the worst finding sets the score and each additional finding adds
a quarter of its weight, capped at 100.
"""

from .scanners.base import Finding

HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 25


def aggregate(findings: list[Finding]) -> int:
    weights = sorted((f.weight for f in findings if f.risky), reverse=True)
    if not weights:
        return 0
    score = weights[0] + sum(w // 4 for w in weights[1:])
    return min(100, score)


def level(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"
