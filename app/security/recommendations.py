"""Security score (0-100) and ordering of recommendations.

Scoring rules:

* each finding removes points according to its severity
  (critical 35, high 15, medium 6, low 2, info 0);
* penalties are capped per category so that many minor findings of the same
  kind (e.g. dozens of apps with permissions) cannot alone drive the score to
  zero;
* any critical finding caps the global score at 39 ("Critique"), any high
  finding at 74: a single serious weakness must stay visible in the grade.
"""

from __future__ import annotations

from app.models.security_report import CATEGORY_LABELS, Category, CategoryScore, Finding, Severity

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 35.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 6.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}
CATEGORY_CAPS = {
    Category.SYSTEM: 30.0,
    Category.BOOT: 50.0,
    Category.APPLICATIONS: 15.0,
    Category.PERMISSIONS: 25.0,
    Category.NETWORK: 20.0,
    Category.ENCRYPTION: 40.0,
    Category.UPDATES: 30.0,
}
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
GRADES = ((90, "excellent", "Excellent"), (75, "good", "Bon"), (60, "average", "Moyen"), (40, "weak", "Faible"))


def grade_for(score: int) -> tuple[str, str]:
    for minimum, key, label in GRADES:
        if score >= minimum:
            return key, label
    return "critical", "Critique"


def compute_score(findings: list[Finding]) -> tuple[int, list[CategoryScore]]:
    categories: list[CategoryScore] = []
    total_penalty = 0.0
    for category in Category:
        items = [f for f in findings if f.category is category]
        raw = sum(SEVERITY_WEIGHTS[f.severity] for f in items)
        cap = CATEGORY_CAPS[category]
        penalty = min(raw, cap)
        total_penalty += penalty
        categories.append(
            CategoryScore(
                category=category,
                label=CATEGORY_LABELS[category],
                penalty=penalty,
                max_penalty=cap,
                score=round(100 * (1 - penalty / cap)),
                findings=len(items),
            )
        )
    score = max(0, round(100 - total_penalty))
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities:
        score = min(score, 39)
    elif Severity.HIGH in severities:
        score = min(score, 74)
    return score, categories


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.category.value, f.id))


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {severity.value: sum(1 for f in findings if f.severity is severity) for severity in SEVERITY_ORDER}
