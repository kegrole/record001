"""Report building: severity ordering and JSON serialization."""

import json

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


def severity_rank(severity):
    return _SEVERITY_RANK.get(severity, _SEVERITY_RANK["unknown"])


def sort_matches(matches):
    """Sort by severity (critical first), then advisory id ascending."""
    return sorted(
        matches,
        key=lambda match: (severity_rank(match.severity), match.advisory_id),
    )


def severity_distribution(matches):
    distribution = {}
    for match in matches:
        distribution[match.severity] = distribution.get(match.severity, 0) + 1
    return distribution


def build_report(matches):
    return {"matches": [match.to_dict() for match in sort_matches(matches)]}


def write_report(matches, path):
    report = build_report(matches)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return report
