"""Local JSON advisory database parsing (no network access)."""
import json


class AdvisoryError(ValueError):
    """Raised when the advisory database cannot be parsed."""


SEVERITIES = ("critical", "high", "medium", "low", "unknown")


class Advisory:
    """A single known-vulnerability record.

    Database shape:
        {"advisories": [{"id": ..., "package": ..., "severity": ...,
                         "affected": "<range>" or ["<range>", ...],
                         "fixed": ...}]}
    """

    __slots__ = ("id", "package", "severity", "affected", "fixed")

    def __init__(self, advisory_id, package, severity, affected, fixed):
        self.id = advisory_id
        self.package = package
        self.severity = severity if severity in SEVERITIES else "unknown"
        self.affected = list(affected)
        self.fixed = fixed

    def __repr__(self):
        return "Advisory(id=%r, package=%r)" % (self.id, self.package)


def parse_advisories(document):
    if isinstance(document, dict):
        records = document.get("advisories")
    elif isinstance(document, list):
        records = document
    else:
        records = None
    if not isinstance(records, list):
        raise AdvisoryError("advisory database must contain an 'advisories' array")
    advisories = []
    for record in records:
        if not isinstance(record, dict):
            raise AdvisoryError("advisory entries must be objects")
        affected = record.get("affected", [])
        if isinstance(affected, str):
            affected = [affected]
        if not isinstance(affected, list):
            raise AdvisoryError("'affected' must be a string or an array of strings")
        advisories.append(
            Advisory(
                advisory_id=record.get("id", ""),
                package=record.get("package", ""),
                severity=str(record.get("severity", "unknown")).lower(),
                affected=affected,
                fixed=record.get("fixed"),
            )
        )
    return advisories


def load_advisories(path):
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    return parse_advisories(document)
