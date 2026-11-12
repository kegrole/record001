"""Match SBOM components against the advisory database."""

from .ranges import Range
from .version import Version, VersionError


class Match:
    """One advisory hitting one installed component."""

    __slots__ = ("advisory_id", "package", "version", "matched_range",
                 "severity", "fixed")

    def __init__(self, advisory_id, package, version, matched_range,
                 severity, fixed):
        self.advisory_id = advisory_id
        self.package = package
        self.version = version
        self.matched_range = matched_range
        self.severity = severity
        self.fixed = fixed

    def to_dict(self):
        return {
            "advisory_id": self.advisory_id,
            "package": self.package,
            "version": self.version,
            "matched_range": self.matched_range,
            "severity": self.severity,
            "fixed": self.fixed,
        }

    def __repr__(self):
        return "Match(%r hits %r@%r)" % (self.advisory_id, self.package,
                                         self.version)


def match(components, advisories):
    """Return the list of Match objects for every advisory/component hit."""
    by_name = {}
    for component in components:
        by_name.setdefault(component.name, []).append(component)

    matches = []
    for advisory in advisories:
        targets = by_name.get(advisory.package)
        if not targets:
            continue
        for component in targets:
            try:
                installed = Version.parse(component.version)
            except VersionError:
                continue
            for affected in advisory.affected:
                if Range.parse(affected).matches(installed):
                    matches.append(
                        Match(
                            advisory_id=advisory.id,
                            package=component.name,
                            version=component.version,
                            matched_range=affected,
                            severity=advisory.severity,
                            fixed=advisory.fixed,
                        )
                    )
                    break
    return matches
