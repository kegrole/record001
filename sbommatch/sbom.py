"""SBOM parsing: CycloneDX 1.5 style and SPDX 2.3 style JSON.

CycloneDX: top-level "components" array with name/version/purl/type.
SPDX:      top-level "packages" array with name/versionInfo/SPDXID.
"""

import json


class SBOMError(ValueError):
    """Raised when an SBOM document cannot be parsed."""


class Component:
    """A single component/package entry from an SBOM."""

    __slots__ = ("name", "version")

    def __init__(self, name, version):
        self.name = name
        self.version = version

    def __repr__(self):
        return "Component(name=%r, version=%r)" % (self.name, self.version)


def detect_format(document):
    if isinstance(document, dict):
        if "components" in document:
            return "cyclonedx"
        if "packages" in document:
            return "spdx"
    raise SBOMError("unrecognized SBOM format: expected 'components' or 'packages'")


def parse_components(document):
    fmt = detect_format(document)
    entries = document[fmt == "cyclonedx" and "components" or "packages"]
    if not isinstance(entries, list):
        raise SBOMError("SBOM entries must be an array")
    components = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if fmt == "cyclonedx":
            version = entry.get("version")
        else:
            version = entry.get("versionInfo")
        if not name or not version:
            continue
        components.append(Component(name, version))
    return components


def load_sbom(path):
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    return parse_components(document)
