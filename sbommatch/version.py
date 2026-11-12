"""Semantic Versioning 2.0.0 parsing and comparison.

Build metadata (+...) is parsed but ignored for precedence, so
1.0.0+build compares equal to 1.0.0.
"""

import re

_SEMVER_RE = re.compile(
    r"^v?"
    r"(?P<major>0|[1-9]\d*)"
    r"(?:\.(?P<minor>0|[1-9]\d*))?"
    r"(?:\.(?P<patch>0|[1-9]\d*))?"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"$"
)


class VersionError(ValueError):
    """Raised when a string is not a valid semantic version."""


def _is_numeric(identifier):
    return identifier.isdigit()


class Version:
    """A parsed semantic version."""

    __slots__ = ("major", "minor", "patch", "prerelease", "build")

    def __init__(self, major, minor, patch, prerelease=(), build=()):
        self.major = major
        self.minor = minor
        self.patch = patch
        self.prerelease = tuple(prerelease)
        self.build = tuple(build)

    @classmethod
    def parse(cls, text):
        if not isinstance(text, str):
            raise VersionError("version must be a string, got %r" % (text,))
        match = _SEMVER_RE.match(text.strip())
        if not match:
            raise VersionError("invalid semantic version: %r" % (text,))
        major = int(match.group("major"))
        minor = int(match.group("minor") or 0)
        patch = int(match.group("patch") or 0)
        prerelease = match.group("prerelease")
        build = match.group("build")
        return cls(
            major,
            minor,
            patch,
            prerelease.split(".") if prerelease else (),
            build.split(".") if build else (),
        )

    @property
    def release_tuple(self):
        return (self.major, self.minor, self.patch)

    def _prerelease_compare(self, other):
        # A version without prerelease has higher precedence than one with.
        if not self.prerelease and not other.prerelease:
            return 0
        if not self.prerelease:
            return 1
        if not other.prerelease:
            return -1
        for left, right in zip(self.prerelease, other.prerelease):
            if left == right:
                continue
            left_num = _is_numeric(left)
            right_num = _is_numeric(right)
            if left_num and right_num:
                return -1 if int(left) < int(right) else 1
            if left_num:
                return -1
            if right_num:
                return 1
            return -1 if left < right else 1
        if len(self.prerelease) == len(other.prerelease):
            return 0
        return -1 if len(self.prerelease) < len(other.prerelease) else 1

    def compare(self, other):
        """Return -1, 0 or 1 by precedence (build metadata ignored)."""
        if self.release_tuple != other.release_tuple:
            return -1 if self.release_tuple < other.release_tuple else 1
        return self._prerelease_compare(other)

    def __eq__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self.compare(other) == 0

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __lt__(self, other):
        return self.compare(other) < 0

    def __le__(self, other):
        return self.compare(other) <= 0

    def __gt__(self, other):
        return self.compare(other) > 0

    def __ge__(self, other):
        return self.compare(other) >= 0

    def __hash__(self):
        return hash((self.release_tuple, self.prerelease))

    def __str__(self):
        text = "%d.%d.%d" % self.release_tuple
        if self.prerelease:
            text += "-" + ".".join(self.prerelease)
        if self.build:
            text += "+" + ".".join(self.build)
        return text

    def __repr__(self):
        return "Version(%r)" % str(self)
