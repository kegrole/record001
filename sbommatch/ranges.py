"""Version range parsing and matching.

Supported syntax (npm-style, whitespace separated comparators, "||" for
alternatives):

    *                     any version
    1.2.3  /  =1.2.3      exact version
    >1.2.3 >=1.2.3 <1.2.3 <=1.2.3
    ^1.2.3                compatible-with (>=1.2.3 <2.0.0)
    ~1.2.3                approximately (>=1.2.3 <1.3.0)
    >=6.5.0 <6.5.3 || >=6.10.0 <6.10.3

Prerelease rule: a version carrying prerelease identifiers only matches
when some comparator in the satisfied alternative explicitly mentions a
prerelease under the same [major, minor, patch] tuple.
"""

from .version import Version

_OPERATORS = (">=", "<=", ">", "<", "=")


class RangeError(ValueError):
    """Raised when a range expression cannot be parsed."""


class Comparator:
    """A single primitive comparison such as >=1.2.3."""

    __slots__ = ("operator", "version")

    def __init__(self, operator, version):
        self.operator = operator
        self.version = version

    def test(self, version):
        outcome = version.compare(self.version)
        if self.operator == ">":
            return outcome > 0
        if self.operator == ">=":
            return outcome >= 0
        if self.operator == "<":
            return outcome < 0
        if self.operator == "<=":
            return outcome <= 0
        if self.operator == "=":
            return outcome == 0
        raise RangeError("unknown operator: %r" % (self.operator,))

    def __str__(self):
        return "%s%s" % (self.operator, self.version)

    def __repr__(self):
        return "Comparator(%r)" % str(self)


def _expand_caret(version):
    lower = Comparator(">=", version)
    if version.major > 0:
        upper = Version(version.major + 1, 0, 0)
    elif version.minor > 0:
        upper = Version(0, version.minor + 1, 0)
    else:
        upper = Version(0, 0, version.patch + 1)
    return [lower, Comparator("<", upper)]


def _expand_tilde(version):
    lower = Comparator(">=", version)
    upper = Version(version.major, version.minor + 1, 0)
    return [lower, Comparator("<", upper)]


def _parse_token(token):
    if token.startswith("^"):
        return _expand_caret(Version.parse(token[1:]))
    if token.startswith("~"):
        return _expand_tilde(Version.parse(token[1:]))
    for operator in _OPERATORS:
        if token.startswith(operator):
            return [Comparator(operator, Version.parse(token[len(operator):]))]
    return [Comparator("=", Version.parse(token))]


class Alternative:
    """One whitespace-separated comparator set (all must hold)."""

    __slots__ = ("comparators", "source")

    def __init__(self, comparators, source):
        self.comparators = comparators
        self.source = source

    def matches(self, version):
        if not all(comparator.test(version) for comparator in self.comparators):
            return False
        if not version.prerelease:
            return True
        # Prerelease versions only match when a comparator in this set
        # names a prerelease under the same release tuple.
        for comparator in self.comparators:
            candidate = comparator.version
            if candidate.prerelease and candidate.release_tuple == version.release_tuple:
                return True
        return False


class Range:
    """A full range expression: alternatives joined by "||"."""

    __slots__ = ("alternatives", "source")

    def __init__(self, alternatives, source):
        self.alternatives = alternatives
        self.source = source

    @classmethod
    def parse(cls, text):
        if not isinstance(text, str):
            raise RangeError("range must be a string, got %r" % (text,))
        source = text.strip()
        if source in ("", "*"):
            return cls([Alternative([], "*")], source or "*")
        alternatives = []
        for part in source.split("||"):
            part = part.strip()
            if not part:
                raise RangeError("empty alternative in range: %r" % (text,))
            if part == "*":
                alternatives.append(Alternative([], "*"))
                continue
            comparators = []
            for token in part.split():
                comparators.extend(_parse_token(token))
            alternatives.append(Alternative(comparators, part))
        return cls(alternatives, source)

    def matches(self, version):
        return any(alternative.matches(version) for alternative in self.alternatives)

    def __str__(self):
        return self.source

    def __repr__(self):
        return "Range(%r)" % self.source
