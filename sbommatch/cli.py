"""Command line entry point.

    python -m sbommatch.cli --sbom SBOM --advisories DB --out REPORT
"""

import argparse
import os
import sys

from .advisories import load_advisories
from .matcher import match
from .report import severity_distribution, sort_matches, write_report
from .sbom import load_sbom


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sbommatch",
        description="Match SBOM components against a local advisory database.",
    )
    parser.add_argument("--sbom", required=True, help="path to the SBOM JSON file")
    parser.add_argument(
        "--advisories", required=True, help="path to the advisory database JSON"
    )
    parser.add_argument("--out", required=True, help="path for the JSON report")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    components = load_sbom(args.sbom)
    advisories = load_advisories(args.advisories)
    matches = sort_matches(match(components, advisories))

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    write_report(matches, args.out)

    distribution = severity_distribution(matches)
    summary = "components=%d matches=%d severity: %s" % (
        len(components),
        len(matches),
        " ".join(
            "%s=%d" % (name, distribution.get(name, 0))
            for name in ("critical", "high", "medium", "low", "unknown")
        ),
    )
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
