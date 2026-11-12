"""End-to-end and unit tests for sbommatch, covering the acceptance spec."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_DIR = os.path.join(REPO_ROOT, "demo")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from sbommatch.advisories import load_advisories, parse_advisories
from sbommatch.matcher import match
from sbommatch.ranges import Range
from sbommatch.report import build_report, sort_matches
from sbommatch.sbom import detect_format, load_sbom, parse_components
from sbommatch.version import Version


def v(text):
    return Version.parse(text)


class TestVersionComparison(unittest.TestCase):
    def test_prerelease_ordering_chain(self):
        ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-rc.1",
            "1.0.0",
        ]
        versions = [v(item) for item in ordered]
        for index in range(len(versions) - 1):
            self.assertLess(versions[index], versions[index + 1])
            self.assertGreater(versions[index + 1], versions[index])

    def test_build_metadata_ignored_in_comparison(self):
        self.assertEqual(v("1.0.0+build").compare(v("1.0.0")), 0)
        self.assertEqual(v("1.0.0+build"), v("1.0.0"))
        self.assertEqual(v("0.9.1+build.7"), v("0.9.1"))

    def test_release_tuple_and_prerelease_parsed(self):
        version = v("18.2.0-beta.3")
        self.assertEqual(version.release_tuple, (18, 2, 0))
        self.assertEqual(version.prerelease, ("beta", "3"))


class TestRanges(unittest.TestCase):
    def assertMatches(self, range_text, version_text):
        self.assertTrue(
            Range.parse(range_text).matches(v(version_text)),
            "%r should match %s" % (range_text, version_text),
        )

    def assertNotMatches(self, range_text, version_text):
        self.assertFalse(
            Range.parse(range_text).matches(v(version_text)),
            "%r should not match %s" % (range_text, version_text),
        )

    def test_caret(self):
        self.assertMatches("^1.0.0", "1.3.0")
        self.assertMatches("^1.2.3", "1.9.9")
        self.assertNotMatches("^1.2.3", "2.0.0")
        self.assertNotMatches("^1.2.3", "1.2.2")

    def test_tilde(self):
        self.assertMatches("~1.2.3", "1.2.9")
        self.assertNotMatches("~1.2.3", "1.3.0")

    def test_comparison_operators(self):
        self.assertMatches(">=1.0.0", "1.0.0")
        self.assertMatches(">1.0.0", "1.0.1")
        self.assertNotMatches(">1.0.0", "1.0.0")
        self.assertMatches("<=1.0.0", "1.0.0")
        self.assertMatches("<1.0.0", "0.9.9")
        self.assertNotMatches("<1.0.0", "1.0.0")
        self.assertMatches("=1.0.0", "1.0.0")
        self.assertNotMatches("=1.0.0", "1.0.1")

    def test_exact_version(self):
        self.assertMatches("1.2.3", "1.2.3")
        self.assertNotMatches("1.2.3", "1.2.4")

    def test_star_matches_anything(self):
        self.assertMatches("*", "7.5.4")
        self.assertMatches("*", "0.0.1")

    def test_multi_range_alternatives(self):
        range_text = ">=6.5.0 <6.5.3 || >=6.10.0 <6.10.3"
        self.assertMatches(range_text, "6.5.0")
        self.assertMatches(range_text, "6.5.2")
        self.assertMatches(range_text, "6.10.1")
        self.assertNotMatches(range_text, "6.5.3")
        self.assertNotMatches(range_text, "6.10.3")
        self.assertNotMatches(range_text, "6.7.0")
        self.assertNotMatches(range_text, "7.0.0")

    def test_strict_upper_bound(self):
        self.assertNotMatches(">=4.0.0 <4.17.21", "4.17.21")
        self.assertMatches(">=4.0.0 <4.17.21", "4.17.20")

    def test_build_metadata_ignored_in_ranges(self):
        self.assertMatches(">=0.9.0 <0.10.0", "0.9.1+build.7")

    def test_prerelease_requires_explicit_tuple(self):
        self.assertNotMatches("^1.2.3", "1.2.3-beta.1")
        self.assertMatches("^1.2.3-beta.1", "1.2.3-beta.1")

    def test_prerelease_range_matches_plain_version(self):
        self.assertMatches(">=1.2.3-alpha <2.0.0", "1.5.0")
        self.assertMatches(">=1.2.3-alpha <2.0.0", "1.2.3-alpha")

    def test_prerelease_upper_bound_excludes_later_release(self):
        self.assertNotMatches(">=18.0.0-beta.1 <18.0.0", "18.2.0-beta.3")
        self.assertMatches(">=18.0.0-beta.1 <18.0.0", "18.0.0-beta.2")


class TestSBOMParsing(unittest.TestCase):
    def test_detect_cyclonedx(self):
        self.assertEqual(detect_format({"components": []}), "cyclonedx")

    def test_detect_spdx(self):
        self.assertEqual(detect_format({"packages": []}), "spdx")

    def test_demo_sbom_loads_six_components(self):
        components = load_sbom(os.path.join(DEMO_DIR, "sbom.json"))
        self.assertEqual(len(components), 6)
        names = {component.name for component in components}
        self.assertEqual(
            names, {"left-pad", "lodash", "express", "react", "toolz", "semver"}
        )

    def test_spdx_field_mapping(self):
        document = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "semver", "versionInfo": "7.5.4", "SPDXID": "SPDXRef-1"}
            ],
        }
        components = parse_components(document)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0].name, "semver")
        self.assertEqual(components[0].version, "7.5.4")


class TestAdvisoriesParsing(unittest.TestCase):
    def test_affected_string_or_list(self):
        advisories = parse_advisories(
            {
                "advisories": [
                    {"id": "A", "package": "x", "severity": "low",
                     "affected": "^1.0.0", "fixed": "1.2.3"},
                    {"id": "B", "package": "y", "severity": "high",
                     "affected": [">=1.0.0 <2.0.0", "=3.0.0"], "fixed": "3.0.1"},
                ]
            }
        )
        self.assertEqual(advisories[0].affected, ["^1.0.0"])
        self.assertEqual(advisories[1].affected, [">=1.0.0 <2.0.0", "=3.0.0"])

    def test_unknown_severity_falls_back(self):
        advisories = parse_advisories(
            {"advisories": [{"id": "A", "package": "x",
                             "severity": "weird", "affected": "*"}]}
        )
        self.assertEqual(advisories[0].severity, "unknown")


class TestDemoEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.components = load_sbom(os.path.join(DEMO_DIR, "sbom.json"))
        cls.advisories = load_advisories(os.path.join(DEMO_DIR, "advisories.json"))
        cls.matches = sort_matches(match(cls.components, cls.advisories))

    def test_exactly_four_hits_in_expected_order(self):
        self.assertEqual(
            [m.advisory_id for m in self.matches],
            ["CVE-2024-1111", "CVE-2024-3333", "CVE-2020-7777", "CVE-2024-2222"],
        )

    def test_hit_details(self):
        expected = [
            ("CVE-2024-1111", "semver", "7.5.4", "*", "critical", "7.5.5"),
            ("CVE-2024-3333", "express", "4.18.2", ">=4.0.0 <5.0.0", "high",
             "4.19.0"),
            ("CVE-2020-7777", "left-pad", "1.3.0", "^1.0.0", "medium", "1.3.1"),
            ("CVE-2024-2222", "toolz", "0.9.1+build.7", ">=0.9.0 <0.10.0",
             "medium", "0.9.2"),
        ]
        self.assertEqual(len(self.matches), len(expected))
        for match_obj, (advisory_id, package, version, matched_range,
                        severity, fixed) in zip(self.matches, expected):
            self.assertEqual(match_obj.advisory_id, advisory_id)
            self.assertEqual(match_obj.package, package)
            self.assertEqual(match_obj.version, version)
            self.assertEqual(match_obj.matched_range, matched_range)
            self.assertEqual(match_obj.severity, severity)
            self.assertEqual(match_obj.fixed, fixed)

    def test_non_hits_and_reasons(self):
        hit_ids = {m.advisory_id for m in self.matches}
        # lodash 4.17.21 is exactly the strict upper bound <4.17.21.
        self.assertNotIn("CVE-2021-23337", hit_ids)
        self.assertFalse(
            Range.parse(">=4.0.0 <4.17.21").matches(v("4.17.21"))
        )
        # qs is not present in the SBOM at all.
        self.assertNotIn("CVE-2022-24999", hit_ids)
        self.assertNotIn("qs", {c.name for c in self.components})
        # react 18.2.0-beta.3: 18.2.0 is beyond the <18.0.0 upper bound.
        self.assertNotIn("CVE-2023-8888", hit_ids)
        self.assertFalse(
            Range.parse(">=18.0.0-beta.1 <18.0.0").matches(v("18.2.0-beta.3"))
        )

    def test_report_fields_complete(self):
        report = build_report(self.matches)
        required = {"advisory_id", "package", "version", "matched_range",
                    "severity", "fixed"}
        self.assertEqual(len(report["matches"]), 4)
        for entry in report["matches"]:
            for field in required:
                self.assertIn(field, entry)
                self.assertIsNotNone(entry[field])


class TestQsMultiRange(unittest.TestCase):
    def test_qs_6_10_1_hits_cve_2022_24999(self):
        components = parse_components(
            {"components": [{"name": "qs", "version": "6.10.1",
                             "purl": "pkg:npm/qs@6.10.1", "type": "library"}]}
        )
        advisories = load_advisories(os.path.join(DEMO_DIR, "advisories.json"))
        matches = match(components, advisories)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].advisory_id, "CVE-2022-24999")
        self.assertEqual(matches[0].matched_range,
                         ">=6.5.0 <6.5.3 || >=6.10.0 <6.10.3")
        self.assertEqual(matches[0].severity, "critical")


class TestSpdxEndToEnd(unittest.TestCase):
    def test_spdx_sbom_hits_cve_2024_1111(self):
        document = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {"name": "semver", "versionInfo": "7.5.4",
                 "SPDXID": "SPDXRef-Package-semver"}
            ],
        }
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump(document, handle)
            path = handle.name
        try:
            components = load_sbom(path)
        finally:
            os.unlink(path)
        advisories = load_advisories(os.path.join(DEMO_DIR, "advisories.json"))
        matches = match(components, advisories)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].advisory_id, "CVE-2024-1111")
        self.assertEqual(matches[0].version, "7.5.4")


class TestCli(unittest.TestCase):
    def test_demo_command(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.json")
            result = subprocess.run(
                [
                    sys.executable, "-m", "sbommatch.cli",
                    "--sbom", os.path.join(DEMO_DIR, "sbom.json"),
                    "--advisories", os.path.join(DEMO_DIR, "advisories.json"),
                    "--out", out_path,
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=90,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("components=6", result.stdout)
            self.assertIn("matches=4", result.stdout)
            self.assertIn("critical=1", result.stdout)
            self.assertIn("high=1", result.stdout)
            self.assertIn("medium=2", result.stdout)
            with open(out_path, "r", encoding="utf-8") as handle:
                report = json.load(handle)
            self.assertEqual(
                [entry["advisory_id"] for entry in report["matches"]],
                ["CVE-2024-1111", "CVE-2024-3333", "CVE-2020-7777",
                 "CVE-2024-2222"],
            )


if __name__ == "__main__":
    unittest.main()
