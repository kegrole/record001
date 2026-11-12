# sbommatch

A dependency vulnerability matcher: SBOM in, known-vulnerability report out.
Pure Python standard library, no third-party dependencies, no network access.

## Usage

```
python -m sbommatch.cli --sbom <SBOM path> --advisories <advisory DB path> --out <report path>
```

Demo:

```
python -m sbommatch.cli --sbom demo/sbom.json --advisories demo/advisories.json --out out/report.json
```

Prints a one-line summary to stdout (component count, match count, severity
distribution) and writes the JSON report to the --out path.

Run the tests:

```
python -m unittest test_sbommatch -v        # from the repo root
# or
python -m unittest discover -s tests -v
```

## Supported SBOM formats (auto-detected)

### CycloneDX 1.5 style

Top-level "components" array. Field mapping:

| SBOM field  | Used as           |
|-------------|-------------------|
| name        | package name      |
| version     | installed version |
| purl        | ignored (metadata) |
| type        | ignored (metadata) |

### SPDX 2.3 style

Top-level "packages" array. Field mapping:

| SBOM field  | Used as           |
|-------------|-------------------|
| name        | package name      |
| versionInfo | installed version |
| SPDXID      | ignored (metadata) |

## Advisory database format

Local JSON file, never fetched over the network:

```
{"advisories": [{"id": "CVE-...", "package": "name", "severity": "high",
                 "affected": ">=1.0.0 <2.0.0 || >=3.0.0 <3.0.1",
                 "fixed": "2.0.0"}]}
```

"affected" may be a single range string or an array of range strings.
Unknown severities are treated as "unknown".

## Version range syntax

| Syntax                | Meaning                                   |
|-----------------------|-------------------------------------------|
| "*"                   | any version                               |
| "1.2.3" or "=1.2.3"   | exactly 1.2.3                             |
| ">1.2.3" ">=1.2.3"    | strictly greater / greater-or-equal       |
| "<1.2.3" "<=1.2.3"    | strictly less / less-or-equal             |
| "^1.2.3"              | >=1.2.3 <2.0.0 (compatible release)       |
| "~1.2.3"              | >=1.2.3 <1.3.0 (approximately equivalent) |
| "a b c"               | all comparators must hold (AND)           |
| "a || b"              | any alternative may hold (OR)             |

## SemVer and prerelease rules

Versions follow SemVer 2.0.0: "major.minor.patch" plus optional
"-prerelease" identifiers and "+build" metadata. Build metadata is ignored
for precedence: 1.0.0+build compares equal to 1.0.0.

Prerelease precedence: 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta
< 1.0.0-beta.2 < 1.0.0-rc.1 < 1.0.0.

A version carrying prerelease identifiers only matches a range alternative
when some comparator in that alternative explicitly names a prerelease under
the same [major, minor, patch] tuple:

- "^1.2.3" does not match 1.2.3-beta.1
- "^1.2.3-beta.1" matches 1.2.3-beta.1
- ">=1.2.3-alpha <2.0.0" matches 1.5.0 (plain versions are unaffected)

## Report format

```
{"matches": [{"advisory_id": "...", "package": "...", "version": "...",
              "matched_range": "...", "severity": "...", "fixed": "..."}]}
```

Matches are sorted by severity (critical > high > medium > low > unknown),
ties broken by advisory id in ascending lexicographic order.
