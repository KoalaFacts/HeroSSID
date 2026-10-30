#!/usr/bin/env python3
"""Fail-closed, structured NuGet dependency advisory gate for .NET 10 CI.

The dotnet package list command may return status 0 despite reported advisories.
NuGetAudit=all and TreatWarningsAsErrors remain separate, existing protections.
No package is downloaded, installed or upgraded by this scanner.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key in NuGet JSON report: " + key)
        result[key] = value
    return result


def _array(container: dict, key: str) -> list:
    value = container.get(key, [])
    if not isinstance(value, list):
        raise ValueError("Invalid NuGet JSON array: " + key)
    return value


def findings_from_report(report_text: str) -> list[str]:
    """Return advisory-bearing package names or fail on untrustworthy report shape.

    NuGet JSON v1 omits frameworks for projects with no reported vulnerabilities.
    Neither an empty/unknown report nor a malformed package collection is clean.
    """
    if not report_text or len(report_text) > 5_000_000:
        raise ValueError("Missing or oversized NuGet JSON report")
    data = json.loads(report_text, object_pairs_hook=_unique_object)
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
        raise ValueError("Unsupported NuGet JSON report version")
    projects = _array(data, "projects")
    if not projects:
        raise ValueError("NuGet report listed no projects; cannot assert dependency safety")
    if data.get("errors"):
        raise ValueError("NuGet JSON report contains scanner errors")

    findings: list[str] = []
    for project in projects:
        if not isinstance(project, dict) or not isinstance(project.get("path"), str) or not project["path"]:
            raise ValueError("NuGet report contains an invalid project")
        for framework in _array(project, "frameworks"):
            if not isinstance(framework, dict):
                raise ValueError("NuGet report contains an invalid target framework")
            for group in ("topLevelPackages", "transitivePackages"):
                for package in _array(framework, group):
                    if not isinstance(package, dict) or not isinstance(package.get("id"), str) or not package["id"]:
                        raise ValueError("NuGet report contains an invalid package")
                    advisories = _array(package, "vulnerabilities")
                    if not all(isinstance(advisory, dict) for advisory in advisories):
                        raise ValueError("NuGet report contains malformed advisory data")
                    if advisories:
                        package_name = package["id"].replace("\n", " ").replace("\r", " ")[:200]
                        version = str(package.get("resolvedVersion", "unknown")).replace("\n", " ")[:80]
                        findings.append(f"{project['path']}: {group}: {package_name} ({version}), "
                                        f"{len(advisories)} advisory(s)")
    return findings


def run_scan(report_path: Path) -> int:
    """Run the real scanner, retain JSON evidence, and block all advisory/error paths."""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("", encoding="utf-8")
    args = ["dotnet", "list", "package", "--vulnerable",
            "--include-transitive", "--format", "json"]
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                encoding="utf-8", errors="replace",
                                check=False, timeout=240)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"NuGet vulnerability scanner could not complete: {exc}", file=sys.stderr)
        return 2

    report_path.write_text(result.stdout, encoding="utf-8")
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        print(f"NuGet vulnerability scanner exited {result.returncode}; scan blocked.",
              file=sys.stderr)
        return 2

    try:
        findings = findings_from_report(result.stdout)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"NuGet vulnerability report could not be validated: {exc}", file=sys.stderr)
        return 2
    if findings:
        print(f"NuGet vulnerability scan blocked: {len(findings)} vulnerable package entry/entries.",
              file=sys.stderr)
        for finding in findings:
            print("  " + finding, file=sys.stderr)
        return 1

    print("NuGet JSON audit: no known direct or transitive advisories in scanned projects.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: check_nuget_vulnerabilities.py <report.json>", file=sys.stderr)
        sys.exit(2)
    sys.exit(run_scan(Path(sys.argv[1])))
