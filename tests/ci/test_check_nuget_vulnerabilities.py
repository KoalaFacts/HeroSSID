"""Negative and positive NuGet audit gate contracts; no .NET or network required."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from check_nuget_vulnerabilities import findings_from_report, run_scan


def report(*projects):
    return json.dumps({"version": 1, "projects": list(projects)})


class NuGetReportTests(unittest.TestCase):
    def test_clean_report_with_omitted_frameworks_is_accepted(self):
        self.assertEqual([], findings_from_report(report({"path": "src/Clean.csproj"})))

    def test_direct_vulnerability_blocks_even_when_scanner_exits_zero(self):
        payload = report({
            "path": "src/Issuer.csproj",
            "frameworks": [{
                "framework": "net10.0",
                "topLevelPackages": [{
                    "id": "Dangerous.Direct",
                    "resolvedVersion": "1.2.3",
                    "vulnerabilities": [{
                        "severity": "High",
                        "advisoryurl": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
                    }]
                }]
            }]
        })
        findings = findings_from_report(payload)
        self.assertEqual(1, len(findings))
        self.assertIn("Dangerous.Direct", findings[0])

    def test_transitive_vulnerability_blocks_even_when_other_projects_clean(self):
        payload = report(
            {"path": "src/Clean.csproj"},
            {
                "path": "src/Verifier.csproj",
                "frameworks": [{
                    "framework": "net10.0",
                    "transitivePackages": [{
                        "id": "Dangerous.Transitive",
                        "resolvedVersion": "2.3.4",
                        "vulnerabilities": [{"severity": "Moderate"}]
                    }]
                }]
            }
        )
        findings = findings_from_report(payload)
        self.assertEqual(1, len(findings))
        self.assertIn("Dangerous.Transitive", findings[0])

    def test_unsupported_or_empty_document_fails_closed(self):
        bad = [
            "",
            "{}",
            '{"version": 999, "projects": [{"path": "x"}]}',
            '{"version": 1, "projects": []}',
            '{"version": 1, "projects": "not an array"}',
            '{"version": 1, "projects": [{"path": "x", "frameworks": {}}]}',
            '{"version": 1, "projects": [{"path": "x", "frameworks": [{"topLevelPackages": [{"id": "p", "vulnerabilities": "unknown"}]}]}]}'
        ]
        for candidate in bad:
            with self.subTest(candidate=candidate):
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    findings_from_report(candidate)


class NuGetCommandTests(unittest.TestCase):
    def test_scan_creates_json_artifact_and_passes_on_clean_report(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            completed = subprocess.CompletedProcess(args=[], returncode=0,
                                                    stdout=report({"path": "src/Clean.csproj"}),
                                                    stderr="")
            with patch("check_nuget_vulnerabilities.subprocess.run", return_value=completed) as run:
                self.assertEqual(0, run_scan(destination))
            self.assertEqual(completed.stdout, destination.read_text(encoding="utf-8"))
            argv = run.call_args.args[0]
            self.assertIn("--format", argv)
            self.assertIn("json", argv)
            self.assertIn("--include-transitive", argv)

    def test_scan_fails_on_vulnerability_with_successful_dotnet_exit(self):
        payload = report({
            "path": "src/A.csproj",
            "frameworks": [{
                "topLevelPackages": [{
                    "id": "Vulnerable",
                    "vulnerabilities": [{"severity": "Low"}]
                }]
            }]
        })
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.CompletedProcess(args=[], returncode=0,
                                                    stdout=payload, stderr="")
            with patch("check_nuget_vulnerabilities.subprocess.run", return_value=completed):
                self.assertNotEqual(0, run_scan(Path(directory) / "report.json"))

    def test_scanner_failure_is_not_masked_by_parseable_clean_report(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.CompletedProcess(args=[], returncode=23,
                                                    stdout=report({"path": "src/Clean.csproj"}),
                                                    stderr="network failure")
            with patch("check_nuget_vulnerabilities.subprocess.run", return_value=completed):
                self.assertNotEqual(0, run_scan(Path(directory) / "report.json"))

    def test_garbled_scanner_output_is_not_mistaken_for_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.CompletedProcess(args=[], returncode=0,
                                                    stdout="restore failed", stderr="")
            with patch("check_nuget_vulnerabilities.subprocess.run", return_value=completed):
                self.assertNotEqual(0, run_scan(Path(directory) / "report.json"))


if __name__ == "__main__":
    unittest.main()
