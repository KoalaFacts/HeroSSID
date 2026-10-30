"""Fail-closed NuGet vulnerability report audit (implementation pending)."""

from pathlib import Path


def findings_from_report(report_text: str) -> list[str]:
    raise NotImplementedError("Implement structured NuGet vulnerability parsing")


def run_scan(report_path: Path) -> int:
    raise NotImplementedError("Implement scanner command and fail-closed audit")
