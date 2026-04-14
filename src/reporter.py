"""Report output: rich CLI table + JUnit XML."""
from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET

from .models import TestReport, Verdict

logger = logging.getLogger("router-auditor.reporter")

_VERDICT_STYLES: dict[Verdict, str] = {
    Verdict.PASS: "green",
    Verdict.FAIL: "bold red",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.SKIP: "dim",
    Verdict.INCONCLUSIVE: "dim yellow",
}

_PLAIN_FLAGS: dict[str, str] = {
    "pass": "[PASS]",
    "fail": "[FAIL]",
    "suspicious": "[SUSP]",
    "skip": "[SKIP]",
    "inconclusive": "[INC ]",
}


def print_cli_report(report: TestReport) -> None:
    """Render to stdout. Falls back to plain print on any rich failure
    (not just ImportError -- terminal quirks, console init errors, etc)."""
    try:
        _print_rich(report)
    except ImportError:
        _print_plain(report)
    except Exception as e:
        logger.warning("rich render failed (%s), falling back to plain", e)
        _print_plain(report)


def _print_rich(report: TestReport) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    verdict_color = (
        "green" if report.overall_verdict == Verdict.PASS else "red"
    )
    header = (
        f"[bold {verdict_color}]{report.overall_verdict.value.upper()}[/] "
        f"-> {report.tier_assignment}\n"
        f"{report.passed}P {report.failed}F {report.suspicious}S "
        f"{report.skipped}K | "
        f"{report.total_latency_ms / 1000:.1f}s | "
        f"${report.estimated_cost_usd:.2f}"
    )
    console.print(Panel(header, title=report.router_endpoint))

    table = Table(show_header=True)
    for col in ("ID", "Name", "Pri", "Verdict", "Time", "Detail"):
        table.add_column(col)

    for r in report.results:
        style = _VERDICT_STYLES.get(r.verdict, "")
        detail = r.skipped_reason or r.evidence.get("reason", "")
        table.add_row(
            r.detector_id,
            r.detector_name,
            r.priority.value,
            f"[{style}]{r.verdict.value.upper()}[/{style}]",
            f"{r.latency_ms:.0f}ms",
            str(detail)[:40],
        )
    console.print(table)

    if report.evidence_notes:
        console.print("\n[yellow]Contradictions:[/]")
        for note in report.evidence_notes:
            console.print(f"  - {note}")


def _print_plain(report: TestReport) -> None:
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"Router: {report.router_endpoint}")
    print(
        f"Verdict: {report.overall_verdict.value.upper()} -> "
        f"{report.tier_assignment}"
    )
    print(
        f"Results: {report.passed}P {report.failed}F "
        f"{report.suspicious}S {report.skipped}K"
    )
    print(sep)

    for r in report.results:
        flag = _PLAIN_FLAGS.get(r.verdict.value, "[?]")
        print(
            f"  {flag} [{r.priority.value}] {r.detector_id} "
            f"{r.detector_name} ({r.latency_ms:.0f}ms)"
        )
        if r.verdict == Verdict.FAIL:
            print(f"     -> {r.evidence.get('reason', '')}")
        elif r.verdict == Verdict.SUSPICIOUS:
            print(f"     -> {r.evidence.get('majority', '')}")

    if report.evidence_notes:
        print("\nContradictions:")
        for note in report.evidence_notes:
            print(f"  - {note}")

    print(
        f"\nTotal: {report.total_latency_ms / 1000:.1f}s | "
        f"~${report.estimated_cost_usd:.2f}"
    )


def write_junit_xml(report: TestReport, path: str) -> None:
    suite = ET.Element("testsuite", {
        "name": "router-auditor",
        "tests": str(report.total_detectors),
        "failures": str(report.failed),
        "skipped": str(report.skipped),
        "time": f"{report.total_latency_ms / 1000:.2f}",
    })

    for r in report.results:
        tc = ET.SubElement(suite, "testcase", {
            "classname": f"router_auditor.{r.priority.value}",
            "name": f"{r.detector_id}_{r.detector_name}",
            "time": f"{r.latency_ms / 1000:.2f}",
        })
        if r.verdict == Verdict.FAIL:
            fail = ET.SubElement(tc, "failure", {
                "message": r.evidence.get("reason", "unknown"),
                "type": r.priority.value,
            })
            fail.text = json.dumps(r.evidence, indent=2)
        elif r.verdict == Verdict.SKIP:
            ET.SubElement(tc, "skipped", {
                "message": r.skipped_reason or "",
            })
        elif r.verdict == Verdict.SUSPICIOUS:
            fail = ET.SubElement(tc, "failure", {
                "message": f"SUSPICIOUS: {r.evidence.get('majority', '')}",
                "type": "suspicious",
            })
            fail.text = json.dumps(r.evidence, indent=2)

    tree = ET.ElementTree(suite)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="unicode", xml_declaration=True)
