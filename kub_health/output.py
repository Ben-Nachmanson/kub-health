"""Rich terminal output for the investigation report."""

from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from kub_health.models import (
    CorrelationGroup,
    Finding,
    InvestigationReport,
    Severity,
)


def render_report(report: InvestigationReport, console: Console) -> None:
    """Render the full investigation report to the terminal."""
    console.print()

    # --- Header ---
    _render_header(report, console)

    # --- Scorecard ---
    _render_scorecard(report, console)

    # --- Root Cause Groups ---
    if report.correlation_groups:
        console.print()
        console.rule("[bold]Root Cause Analysis[/bold]")
        for i, group in enumerate(report.correlation_groups, 1):
            _render_correlation_group(group, i, console)

    # --- Uncorrelated Findings ---
    if report.uncorrelated_findings:
        console.print()
        console.rule("[bold]Additional Findings[/bold]")
        _render_findings_table(report.uncorrelated_findings, console)

    # --- Detailed Breakdown by Category ---
    console.print()
    console.rule("[bold]Findings by Category[/bold]")
    _render_category_breakdown(report, console)

    # --- AI Analysis ---
    if report.ai_analysis:
        console.print()
        console.rule("[bold]AI Investigation Analysis[/bold]")
        console.print()
        console.print(Markdown(report.ai_analysis))
        console.print()

    # --- Footer ---
    _render_footer(report, console)


def _render_header(report: InvestigationReport, console: Console) -> None:
    """Render the report header with cluster info."""
    health_color = {
        Severity.CRITICAL: "red",
        Severity.WARNING: "yellow",
        Severity.INFO: "blue",
        Severity.OK: "green",
    }[report.overall_health]

    health_label = {
        Severity.CRITICAL: "CRITICAL",
        Severity.WARNING: "DEGRADED",
        Severity.INFO: "INFORMATIONAL",
        Severity.OK: "HEALTHY",
    }[report.overall_health]

    header = Text()
    header.append("Cluster: ", style="bold")
    header.append(report.cluster_name, style="bold cyan")
    header.append("  |  Context: ", style="bold")
    header.append(report.context, style="cyan")
    header.append("  |  Status: ", style="bold")
    header.append(health_label, style=f"bold {health_color}")

    console.print(
        Panel(
            header,
            title="[bold]Kubernetes Cluster Investigation[/bold]",
            subtitle=report.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            border_style=health_color,
        )
    )


def _render_scorecard(report: InvestigationReport, console: Console) -> None:
    """Render a summary scorecard."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("metric", style="bold")
    table.add_column("value", justify="right")

    table.add_row("Nodes", str(report.node_count))
    table.add_row("Pods", str(report.pod_count))
    table.add_row("Namespaces", str(report.namespace_count))
    table.add_row("", "")

    crit_style = "bold red" if report.total_critical > 0 else "green"
    warn_style = "bold yellow" if report.total_warnings > 0 else "green"

    table.add_row("Total Findings", str(report.total_findings))
    table.add_row(
        Text("Critical", style=crit_style),
        Text(str(report.total_critical), style=crit_style),
    )
    table.add_row(
        Text("Warnings", style=warn_style),
        Text(str(report.total_warnings), style=warn_style),
    )
    table.add_row("Root Causes Identified", str(report.root_cause_count))

    console.print(
        Panel(table, title="[bold]Summary[/bold]", border_style="dim")
    )


def _render_correlation_group(
    group: CorrelationGroup, index: int, console: Console
) -> None:
    """Render a single root cause correlation group."""
    severity = group.severity
    color = _severity_color(severity)

    tree = Tree(
        Text.assemble(
            (f"Issue #{index} ", "bold"),
            (f"[{severity.value.upper()}] ", f"bold {color}"),
            (group.summary or "", ""),
        )
    )

    # Root cause
    if group.root_cause:
        rc = group.root_cause
        root_branch = tree.add(
            Text.assemble(
                ("Root Cause: ", "bold red"),
                (f"{rc.resource} ", "cyan"),
                (f"- {rc.message}", ""),
            )
        )
        if rc.remediation:
            root_branch.add(Text(f"Fix: {rc.remediation}", style="green"))
        if rc.evidence:
            ev_branch = root_branch.add(Text("Evidence:", style="dim"))
            for e in rc.evidence:
                ev_branch.add(Text(f"$ {e}", style="dim italic"))

    # Symptoms
    if group.symptoms:
        symptom_branch = tree.add(
            Text(f"Symptoms ({len(group.symptoms)}):", style="bold yellow")
        )
        for s in group.symptoms[:10]:  # Limit display
            symptom_branch.add(
                Text.assemble(
                    (s.severity.rich_label, ""),
                    (f" {s.resource} ", "cyan"),
                    (f"- {s.message}", ""),
                )
            )
        if len(group.symptoms) > 10:
            symptom_branch.add(
                Text(f"... and {len(group.symptoms) - 10} more", style="dim")
            )

    # Blast radius
    if group.affected_resources and len(group.affected_resources) > 2:
        tree.add(
            Text(
                f"Blast radius: {len(group.affected_resources)} resources affected",
                style="bold magenta",
            )
        )

    # Timeline
    if group.timeline:
        timeline_branch = tree.add(Text("Recent Events:", style="dim"))
        for evt in sorted(group.timeline)[-5:]:
            evt_color = "red" if evt.event_type == "Warning" else "dim"
            timeline_branch.add(
                Text(
                    f"[{evt.timestamp.strftime('%H:%M:%S')}] "
                    f"{evt.reason}: {evt.message[:100]}",
                    style=evt_color,
                )
            )

    console.print(Panel(tree, border_style=color))


def _render_findings_table(findings: list[Finding], console: Console) -> None:
    """Render a table of findings."""
    table = Table(show_lines=True)
    table.add_column("Sev", width=6, justify="center")
    table.add_column("Resource", style="cyan", max_width=40)
    table.add_column("Issue", max_width=60)
    table.add_column("Category", style="dim", max_width=20)

    for f in sorted(findings, key=lambda x: x.severity.sort_order):
        table.add_row(
            f.severity.rich_label,
            str(f.resource),
            f.message[:60],
            f.category.value,
        )

    console.print(table)


def _render_category_breakdown(report: InvestigationReport, console: Console) -> None:
    """Render findings grouped by check category."""
    for cr in report.check_results:
        if not cr.findings:
            continue

        severity = cr.worst_severity
        color = _severity_color(severity)

        table = Table(title=cr.category.value, show_lines=False, border_style=color)
        table.add_column("Sev", width=6, justify="center")
        table.add_column("Resource", style="cyan", max_width=40)
        table.add_column("Issue", max_width=70)

        for f in sorted(cr.findings, key=lambda x: x.severity.sort_order)[:20]:
            table.add_row(
                f.severity.rich_label,
                str(f.resource),
                f.message[:70],
            )

        if len(cr.findings) > 20:
            table.add_row("", "", f"... {len(cr.findings) - 20} more findings")

        console.print(table)
        console.print()


def _render_footer(report: InvestigationReport, console: Console) -> None:
    """Render the report footer."""
    console.rule(style="dim")
    console.print(
        f"[dim]kub-health investigation complete. "
        f"{report.total_findings} findings, "
        f"{report.root_cause_count} root causes identified. "
        f"Cluster: {report.cluster_name}[/dim]"
    )
    console.print()


def _severity_color(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "red",
        Severity.WARNING: "yellow",
        Severity.INFO: "blue",
        Severity.OK: "green",
    }[severity]
