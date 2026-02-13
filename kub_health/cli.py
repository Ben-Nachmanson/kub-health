"""CLI entry point for kub-health.

Usage:
    kub-health investigate [--namespace NS] [--context CTX] [--no-ai] [--provider PROVIDER]
    kub-health investigate --help
"""

from __future__ import annotations

import logging
import sys
import time
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from kub_health import __version__
from kub_health.ai.analyzer import AIConfig, run_analysis
from kub_health.checks.deployments import check_deployments
from kub_health.checks.events import check_events
from kub_health.checks.networking import check_networking
from kub_health.checks.nodes import check_nodes
from kub_health.checks.pods import check_pods
from kub_health.checks.rbac import check_rbac
from kub_health.checks.resources import check_resources
from kub_health.checks.storage import check_storage
from kub_health.collector.snapshot import collect_snapshot
from kub_health.config import Config
from kub_health.correlator.dependency_graph import build_dependency_graph
from kub_health.correlator.engine import correlate_findings
from kub_health.correlator.timeline import build_timeline
from kub_health.k8s_client import K8sClient
from kub_health.models import CheckCategory, CheckResult, InvestigationReport
from kub_health.output import render_report

console = Console()

CHECKS = {
    "pods": ("Pod Health", check_pods),
    "nodes": ("Node Health", check_nodes),
    "resources": ("Resource Utilization", check_resources),
    "deployments": ("Deployment Status", check_deployments),
    "events": ("Events & Warnings", check_events),
    "networking": ("Networking", check_networking),
    "storage": ("Storage", check_storage),
    "rbac": ("RBAC & Security", check_rbac),
}


@click.group()
@click.version_option(version=__version__, prog_name="kub-health")
def main():
    """AI-powered Kubernetes cluster investigation engine.

    Connects to your cluster, collects state, runs health checks, correlates
    findings into root causes, and optionally runs AI analysis.
    """
    pass


@main.command()
@click.option("--namespace", "-n", default="", help="Limit to a specific namespace (default: all)")
@click.option("--context", "-c", default="", help="Kubernetes context to use")
@click.option("--kubeconfig", "-k", default="", help="Path to kubeconfig file")
@click.option(
    "--provider",
    "-p",
    type=click.Choice(["openai", "anthropic", "ollama"]),
    default=None,
    help="AI provider for analysis",
)
@click.option("--model", "-m", default="", help="AI model to use (e.g., gpt-4o, claude-sonnet-4-20250514, llama3.1)")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis")
@click.option("--config", "config_path", default="", help="Path to config file")
@click.option("--skip", multiple=True, help="Skip specific checks (e.g., --skip rbac --skip events)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def investigate(
    namespace: str,
    context: str,
    kubeconfig: str,
    provider: str | None,
    model: str,
    no_ai: bool,
    config_path: str,
    skip: tuple[str, ...],
    verbose: bool,
):
    """Run a full cluster health investigation."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    # Load config (file -> env -> CLI flags)
    cfg = Config.load(config_path or None)

    # CLI flag overrides
    if namespace:
        cfg.namespace = namespace
    if context:
        cfg.context = context
    if kubeconfig:
        cfg.kubeconfig = kubeconfig
    if provider:
        cfg.ai.provider = provider
    if model:
        cfg.ai.model = model
    if no_ai:
        cfg.no_ai = True
    if skip:
        cfg.skip_checks = list(skip)

    # Connect to cluster
    console.print("[bold]Connecting to Kubernetes cluster...[/bold]")
    k8s = K8sClient(kubeconfig=cfg.kubeconfig or None, context=cfg.context or None)

    try:
        k8s.connect()
    except Exception as exc:
        console.print(f"[bold red]Failed to connect to cluster:[/bold red] {exc}")
        console.print(
            "\n[dim]Make sure your kubeconfig is valid and the cluster is reachable.\n"
            "You can specify a context with --context or a kubeconfig with --kubeconfig.[/dim]"
        )
        sys.exit(1)

    cluster_name = k8s.get_cluster_name()
    context_name = k8s.get_context_name()
    console.print(f"[green]Connected to cluster:[/green] {cluster_name} (context: {context_name})")
    console.print()

    # Phase 1: Collect cluster state
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        t0 = time.time()
        snap = collect_snapshot(k8s, namespace=cfg.namespace or None, progress=progress)
        collect_time = time.time() - t0

    console.print(
        f"[dim]Collected {len(snap.pods)} pods, {len(snap.nodes)} nodes, "
        f"{len(snap.deployments)} deployments, {len(snap.services)} services, "
        f"{len(snap.events)} events in {collect_time:.1f}s[/dim]"
    )
    console.print()

    # Phase 2: Run health checks
    console.print("[bold]Running health checks...[/bold]")
    check_results: list[CheckResult] = []
    active_checks = {k: v for k, v in CHECKS.items() if k not in cfg.skip_checks}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task_id = progress.add_task("Analyzing...", total=len(active_checks))

        for check_name, (label, check_fn) in active_checks.items():
            progress.update(task_id, description=f"Checking {label}...")
            t0 = time.time()
            try:
                result = check_fn(snap)
                result.duration_ms = (time.time() - t0) * 1000
                check_results.append(result)
            except Exception as exc:
                console.print(f"[yellow]Warning: {label} check failed: {exc}[/yellow]")
                check_results.append(
                    CheckResult(category=CheckCategory(label), error=str(exc))
                )
            progress.advance(task_id)

    total_findings = sum(len(cr.findings) for cr in check_results)
    console.print(f"[dim]Found {total_findings} findings across {len(active_checks)} check categories[/dim]")
    console.print()

    # Phase 3: Build dependency graph and correlate
    console.print("[bold]Correlating findings...[/bold]")
    t0 = time.time()
    dep_graph = build_dependency_graph(snap)
    timeline = build_timeline(snap)
    correlation_groups, uncorrelated = correlate_findings(check_results, dep_graph, timeline)
    correlate_time = time.time() - t0

    console.print(
        f"[dim]Identified {len(correlation_groups)} root cause group(s), "
        f"{len(uncorrelated)} uncorrelated finding(s), "
        f"{len(dep_graph.edges)} dependency edges, "
        f"{len(timeline)} timeline events "
        f"in {correlate_time:.1f}s[/dim]"
    )
    console.print()

    # Build report
    report = InvestigationReport(
        cluster_name=cluster_name,
        context=context_name,
        check_results=check_results,
        correlation_groups=correlation_groups,
        uncorrelated_findings=uncorrelated,
        node_count=len(snap.nodes),
        pod_count=len(snap.pods),
        namespace_count=len(snap.namespaces),
    )

    # Phase 4: AI analysis
    if not cfg.no_ai and total_findings > 0:
        console.print("[bold]Running AI analysis...[/bold]")
        ai_config = cfg.ai
        ai_config.__post_init__()  # Ensure defaults are set

        console.print(
            f"[dim]Using {ai_config.provider} ({ai_config.model})[/dim]"
        )

        with console.status("[bold]AI is analyzing the investigation report...[/bold]"):
            report_text = report.findings_summary_text()
            report.ai_analysis = run_analysis(ai_config, report_text)

        console.print("[green]AI analysis complete.[/green]")
        console.print()
    elif cfg.no_ai:
        console.print("[dim]AI analysis skipped (--no-ai flag)[/dim]")
    elif total_findings == 0:
        console.print("[green]No findings to analyze - cluster looks healthy![/green]")

    # Phase 5: Render the report
    render_report(report, console)


@main.command()
@click.option("--context", "-c", default="", help="Kubernetes context to use")
@click.option("--kubeconfig", "-k", default="", help="Path to kubeconfig file")
def status(context: str, kubeconfig: str):
    """Quick cluster connectivity check and basic stats."""
    k8s = K8sClient(kubeconfig=kubeconfig or None, context=context or None)

    try:
        k8s.connect()
    except Exception as exc:
        console.print(f"[bold red]Cannot connect to cluster:[/bold red] {exc}")
        sys.exit(1)

    console.print(f"[green]Cluster:[/green] {k8s.get_cluster_name()}")
    console.print(f"[green]Context:[/green] {k8s.get_context_name()}")

    try:
        nodes = k8s.core_v1.list_node()
        pods = k8s.core_v1.list_pod_for_all_namespaces()
        namespaces = k8s.core_v1.list_namespace()

        ready_nodes = sum(
            1
            for n in nodes.items
            if any(c.type == "Ready" and c.status == "True" for c in (n.status.conditions or []))
        )

        running_pods = sum(1 for p in pods.items if p.status.phase == "Running")

        console.print(f"[green]Nodes:[/green] {ready_nodes}/{len(nodes.items)} ready")
        console.print(f"[green]Pods:[/green] {running_pods}/{len(pods.items)} running")
        console.print(f"[green]Namespaces:[/green] {len(namespaces.items)}")
    except Exception as exc:
        console.print(f"[yellow]Could not fetch cluster stats:[/yellow] {exc}")


@main.command()
def init():
    """Generate a sample configuration file."""
    sample = """\
# kub-health configuration
# Place this file at .kub-health.yaml in your project or home directory.

# Kubernetes connection
# kubeconfig: ~/.kube/config
# context: my-cluster
# namespace: ""  # empty = all namespaces

# AI provider configuration
ai:
  provider: ollama  # openai, anthropic, ollama
  model: ""  # auto-detected per provider (gpt-4o, claude-sonnet-4-20250514, llama3.1)
  # api_key: ""  # or set OPENAI_API_KEY / ANTHROPIC_API_KEY env vars
  base_url: "http://localhost:11434"  # Ollama endpoint
  temperature: 0.3
  max_tokens: 4096

# Check configuration
skip_checks: []  # e.g., [rbac, events]
skip_namespaces:
  - kube-system
  - kube-public
  - kube-node-lease

# Output
show_ok: false
# severity_filter: warning  # only show warning+ findings
"""
    from pathlib import Path

    out_path = Path.cwd() / ".kub-health.yaml"
    if out_path.exists():
        console.print(f"[yellow]Config file already exists:[/yellow] {out_path}")
        return

    out_path.write_text(sample)
    console.print(f"[green]Created config file:[/green] {out_path}")
    console.print("[dim]Edit it to configure your AI provider and preferences.[/dim]")


if __name__ == "__main__":
    main()
