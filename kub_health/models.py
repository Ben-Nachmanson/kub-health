"""Data models for the SRE investigation engine.

Core concepts:
- ClusterSnapshot: Point-in-time capture of all cluster state
- Finding: A single detected issue with severity and context
- CorrelationGroup: Related findings that share a root cause
- InvestigationReport: Full report with correlated findings and AI analysis
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity level for health check findings."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"

    @property
    def rich_label(self) -> str:
        return {
            Severity.CRITICAL: "[bold red]CRIT[/bold red]",
            Severity.WARNING: "[yellow]WARN[/yellow]",
            Severity.INFO: "[blue]INFO[/blue]",
            Severity.OK: "[green] OK [/green]",
        }[self]

    @property
    def sort_order(self) -> int:
        return {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2, Severity.OK: 3}[self]


class CheckCategory(str, Enum):
    """Category groupings for health checks."""

    PODS = "Pod Health"
    NODES = "Node Health"
    RESOURCES = "Resource Utilization"
    DEPLOYMENTS = "Deployment Status"
    EVENTS = "Events & Warnings"
    NETWORKING = "Networking"
    STORAGE = "Storage"
    RBAC = "RBAC & Security"


# ---------------------------------------------------------------------------
# Resource key: a canonical identifier for any K8s resource
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceKey:
    """Unique identifier for a Kubernetes resource."""

    kind: str
    name: str
    namespace: str = ""

    def __str__(self) -> str:
        if self.namespace:
            return f"{self.kind}/{self.namespace}/{self.name}"
        return f"{self.kind}/{self.name}"


# ---------------------------------------------------------------------------
# Cluster Snapshot: point-in-time state of all cluster resources
# ---------------------------------------------------------------------------


@dataclass
class ClusterSnapshot:
    """Point-in-time capture of all relevant cluster state.

    The collector populates this with raw K8s API objects. Health checks and
    the correlation engine both read from this snapshot so the cluster is only
    queried once.
    """

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Raw K8s API objects (as returned by the Python client)
    pods: list[Any] = field(default_factory=list)
    nodes: list[Any] = field(default_factory=list)
    deployments: list[Any] = field(default_factory=list)
    replicasets: list[Any] = field(default_factory=list)
    statefulsets: list[Any] = field(default_factory=list)
    daemonsets: list[Any] = field(default_factory=list)
    services: list[Any] = field(default_factory=list)
    endpoints: list[Any] = field(default_factory=list)
    ingresses: list[Any] = field(default_factory=list)
    network_policies: list[Any] = field(default_factory=list)
    pvcs: list[Any] = field(default_factory=list)
    pvs: list[Any] = field(default_factory=list)
    storage_classes: list[Any] = field(default_factory=list)
    configmaps: list[Any] = field(default_factory=list)
    secrets: list[Any] = field(default_factory=list)  # metadata only, no data
    service_accounts: list[Any] = field(default_factory=list)
    roles: list[Any] = field(default_factory=list)
    cluster_roles: list[Any] = field(default_factory=list)
    role_bindings: list[Any] = field(default_factory=list)
    cluster_role_bindings: list[Any] = field(default_factory=list)
    events: list[Any] = field(default_factory=list)
    namespaces: list[Any] = field(default_factory=list)
    resource_quotas: list[Any] = field(default_factory=list)
    limit_ranges: list[Any] = field(default_factory=list)
    hpas: list[Any] = field(default_factory=list)
    pod_disruption_budgets: list[Any] = field(default_factory=list)

    # Metrics (from metrics-server, may be empty if unavailable)
    pod_metrics: list[Any] = field(default_factory=list)
    node_metrics: list[Any] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Finding: a single detected issue
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single health check finding with full context."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    category: CheckCategory = CheckCategory.PODS
    severity: Severity = Severity.INFO
    resource: ResourceKey = field(default_factory=lambda: ResourceKey("Unknown", "unknown"))
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    # Links to related resources (for the correlation engine)
    related_resources: list[ResourceKey] = field(default_factory=list)
    # Raw evidence: kubectl-equivalent commands or data snippets
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "resource": str(self.resource),
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation,
            "related_resources": [str(r) for r in self.related_resources],
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# Dependency graph edge
# ---------------------------------------------------------------------------


class DependencyType(str, Enum):
    """Types of relationships between K8s resources."""

    OWNS = "owns"  # Deployment -> ReplicaSet -> Pod
    SELECTS = "selects"  # Service -> Pod (via label selector)
    MOUNTS = "mounts"  # Pod -> PVC, Pod -> ConfigMap, Pod -> Secret
    RUNS_ON = "runs_on"  # Pod -> Node
    BINDS = "binds"  # RoleBinding -> Role + ServiceAccount
    TARGETS = "targets"  # NetworkPolicy -> Pod (via selector)
    SCALES = "scales"  # HPA -> Deployment/StatefulSet
    REFERENCES = "references"  # Generic reference (e.g., Ingress -> Service)


@dataclass(frozen=True)
class DependencyEdge:
    """A directed edge in the resource dependency graph."""

    source: ResourceKey
    target: ResourceKey
    dep_type: DependencyType
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.source, self.target, self.dep_type))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DependencyEdge):
            return False
        return (
            self.source == other.source
            and self.target == other.target
            and self.dep_type == other.dep_type
        )


# ---------------------------------------------------------------------------
# Dependency Graph
# ---------------------------------------------------------------------------


@dataclass
class DependencyGraph:
    """Directed graph of resource dependencies across the cluster."""

    edges: list[DependencyEdge] = field(default_factory=list)
    _adjacency: dict[ResourceKey, list[DependencyEdge]] = field(
        default_factory=dict, repr=False
    )
    _reverse: dict[ResourceKey, list[DependencyEdge]] = field(
        default_factory=dict, repr=False
    )

    def add_edge(self, edge: DependencyEdge) -> None:
        self.edges.append(edge)
        self._adjacency.setdefault(edge.source, []).append(edge)
        self._reverse.setdefault(edge.target, []).append(edge)

    def dependents_of(self, key: ResourceKey) -> list[DependencyEdge]:
        """What resources depend on `key`? (reverse lookup)"""
        return self._reverse.get(key, [])

    def dependencies_of(self, key: ResourceKey) -> list[DependencyEdge]:
        """What does `key` depend on? (forward lookup)"""
        return self._adjacency.get(key, [])

    def impact_radius(self, key: ResourceKey, visited: set[ResourceKey] | None = None) -> set[ResourceKey]:
        """Recursively find all resources impacted if `key` is unhealthy."""
        if visited is None:
            visited = set()
        if key in visited:
            return visited
        visited.add(key)
        for edge in self.dependents_of(key):
            self.impact_radius(edge.source, visited)
        return visited

    def dependency_chain(self, key: ResourceKey, visited: set[ResourceKey] | None = None) -> set[ResourceKey]:
        """Recursively find all resources that `key` depends on."""
        if visited is None:
            visited = set()
        if key in visited:
            return visited
        visited.add(key)
        for edge in self.dependencies_of(key):
            self.dependency_chain(edge.target, visited)
        return visited


# ---------------------------------------------------------------------------
# Event timeline
# ---------------------------------------------------------------------------


@dataclass
class TimelineEvent:
    """A single event in the cluster timeline."""

    timestamp: datetime
    resource: ResourceKey
    event_type: str  # "Normal" or "Warning"
    reason: str
    message: str
    count: int = 1
    source_component: str = ""

    def __lt__(self, other: TimelineEvent) -> bool:
        return self.timestamp < other.timestamp


# ---------------------------------------------------------------------------
# Correlation: groups of related findings with root cause
# ---------------------------------------------------------------------------


@dataclass
class CorrelationGroup:
    """A group of findings that share a common root cause."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    root_cause: Finding | None = None
    symptoms: list[Finding] = field(default_factory=list)
    affected_resources: set[ResourceKey] = field(default_factory=set)
    timeline: list[TimelineEvent] = field(default_factory=list)
    summary: str = ""

    @property
    def severity(self) -> Severity:
        if self.root_cause:
            return self.root_cause.severity
        if self.symptoms:
            return min(self.symptoms, key=lambda f: f.severity.sort_order).severity
        return Severity.OK

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        if self.root_cause:
            findings.append(self.root_cause)
        findings.extend(self.symptoms)
        return findings


# ---------------------------------------------------------------------------
# Check Result (per-module output)
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """Result from a single health check module."""

    category: CheckCategory
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.OK
        return min(self.findings, key=lambda f: f.severity.sort_order).severity


# ---------------------------------------------------------------------------
# Investigation Report: the final output
# ---------------------------------------------------------------------------


@dataclass
class InvestigationReport:
    """Full SRE investigation report for a cluster."""

    cluster_name: str
    context: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Raw results from each check module
    check_results: list[CheckResult] = field(default_factory=list)

    # Correlated findings (root cause groups)
    correlation_groups: list[CorrelationGroup] = field(default_factory=list)

    # Uncorrelated findings (couldn't be grouped)
    uncorrelated_findings: list[Finding] = field(default_factory=list)

    # AI-generated analysis
    ai_analysis: str = ""

    # Cluster-level summary stats
    node_count: int = 0
    pod_count: int = 0
    namespace_count: int = 0

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.check_results)

    @property
    def total_critical(self) -> int:
        return sum(r.critical_count for r in self.check_results)

    @property
    def total_warnings(self) -> int:
        return sum(r.warning_count for r in self.check_results)

    @property
    def overall_health(self) -> Severity:
        if not self.check_results:
            return Severity.OK
        worst = min(
            (r.worst_severity for r in self.check_results),
            key=lambda s: s.sort_order,
            default=Severity.OK,
        )
        return worst

    @property
    def root_cause_count(self) -> int:
        return len(self.correlation_groups)

    def all_findings_sorted(self) -> list[Finding]:
        """Return all findings sorted by severity."""
        findings = []
        for result in self.check_results:
            findings.extend(result.findings)
        return sorted(findings, key=lambda f: f.severity.sort_order)

    def findings_summary_text(self) -> str:
        """Produce a text summary of all findings for AI analysis."""
        lines = [
            f"# Kubernetes Cluster Investigation: {self.cluster_name}",
            f"Context: {self.context}",
            f"Timestamp: {self.timestamp.isoformat()}",
            f"Nodes: {self.node_count} | Pods: {self.pod_count} | Namespaces: {self.namespace_count}",
            "",
        ]

        # Correlation groups first
        if self.correlation_groups:
            lines.append("## Root Cause Analysis")
            for i, group in enumerate(self.correlation_groups, 1):
                lines.append(f"\n### Issue #{i} [{group.severity.value.upper()}]")
                if group.root_cause:
                    lines.append(f"Root Cause: {group.root_cause.resource} - {group.root_cause.message}")
                    if group.root_cause.details:
                        for k, v in group.root_cause.details.items():
                            lines.append(f"  {k}: {v}")
                if group.symptoms:
                    lines.append(f"Symptoms ({len(group.symptoms)}):")
                    for s in group.symptoms:
                        lines.append(f"  - {s.resource}: {s.message}")
                if group.affected_resources:
                    lines.append(f"Blast radius: {len(group.affected_resources)} resources affected")
                if group.timeline:
                    lines.append("Timeline:")
                    for evt in sorted(group.timeline)[-5:]:  # last 5 events
                        lines.append(
                            f"  [{evt.timestamp.strftime('%H:%M:%S')}] "
                            f"{evt.resource}: {evt.reason} - {evt.message}"
                        )

        # Uncorrelated findings
        if self.uncorrelated_findings:
            lines.append("\n## Additional Findings")
            for f in sorted(self.uncorrelated_findings, key=lambda x: x.severity.sort_order):
                lines.append(f"- [{f.severity.value.upper()}] {f.resource}: {f.message}")
                if f.details:
                    for k, v in f.details.items():
                        lines.append(f"    {k}: {v}")

        # Per-category breakdown
        lines.append("\n## Detailed Findings by Category")
        for result in self.check_results:
            if not result.findings:
                continue
            lines.append(f"\n### {result.category.value}")
            for f in sorted(result.findings, key=lambda x: x.severity.sort_order):
                ns = f"[{f.resource.namespace}]" if f.resource.namespace else ""
                lines.append(
                    f"- [{f.severity.value.upper()}] {f.resource.kind}/{f.resource.name} "
                    f"{ns}: {f.message}"
                )
                if f.evidence:
                    for e in f.evidence:
                        lines.append(f"    Evidence: {e}")
                if f.details:
                    for k, v in f.details.items():
                        lines.append(f"    {k}: {v}")

        return "\n".join(lines)
