"""Correlation engine.

Takes raw findings from all health check modules, the dependency graph, and
the event timeline, then groups related findings into CorrelationGroups with
identified root causes.

This is the core intelligence of the SRE investigation engine. It answers:
"These 15 findings are actually 3 root causes."
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from kub_health.correlator.timeline import events_for_resource
from kub_health.models import (
    CheckResult,
    CorrelationGroup,
    DependencyGraph,
    DependencyType,
    Finding,
    ResourceKey,
    Severity,
    TimelineEvent,
)


def correlate_findings(
    check_results: list[CheckResult],
    graph: DependencyGraph,
    timeline: list[TimelineEvent],
) -> tuple[list[CorrelationGroup], list[Finding]]:
    """Correlate findings into root-cause groups.

    Returns:
        Tuple of (correlated groups, uncorrelated findings).
    """
    # Collect all findings
    all_findings: list[Finding] = []
    for cr in check_results:
        all_findings.extend(cr.findings)

    if not all_findings:
        return [], []

    # Index findings by resource
    findings_by_resource: dict[ResourceKey, list[Finding]] = defaultdict(list)
    for f in all_findings:
        findings_by_resource[f.resource].append(f)

    groups: list[CorrelationGroup] = []
    claimed: set[str] = set()  # finding IDs already in a group

    # --- Strategy 1: Node-level correlation ---
    # If a node is unhealthy, all pods on that node are symptoms
    _correlate_node_issues(groups, claimed, findings_by_resource, graph, timeline)

    # --- Strategy 2: Deployment-level correlation ---
    # If multiple pods of a deployment are failing, the root cause is the deployment
    _correlate_deployment_issues(groups, claimed, findings_by_resource, graph, timeline)

    # --- Strategy 3: PVC/Storage correlation ---
    # If a PVC is unbound, pods waiting on it are symptoms
    _correlate_storage_issues(groups, claimed, findings_by_resource, graph, timeline)

    # --- Strategy 4: Service/Networking correlation ---
    # Service with no endpoints + pods not ready -> pods are root cause
    _correlate_service_issues(groups, claimed, findings_by_resource, graph, timeline)

    # --- Strategy 5: ConfigMap/Secret missing correlation ---
    # Pods failing because of missing config -> group by the missing resource
    _correlate_config_issues(groups, claimed, findings_by_resource, graph, timeline)

    # Remaining uncorrelated findings
    uncorrelated = [f for f in all_findings if f.id not in claimed]

    return groups, uncorrelated


def _correlate_node_issues(
    groups: list[CorrelationGroup],
    claimed: set[str],
    findings_by_resource: dict[ResourceKey, list[Finding]],
    graph: DependencyGraph,
    timeline: list[TimelineEvent],
) -> None:
    """If a node has issues, group all pod findings on that node as symptoms."""
    node_findings = {
        rk: findings
        for rk, findings in findings_by_resource.items()
        if rk.kind == "Node" and any(f.severity in (Severity.CRITICAL, Severity.WARNING) for f in findings)
    }

    for node_key, node_issues in node_findings.items():
        # Find all pods on this node
        pod_edges = [
            e for e in graph.dependents_of(node_key)
            if e.dep_type == DependencyType.RUNS_ON and e.source.kind == "Pod"
        ]

        symptoms: list[Finding] = []
        affected: set[ResourceKey] = {node_key}

        for edge in pod_edges:
            pod_key = edge.source
            affected.add(pod_key)
            pod_findings = findings_by_resource.get(pod_key, [])
            for f in pod_findings:
                if f.id not in claimed:
                    symptoms.append(f)

        if not symptoms:
            continue

        # Pick the most severe node finding as root cause
        root = max(node_issues, key=lambda f: -f.severity.sort_order)

        # Get relevant timeline events
        node_events = events_for_resource(timeline, node_key)

        group = CorrelationGroup(
            root_cause=root,
            symptoms=symptoms,
            affected_resources=affected,
            timeline=node_events[-20:],  # Last 20 events
            summary=f"Node '{node_key.name}' issue ({root.message}) is affecting "
            f"{len(symptoms)} pod(s) on this node.",
        )
        groups.append(group)

        # Claim findings
        claimed.add(root.id)
        for s in symptoms:
            claimed.add(s.id)
        # Claim other node findings too
        for nf in node_issues:
            claimed.add(nf.id)


def _correlate_deployment_issues(
    groups: list[CorrelationGroup],
    claimed: set[str],
    findings_by_resource: dict[ResourceKey, list[Finding]],
    graph: DependencyGraph,
    timeline: list[TimelineEvent],
) -> None:
    """Group pod failures under their parent deployment/statefulset."""
    # Find all deployment/statefulset findings
    for rk, findings in list(findings_by_resource.items()):
        if rk.kind not in ("Deployment", "StatefulSet", "DaemonSet"):
            continue

        unclaimed_findings = [f for f in findings if f.id not in claimed]
        if not unclaimed_findings:
            continue

        # Find owned pods (through ReplicaSet for Deployments)
        owned_resources = graph.dependency_chain(rk)
        pod_findings: list[Finding] = []
        affected: set[ResourceKey] = {rk}

        for res in owned_resources:
            affected.add(res)
            for f in findings_by_resource.get(res, []):
                if f.id not in claimed:
                    pod_findings.append(f)

        if not pod_findings and len(unclaimed_findings) <= 1:
            continue

        # The deployment-level finding is the root cause, pod findings are symptoms
        root = max(unclaimed_findings, key=lambda f: -f.severity.sort_order)
        symptoms = [f for f in pod_findings if f.id != root.id]

        events = events_for_resource(timeline, rk)
        for res in owned_resources:
            if res.kind == "Pod":
                events.extend(events_for_resource(timeline, res)[-5:])
        events.sort()

        group = CorrelationGroup(
            root_cause=root,
            symptoms=symptoms,
            affected_resources=affected,
            timeline=events[-20:],
            summary=f"{rk.kind} '{rk.name}' in {rk.namespace}: {root.message}. "
            f"{len(symptoms)} related finding(s).",
        )
        groups.append(group)

        claimed.add(root.id)
        for s in symptoms:
            claimed.add(s.id)
        for f in unclaimed_findings:
            claimed.add(f.id)


def _correlate_storage_issues(
    groups: list[CorrelationGroup],
    claimed: set[str],
    findings_by_resource: dict[ResourceKey, list[Finding]],
    graph: DependencyGraph,
    timeline: list[TimelineEvent],
) -> None:
    """Group pod issues caused by storage problems."""
    pvc_findings = {
        rk: findings
        for rk, findings in findings_by_resource.items()
        if rk.kind == "PVC" and any(f.id not in claimed for f in findings)
    }

    for pvc_key, pvc_issues in pvc_findings.items():
        unclaimed = [f for f in pvc_issues if f.id not in claimed]
        if not unclaimed:
            continue

        # Find pods that mount this PVC
        pod_edges = [
            e for e in graph.dependents_of(pvc_key)
            if e.dep_type == DependencyType.MOUNTS and e.source.kind == "Pod"
        ]

        symptoms: list[Finding] = []
        affected: set[ResourceKey] = {pvc_key}

        for edge in pod_edges:
            affected.add(edge.source)
            for f in findings_by_resource.get(edge.source, []):
                if f.id not in claimed:
                    symptoms.append(f)

        if not symptoms and len(unclaimed) <= 1:
            continue

        root = max(unclaimed, key=lambda f: -f.severity.sort_order)

        group = CorrelationGroup(
            root_cause=root,
            symptoms=symptoms,
            affected_resources=affected,
            timeline=events_for_resource(timeline, pvc_key)[-10:],
            summary=f"PVC '{pvc_key.name}' in {pvc_key.namespace}: {root.message}. "
            f"{len(symptoms)} pod(s) affected.",
        )
        groups.append(group)

        claimed.add(root.id)
        for s in symptoms:
            claimed.add(s.id)
        for f in unclaimed:
            claimed.add(f.id)


def _correlate_service_issues(
    groups: list[CorrelationGroup],
    claimed: set[str],
    findings_by_resource: dict[ResourceKey, list[Finding]],
    graph: DependencyGraph,
    timeline: list[TimelineEvent],
) -> None:
    """Correlate service endpoint issues with pod readiness."""
    svc_findings = {
        rk: findings
        for rk, findings in findings_by_resource.items()
        if rk.kind == "Service" and any(f.id not in claimed for f in findings)
    }

    for svc_key, svc_issues in svc_findings.items():
        unclaimed = [f for f in svc_issues if f.id not in claimed]
        if not unclaimed:
            continue

        # Find pods selected by this service
        pod_edges = [
            e for e in graph.dependencies_of(svc_key)
            if e.dep_type == DependencyType.SELECTS and e.target.kind == "Pod"
        ]

        symptoms: list[Finding] = []
        affected: set[ResourceKey] = {svc_key}

        for edge in pod_edges:
            affected.add(edge.target)
            for f in findings_by_resource.get(edge.target, []):
                if f.id not in claimed:
                    symptoms.append(f)

        # Also check ingresses pointing to this service
        ing_edges = [
            e for e in graph.dependents_of(svc_key)
            if e.source.kind == "Ingress"
        ]
        for edge in ing_edges:
            affected.add(edge.source)
            for f in findings_by_resource.get(edge.source, []):
                if f.id not in claimed:
                    symptoms.append(f)

        if not symptoms:
            continue

        # The pod issues are actually the root cause, service is the symptom
        # (reversed from what you might expect)
        if symptoms and any(s.severity == Severity.CRITICAL for s in symptoms):
            root = max(symptoms, key=lambda f: -f.severity.sort_order)
            svc_symptoms = [f for f in unclaimed if f.id != root.id]
            all_symptoms = svc_symptoms + [s for s in symptoms if s.id != root.id]
        else:
            root = max(unclaimed, key=lambda f: -f.severity.sort_order)
            all_symptoms = symptoms

        group = CorrelationGroup(
            root_cause=root,
            symptoms=all_symptoms,
            affected_resources=affected,
            timeline=events_for_resource(timeline, svc_key)[-10:],
            summary=f"Service '{svc_key.name}' in {svc_key.namespace}: "
            f"{root.message}. {len(all_symptoms)} related finding(s).",
        )
        groups.append(group)

        claimed.add(root.id)
        for s in all_symptoms:
            claimed.add(s.id)
        for f in unclaimed:
            claimed.add(f.id)


def _correlate_config_issues(
    groups: list[CorrelationGroup],
    claimed: set[str],
    findings_by_resource: dict[ResourceKey, list[Finding]],
    graph: DependencyGraph,
    timeline: list[TimelineEvent],
) -> None:
    """Group pods that are failing due to the same missing ConfigMap/Secret."""
    # Look for findings about missing ConfigMaps/Secrets
    missing_refs: dict[ResourceKey, list[Finding]] = defaultdict(list)

    for rk, findings in findings_by_resource.items():
        for f in findings:
            if f.id in claimed:
                continue
            # Check if the finding references a missing ConfigMap or Secret
            for related in f.related_resources:
                if related.kind in ("ConfigMap", "Secret"):
                    missing_refs[related].append(f)

    for ref_key, ref_findings in missing_refs.items():
        if len(ref_findings) < 2:
            continue  # Not worth grouping single findings

        root = Finding(
            category=ref_findings[0].category,
            severity=Severity.CRITICAL,
            resource=ref_key,
            message=f"{ref_key.kind} '{ref_key.name}' is missing or inaccessible, "
            f"affecting {len(ref_findings)} pod(s)",
            remediation=f"Create the {ref_key.kind} '{ref_key.name}' in namespace "
            f"'{ref_key.namespace}', or update the pods that reference it.",
        )

        group = CorrelationGroup(
            root_cause=root,
            symptoms=ref_findings,
            affected_resources={ref_key} | {f.resource for f in ref_findings},
            summary=f"Missing {ref_key.kind} '{ref_key.name}' in {ref_key.namespace} "
            f"is causing {len(ref_findings)} pod failure(s).",
        )
        groups.append(group)

        for f in ref_findings:
            claimed.add(f.id)
