"""Node health analyzer.

Detects: NotReady nodes, MemoryPressure, DiskPressure, PIDPressure,
unschedulable nodes, high resource allocation ratios, kernel/runtime issues.
"""

from __future__ import annotations

from datetime import datetime, timezone

from kub_health.models import (
    CheckCategory,
    CheckResult,
    ClusterSnapshot,
    Finding,
    ResourceKey,
    Severity,
)

ALLOC_WARN_PCT = 80
ALLOC_CRIT_PCT = 95


def check_nodes(snap: ClusterSnapshot) -> CheckResult:
    """Analyze all nodes in the snapshot for health issues."""
    result = CheckResult(category=CheckCategory.NODES)
    now = datetime.now(timezone.utc)

    # Build a map of node -> pods for allocation analysis
    node_pods: dict[str, list] = {}
    for pod in snap.pods:
        node = pod.spec.node_name or ""
        if node:
            node_pods.setdefault(node, []).append(pod)

    # Build node metrics map
    node_metrics_map: dict[str, dict] = {}
    for nm in snap.node_metrics:
        name = nm.get("metadata", {}).get("name", "")
        if name:
            node_metrics_map[name] = nm

    for node in snap.nodes:
        name = node.metadata.name
        node_key = ResourceKey("Node", name)

        # --- Node conditions ---
        _check_conditions(result, node, node_key, now)

        # --- Unschedulable ---
        if node.spec.unschedulable:
            result.findings.append(
                Finding(
                    category=CheckCategory.NODES,
                    severity=Severity.WARNING,
                    resource=node_key,
                    message="Node is cordoned (unschedulable)",
                    details={"unschedulable": True},
                    evidence=[f"kubectl describe node {name}"],
                    remediation="If this is intentional (maintenance), no action needed. "
                    "Otherwise: `kubectl uncordon {name}`",
                )
            )

        # --- Taints that prevent all scheduling ---
        taints = node.spec.taints or []
        noschedule_taints = [t for t in taints if t.effect == "NoSchedule"]
        noexecute_taints = [t for t in taints if t.effect == "NoExecute"]
        if noexecute_taints:
            for taint in noexecute_taints:
                if taint.key in ("node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"):
                    continue  # These are system taints, handled by conditions
                result.findings.append(
                    Finding(
                        category=CheckCategory.NODES,
                        severity=Severity.WARNING,
                        resource=node_key,
                        message=f"NoExecute taint: {taint.key}={taint.value or ''}",
                        details={"taint_key": taint.key, "taint_value": taint.value, "effect": "NoExecute"},
                        evidence=[f"kubectl describe node {name} | grep -A5 Taints"],
                        remediation="NoExecute taints evict existing pods. Verify this is "
                        "intentional and that workloads have matching tolerations.",
                    )
                )

        # --- Resource allocation analysis ---
        _check_allocation(result, node, node_key, node_pods.get(name, []))

        # --- Actual usage from metrics-server ---
        metrics = node_metrics_map.get(name)
        if metrics:
            _check_metrics(result, node, node_key, metrics)

    return result


def _check_conditions(result: CheckResult, node, node_key: ResourceKey, now: datetime) -> None:
    """Check node conditions for unhealthy states."""
    conditions = node.status.conditions or []

    has_ready = False
    for cond in conditions:
        if cond.type == "Ready":
            has_ready = True
            if cond.status != "True":
                not_ready_min = 0.0
                if cond.last_transition_time:
                    not_ready_min = (now - cond.last_transition_time).total_seconds() / 60

                result.findings.append(
                    Finding(
                        category=CheckCategory.NODES,
                        severity=Severity.CRITICAL,
                        resource=node_key,
                        message=f"Node NotReady for {not_ready_min:.0f}m "
                        f"({cond.reason or 'unknown'})",
                        details={
                            "not_ready_minutes": round(not_ready_min),
                            "reason": cond.reason or "",
                            "message": cond.message or "",
                        },
                        evidence=[
                            f"kubectl describe node {node.metadata.name}",
                            f"kubectl get events --field-selector involvedObject.name={node.metadata.name}",
                        ],
                        remediation="Check kubelet status on the node, network connectivity, "
                        "and system resources. A NotReady node can't run new pods and "
                        "existing pods may be evicted.",
                    )
                )

        elif cond.type in ("MemoryPressure", "DiskPressure", "PIDPressure") and cond.status == "True":
            result.findings.append(
                Finding(
                    category=CheckCategory.NODES,
                    severity=Severity.CRITICAL,
                    resource=node_key,
                    message=f"Node under {cond.type}: {cond.message or cond.reason or ''}",
                    details={
                        "condition": cond.type,
                        "reason": cond.reason or "",
                        "message": cond.message or "",
                    },
                    evidence=[f"kubectl describe node {node.metadata.name}"],
                    remediation=_pressure_remediation(cond.type),
                )
            )

        elif cond.type == "NetworkUnavailable" and cond.status == "True":
            result.findings.append(
                Finding(
                    category=CheckCategory.NODES,
                    severity=Severity.CRITICAL,
                    resource=node_key,
                    message=f"Node network unavailable: {cond.message or cond.reason or ''}",
                    details={"reason": cond.reason or "", "message": cond.message or ""},
                    evidence=[f"kubectl describe node {node.metadata.name}"],
                    remediation="Check the CNI plugin (Calico, Flannel, etc.) status on this node. "
                    "The network plugin may need to be reinstalled or the node rebooted.",
                )
            )

    if not has_ready:
        result.findings.append(
            Finding(
                category=CheckCategory.NODES,
                severity=Severity.CRITICAL,
                resource=node_key,
                message="Node has no Ready condition - unusual state",
                evidence=[f"kubectl describe node {node.metadata.name}"],
            )
        )


def _check_allocation(
    result: CheckResult, node, node_key: ResourceKey, pods: list
) -> None:
    """Check how heavily resources are allocated on this node."""
    allocatable = node.status.allocatable or {}
    alloc_cpu = _parse_cpu(allocatable.get("cpu", "0"))
    alloc_mem = _parse_memory(allocatable.get("memory", "0"))

    if alloc_cpu == 0 or alloc_mem == 0:
        return

    # Sum up requests from all pods on this node
    req_cpu = 0.0
    req_mem = 0.0
    for pod in pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        for container in pod.spec.containers or []:
            resources = container.resources
            if resources and resources.requests:
                req_cpu += _parse_cpu(resources.requests.get("cpu", "0"))
                req_mem += _parse_memory(resources.requests.get("memory", "0"))

    cpu_pct = (req_cpu / alloc_cpu) * 100 if alloc_cpu else 0
    mem_pct = (req_mem / alloc_mem) * 100 if alloc_mem else 0

    if cpu_pct >= ALLOC_CRIT_PCT:
        severity = Severity.CRITICAL
    elif cpu_pct >= ALLOC_WARN_PCT:
        severity = Severity.WARNING
    else:
        severity = None

    if severity:
        result.findings.append(
            Finding(
                category=CheckCategory.NODES,
                severity=severity,
                resource=node_key,
                message=f"CPU allocation at {cpu_pct:.0f}% "
                f"({req_cpu:.1f} / {alloc_cpu:.1f} cores requested)",
                details={
                    "requested_cpu_cores": round(req_cpu, 2),
                    "allocatable_cpu_cores": round(alloc_cpu, 2),
                    "allocation_pct": round(cpu_pct, 1),
                    "pod_count": len(pods),
                },
                evidence=[f"kubectl describe node {node.metadata.name} | grep -A10 'Allocated resources'"],
                remediation="High CPU allocation means new pods may not schedule. "
                "Consider adding nodes or right-sizing pod CPU requests.",
            )
        )

    if mem_pct >= ALLOC_CRIT_PCT:
        severity = Severity.CRITICAL
    elif mem_pct >= ALLOC_WARN_PCT:
        severity = Severity.WARNING
    else:
        severity = None

    if severity:
        result.findings.append(
            Finding(
                category=CheckCategory.NODES,
                severity=severity,
                resource=node_key,
                message=f"Memory allocation at {mem_pct:.0f}% "
                f"({_fmt_memory(req_mem)} / {_fmt_memory(alloc_mem)} requested)",
                details={
                    "requested_memory_bytes": int(req_mem),
                    "allocatable_memory_bytes": int(alloc_mem),
                    "allocation_pct": round(mem_pct, 1),
                    "pod_count": len(pods),
                },
                evidence=[f"kubectl describe node {node.metadata.name} | grep -A10 'Allocated resources'"],
                remediation="High memory allocation means new pods may not schedule and "
                "existing pods risk OOM. Consider adding nodes or reducing memory requests.",
            )
        )


def _check_metrics(result: CheckResult, node, node_key: ResourceKey, metrics: dict) -> None:
    """Check actual resource usage from metrics-server."""
    usage = metrics.get("usage", {})
    allocatable = node.status.allocatable or {}

    if not usage:
        return

    actual_cpu = _parse_cpu(usage.get("cpu", "0"))
    actual_mem = _parse_memory(usage.get("memory", "0"))
    alloc_cpu = _parse_cpu(allocatable.get("cpu", "0"))
    alloc_mem = _parse_memory(allocatable.get("memory", "0"))

    if alloc_cpu > 0:
        usage_pct = (actual_cpu / alloc_cpu) * 100
        if usage_pct >= 90:
            result.findings.append(
                Finding(
                    category=CheckCategory.NODES,
                    severity=Severity.CRITICAL,
                    resource=node_key,
                    message=f"Actual CPU usage at {usage_pct:.0f}% "
                    f"({actual_cpu:.1f} / {alloc_cpu:.1f} cores)",
                    details={"actual_cpu": round(actual_cpu, 2), "usage_pct": round(usage_pct, 1)},
                    remediation="Node is CPU-saturated. Workloads will be throttled. "
                    "Consider scaling horizontally or moving workloads.",
                )
            )

    if alloc_mem > 0:
        usage_pct = (actual_mem / alloc_mem) * 100
        if usage_pct >= 90:
            result.findings.append(
                Finding(
                    category=CheckCategory.NODES,
                    severity=Severity.CRITICAL,
                    resource=node_key,
                    message=f"Actual memory usage at {usage_pct:.0f}% "
                    f"({_fmt_memory(actual_mem)} / {_fmt_memory(alloc_mem)})",
                    details={"actual_memory": int(actual_mem), "usage_pct": round(usage_pct, 1)},
                    remediation="Node is near memory exhaustion. OOM kills are likely. "
                    "Consider adding nodes or reducing workloads.",
                )
            )


# --- Helpers ---

def _parse_cpu(val: str | int | float) -> float:
    """Parse K8s CPU value to cores (float)."""
    s = str(val)
    if s.endswith("m"):
        return float(s[:-1]) / 1000
    if s.endswith("n"):
        return float(s[:-1]) / 1_000_000_000
    return float(s)


def _parse_memory(val: str | int | float) -> float:
    """Parse K8s memory value to bytes (float)."""
    s = str(val)
    suffixes = {
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
        "k": 1000,
        "m": 0.001,  # millibytes (edge case)
    }
    for suffix, multiplier in sorted(suffixes.items(), key=lambda x: -len(x[0])):
        if s.endswith(suffix):
            return float(s[: -len(suffix)]) * multiplier
    return float(s)


def _fmt_memory(bytes_val: float) -> str:
    """Format bytes to human-readable."""
    if bytes_val >= 1024**3:
        return f"{bytes_val / 1024**3:.1f}Gi"
    if bytes_val >= 1024**2:
        return f"{bytes_val / 1024**2:.0f}Mi"
    return f"{bytes_val / 1024:.0f}Ki"


def _pressure_remediation(condition_type: str) -> str:
    return {
        "MemoryPressure": "Node is running low on memory. Pods may be evicted. "
        "Check for memory-heavy workloads, consider adding memory or nodes.",
        "DiskPressure": "Node disk is nearly full. Pods may be evicted. "
        "Clean up images (`crictl rmi --prune`), check log volume, "
        "or increase disk size.",
        "PIDPressure": "Too many processes on the node. May indicate a fork bomb "
        "or too many pods. Check per-pod PID limits.",
    }.get(condition_type, "Investigate node resource pressure.")
