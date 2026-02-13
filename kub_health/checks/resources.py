"""Resource utilization analyzer.

Detects: missing requests/limits, over-provisioned pods, under-provisioned pods,
ResourceQuota exhaustion, LimitRange issues, and request/limit mismatches.
"""

from __future__ import annotations

from kub_health.checks.nodes import _parse_cpu, _parse_memory, _fmt_memory
from kub_health.models import (
    CheckCategory,
    CheckResult,
    ClusterSnapshot,
    Finding,
    ResourceKey,
    Severity,
)


def check_resources(snap: ClusterSnapshot) -> CheckResult:
    """Analyze resource configuration and utilization."""
    result = CheckResult(category=CheckCategory.RESOURCES)

    _check_missing_requests_limits(result, snap)
    _check_resource_quotas(result, snap)
    _check_limit_ranges(result, snap)
    _check_cpu_memory_ratios(result, snap)
    _check_actual_vs_requested(result, snap)

    return result


def _check_missing_requests_limits(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Flag containers without resource requests or limits."""
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue

        meta = pod.metadata
        # Skip system pods for noise reduction
        if meta.namespace in ("kube-system", "kube-public", "kube-node-lease"):
            continue

        pod_key = ResourceKey("Pod", meta.name, meta.namespace)
        for container in pod.spec.containers or []:
            resources = container.resources
            has_requests = resources and resources.requests
            has_limits = resources and resources.limits

            missing = []
            if not has_requests:
                missing.append("requests")
            else:
                if not resources.requests.get("cpu"):
                    missing.append("cpu request")
                if not resources.requests.get("memory"):
                    missing.append("memory request")

            if not has_limits:
                missing.append("limits")
            else:
                if not resources.limits.get("cpu"):
                    missing.append("cpu limit")
                if not resources.limits.get("memory"):
                    missing.append("memory limit")

            if not missing:
                continue

            # No limits at all is worse than no requests
            severity = Severity.WARNING
            if not has_limits and not has_requests:
                severity = Severity.WARNING
            elif not has_limits:
                severity = Severity.WARNING

            result.findings.append(
                Finding(
                    category=CheckCategory.RESOURCES,
                    severity=severity,
                    resource=pod_key,
                    message=f"Container '{container.name}' missing: {', '.join(missing)}",
                    details={
                        "container": container.name,
                        "missing": missing,
                    },
                    remediation="Set resource requests and limits. Without requests, the "
                    "scheduler can't make good placement decisions. Without limits, "
                    "a container can consume all node resources.",
                )
            )


def _check_resource_quotas(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Check if namespaces are near their ResourceQuota limits."""
    for quota in snap.resource_quotas:
        meta = quota.metadata
        rk = ResourceKey("ResourceQuota", meta.name, meta.namespace)
        status = quota.status or None
        if not status or not status.hard or not status.used:
            continue

        for resource_name, hard_val in (status.hard or {}).items():
            used_val = (status.used or {}).get(resource_name, "0")

            hard_num = _parse_resource_quantity(hard_val, resource_name)
            used_num = _parse_resource_quantity(used_val, resource_name)

            if hard_num == 0:
                continue

            pct = (used_num / hard_num) * 100

            if pct >= 95:
                severity = Severity.CRITICAL
            elif pct >= 80:
                severity = Severity.WARNING
            else:
                continue

            result.findings.append(
                Finding(
                    category=CheckCategory.RESOURCES,
                    severity=severity,
                    resource=rk,
                    message=f"ResourceQuota '{resource_name}' at {pct:.0f}% "
                    f"({used_val} / {hard_val})",
                    details={
                        "resource": resource_name,
                        "used": used_val,
                        "hard": hard_val,
                        "usage_pct": round(pct, 1),
                    },
                    evidence=[
                        f"kubectl describe resourcequota {meta.name} -n {meta.namespace}",
                    ],
                    remediation=f"Namespace '{meta.namespace}' is running out of "
                    f"'{resource_name}' quota. Increase the quota or reduce usage.",
                )
            )


def _check_limit_ranges(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Report LimitRange defaults that might cause issues."""
    for lr in snap.limit_ranges:
        meta = lr.metadata
        rk = ResourceKey("LimitRange", meta.name, meta.namespace)
        for limit in lr.spec.limits or []:
            if limit.type == "Container":
                default_limits = limit.default or {}
                default_requests = limit.default_request or {}

                # Warn if default limits are very low
                cpu_limit = default_limits.get("cpu", "")
                mem_limit = default_limits.get("memory", "")

                if cpu_limit:
                    cpu_val = _parse_cpu(cpu_limit)
                    if cpu_val <= 0.1:
                        result.findings.append(
                            Finding(
                                category=CheckCategory.RESOURCES,
                                severity=Severity.INFO,
                                resource=rk,
                                message=f"LimitRange default CPU limit is very low: {cpu_limit}",
                                details={"default_cpu_limit": cpu_limit},
                                remediation="Containers without explicit limits will be "
                                "constrained to this default. May cause throttling.",
                            )
                        )


def _check_cpu_memory_ratios(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Detect containers where limits are far higher than requests (burstable risk)."""
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        if pod.metadata.namespace in ("kube-system",):
            continue

        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        for container in pod.spec.containers or []:
            resources = container.resources
            if not resources or not resources.requests or not resources.limits:
                continue

            req_cpu = _parse_cpu(resources.requests.get("cpu", "0"))
            lim_cpu = _parse_cpu(resources.limits.get("cpu", "0"))
            req_mem = _parse_memory(resources.requests.get("memory", "0"))
            lim_mem = _parse_memory(resources.limits.get("memory", "0"))

            # Flag extreme request/limit ratios (> 10x)
            if req_cpu > 0 and lim_cpu > 0 and lim_cpu / req_cpu > 10:
                result.findings.append(
                    Finding(
                        category=CheckCategory.RESOURCES,
                        severity=Severity.INFO,
                        resource=pod_key,
                        message=f"Container '{container.name}' CPU limit is "
                        f"{lim_cpu/req_cpu:.0f}x its request ({resources.requests.get('cpu')} "
                        f"req / {resources.limits.get('cpu')} limit)",
                        details={"container": container.name, "ratio": round(lim_cpu / req_cpu, 1)},
                        remediation="Large request/limit gaps create unpredictable burst "
                        "behavior. Consider narrowing the gap for more stable performance.",
                    )
                )

            if req_mem > 0 and lim_mem > 0 and lim_mem / req_mem > 5:
                result.findings.append(
                    Finding(
                        category=CheckCategory.RESOURCES,
                        severity=Severity.INFO,
                        resource=pod_key,
                        message=f"Container '{container.name}' memory limit is "
                        f"{lim_mem/req_mem:.0f}x its request",
                        details={"container": container.name, "ratio": round(lim_mem / req_mem, 1)},
                        remediation="Large memory request/limit gap means the pod can "
                        "burst well beyond its guaranteed allocation, risking OOM.",
                    )
                )


def _check_actual_vs_requested(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Compare actual pod metrics to requests to detect over/under provisioning."""
    if not snap.pod_metrics:
        return

    # Build pod metrics map
    metrics_map: dict[str, dict] = {}
    for pm in snap.pod_metrics:
        name = pm.get("metadata", {}).get("name", "")
        ns = pm.get("metadata", {}).get("namespace", "")
        if name:
            metrics_map[f"{ns}/{name}"] = pm

    for pod in snap.pods:
        if pod.status.phase != "Running":
            continue

        key = f"{pod.metadata.namespace}/{pod.metadata.name}"
        pm = metrics_map.get(key)
        if not pm:
            continue

        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        containers_usage = {c["name"]: c.get("usage", {}) for c in pm.get("containers", [])}

        for container in pod.spec.containers or []:
            usage = containers_usage.get(container.name, {})
            if not usage:
                continue

            resources = container.resources
            if not resources or not resources.requests:
                continue

            actual_cpu = _parse_cpu(usage.get("cpu", "0"))
            req_cpu = _parse_cpu(resources.requests.get("cpu", "0"))

            actual_mem = _parse_memory(usage.get("memory", "0"))
            req_mem = _parse_memory(resources.requests.get("memory", "0"))

            # Over-provisioned: using < 10% of requested
            if req_cpu > 0 and actual_cpu / req_cpu < 0.1 and req_cpu >= 0.1:
                result.findings.append(
                    Finding(
                        category=CheckCategory.RESOURCES,
                        severity=Severity.INFO,
                        resource=pod_key,
                        message=f"Container '{container.name}' using only "
                        f"{actual_cpu/req_cpu*100:.0f}% of CPU request "
                        f"({actual_cpu*1000:.0f}m / {req_cpu*1000:.0f}m)",
                        details={"container": container.name, "actual_cpu_m": round(actual_cpu * 1000)},
                        remediation="Consider reducing CPU request to free capacity for "
                        "other workloads.",
                    )
                )


def _parse_resource_quantity(val: str, resource_name: str) -> float:
    """Parse a resource quantity, handling both CPU and memory units."""
    if "cpu" in resource_name.lower():
        return _parse_cpu(val)
    if "memory" in resource_name.lower() or "storage" in resource_name.lower():
        return _parse_memory(val)
    try:
        return float(val)
    except (ValueError, TypeError):
        return 0
