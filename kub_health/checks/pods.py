"""Pod health analyzer.

Detects: CrashLoopBackOff, OOMKilled, ImagePullBackOff, high restarts, stuck
pending, unready pods, init container failures, sidecar issues.
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

RESTART_WARN = 5
RESTART_CRIT = 20
PENDING_WARN_MIN = 5
PENDING_CRIT_MIN = 15
UNREADY_WARN_MIN = 5


def check_pods(snap: ClusterSnapshot) -> CheckResult:
    """Analyze all pods in the snapshot for health issues."""
    result = CheckResult(category=CheckCategory.PODS)
    now = datetime.now(timezone.utc)

    for pod in snap.pods:
        meta = pod.metadata
        status = pod.status
        pod_key = ResourceKey("Pod", meta.name, meta.namespace)
        node_key = ResourceKey("Node", pod.spec.node_name or "unscheduled")

        phase = status.phase or "Unknown"

        # --- Pending pods ---
        if phase == "Pending":
            _check_pending(result, pod, pod_key, node_key, now)
            continue

        # --- Failed pods ---
        if phase == "Failed":
            reason = status.reason or ""
            msg = status.message or "Pod failed"
            result.findings.append(
                Finding(
                    category=CheckCategory.PODS,
                    severity=Severity.CRITICAL,
                    resource=pod_key,
                    message=f"Pod in Failed state: {reason} - {msg}",
                    details={"phase": phase, "reason": reason},
                    related_resources=[node_key],
                    remediation="Check pod events and logs. If Evicted, review node "
                    "resource pressure. If Error, check the container exit codes.",
                )
            )
            continue

        # --- Container status checks ---
        all_cs = []
        for cs in status.container_statuses or []:
            all_cs.append(("container", cs))
        for cs in status.init_container_statuses or []:
            all_cs.append(("init-container", cs))

        for container_kind, cs in all_cs:
            _check_container_status(result, pod_key, node_key, container_kind, cs, meta)

        # --- Readiness check ---
        _check_readiness(result, pod, pod_key, node_key, now)

    return result


def _check_pending(
    result: CheckResult, pod, pod_key: ResourceKey, node_key: ResourceKey, now: datetime
) -> None:
    """Check pending pods for scheduling issues."""
    conditions = pod.status.conditions or []
    schedule_reason = ""
    schedule_msg = ""
    for cond in conditions:
        if cond.type == "PodScheduled" and cond.status == "False":
            schedule_reason = cond.reason or "Unknown"
            schedule_msg = cond.message or ""
            break

    pending_min = 0.0
    if pod.metadata.creation_timestamp:
        pending_min = (now - pod.metadata.creation_timestamp).total_seconds() / 60

    if pending_min < PENDING_WARN_MIN:
        severity = Severity.INFO
    elif pending_min < PENDING_CRIT_MIN:
        severity = Severity.WARNING
    else:
        severity = Severity.CRITICAL

    # Identify related resources (e.g., PVCs the pod wants)
    related = [node_key]
    for vol in pod.spec.volumes or []:
        if vol.persistent_volume_claim:
            related.append(
                ResourceKey("PVC", vol.persistent_volume_claim.claim_name, pod.metadata.namespace)
            )

    result.findings.append(
        Finding(
            category=CheckCategory.PODS,
            severity=severity,
            resource=pod_key,
            message=f"Pending for {pending_min:.0f}m - {schedule_reason}: {schedule_msg}"
            if schedule_reason
            else f"Pending for {pending_min:.0f}m",
            details={
                "pending_minutes": round(pending_min),
                "schedule_reason": schedule_reason,
                "schedule_message": schedule_msg,
            },
            related_resources=related,
            evidence=[
                f"kubectl describe pod {pod.metadata.name} -n {pod.metadata.namespace}",
                f"kubectl get events -n {pod.metadata.namespace} --field-selector involvedObject.name={pod.metadata.name}",
            ],
            remediation="Common causes: insufficient CPU/memory on nodes, unsatisfiable "
            "node affinity/selectors, taints without tolerations, unbound PVCs, "
            "or ResourceQuota limits reached.",
        )
    )


def _check_container_status(
    result: CheckResult,
    pod_key: ResourceKey,
    node_key: ResourceKey,
    container_kind: str,
    cs,
    meta,
) -> None:
    """Check a single container status for issues."""
    cname = cs.name

    # --- Waiting state issues ---
    if cs.state and cs.state.waiting:
        reason = cs.state.waiting.reason or ""
        wait_msg = cs.state.waiting.message or ""

        if reason == "CrashLoopBackOff":
            result.findings.append(
                Finding(
                    category=CheckCategory.PODS,
                    severity=Severity.CRITICAL,
                    resource=pod_key,
                    message=f"{container_kind} '{cname}' in CrashLoopBackOff "
                    f"({cs.restart_count} restarts)",
                    details={
                        "container": cname,
                        "container_kind": container_kind,
                        "restart_count": cs.restart_count,
                        "image": cs.image,
                    },
                    related_resources=[node_key],
                    evidence=[
                        f"kubectl logs {meta.name} -c {cname} -n {meta.namespace} --previous",
                        f"kubectl describe pod {meta.name} -n {meta.namespace}",
                    ],
                    remediation="Check previous container logs for crash reason. Common causes: "
                    "app crash at startup, missing config/secrets, bad entrypoint, "
                    "health check failing immediately.",
                )
            )

        elif reason in ("ImagePullBackOff", "ErrImagePull", "InvalidImageName"):
            result.findings.append(
                Finding(
                    category=CheckCategory.PODS,
                    severity=Severity.CRITICAL,
                    resource=pod_key,
                    message=f"{container_kind} '{cname}' image pull failure: {reason}",
                    details={
                        "container": cname,
                        "reason": reason,
                        "image": cs.image,
                        "message": wait_msg,
                    },
                    related_resources=[node_key],
                    evidence=[
                        f"kubectl describe pod {meta.name} -n {meta.namespace}",
                    ],
                    remediation="Verify image name/tag, check imagePullSecrets, ensure "
                    "registry is reachable from the node. For private registries, "
                    "confirm the pull secret exists in the pod's namespace.",
                )
            )

        elif reason == "CreateContainerConfigError":
            result.findings.append(
                Finding(
                    category=CheckCategory.PODS,
                    severity=Severity.CRITICAL,
                    resource=pod_key,
                    message=f"{container_kind} '{cname}' config error: {wait_msg}",
                    details={"container": cname, "reason": reason, "message": wait_msg},
                    related_resources=[node_key],
                    evidence=[
                        f"kubectl describe pod {meta.name} -n {meta.namespace}",
                    ],
                    remediation="A referenced ConfigMap, Secret, or ServiceAccount "
                    "likely doesn't exist. Check the pod spec for volume mounts "
                    "and env var references.",
                )
            )

        elif reason and reason not in ("ContainerCreating", "PodInitializing"):
            # Catch other unexpected waiting states
            result.findings.append(
                Finding(
                    category=CheckCategory.PODS,
                    severity=Severity.WARNING,
                    resource=pod_key,
                    message=f"{container_kind} '{cname}' waiting: {reason} - {wait_msg}",
                    details={"container": cname, "reason": reason, "message": wait_msg},
                    related_resources=[node_key],
                )
            )

    # --- OOMKilled (last termination) ---
    if cs.last_state and cs.last_state.terminated:
        term = cs.last_state.terminated
        if term.reason == "OOMKilled":
            result.findings.append(
                Finding(
                    category=CheckCategory.PODS,
                    severity=Severity.CRITICAL,
                    resource=pod_key,
                    message=f"{container_kind} '{cname}' was OOMKilled "
                    f"(exit code {term.exit_code}, {cs.restart_count} restarts)",
                    details={
                        "container": cname,
                        "exit_code": term.exit_code,
                        "restart_count": cs.restart_count,
                        "finished_at": str(term.finished_at) if term.finished_at else "",
                    },
                    related_resources=[node_key],
                    evidence=[
                        f"kubectl logs {meta.name} -c {cname} -n {meta.namespace} --previous",
                    ],
                    remediation="Increase memory limits or investigate the application for "
                    "memory leaks. Check if memory requests match actual usage patterns.",
                )
            )
        elif term.exit_code != 0 and term.reason not in ("Completed",):
            result.findings.append(
                Finding(
                    category=CheckCategory.PODS,
                    severity=Severity.WARNING,
                    resource=pod_key,
                    message=f"{container_kind} '{cname}' last terminated: "
                    f"{term.reason} (exit {term.exit_code})",
                    details={
                        "container": cname,
                        "reason": term.reason,
                        "exit_code": term.exit_code,
                        "restart_count": cs.restart_count,
                    },
                    related_resources=[node_key],
                )
            )

    # --- High restart count (not already flagged as CrashLoop) ---
    if cs.restart_count >= RESTART_WARN:
        already_crashloop = any(
            f.resource == pod_key and "CrashLoopBackOff" in f.message
            for f in result.findings
        )
        if not already_crashloop:
            severity = Severity.CRITICAL if cs.restart_count >= RESTART_CRIT else Severity.WARNING
            result.findings.append(
                Finding(
                    category=CheckCategory.PODS,
                    severity=severity,
                    resource=pod_key,
                    message=f"{container_kind} '{cname}' has {cs.restart_count} restarts",
                    details={
                        "container": cname,
                        "restart_count": cs.restart_count,
                        "container_kind": container_kind,
                    },
                    related_resources=[node_key],
                    evidence=[
                        f"kubectl logs {meta.name} -c {cname} -n {meta.namespace} --previous",
                    ],
                    remediation="Investigate container restart history. May indicate "
                    "intermittent crashes, liveness probe failures, or resource limits.",
                )
            )


def _check_readiness(
    result: CheckResult, pod, pod_key: ResourceKey, node_key: ResourceKey, now: datetime
) -> None:
    """Check if a running pod has containers that aren't ready."""
    if pod.status.phase != "Running":
        return

    conditions = pod.status.conditions or []
    for cond in conditions:
        if cond.type == "Ready" and cond.status == "False":
            unready_min = 0.0
            if cond.last_transition_time:
                unready_min = (now - cond.last_transition_time).total_seconds() / 60

            if unready_min < UNREADY_WARN_MIN:
                continue

            severity = Severity.WARNING if unready_min < 30 else Severity.CRITICAL
            result.findings.append(
                Finding(
                    category=CheckCategory.PODS,
                    severity=severity,
                    resource=pod_key,
                    message=f"Pod running but not Ready for {unready_min:.0f}m "
                    f"({cond.reason or 'unknown reason'})",
                    details={
                        "unready_minutes": round(unready_min),
                        "reason": cond.reason or "",
                        "message": cond.message or "",
                    },
                    related_resources=[node_key],
                    evidence=[
                        f"kubectl describe pod {pod.metadata.name} -n {pod.metadata.namespace}",
                    ],
                    remediation="Check readiness probe configuration. The pod is running "
                    "but failing its readiness check, so it won't receive traffic.",
                )
            )
            break
