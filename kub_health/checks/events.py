"""Events & warnings analyzer.

Detects: recurring warning events, frequent events, back-off events,
failed scheduling, failed mounts, and other cluster-level warnings.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from kub_health.models import (
    CheckCategory,
    CheckResult,
    ClusterSnapshot,
    Finding,
    ResourceKey,
    Severity,
)

# Events with high counts are suspicious
HIGH_COUNT_WARN = 10
HIGH_COUNT_CRIT = 50

# Warning reasons that indicate real problems
CRITICAL_REASONS = {
    "FailedScheduling",
    "FailedMount",
    "FailedAttachVolume",
    "FailedCreate",
    "Unhealthy",
    "BackOff",
    "Evicted",
    "OOMKilling",
    "NodeNotReady",
    "Rebooted",
    "SystemOOM",
    "FreeDiskSpaceFailed",
    "EvictionThresholdMet",
    "NetworkNotReady",
}

NOISE_REASONS = {
    "Pulling",
    "Pulled",
    "Scheduled",
    "Started",
    "Created",
    "SuccessfulCreate",
    "Killing",
}


def check_events(snap: ClusterSnapshot) -> CheckResult:
    """Analyze cluster events for warning patterns."""
    result = CheckResult(category=CheckCategory.EVENTS)
    now = datetime.now(timezone.utc)

    # Group events by involved object + reason
    event_groups: dict[str, list] = defaultdict(list)
    warning_events = []

    for event in snap.events:
        if event.type == "Normal" and event.reason in NOISE_REASONS:
            continue

        obj = event.involved_object
        key = f"{obj.kind}/{obj.namespace or ''}/{obj.name}:{event.reason}"
        event_groups[key].append(event)

        if event.type == "Warning":
            warning_events.append(event)

    # --- High-frequency warning events ---
    for key, events in event_groups.items():
        total_count = sum(e.count or 1 for e in events)
        if total_count < HIGH_COUNT_WARN:
            continue

        sample = events[0]
        obj = sample.involved_object
        rk = ResourceKey(obj.kind or "Unknown", obj.name or "unknown", obj.namespace or "")

        severity = Severity.CRITICAL if total_count >= HIGH_COUNT_CRIT else Severity.WARNING

        # Latest event message
        latest = max(events, key=lambda e: e.last_timestamp or e.metadata.creation_timestamp or now)
        msg = latest.message or ""

        result.findings.append(
            Finding(
                category=CheckCategory.EVENTS,
                severity=severity,
                resource=rk,
                message=f"Event '{sample.reason}' occurred {total_count} times: {msg[:200]}",
                details={
                    "reason": sample.reason,
                    "total_count": total_count,
                    "event_type": sample.type,
                    "source": f"{sample.source.component or ''}/{sample.source.host or ''}"
                    if sample.source
                    else "",
                },
                evidence=[
                    f"kubectl get events -n {obj.namespace or 'default'} "
                    f"--field-selector involvedObject.name={obj.name}",
                ],
            )
        )

    # --- Critical warning events (even low count) ---
    for event in warning_events:
        if event.reason not in CRITICAL_REASONS:
            continue
        if (event.count or 1) >= HIGH_COUNT_WARN:
            continue  # Already handled above

        obj = event.involved_object
        rk = ResourceKey(obj.kind or "Unknown", obj.name or "unknown", obj.namespace or "")
        count = event.count or 1

        # Determine age
        event_time = event.last_timestamp or event.metadata.creation_timestamp
        age_min = (now - event_time).total_seconds() / 60 if event_time else 0

        # Only flag recent events (last 30 minutes)
        if age_min > 30:
            continue

        result.findings.append(
            Finding(
                category=CheckCategory.EVENTS,
                severity=Severity.WARNING,
                resource=rk,
                message=f"{event.reason} ({count}x, {age_min:.0f}m ago): "
                f"{(event.message or '')[:200]}",
                details={
                    "reason": event.reason,
                    "count": count,
                    "age_minutes": round(age_min),
                    "message": event.message or "",
                },
                evidence=[
                    f"kubectl describe {obj.kind.lower()} {obj.name} -n {obj.namespace or 'default'}",
                ],
                remediation=_event_remediation(event.reason),
            )
        )

    return result


def _event_remediation(reason: str) -> str:
    remediations = {
        "FailedScheduling": "Check node resources, affinity rules, taints/tolerations, "
        "and resource quotas.",
        "FailedMount": "Verify the volume exists, PVC is bound, and the node can access "
        "the storage backend.",
        "FailedAttachVolume": "Check if the volume is already attached to another node "
        "(common with RWO volumes). Verify the storage driver.",
        "Unhealthy": "Readiness or liveness probe is failing. Check probe configuration "
        "and application health.",
        "BackOff": "Container is repeatedly crashing. Check logs for crash reason.",
        "Evicted": "Pod was evicted due to node resource pressure. Check node disk and memory.",
        "OOMKilling": "Process was killed by the OOM killer. Increase memory limits.",
        "NodeNotReady": "Node lost contact with the control plane. Check kubelet and network.",
        "SystemOOM": "System-level OOM event. The node is critically low on memory.",
        "EvictionThresholdMet": "Node hit eviction threshold. Pods will be evicted. "
        "Check node disk and memory usage.",
    }
    return remediations.get(reason, "")
