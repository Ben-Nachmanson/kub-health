"""Deployment / StatefulSet / DaemonSet health analyzer.

Detects: failed rollouts, replica mismatches, stale ReplicaSets, stuck
rollouts, degraded DaemonSets, unavailable StatefulSets.
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

ROLLOUT_STUCK_MIN = 10


def check_deployments(snap: ClusterSnapshot) -> CheckResult:
    """Analyze workload controllers for health issues."""
    result = CheckResult(category=CheckCategory.DEPLOYMENTS)
    now = datetime.now(timezone.utc)

    _check_deploys(result, snap, now)
    _check_statefulsets(result, snap, now)
    _check_daemonsets(result, snap, now)
    _check_stale_replicasets(result, snap)

    return result


def _check_deploys(result: CheckResult, snap: ClusterSnapshot, now: datetime) -> None:
    for dep in snap.deployments:
        meta = dep.metadata
        spec = dep.spec
        status = dep.status
        rk = ResourceKey("Deployment", meta.name, meta.namespace)

        desired = spec.replicas if spec.replicas is not None else 1
        ready = status.ready_replicas or 0
        available = status.available_replicas or 0
        updated = status.updated_replicas or 0
        total = status.replicas or 0

        # --- Zero replicas (scaled to 0) ---
        if desired == 0:
            continue

        # --- No ready replicas ---
        if ready == 0 and desired > 0:
            result.findings.append(
                Finding(
                    category=CheckCategory.DEPLOYMENTS,
                    severity=Severity.CRITICAL,
                    resource=rk,
                    message=f"No ready replicas (0/{desired})",
                    details={"desired": desired, "ready": ready, "available": available},
                    evidence=[
                        f"kubectl rollout status deployment/{meta.name} -n {meta.namespace}",
                        f"kubectl get pods -l app={meta.name} -n {meta.namespace}",
                    ],
                    remediation="Check pod status for this deployment. The pods may be "
                    "crashing, stuck pending, or failing health checks.",
                )
            )
            continue

        # --- Partial availability ---
        if ready < desired:
            severity = Severity.WARNING if ready > desired // 2 else Severity.CRITICAL
            result.findings.append(
                Finding(
                    category=CheckCategory.DEPLOYMENTS,
                    severity=severity,
                    resource=rk,
                    message=f"Degraded: {ready}/{desired} replicas ready",
                    details={
                        "desired": desired,
                        "ready": ready,
                        "available": available,
                        "updated": updated,
                    },
                    evidence=[
                        f"kubectl rollout status deployment/{meta.name} -n {meta.namespace}",
                    ],
                    remediation="Some replicas are not ready. Check individual pod status "
                    "for crash loops, pending state, or readiness probe failures.",
                )
            )

        # --- Stuck rollout (updated != desired for too long) ---
        if updated < desired or total > desired:
            conditions = status.conditions or []
            for cond in conditions:
                if cond.type == "Progressing" and cond.status == "False":
                    result.findings.append(
                        Finding(
                            category=CheckCategory.DEPLOYMENTS,
                            severity=Severity.CRITICAL,
                            resource=rk,
                            message=f"Rollout stuck: {cond.reason or 'unknown'} "
                            f"- {cond.message or ''}",
                            details={
                                "reason": cond.reason or "",
                                "updated": updated,
                                "desired": desired,
                                "total_replicas": total,
                            },
                            evidence=[
                                f"kubectl rollout status deployment/{meta.name} -n {meta.namespace}",
                                f"kubectl rollout history deployment/{meta.name} -n {meta.namespace}",
                            ],
                            remediation="The deployment rollout is stuck. Consider rolling "
                            "back: `kubectl rollout undo deployment/{name} -n {ns}`".format(
                                name=meta.name, ns=meta.namespace
                            ),
                        )
                    )
                    break


def _check_statefulsets(result: CheckResult, snap: ClusterSnapshot, now: datetime) -> None:
    for sts in snap.statefulsets:
        meta = sts.metadata
        spec = sts.spec
        status = sts.status
        rk = ResourceKey("StatefulSet", meta.name, meta.namespace)

        desired = spec.replicas if spec.replicas is not None else 1
        ready = status.ready_replicas or 0

        if desired == 0:
            continue

        if ready == 0 and desired > 0:
            result.findings.append(
                Finding(
                    category=CheckCategory.DEPLOYMENTS,
                    severity=Severity.CRITICAL,
                    resource=rk,
                    message=f"StatefulSet has no ready replicas (0/{desired})",
                    details={"desired": desired, "ready": ready},
                    evidence=[
                        f"kubectl rollout status statefulset/{meta.name} -n {meta.namespace}",
                    ],
                    remediation="Check pod status. StatefulSets roll out sequentially, "
                    "so a single bad pod blocks the entire rollout.",
                )
            )
        elif ready < desired:
            result.findings.append(
                Finding(
                    category=CheckCategory.DEPLOYMENTS,
                    severity=Severity.WARNING,
                    resource=rk,
                    message=f"StatefulSet degraded: {ready}/{desired} replicas ready",
                    details={"desired": desired, "ready": ready},
                    evidence=[
                        f"kubectl get pods -l app={meta.name} -n {meta.namespace}",
                    ],
                )
            )


def _check_daemonsets(result: CheckResult, snap: ClusterSnapshot, now: datetime) -> None:
    for ds in snap.daemonsets:
        meta = ds.metadata
        status = ds.status
        rk = ResourceKey("DaemonSet", meta.name, meta.namespace)

        desired = status.desired_number_scheduled or 0
        ready = status.number_ready or 0
        misscheduled = status.number_misscheduled or 0

        if desired == 0:
            continue

        if ready < desired:
            missing = desired - ready
            severity = Severity.WARNING if missing <= desired // 4 else Severity.CRITICAL
            result.findings.append(
                Finding(
                    category=CheckCategory.DEPLOYMENTS,
                    severity=severity,
                    resource=rk,
                    message=f"DaemonSet missing pods on {missing}/{desired} nodes "
                    f"({ready} ready)",
                    details={
                        "desired": desired,
                        "ready": ready,
                        "missing": missing,
                        "misscheduled": misscheduled,
                    },
                    evidence=[
                        f"kubectl get pods -l app={meta.name} -n {meta.namespace} -o wide",
                    ],
                    remediation="Check node taints/tolerations and pod status on affected "
                    "nodes. DaemonSets should run on every eligible node.",
                )
            )

        if misscheduled > 0:
            result.findings.append(
                Finding(
                    category=CheckCategory.DEPLOYMENTS,
                    severity=Severity.WARNING,
                    resource=rk,
                    message=f"DaemonSet has {misscheduled} mis-scheduled pods",
                    details={"misscheduled": misscheduled},
                )
            )


def _check_stale_replicasets(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Detect old ReplicaSets with non-zero replicas (failed rollback cleanup)."""
    # Map deployment -> latest RS revision
    deploy_revisions: dict[str, int] = {}
    for rs in snap.replicasets:
        if not rs.metadata.owner_references:
            continue
        for owner in rs.metadata.owner_references:
            if owner.kind == "Deployment":
                rev = int(rs.metadata.annotations.get("deployment.kubernetes.io/revision", "0"))
                key = f"{rs.metadata.namespace}/{owner.name}"
                deploy_revisions[key] = max(deploy_revisions.get(key, 0), rev)

    for rs in snap.replicasets:
        if not rs.metadata.owner_references:
            continue
        if (rs.status.replicas or 0) == 0:
            continue

        for owner in rs.metadata.owner_references:
            if owner.kind == "Deployment":
                rev = int(rs.metadata.annotations.get("deployment.kubernetes.io/revision", "0"))
                key = f"{rs.metadata.namespace}/{owner.name}"
                latest = deploy_revisions.get(key, 0)
                if rev < latest and rev > 0:
                    result.findings.append(
                        Finding(
                            category=CheckCategory.DEPLOYMENTS,
                            severity=Severity.INFO,
                            resource=ResourceKey("ReplicaSet", rs.metadata.name, rs.metadata.namespace),
                            message=f"Old ReplicaSet (rev {rev}, latest {latest}) still has "
                            f"{rs.status.replicas} replicas - possible stuck rollout",
                            details={
                                "revision": rev,
                                "latest_revision": latest,
                                "replicas": rs.status.replicas,
                                "deployment": owner.name,
                            },
                            related_resources=[
                                ResourceKey("Deployment", owner.name, rs.metadata.namespace)
                            ],
                        )
                    )
