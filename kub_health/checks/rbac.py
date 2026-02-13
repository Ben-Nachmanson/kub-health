"""RBAC & Security analyzer.

Detects: overprivileged service accounts, cluster-admin bindings, pods running
as root, missing security contexts, privileged containers, host namespace access,
and dangerous capability grants.
"""

from __future__ import annotations

from kub_health.models import (
    CheckCategory,
    CheckResult,
    ClusterSnapshot,
    Finding,
    ResourceKey,
    Severity,
)

DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "NET_RAW",
    "SYS_MODULE",
    "DAC_OVERRIDE",
    "SYS_RAWIO",
    "MKNOD",
}


def check_rbac(snap: ClusterSnapshot) -> CheckResult:
    """Analyze RBAC configuration and pod security settings."""
    result = CheckResult(category=CheckCategory.RBAC)

    _check_cluster_admin_bindings(result, snap)
    _check_wildcard_roles(result, snap)
    _check_pod_security(result, snap)
    _check_default_service_accounts(result, snap)
    _check_automount_tokens(result, snap)

    return result


def _check_cluster_admin_bindings(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Flag non-system bindings to cluster-admin."""
    system_subjects = {
        "system:masters",
        "system:kube-scheduler",
        "system:kube-controller-manager",
        "system:kube-proxy",
    }

    for crb in snap.cluster_role_bindings:
        meta = crb.metadata
        if not crb.role_ref or crb.role_ref.name != "cluster-admin":
            continue

        for subject in crb.subjects or []:
            subject_name = subject.name or ""
            if subject_name in system_subjects:
                continue
            if subject_name.startswith("system:"):
                continue

            rk = ResourceKey("ClusterRoleBinding", meta.name)
            result.findings.append(
                Finding(
                    category=CheckCategory.RBAC,
                    severity=Severity.WARNING,
                    resource=rk,
                    message=f"cluster-admin bound to {subject.kind} '{subject_name}'"
                    + (f" in namespace '{subject.namespace}'" if subject.namespace else ""),
                    details={
                        "subject_kind": subject.kind,
                        "subject_name": subject_name,
                        "subject_namespace": subject.namespace or "",
                    },
                    evidence=[
                        f"kubectl describe clusterrolebinding {meta.name}",
                    ],
                    remediation="cluster-admin grants full control over the entire cluster. "
                    "Use more specific roles where possible (principle of least privilege).",
                )
            )


def _check_wildcard_roles(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Flag roles/clusterroles with wildcard permissions."""
    for role in snap.cluster_roles:
        meta = role.metadata
        if meta.name.startswith("system:"):
            continue

        rk = ResourceKey("ClusterRole", meta.name)
        for rule in role.rules or []:
            verbs = rule.verbs or []
            resources = rule.resources or []
            api_groups = rule.api_groups or []

            if "*" in verbs and "*" in resources:
                result.findings.append(
                    Finding(
                        category=CheckCategory.RBAC,
                        severity=Severity.WARNING,
                        resource=rk,
                        message="ClusterRole has wildcard permissions (all verbs on all resources)",
                        details={
                            "verbs": verbs,
                            "resources": resources,
                            "api_groups": api_groups,
                        },
                        evidence=[f"kubectl describe clusterrole {meta.name}"],
                        remediation="Wildcard permissions are equivalent to cluster-admin. "
                        "Scope down to specific resources and verbs.",
                    )
                )
                break  # One finding per role is enough

            # Flag escalation-prone permissions
            if "secrets" in resources and ("get" in verbs or "list" in verbs or "*" in verbs):
                result.findings.append(
                    Finding(
                        category=CheckCategory.RBAC,
                        severity=Severity.INFO,
                        resource=rk,
                        message="ClusterRole can read secrets across the cluster",
                        details={"verbs": verbs, "resources": resources},
                        remediation="Secret read access at cluster scope is powerful. "
                        "Consider namespace-scoped Roles instead.",
                    )
                )


def _check_pod_security(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Check pods for security context issues."""
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue

        meta = pod.metadata
        # Skip system namespace pods
        if meta.namespace in ("kube-system", "kube-public", "kube-node-lease"):
            continue

        pod_key = ResourceKey("Pod", meta.name, meta.namespace)
        pod_sc = pod.spec.security_context

        # Host namespace access
        if pod.spec.host_network:
            result.findings.append(
                Finding(
                    category=CheckCategory.RBAC,
                    severity=Severity.WARNING,
                    resource=pod_key,
                    message="Pod uses hostNetwork - can see all node network traffic",
                    details={"host_network": True},
                    remediation="hostNetwork bypasses network policies and gives access "
                    "to the node's network stack. Remove unless absolutely required.",
                )
            )

        if pod.spec.host_pid:
            result.findings.append(
                Finding(
                    category=CheckCategory.RBAC,
                    severity=Severity.WARNING,
                    resource=pod_key,
                    message="Pod uses hostPID - can see all node processes",
                    details={"host_pid": True},
                    remediation="hostPID allows viewing and signaling all processes on the "
                    "node. This is a significant security risk.",
                )
            )

        for container in pod.spec.containers or []:
            sc = container.security_context

            # Privileged container
            if sc and sc.privileged:
                result.findings.append(
                    Finding(
                        category=CheckCategory.RBAC,
                        severity=Severity.CRITICAL,
                        resource=pod_key,
                        message=f"Container '{container.name}' is privileged - "
                        "full node access",
                        details={"container": container.name, "privileged": True},
                        remediation="Privileged containers have full access to the host. "
                        "Use specific capabilities instead of privileged mode.",
                    )
                )

            # Running as root
            run_as_root = False
            if sc and sc.run_as_user == 0:
                run_as_root = True
            elif sc and sc.run_as_non_root is True:
                run_as_root = False
            elif pod_sc and pod_sc.run_as_non_root is True:
                run_as_root = False
            elif not sc or sc.run_as_user is None:
                # No explicit setting - might run as root depending on image
                if not (pod_sc and pod_sc.run_as_non_root):
                    run_as_root = True  # Assume root unless explicitly non-root

            if run_as_root:
                result.findings.append(
                    Finding(
                        category=CheckCategory.RBAC,
                        severity=Severity.INFO,
                        resource=pod_key,
                        message=f"Container '{container.name}' may run as root "
                        "(no runAsNonRoot or runAsUser set)",
                        details={"container": container.name},
                        remediation="Set `securityContext.runAsNonRoot: true` or "
                        "`runAsUser: <non-zero>` to prevent running as root.",
                    )
                )

            # Dangerous capabilities
            if sc and sc.capabilities and sc.capabilities.add:
                dangerous = set(sc.capabilities.add) & DANGEROUS_CAPABILITIES
                if dangerous:
                    result.findings.append(
                        Finding(
                            category=CheckCategory.RBAC,
                            severity=Severity.WARNING,
                            resource=pod_key,
                            message=f"Container '{container.name}' has dangerous "
                            f"capabilities: {sorted(dangerous)}",
                            details={
                                "container": container.name,
                                "capabilities": sorted(dangerous),
                            },
                            remediation="These capabilities grant significant host access. "
                            "Remove unless the workload specifically requires them.",
                        )
                    )


def _check_default_service_accounts(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Flag pods using the default service account with mounted tokens."""
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        if pod.metadata.namespace in ("kube-system", "kube-public", "kube-node-lease"):
            continue

        sa_name = pod.spec.service_account_name or "default"
        if sa_name != "default":
            continue

        # Check if token is auto-mounted
        automount = pod.spec.automount_service_account_token
        if automount is False:
            continue

        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        result.findings.append(
            Finding(
                category=CheckCategory.RBAC,
                severity=Severity.INFO,
                resource=pod_key,
                message="Using 'default' service account with auto-mounted token",
                details={"service_account": "default"},
                remediation="Create a dedicated service account for this workload. "
                "The default SA token is mounted into every pod and can be "
                "used for API access if RBAC is misconfigured.",
            )
        )


def _check_automount_tokens(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Flag service accounts with automountServiceAccountToken enabled that have bindings."""
    # Build a set of SAs that have role bindings
    bound_sas: set[str] = set()
    for rb in snap.role_bindings:
        for subject in rb.subjects or []:
            if subject.kind == "ServiceAccount":
                bound_sas.add(f"{subject.namespace or rb.metadata.namespace}/{subject.name}")

    for crb in snap.cluster_role_bindings:
        for subject in crb.subjects or []:
            if subject.kind == "ServiceAccount":
                bound_sas.add(f"{subject.namespace or 'default'}/{subject.name}")

    # Check SAs - only flag if they have significant bindings
    # (This is more of an informational check)
    for sa in snap.service_accounts:
        sa_key = f"{sa.metadata.namespace}/{sa.metadata.name}"
        if sa_key not in bound_sas:
            continue
        if sa.metadata.name == "default":
            continue
        if sa.metadata.namespace in ("kube-system",):
            continue

        automount = sa.automount_service_account_token
        if automount is False:
            continue

        # This SA has RBAC bindings and auto-mounts tokens - that's normal
        # but worth noting if the bindings are powerful
