"""Networking analyzer.

Detects: services with no endpoints, selector/label mismatches, ingress
misconfigurations, NetworkPolicy issues, services pointing at wrong ports.
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


def check_networking(snap: ClusterSnapshot) -> CheckResult:
    """Analyze networking configuration for issues."""
    result = CheckResult(category=CheckCategory.NETWORKING)

    _check_services_endpoints(result, snap)
    _check_service_selector_matches(result, snap)
    _check_ingresses(result, snap)
    _check_network_policies(result, snap)

    return result


def _check_services_endpoints(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Detect services with no ready endpoints."""
    # Build endpoints map: ns/name -> list of addresses
    ep_map: dict[str, int] = {}
    for ep in snap.endpoints:
        key = f"{ep.metadata.namespace}/{ep.metadata.name}"
        ready_count = 0
        for subset in ep.subsets or []:
            ready_count += len(subset.addresses or [])
        ep_map[key] = ready_count

    for svc in snap.services:
        meta = svc.metadata
        svc_key = ResourceKey("Service", meta.name, meta.namespace)

        # Skip headless services and ExternalName
        if svc.spec.type == "ExternalName":
            continue
        if svc.spec.cluster_ip == "None":
            continue  # Headless - endpoints managed differently

        # Skip services without selectors (manually managed endpoints)
        if not svc.spec.selector:
            continue

        ep_key = f"{meta.namespace}/{meta.name}"
        ready = ep_map.get(ep_key, 0)

        if ready == 0:
            result.findings.append(
                Finding(
                    category=CheckCategory.NETWORKING,
                    severity=Severity.CRITICAL,
                    resource=svc_key,
                    message="Service has no ready endpoints - traffic will fail",
                    details={
                        "type": svc.spec.type,
                        "selector": dict(svc.spec.selector),
                        "ports": [
                            {"port": p.port, "target_port": str(p.target_port), "protocol": p.protocol}
                            for p in (svc.spec.ports or [])
                        ],
                    },
                    evidence=[
                        f"kubectl get endpoints {meta.name} -n {meta.namespace}",
                        f"kubectl get pods -l {_selector_str(svc.spec.selector)} -n {meta.namespace}",
                    ],
                    remediation="No pods match this service's selector, or matching pods "
                    "aren't ready. Verify label selectors match pod labels and that "
                    "pods are passing readiness probes.",
                )
            )


def _check_service_selector_matches(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Check that service selectors actually match existing pods."""
    # Build a set of (namespace, label_set) for all pods
    pod_labels: dict[str, list[dict[str, str]]] = {}
    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue
        ns = pod.metadata.namespace
        labels = dict(pod.metadata.labels or {})
        pod_labels.setdefault(ns, []).append(labels)

    for svc in snap.services:
        if not svc.spec.selector:
            continue
        if svc.spec.type == "ExternalName":
            continue

        meta = svc.metadata
        selector = dict(svc.spec.selector)
        ns = meta.namespace

        # Check if ANY pod in the namespace matches
        ns_pods = pod_labels.get(ns, [])
        matching = sum(
            1
            for labels in ns_pods
            if all(labels.get(k) == v for k, v in selector.items())
        )

        if matching == 0:
            svc_key = ResourceKey("Service", meta.name, ns)
            # Don't duplicate if already flagged by endpoint check
            already = any(
                f.resource == svc_key and "no ready endpoints" in f.message.lower()
                for f in result.findings
            )
            if not already:
                result.findings.append(
                    Finding(
                        category=CheckCategory.NETWORKING,
                        severity=Severity.WARNING,
                        resource=svc_key,
                        message=f"Selector {selector} matches 0 running pods in namespace",
                        details={"selector": selector, "matching_pods": 0},
                        evidence=[
                            f"kubectl get pods -l {_selector_str(selector)} -n {ns}",
                        ],
                        remediation="The service selector doesn't match any pod labels. "
                        "This usually means a label typo or the deployment hasn't been created.",
                    )
                )

    # --- Check for port mismatches ---
    for svc in snap.services:
        if not svc.spec.selector or svc.spec.type == "ExternalName":
            continue

        meta = svc.metadata
        selector = dict(svc.spec.selector)

        for pod in snap.pods:
            if pod.metadata.namespace != meta.namespace:
                continue
            if pod.status.phase in ("Succeeded", "Failed"):
                continue
            pod_labels_dict = dict(pod.metadata.labels or {})
            if not all(pod_labels_dict.get(k) == v for k, v in selector.items()):
                continue

            # This pod matches - check port alignment
            container_ports = set()
            for container in pod.spec.containers or []:
                for cp in container.ports or []:
                    container_ports.add((cp.container_port, cp.protocol or "TCP"))
                    if cp.name:
                        container_ports.add((cp.name, cp.protocol or "TCP"))

            for sp in svc.spec.ports or []:
                target = sp.target_port
                protocol = sp.protocol or "TCP"
                # target_port can be int or string (named port)
                if isinstance(target, int):
                    match_key = (target, protocol)
                else:
                    match_key = (str(target), protocol)

                if match_key not in container_ports and container_ports:
                    svc_key = ResourceKey("Service", meta.name, meta.namespace)
                    result.findings.append(
                        Finding(
                            category=CheckCategory.NETWORKING,
                            severity=Severity.WARNING,
                            resource=svc_key,
                            message=f"Service port {sp.port} targets port {target} "
                            f"which isn't exposed by matching pods",
                            details={
                                "service_port": sp.port,
                                "target_port": str(target),
                                "container_ports": [str(p) for p in container_ports],
                            },
                            remediation="The service's targetPort doesn't match any "
                            "containerPort. Traffic will be dropped or refused.",
                        )
                    )
            break  # Only need to check one matching pod


def _check_ingresses(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Check ingress resources for misconfigurations."""
    svc_set = {
        f"{s.metadata.namespace}/{s.metadata.name}" for s in snap.services
    }

    for ing in snap.ingresses:
        meta = ing.metadata
        rk = ResourceKey("Ingress", meta.name, meta.namespace)

        for rule in ing.spec.rules or []:
            if not rule.http:
                continue
            for path in rule.http.paths or []:
                backend = path.backend
                if not backend or not backend.service:
                    continue

                svc_name = backend.service.name
                svc_ref = f"{meta.namespace}/{svc_name}"

                if svc_ref not in svc_set:
                    result.findings.append(
                        Finding(
                            category=CheckCategory.NETWORKING,
                            severity=Severity.CRITICAL,
                            resource=rk,
                            message=f"Ingress references non-existent service '{svc_name}'",
                            details={
                                "host": rule.host or "*",
                                "path": path.path or "/",
                                "service": svc_name,
                            },
                            related_resources=[
                                ResourceKey("Service", svc_name, meta.namespace)
                            ],
                            evidence=[
                                f"kubectl describe ingress {meta.name} -n {meta.namespace}",
                            ],
                            remediation="The backend service doesn't exist. Create the "
                            "service or fix the ingress backend reference.",
                        )
                    )

        # Check TLS configuration
        for tls in ing.spec.tls or []:
            if tls.secret_name:
                secret_exists = any(
                    s.metadata.name == tls.secret_name and s.metadata.namespace == meta.namespace
                    for s in snap.secrets
                )
                if not secret_exists:
                    result.findings.append(
                        Finding(
                            category=CheckCategory.NETWORKING,
                            severity=Severity.WARNING,
                            resource=rk,
                            message=f"TLS secret '{tls.secret_name}' not found",
                            details={
                                "secret": tls.secret_name,
                                "hosts": tls.hosts or [],
                            },
                            remediation="The TLS secret doesn't exist. HTTPS will fail. "
                            "Create the secret or use cert-manager for automatic provisioning.",
                        )
                    )


def _check_network_policies(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Detect network policies that may be overly restrictive."""
    if not snap.network_policies:
        return

    # Find namespaces with network policies
    ns_with_policies: dict[str, list] = {}
    for np in snap.network_policies:
        ns = np.metadata.namespace
        ns_with_policies.setdefault(ns, []).append(np)

    for ns, policies in ns_with_policies.items():
        for np in policies:
            rk = ResourceKey("NetworkPolicy", np.metadata.name, ns)
            spec = np.spec

            # Default-deny policies (empty ingress/egress rules)
            policy_types = spec.policy_types or []
            if "Ingress" in policy_types and not spec.ingress:
                result.findings.append(
                    Finding(
                        category=CheckCategory.NETWORKING,
                        severity=Severity.INFO,
                        resource=rk,
                        message="Default-deny ingress policy - all inbound traffic blocked "
                        "for matched pods unless explicitly allowed",
                        details={
                            "pod_selector": dict(spec.pod_selector.match_labels or {})
                            if spec.pod_selector and spec.pod_selector.match_labels
                            else "all pods",
                        },
                        remediation="This is often intentional for security. Ensure other "
                        "NetworkPolicies explicitly allow required traffic.",
                    )
                )

            if "Egress" in policy_types and not spec.egress:
                result.findings.append(
                    Finding(
                        category=CheckCategory.NETWORKING,
                        severity=Severity.WARNING,
                        resource=rk,
                        message="Default-deny egress policy - all outbound traffic blocked. "
                        "This may break DNS resolution.",
                        details={
                            "pod_selector": dict(spec.pod_selector.match_labels or {})
                            if spec.pod_selector and spec.pod_selector.match_labels
                            else "all pods",
                        },
                        remediation="Ensure DNS (port 53 UDP/TCP to kube-dns) is explicitly "
                        "allowed, or pods won't be able to resolve service names.",
                    )
                )


def _selector_str(selector: dict) -> str:
    """Convert a selector dict to a kubectl-compatible label selector string."""
    return ",".join(f"{k}={v}" for k, v in selector.items())
