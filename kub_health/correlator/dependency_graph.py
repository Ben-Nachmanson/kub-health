"""Dependency graph builder.

Maps relationships between K8s resources so the correlation engine can trace
how an issue in one resource (e.g., a failing Node) cascades to others
(e.g., all Pods on that Node, Services pointing at those Pods, etc.).
"""

from __future__ import annotations

from kub_health.models import (
    ClusterSnapshot,
    DependencyEdge,
    DependencyGraph,
    DependencyType,
    ResourceKey,
)


def build_dependency_graph(snap: ClusterSnapshot) -> DependencyGraph:
    """Build a complete dependency graph from a cluster snapshot."""
    graph = DependencyGraph()

    _map_pod_to_node(graph, snap)
    _map_replicaset_to_deployment(graph, snap)
    _map_pod_to_replicaset(graph, snap)
    _map_pod_to_statefulset(graph, snap)
    _map_pod_to_daemonset(graph, snap)
    _map_service_to_pods(graph, snap)
    _map_ingress_to_service(graph, snap)
    _map_pod_to_pvc(graph, snap)
    _map_pod_to_configmap_secret(graph, snap)
    _map_hpa_to_workload(graph, snap)
    _map_network_policy_to_pods(graph, snap)
    _map_rbac_bindings(graph, snap)

    return graph


def _map_pod_to_node(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    """Pod -> Node (runs_on)."""
    for pod in snap.pods:
        node_name = pod.spec.node_name
        if not node_name:
            continue
        graph.add_edge(
            DependencyEdge(
                source=ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace),
                target=ResourceKey("Node", node_name),
                dep_type=DependencyType.RUNS_ON,
            )
        )


def _map_replicaset_to_deployment(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    """ReplicaSet -> Deployment (owned by)."""
    for rs in snap.replicasets:
        for owner in rs.metadata.owner_references or []:
            if owner.kind == "Deployment":
                graph.add_edge(
                    DependencyEdge(
                        source=ResourceKey("Deployment", owner.name, rs.metadata.namespace),
                        target=ResourceKey("ReplicaSet", rs.metadata.name, rs.metadata.namespace),
                        dep_type=DependencyType.OWNS,
                    )
                )


def _map_pod_to_replicaset(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    """Pod -> ReplicaSet (owned by)."""
    for pod in snap.pods:
        for owner in pod.metadata.owner_references or []:
            if owner.kind == "ReplicaSet":
                graph.add_edge(
                    DependencyEdge(
                        source=ResourceKey("ReplicaSet", owner.name, pod.metadata.namespace),
                        target=ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace),
                        dep_type=DependencyType.OWNS,
                    )
                )


def _map_pod_to_statefulset(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    for pod in snap.pods:
        for owner in pod.metadata.owner_references or []:
            if owner.kind == "StatefulSet":
                graph.add_edge(
                    DependencyEdge(
                        source=ResourceKey("StatefulSet", owner.name, pod.metadata.namespace),
                        target=ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace),
                        dep_type=DependencyType.OWNS,
                    )
                )


def _map_pod_to_daemonset(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    for pod in snap.pods:
        for owner in pod.metadata.owner_references or []:
            if owner.kind == "DaemonSet":
                graph.add_edge(
                    DependencyEdge(
                        source=ResourceKey("DaemonSet", owner.name, pod.metadata.namespace),
                        target=ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace),
                        dep_type=DependencyType.OWNS,
                    )
                )


def _map_service_to_pods(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    """Service -> Pods (via label selector)."""
    for svc in snap.services:
        if not svc.spec.selector:
            continue

        selector = dict(svc.spec.selector)
        svc_key = ResourceKey("Service", svc.metadata.name, svc.metadata.namespace)

        for pod in snap.pods:
            if pod.metadata.namespace != svc.metadata.namespace:
                continue
            pod_labels = dict(pod.metadata.labels or {})
            if all(pod_labels.get(k) == v for k, v in selector.items()):
                graph.add_edge(
                    DependencyEdge(
                        source=svc_key,
                        target=ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace),
                        dep_type=DependencyType.SELECTS,
                    )
                )


def _map_ingress_to_service(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    """Ingress -> Service."""
    for ing in snap.ingresses:
        ing_key = ResourceKey("Ingress", ing.metadata.name, ing.metadata.namespace)
        for rule in ing.spec.rules or []:
            if not rule.http:
                continue
            for path in rule.http.paths or []:
                if path.backend and path.backend.service:
                    graph.add_edge(
                        DependencyEdge(
                            source=ing_key,
                            target=ResourceKey(
                                "Service",
                                path.backend.service.name,
                                ing.metadata.namespace,
                            ),
                            dep_type=DependencyType.REFERENCES,
                            metadata={"host": rule.host or "*", "path": path.path or "/"},
                        )
                    )


def _map_pod_to_pvc(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    """Pod -> PVC (mounts)."""
    for pod in snap.pods:
        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        for vol in pod.spec.volumes or []:
            if vol.persistent_volume_claim:
                graph.add_edge(
                    DependencyEdge(
                        source=pod_key,
                        target=ResourceKey(
                            "PVC",
                            vol.persistent_volume_claim.claim_name,
                            pod.metadata.namespace,
                        ),
                        dep_type=DependencyType.MOUNTS,
                    )
                )


def _map_pod_to_configmap_secret(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    """Pod -> ConfigMap/Secret (mounts or env refs)."""
    for pod in snap.pods:
        pod_key = ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace)
        ns = pod.metadata.namespace

        # Volume mounts
        for vol in pod.spec.volumes or []:
            if vol.config_map:
                graph.add_edge(
                    DependencyEdge(
                        source=pod_key,
                        target=ResourceKey("ConfigMap", vol.config_map.name, ns),
                        dep_type=DependencyType.MOUNTS,
                    )
                )
            if vol.secret:
                graph.add_edge(
                    DependencyEdge(
                        source=pod_key,
                        target=ResourceKey("Secret", vol.secret.secret_name, ns),
                        dep_type=DependencyType.MOUNTS,
                    )
                )

        # Env var references
        for container in pod.spec.containers or []:
            for env in container.env or []:
                if env.value_from:
                    if env.value_from.config_map_key_ref:
                        ref = env.value_from.config_map_key_ref
                        graph.add_edge(
                            DependencyEdge(
                                source=pod_key,
                                target=ResourceKey("ConfigMap", ref.name, ns),
                                dep_type=DependencyType.MOUNTS,
                            )
                        )
                    if env.value_from.secret_key_ref:
                        ref = env.value_from.secret_key_ref
                        graph.add_edge(
                            DependencyEdge(
                                source=pod_key,
                                target=ResourceKey("Secret", ref.name, ns),
                                dep_type=DependencyType.MOUNTS,
                            )
                        )

            for env_from in container.env_from or []:
                if env_from.config_map_ref:
                    graph.add_edge(
                        DependencyEdge(
                            source=pod_key,
                            target=ResourceKey("ConfigMap", env_from.config_map_ref.name, ns),
                            dep_type=DependencyType.MOUNTS,
                        )
                    )
                if env_from.secret_ref:
                    graph.add_edge(
                        DependencyEdge(
                            source=pod_key,
                            target=ResourceKey("Secret", env_from.secret_ref.name, ns),
                            dep_type=DependencyType.MOUNTS,
                        )
                    )


def _map_hpa_to_workload(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    """HPA -> Deployment/StatefulSet (scales)."""
    for hpa in snap.hpas:
        target = hpa.spec.scale_target_ref
        if not target:
            continue
        graph.add_edge(
            DependencyEdge(
                source=ResourceKey("HPA", hpa.metadata.name, hpa.metadata.namespace),
                target=ResourceKey(target.kind, target.name, hpa.metadata.namespace),
                dep_type=DependencyType.SCALES,
            )
        )


def _map_network_policy_to_pods(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    """NetworkPolicy -> Pods (targets via selector)."""
    for np in snap.network_policies:
        np_key = ResourceKey("NetworkPolicy", np.metadata.name, np.metadata.namespace)
        selector = {}
        if np.spec.pod_selector and np.spec.pod_selector.match_labels:
            selector = dict(np.spec.pod_selector.match_labels)

        for pod in snap.pods:
            if pod.metadata.namespace != np.metadata.namespace:
                continue
            pod_labels = dict(pod.metadata.labels or {})
            # Empty selector matches all pods in the namespace
            if not selector or all(pod_labels.get(k) == v for k, v in selector.items()):
                graph.add_edge(
                    DependencyEdge(
                        source=np_key,
                        target=ResourceKey("Pod", pod.metadata.name, pod.metadata.namespace),
                        dep_type=DependencyType.TARGETS,
                    )
                )


def _map_rbac_bindings(graph: DependencyGraph, snap: ClusterSnapshot) -> None:
    """RoleBinding -> Role + ServiceAccount."""
    for rb in snap.role_bindings:
        rb_key = ResourceKey("RoleBinding", rb.metadata.name, rb.metadata.namespace)

        # Binding -> Role
        if rb.role_ref:
            role_kind = rb.role_ref.kind  # "Role" or "ClusterRole"
            role_ns = rb.metadata.namespace if role_kind == "Role" else ""
            graph.add_edge(
                DependencyEdge(
                    source=rb_key,
                    target=ResourceKey(role_kind, rb.role_ref.name, role_ns),
                    dep_type=DependencyType.BINDS,
                )
            )

        # Binding -> Subjects
        for subject in rb.subjects or []:
            if subject.kind == "ServiceAccount":
                graph.add_edge(
                    DependencyEdge(
                        source=rb_key,
                        target=ResourceKey(
                            "ServiceAccount",
                            subject.name,
                            subject.namespace or rb.metadata.namespace,
                        ),
                        dep_type=DependencyType.BINDS,
                    )
                )
