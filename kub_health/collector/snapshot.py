"""Cluster snapshot collector.

Queries every relevant K8s API once and stores the results in a ClusterSnapshot.
All health checks and the correlation engine operate on this snapshot, so the
cluster is only hit with API calls during the collection phase.
"""

from __future__ import annotations

import logging
from typing import Any

from rich.progress import Progress, SpinnerColumn, TextColumn

from kub_health.k8s_client import K8sClient
from kub_health.models import ClusterSnapshot

logger = logging.getLogger(__name__)


def _safe_list(func: Any, *args: Any, **kwargs: Any) -> list[Any]:
    """Call a K8s list API and return .items, swallowing 403/404 errors."""
    try:
        result = func(*args, **kwargs)
        return result.items if hasattr(result, "items") else []
    except Exception as exc:
        # Forbidden (RBAC), NotFound, or API group not available
        logger.debug("API call %s failed: %s", func.__name__, exc)
        return []


def collect_snapshot(
    k8s: K8sClient,
    namespace: str | None = None,
    progress: Progress | None = None,
) -> ClusterSnapshot:
    """Collect a full point-in-time snapshot of the cluster.

    Args:
        k8s: Connected K8sClient instance.
        namespace: If set, limit collection to this namespace. None = all namespaces.
        progress: Optional Rich Progress bar to show collection status.
    """
    snap = ClusterSnapshot()

    # Define all collection tasks: (label, snapshot_field, api_call, args)
    # For namespaced resources we call either list_namespaced_* or list_*_for_all_namespaces
    core = k8s.core_v1
    apps = k8s.apps_v1
    net = k8s.networking_v1
    rbac = k8s.rbac_v1
    storage = k8s.storage_v1

    ns_args: dict[str, Any] = {"namespace": namespace} if namespace else {}

    def _ns_call(namespaced_fn: Any, all_ns_fn: Any) -> Any:
        return namespaced_fn if namespace else all_ns_fn

    tasks: list[tuple[str, str, Any, dict[str, Any]]] = [
        # Core
        ("Namespaces", "namespaces", core.list_namespace, {}),
        ("Nodes", "nodes", core.list_node, {}),
        (
            "Pods",
            "pods",
            _ns_call(core.list_namespaced_pod, core.list_pod_for_all_namespaces),
            ns_args,
        ),
        (
            "Services",
            "services",
            _ns_call(core.list_namespaced_service, core.list_service_for_all_namespaces),
            ns_args,
        ),
        (
            "Endpoints",
            "endpoints",
            _ns_call(core.list_namespaced_endpoints, core.list_endpoints_for_all_namespaces),
            ns_args,
        ),
        (
            "ConfigMaps",
            "configmaps",
            _ns_call(core.list_namespaced_config_map, core.list_config_map_for_all_namespaces),
            ns_args,
        ),
        (
            "Secrets (metadata)",
            "secrets",
            _ns_call(core.list_namespaced_secret, core.list_secret_for_all_namespaces),
            ns_args,
        ),
        (
            "ServiceAccounts",
            "service_accounts",
            _ns_call(
                core.list_namespaced_service_account,
                core.list_service_account_for_all_namespaces,
            ),
            ns_args,
        ),
        (
            "Events",
            "events",
            _ns_call(core.list_namespaced_event, core.list_event_for_all_namespaces),
            ns_args,
        ),
        (
            "PVCs",
            "pvcs",
            _ns_call(
                core.list_namespaced_persistent_volume_claim,
                core.list_persistent_volume_claim_for_all_namespaces,
            ),
            ns_args,
        ),
        ("PVs", "pvs", core.list_persistent_volume, {}),
        (
            "ResourceQuotas",
            "resource_quotas",
            _ns_call(
                core.list_namespaced_resource_quota,
                core.list_resource_quota_for_all_namespaces,
            ),
            ns_args,
        ),
        (
            "LimitRanges",
            "limit_ranges",
            _ns_call(core.list_namespaced_limit_range, core.list_limit_range_for_all_namespaces),
            ns_args,
        ),
        # Apps
        (
            "Deployments",
            "deployments",
            _ns_call(apps.list_namespaced_deployment, apps.list_deployment_for_all_namespaces),
            ns_args,
        ),
        (
            "ReplicaSets",
            "replicasets",
            _ns_call(apps.list_namespaced_replica_set, apps.list_replica_set_for_all_namespaces),
            ns_args,
        ),
        (
            "StatefulSets",
            "statefulsets",
            _ns_call(apps.list_namespaced_stateful_set, apps.list_stateful_set_for_all_namespaces),
            ns_args,
        ),
        (
            "DaemonSets",
            "daemonsets",
            _ns_call(apps.list_namespaced_daemon_set, apps.list_daemon_set_for_all_namespaces),
            ns_args,
        ),
        # Networking
        (
            "Ingresses",
            "ingresses",
            _ns_call(net.list_namespaced_ingress, net.list_ingress_for_all_namespaces),
            ns_args,
        ),
        (
            "NetworkPolicies",
            "network_policies",
            _ns_call(
                net.list_namespaced_network_policy,
                net.list_network_policy_for_all_namespaces,
            ),
            ns_args,
        ),
        # RBAC
        ("ClusterRoles", "cluster_roles", rbac.list_cluster_role, {}),
        ("ClusterRoleBindings", "cluster_role_bindings", rbac.list_cluster_role_binding, {}),
        (
            "Roles",
            "roles",
            _ns_call(rbac.list_namespaced_role, rbac.list_role_for_all_namespaces),
            ns_args,
        ),
        (
            "RoleBindings",
            "role_bindings",
            _ns_call(
                rbac.list_namespaced_role_binding,
                rbac.list_role_binding_for_all_namespaces,
            ),
            ns_args,
        ),
        # Storage
        ("StorageClasses", "storage_classes", storage.list_storage_class, {}),
    ]

    # Autoscaling and Policy APIs (may not be available)
    try:
        from kubernetes.client import AutoscalingV2Api, PolicyV1Api

        autoscaling = AutoscalingV2Api(k8s.api)
        policy = PolicyV1Api(k8s.api)
        tasks.extend([
            (
                "HPAs",
                "hpas",
                _ns_call(
                    autoscaling.list_namespaced_horizontal_pod_autoscaler,
                    autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces,
                ),
                ns_args,
            ),
            (
                "PDBs",
                "pod_disruption_budgets",
                _ns_call(
                    policy.list_namespaced_pod_disruption_budget,
                    policy.list_pod_disruption_budget_for_all_namespaces,
                ),
                ns_args,
            ),
        ])
    except ImportError:
        logger.debug("AutoscalingV2 or PolicyV1 API not available")

    # Collect metrics (best-effort)
    tasks.append(("Pod Metrics", "pod_metrics", _collect_pod_metrics, {"k8s": k8s, "namespace": namespace}))
    tasks.append(("Node Metrics", "node_metrics", _collect_node_metrics, {"k8s": k8s}))

    # Execute all collection tasks
    if progress:
        task_id = progress.add_task("Collecting cluster state...", total=len(tasks))

    for label, field_name, api_fn, api_args in tasks:
        if progress:
            progress.update(task_id, description=f"Collecting {label}...")

        items = _safe_list(api_fn, **api_args) if api_fn not in (_collect_pod_metrics, _collect_node_metrics) else api_fn(**api_args)
        setattr(snap, field_name, items)

        if progress:
            progress.advance(task_id)

    return snap


def _collect_pod_metrics(k8s: K8sClient, namespace: str | None = None) -> list[Any]:
    """Try to collect pod metrics from metrics-server."""
    try:
        from kubernetes.client import CustomObjectsApi

        custom = CustomObjectsApi(k8s.api)
        if namespace:
            result = custom.list_namespaced_custom_object(
                group="metrics.k8s.io",
                version="v1beta1",
                namespace=namespace,
                plural="pods",
            )
        else:
            result = custom.list_cluster_custom_object(
                group="metrics.k8s.io",
                version="v1beta1",
                plural="pods",
            )
        return result.get("items", [])
    except Exception as exc:
        logger.debug("metrics-server not available for pods: %s", exc)
        return []


def _collect_node_metrics(k8s: K8sClient) -> list[Any]:
    """Try to collect node metrics from metrics-server."""
    try:
        from kubernetes.client import CustomObjectsApi

        custom = CustomObjectsApi(k8s.api)
        result = custom.list_cluster_custom_object(
            group="metrics.k8s.io",
            version="v1beta1",
            plural="nodes",
        )
        return result.get("items", [])
    except Exception as exc:
        logger.debug("metrics-server not available for nodes: %s", exc)
        return []
