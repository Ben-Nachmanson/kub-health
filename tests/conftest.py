"""Shared fixtures and helpers for kub-health tests.

We build lightweight mock objects that replicate the attribute-access interface
of the kubernetes Python client objects, without requiring the kubernetes
package itself for model instantiation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from kub_health.models import ClusterSnapshot


# ---------------------------------------------------------------------------
# Generic attribute-bag that behaves like a K8s API object
# ---------------------------------------------------------------------------


class K8sObj:
    """Minimal mock for K8s API objects.  Supports nested attribute access."""

    def __init__(self, **kwargs: Any):
        for k, v in kwargs.items():
            if isinstance(v, dict):
                setattr(self, k, K8sObj(**v))
            else:
                setattr(self, k, v)

    def __getattr__(self, name: str) -> Any:
        # Return None for any attribute not set (mirrors K8s client behaviour)
        return None

    def __iter__(self):
        """Allow dict() conversion for label selectors."""
        d = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        return iter(d.items())

    def items(self):
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}.items()

    def get(self, key, default=None):
        return getattr(self, key, default)


# ---------------------------------------------------------------------------
# Pod factory
# ---------------------------------------------------------------------------

def make_pod(
    name: str,
    namespace: str = "default",
    node_name: str = "node-1",
    phase: str = "Running",
    labels: dict | None = None,
    owner_kind: str | None = None,
    owner_name: str | None = None,
    containers: list[dict] | None = None,
    container_statuses: list | None = None,
    init_container_statuses: list | None = None,
    conditions: list | None = None,
    creation_timestamp: datetime | None = None,
    volumes: list | None = None,
) -> K8sObj:
    owners = []
    if owner_kind and owner_name:
        owners = [K8sObj(kind=owner_kind, name=owner_name)]

    pod_containers = []
    if containers:
        for c in containers:
            pod_containers.append(K8sObj(**c))

    meta = K8sObj(
        name=name,
        namespace=namespace,
        owner_references=owners or None,
        creation_timestamp=creation_timestamp or datetime.now(timezone.utc),
    )
    # Set labels as a plain dict since production code calls dict() on it
    meta.labels = labels or {"app": name}

    return K8sObj(
        metadata=meta,
        spec=K8sObj(
            node_name=node_name,
            containers=pod_containers or [K8sObj(name="main", env=[], env_from=[])],
            volumes=volumes or [],
        ),
        status=K8sObj(
            phase=phase,
            conditions=conditions,
            container_statuses=container_statuses,
            init_container_statuses=init_container_statuses,
            reason=None,
            message=None,
        ),
    )


# ---------------------------------------------------------------------------
# Node factory
# ---------------------------------------------------------------------------


def make_node(
    name: str,
    conditions: list | None = None,
) -> K8sObj:
    if conditions is None:
        conditions = [K8sObj(type="Ready", status="True", reason="KubeletReady", message="")]
    return K8sObj(
        metadata=K8sObj(name=name, namespace="", labels={}),
        spec=K8sObj(),
        status=K8sObj(
            conditions=conditions,
            allocatable={"cpu": "4", "memory": "8Gi", "pods": "110"},
            capacity={"cpu": "4", "memory": "8Gi", "pods": "110"},
        ),
    )


# ---------------------------------------------------------------------------
# Deployment / ReplicaSet factories
# ---------------------------------------------------------------------------


def make_deployment(
    name: str,
    namespace: str = "default",
    replicas: int = 3,
    ready_replicas: int | None = None,
    available_replicas: int | None = None,
    updated_replicas: int | None = None,
    conditions: list | None = None,
    selector: dict | None = None,
) -> K8sObj:
    return K8sObj(
        metadata=K8sObj(name=name, namespace=namespace, labels={"app": name}),
        spec=K8sObj(
            replicas=replicas,
            selector=K8sObj(match_labels=selector or {"app": name}),
        ),
        status=K8sObj(
            replicas=replicas,
            ready_replicas=ready_replicas if ready_replicas is not None else replicas,
            available_replicas=available_replicas if available_replicas is not None else replicas,
            updated_replicas=updated_replicas if updated_replicas is not None else replicas,
            conditions=conditions or [],
        ),
    )


def make_replicaset(
    name: str,
    namespace: str = "default",
    owner_deployment: str | None = None,
    replicas: int = 3,
) -> K8sObj:
    owners = []
    if owner_deployment:
        owners = [K8sObj(kind="Deployment", name=owner_deployment)]
    return K8sObj(
        metadata=K8sObj(
            name=name,
            namespace=namespace,
            owner_references=owners or None,
        ),
        spec=K8sObj(replicas=replicas),
        status=K8sObj(replicas=replicas),
    )


# ---------------------------------------------------------------------------
# Service factory
# ---------------------------------------------------------------------------


def make_service(
    name: str,
    namespace: str = "default",
    selector: dict | None = None,
    ports: list | None = None,
) -> K8sObj:
    svc = K8sObj(
        metadata=K8sObj(name=name, namespace=namespace, labels={}),
        spec=K8sObj(
            ports=ports or [K8sObj(port=80, target_port=8080, protocol="TCP")],
        ),
    )
    # Set selector as a plain dict (not a K8sObj) since production code calls dict() on it
    svc.spec.selector = selector or {"app": name}
    return svc


# ---------------------------------------------------------------------------
# PVC factory
# ---------------------------------------------------------------------------


def make_pvc(
    name: str,
    namespace: str = "default",
    phase: str = "Bound",
    storage_class: str = "standard",
) -> K8sObj:
    return K8sObj(
        metadata=K8sObj(name=name, namespace=namespace, labels={}),
        spec=K8sObj(storage_class_name=storage_class),
        status=K8sObj(phase=phase),
    )


# ---------------------------------------------------------------------------
# Event factory
# ---------------------------------------------------------------------------


def make_event(
    resource_kind: str,
    resource_name: str,
    resource_namespace: str = "default",
    event_type: str = "Warning",
    reason: str = "BackOff",
    message: str = "",
    count: int = 1,
    timestamp: datetime | None = None,
) -> K8sObj:
    ts = timestamp or datetime.now(timezone.utc)
    return K8sObj(
        involved_object=K8sObj(
            kind=resource_kind,
            name=resource_name,
            namespace=resource_namespace,
        ),
        type=event_type,
        reason=reason,
        message=message,
        count=count,
        last_timestamp=ts,
        event_time=None,
        metadata=K8sObj(creation_timestamp=ts),
        source=K8sObj(component="kubelet"),
    )


# ---------------------------------------------------------------------------
# Empty snapshot fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_snapshot() -> ClusterSnapshot:
    return ClusterSnapshot()
