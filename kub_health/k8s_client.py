"""Kubernetes client wrapper for health checks."""

from __future__ import annotations

from kubernetes import client, config
from kubernetes.client import (
    ApiextensionsV1Api,
    AppsV1Api,
    CoreV1Api,
    NetworkingV1Api,
    RbacAuthorizationV1Api,
    StorageV1Api,
)
from kubernetes.config.config_exception import ConfigException


class K8sClient:
    """Wraps the Kubernetes Python client, loading config once and exposing typed API groups."""

    def __init__(self, kubeconfig: str | None = None, context: str | None = None):
        self.kubeconfig = kubeconfig
        self.context = context
        self._api_client: client.ApiClient | None = None

    def connect(self) -> None:
        """Load kubeconfig and create the API client."""
        try:
            config.load_kube_config(
                config_file=self.kubeconfig,
                context=self.context,
            )
        except ConfigException:
            # Fall back to in-cluster config (running inside a pod)
            config.load_incluster_config()

        self._api_client = client.ApiClient()

    @property
    def api(self) -> client.ApiClient:
        if self._api_client is None:
            raise RuntimeError("K8sClient not connected. Call connect() first.")
        return self._api_client

    @property
    def core_v1(self) -> CoreV1Api:
        return CoreV1Api(self.api)

    @property
    def apps_v1(self) -> AppsV1Api:
        return AppsV1Api(self.api)

    @property
    def networking_v1(self) -> NetworkingV1Api:
        return NetworkingV1Api(self.api)

    @property
    def rbac_v1(self) -> RbacAuthorizationV1Api:
        return RbacAuthorizationV1Api(self.api)

    @property
    def storage_v1(self) -> StorageV1Api:
        return StorageV1Api(self.api)

    @property
    def extensions_v1(self) -> ApiextensionsV1Api:
        return ApiextensionsV1Api(self.api)

    def get_cluster_name(self) -> str:
        """Return the current cluster name from kubeconfig context."""
        try:
            _, active_context = config.list_kube_config_contexts(
                config_file=self.kubeconfig,
            )
            return active_context.get("context", {}).get("cluster", "unknown")
        except ConfigException:
            return "in-cluster"

    def get_context_name(self) -> str:
        """Return the current context name."""
        try:
            _, active_context = config.list_kube_config_contexts(
                config_file=self.kubeconfig,
            )
            return active_context.get("name", "unknown")
        except ConfigException:
            return "in-cluster"
