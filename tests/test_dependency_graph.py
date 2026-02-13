"""Tests for the dependency graph builder."""

from kub_health.correlator.dependency_graph import build_dependency_graph
from kub_health.models import ClusterSnapshot, DependencyType, ResourceKey

from tests.conftest import (
    K8sObj,
    make_deployment,
    make_node,
    make_pod,
    make_pvc,
    make_replicaset,
    make_service,
)


class TestBuildDependencyGraph:
    def test_pod_to_node_edge(self):
        snap = ClusterSnapshot(
            pods=[make_pod("p1", node_name="node-1")],
            nodes=[make_node("node-1")],
        )
        g = build_dependency_graph(snap)
        pod_key = ResourceKey("Pod", "p1", "default")
        deps = g.dependencies_of(pod_key)
        assert len(deps) == 1
        assert deps[0].target == ResourceKey("Node", "node-1")
        assert deps[0].dep_type == DependencyType.RUNS_ON

    def test_pod_without_node(self):
        """Unscheduled pods should not create a RUNS_ON edge."""
        snap = ClusterSnapshot(
            pods=[make_pod("p1", node_name=None)],
        )
        g = build_dependency_graph(snap)
        assert len(g.edges) == 0

    def test_replicaset_to_deployment(self):
        snap = ClusterSnapshot(
            replicasets=[make_replicaset("d-abc123", owner_deployment="d")],
        )
        g = build_dependency_graph(snap)
        deploy_key = ResourceKey("Deployment", "d", "default")
        edges = g.dependencies_of(deploy_key)
        assert len(edges) == 1
        assert edges[0].target.kind == "ReplicaSet"
        assert edges[0].dep_type == DependencyType.OWNS

    def test_pod_to_replicaset(self):
        snap = ClusterSnapshot(
            pods=[make_pod("p1", owner_kind="ReplicaSet", owner_name="rs-1")],
        )
        g = build_dependency_graph(snap)
        rs_key = ResourceKey("ReplicaSet", "rs-1", "default")
        edges = g.dependencies_of(rs_key)
        assert len(edges) == 1
        assert edges[0].target == ResourceKey("Pod", "p1", "default")

    def test_full_deployment_chain(self):
        """Deployment -> ReplicaSet -> Pod chain is traversable."""
        snap = ClusterSnapshot(
            deployments=[make_deployment("web")],
            replicasets=[make_replicaset("web-rs", owner_deployment="web")],
            pods=[make_pod("web-rs-pod1", owner_kind="ReplicaSet", owner_name="web-rs")],
        )
        g = build_dependency_graph(snap)
        chain = g.dependency_chain(ResourceKey("Deployment", "web", "default"))
        assert ResourceKey("ReplicaSet", "web-rs", "default") in chain
        assert ResourceKey("Pod", "web-rs-pod1", "default") in chain

    def test_service_selects_pods(self):
        snap = ClusterSnapshot(
            services=[make_service("svc", selector={"app": "web"})],
            pods=[
                make_pod("p1", labels={"app": "web"}),
                make_pod("p2", labels={"app": "api"}),
            ],
        )
        g = build_dependency_graph(snap)
        svc_key = ResourceKey("Service", "svc", "default")
        edges = g.dependencies_of(svc_key)
        assert len(edges) == 1
        assert edges[0].target == ResourceKey("Pod", "p1", "default")
        assert edges[0].dep_type == DependencyType.SELECTS

    def test_service_different_namespace_no_match(self):
        snap = ClusterSnapshot(
            services=[make_service("svc", namespace="production", selector={"app": "web"})],
            pods=[make_pod("p1", namespace="staging", labels={"app": "web"})],
        )
        g = build_dependency_graph(snap)
        svc_key = ResourceKey("Service", "svc", "production")
        edges = g.dependencies_of(svc_key)
        assert len(edges) == 0

    def test_pod_to_pvc(self):
        snap = ClusterSnapshot(
            pods=[
                make_pod(
                    "p1",
                    volumes=[K8sObj(persistent_volume_claim=K8sObj(claim_name="data-pvc"), config_map=None, secret=None)],
                )
            ],
            pvcs=[make_pvc("data-pvc")],
        )
        g = build_dependency_graph(snap)
        pod_key = ResourceKey("Pod", "p1", "default")
        edges = g.dependencies_of(pod_key)
        pvc_edges = [e for e in edges if e.dep_type == DependencyType.MOUNTS]
        assert len(pvc_edges) == 1
        assert pvc_edges[0].target == ResourceKey("PVC", "data-pvc", "default")

    def test_pod_to_configmap_volume(self):
        snap = ClusterSnapshot(
            pods=[
                make_pod(
                    "p1",
                    volumes=[K8sObj(
                        config_map=K8sObj(name="my-config"),
                        persistent_volume_claim=None,
                        secret=None,
                    )],
                )
            ],
        )
        g = build_dependency_graph(snap)
        pod_key = ResourceKey("Pod", "p1", "default")
        edges = g.dependencies_of(pod_key)
        cm_edges = [e for e in edges if e.target.kind == "ConfigMap"]
        assert len(cm_edges) == 1
        assert cm_edges[0].target.name == "my-config"

    def test_pod_to_secret_volume(self):
        snap = ClusterSnapshot(
            pods=[
                make_pod(
                    "p1",
                    volumes=[K8sObj(
                        secret=K8sObj(secret_name="my-secret"),
                        persistent_volume_claim=None,
                        config_map=None,
                    )],
                )
            ],
        )
        g = build_dependency_graph(snap)
        pod_key = ResourceKey("Pod", "p1", "default")
        edges = g.dependencies_of(pod_key)
        secret_edges = [e for e in edges if e.target.kind == "Secret"]
        assert len(secret_edges) == 1
        assert secret_edges[0].target.name == "my-secret"

    def test_ingress_to_service(self):
        snap = ClusterSnapshot(
            ingresses=[
                K8sObj(
                    metadata=K8sObj(name="ing-1", namespace="default"),
                    spec=K8sObj(
                        rules=[
                            K8sObj(
                                host="example.com",
                                http=K8sObj(
                                    paths=[
                                        K8sObj(
                                            path="/",
                                            backend=K8sObj(
                                                service=K8sObj(name="web-svc"),
                                            ),
                                        )
                                    ]
                                ),
                            )
                        ]
                    ),
                )
            ],
        )
        g = build_dependency_graph(snap)
        ing_key = ResourceKey("Ingress", "ing-1", "default")
        edges = g.dependencies_of(ing_key)
        assert len(edges) == 1
        assert edges[0].target == ResourceKey("Service", "web-svc", "default")
        assert edges[0].dep_type == DependencyType.REFERENCES

    def test_impact_radius_node_failure(self):
        """If a node fails, all pods on it should be in the impact radius."""
        snap = ClusterSnapshot(
            nodes=[make_node("node-1")],
            pods=[
                make_pod("p1", node_name="node-1"),
                make_pod("p2", node_name="node-1"),
                make_pod("p3", node_name="node-2"),
            ],
        )
        g = build_dependency_graph(snap)
        impact = g.impact_radius(ResourceKey("Node", "node-1"))
        assert ResourceKey("Pod", "p1", "default") in impact
        assert ResourceKey("Pod", "p2", "default") in impact
        assert ResourceKey("Pod", "p3", "default") not in impact

    def test_empty_snapshot(self, empty_snapshot):
        g = build_dependency_graph(empty_snapshot)
        assert len(g.edges) == 0
