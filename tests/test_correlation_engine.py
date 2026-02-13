"""Tests for the correlation engine."""

from datetime import datetime, timedelta, timezone

from kub_health.correlator.dependency_graph import build_dependency_graph
from kub_health.correlator.engine import correlate_findings
from kub_health.correlator.timeline import build_timeline
from kub_health.models import (
    CheckCategory,
    CheckResult,
    ClusterSnapshot,
    DependencyGraph,
    Finding,
    ResourceKey,
    Severity,
    TimelineEvent,
)

from tests.conftest import (
    K8sObj,
    make_event,
    make_node,
    make_pod,
    make_pvc,
    make_replicaset,
    make_service,
    make_deployment,
)


def _empty_timeline():
    return []


class TestCorrelateFindings:
    def test_empty_findings(self):
        groups, uncorrelated = correlate_findings([], DependencyGraph(), [])
        assert groups == []
        assert uncorrelated == []

    def test_single_uncorrelated_finding(self):
        """A standalone finding with no related resources stays uncorrelated."""
        cr = CheckResult(
            category=CheckCategory.PODS,
            findings=[
                Finding(
                    category=CheckCategory.PODS,
                    severity=Severity.WARNING,
                    resource=ResourceKey("Pod", "lonely-pod", "default"),
                    message="High restart count",
                )
            ],
        )
        groups, uncorrelated = correlate_findings([cr], DependencyGraph(), [])
        assert len(groups) == 0
        assert len(uncorrelated) == 1
        assert uncorrelated[0].message == "High restart count"


class TestNodeCorrelation:
    def test_node_issue_claims_pod_findings(self):
        """Node CRITICAL finding should group pod findings on that node."""
        node_finding = Finding(
            category=CheckCategory.NODES,
            severity=Severity.CRITICAL,
            resource=ResourceKey("Node", "node-1"),
            message="Node NotReady",
        )
        pod_finding = Finding(
            category=CheckCategory.PODS,
            severity=Severity.CRITICAL,
            resource=ResourceKey("Pod", "p1", "default"),
            message="CrashLoopBackOff",
        )

        snap = ClusterSnapshot(
            nodes=[make_node("node-1", conditions=[K8sObj(type="Ready", status="False", reason="KubeletDown", message="")])],
            pods=[make_pod("p1", node_name="node-1")],
        )
        graph = build_dependency_graph(snap)
        timeline = build_timeline(snap)

        crs = [
            CheckResult(category=CheckCategory.NODES, findings=[node_finding]),
            CheckResult(category=CheckCategory.PODS, findings=[pod_finding]),
        ]

        groups, uncorrelated = correlate_findings(crs, graph, timeline)
        assert len(groups) == 1
        assert groups[0].root_cause.resource.kind == "Node"
        assert len(groups[0].symptoms) == 1
        assert groups[0].symptoms[0].resource.kind == "Pod"
        assert len(uncorrelated) == 0

    def test_node_info_severity_not_grouped(self):
        """Node findings with only INFO severity should not trigger grouping."""
        node_finding = Finding(
            category=CheckCategory.NODES,
            severity=Severity.INFO,
            resource=ResourceKey("Node", "node-1"),
            message="Low allocation",
        )
        pod_finding = Finding(
            category=CheckCategory.PODS,
            severity=Severity.WARNING,
            resource=ResourceKey("Pod", "p1", "default"),
            message="High restarts",
        )

        snap = ClusterSnapshot(
            nodes=[make_node("node-1")],
            pods=[make_pod("p1", node_name="node-1")],
        )
        graph = build_dependency_graph(snap)

        crs = [
            CheckResult(category=CheckCategory.NODES, findings=[node_finding]),
            CheckResult(category=CheckCategory.PODS, findings=[pod_finding]),
        ]

        groups, uncorrelated = correlate_findings(crs, graph, [])
        # Node finding is INFO, so no node-level grouping happens
        assert len(groups) == 0
        assert len(uncorrelated) == 2


class TestDeploymentCorrelation:
    def test_deployment_groups_pod_findings(self):
        """Deployment finding should claim related pod findings."""
        deploy_finding = Finding(
            category=CheckCategory.DEPLOYMENTS,
            severity=Severity.WARNING,
            resource=ResourceKey("Deployment", "web", "default"),
            message="Replica mismatch",
        )
        pod_finding = Finding(
            category=CheckCategory.PODS,
            severity=Severity.CRITICAL,
            resource=ResourceKey("Pod", "web-rs-pod1", "default"),
            message="CrashLoopBackOff",
        )

        snap = ClusterSnapshot(
            deployments=[make_deployment("web", ready_replicas=1)],
            replicasets=[make_replicaset("web-rs", owner_deployment="web")],
            pods=[make_pod("web-rs-pod1", owner_kind="ReplicaSet", owner_name="web-rs")],
        )
        graph = build_dependency_graph(snap)

        crs = [
            CheckResult(category=CheckCategory.DEPLOYMENTS, findings=[deploy_finding]),
            CheckResult(category=CheckCategory.PODS, findings=[pod_finding]),
        ]

        groups, uncorrelated = correlate_findings(crs, graph, [])
        assert len(groups) == 1
        assert groups[0].root_cause.resource.kind == "Deployment"
        assert len(uncorrelated) == 0


class TestStorageCorrelation:
    def test_pvc_issue_claims_pod_findings(self):
        """Unbound PVC finding should group pod findings that mount it."""
        pvc_finding = Finding(
            category=CheckCategory.STORAGE,
            severity=Severity.CRITICAL,
            resource=ResourceKey("PVC", "data-vol", "default"),
            message="PVC is Pending (unbound)",
        )
        pod_finding = Finding(
            category=CheckCategory.PODS,
            severity=Severity.WARNING,
            resource=ResourceKey("Pod", "db-0", "default"),
            message="Pending for 30m",
        )

        snap = ClusterSnapshot(
            pvcs=[make_pvc("data-vol", phase="Pending")],
            pods=[
                make_pod(
                    "db-0",
                    phase="Pending",
                    volumes=[K8sObj(persistent_volume_claim=K8sObj(claim_name="data-vol"), config_map=None, secret=None)],
                )
            ],
        )
        graph = build_dependency_graph(snap)

        crs = [
            CheckResult(category=CheckCategory.STORAGE, findings=[pvc_finding]),
            CheckResult(category=CheckCategory.PODS, findings=[pod_finding]),
        ]

        groups, uncorrelated = correlate_findings(crs, graph, [])
        assert len(groups) == 1
        assert groups[0].root_cause.resource.kind == "PVC"
        assert len(uncorrelated) == 0


class TestServiceCorrelation:
    def test_service_no_endpoints_with_critical_pod(self):
        """Service finding + critical pod finding -> pod becomes root cause."""
        svc_finding = Finding(
            category=CheckCategory.NETWORKING,
            severity=Severity.WARNING,
            resource=ResourceKey("Service", "web-svc", "default"),
            message="No endpoints",
        )
        pod_finding = Finding(
            category=CheckCategory.PODS,
            severity=Severity.CRITICAL,
            resource=ResourceKey("Pod", "web-1", "default"),
            message="CrashLoopBackOff",
        )

        snap = ClusterSnapshot(
            services=[make_service("web-svc", selector={"app": "web"})],
            pods=[make_pod("web-1", labels={"app": "web"})],
        )
        graph = build_dependency_graph(snap)

        crs = [
            CheckResult(category=CheckCategory.NETWORKING, findings=[svc_finding]),
            CheckResult(category=CheckCategory.PODS, findings=[pod_finding]),
        ]

        groups, uncorrelated = correlate_findings(crs, graph, [])
        assert len(groups) == 1
        # Critical pod should be the root cause (reversed causality)
        assert groups[0].root_cause.resource.kind == "Pod"


class TestConfigCorrelation:
    def test_missing_configmap_groups_pods(self):
        """Two pods referencing the same missing ConfigMap get grouped."""
        missing_cm = ResourceKey("ConfigMap", "app-config", "default")
        f1 = Finding(
            category=CheckCategory.PODS,
            severity=Severity.CRITICAL,
            resource=ResourceKey("Pod", "p1", "default"),
            message="CreateContainerConfigError",
            related_resources=[missing_cm],
        )
        f2 = Finding(
            category=CheckCategory.PODS,
            severity=Severity.CRITICAL,
            resource=ResourceKey("Pod", "p2", "default"),
            message="CreateContainerConfigError",
            related_resources=[missing_cm],
        )

        crs = [CheckResult(category=CheckCategory.PODS, findings=[f1, f2])]
        groups, uncorrelated = correlate_findings(crs, DependencyGraph(), [])

        assert len(groups) == 1
        assert groups[0].root_cause.resource == missing_cm
        assert "missing" in groups[0].root_cause.message.lower()
        assert len(groups[0].symptoms) == 2

    def test_single_pod_missing_config_not_grouped(self):
        """A single pod referencing a missing ConfigMap doesn't warrant a group."""
        f1 = Finding(
            category=CheckCategory.PODS,
            severity=Severity.CRITICAL,
            resource=ResourceKey("Pod", "p1", "default"),
            message="CreateContainerConfigError",
            related_resources=[ResourceKey("ConfigMap", "app-config", "default")],
        )

        crs = [CheckResult(category=CheckCategory.PODS, findings=[f1])]
        groups, uncorrelated = correlate_findings(crs, DependencyGraph(), [])

        assert len(groups) == 0
        assert len(uncorrelated) == 1


class TestStrategyOrdering:
    def test_node_claims_before_deployment(self):
        """Node-level correlation should claim findings before deployment-level."""
        node_finding = Finding(
            category=CheckCategory.NODES,
            severity=Severity.CRITICAL,
            resource=ResourceKey("Node", "node-1"),
            message="Node NotReady",
        )
        deploy_finding = Finding(
            category=CheckCategory.DEPLOYMENTS,
            severity=Severity.WARNING,
            resource=ResourceKey("Deployment", "web", "default"),
            message="Replica mismatch",
        )
        pod_finding = Finding(
            category=CheckCategory.PODS,
            severity=Severity.CRITICAL,
            resource=ResourceKey("Pod", "web-rs-pod1", "default"),
            message="CrashLoopBackOff",
        )

        snap = ClusterSnapshot(
            nodes=[make_node("node-1", conditions=[K8sObj(type="Ready", status="False", reason="KubeletDown", message="")])],
            deployments=[make_deployment("web", ready_replicas=1)],
            replicasets=[make_replicaset("web-rs", owner_deployment="web")],
            pods=[make_pod("web-rs-pod1", node_name="node-1", owner_kind="ReplicaSet", owner_name="web-rs")],
        )
        graph = build_dependency_graph(snap)

        crs = [
            CheckResult(category=CheckCategory.NODES, findings=[node_finding]),
            CheckResult(category=CheckCategory.DEPLOYMENTS, findings=[deploy_finding]),
            CheckResult(category=CheckCategory.PODS, findings=[pod_finding]),
        ]

        groups, uncorrelated = correlate_findings(crs, graph, [])

        # Node group should claim the pod finding
        node_groups = [g for g in groups if g.root_cause.resource.kind == "Node"]
        assert len(node_groups) == 1
        node_symptom_ids = {s.id for s in node_groups[0].symptoms}
        assert pod_finding.id in node_symptom_ids

        # Deployment finding should still end up somewhere (either own group or uncorrelated)
        # but should NOT have the pod finding as a symptom
        deploy_groups = [g for g in groups if g.root_cause and g.root_cause.resource.kind == "Deployment"]
        for dg in deploy_groups:
            assert pod_finding.id not in {s.id for s in dg.symptoms}
