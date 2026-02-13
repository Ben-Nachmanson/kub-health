"""Tests for kub_health.models data structures."""

from datetime import datetime, timezone

from kub_health.models import (
    CheckCategory,
    CheckResult,
    CorrelationGroup,
    DependencyEdge,
    DependencyGraph,
    DependencyType,
    Finding,
    InvestigationReport,
    ResourceKey,
    Severity,
    TimelineEvent,
)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_sort_order_critical_first(self):
        assert Severity.CRITICAL.sort_order < Severity.WARNING.sort_order
        assert Severity.WARNING.sort_order < Severity.INFO.sort_order
        assert Severity.INFO.sort_order < Severity.OK.sort_order

    def test_rich_labels_exist(self):
        for s in Severity:
            assert s.rich_label  # not empty


# ---------------------------------------------------------------------------
# ResourceKey
# ---------------------------------------------------------------------------


class TestResourceKey:
    def test_str_with_namespace(self):
        rk = ResourceKey("Pod", "my-pod", "default")
        assert str(rk) == "Pod/default/my-pod"

    def test_str_without_namespace(self):
        rk = ResourceKey("Node", "node-1")
        assert str(rk) == "Node/node-1"

    def test_frozen(self):
        rk = ResourceKey("Pod", "p", "ns")
        # Should be hashable (usable in sets/dicts)
        s = {rk}
        assert rk in s

    def test_equality(self):
        a = ResourceKey("Pod", "p", "ns")
        b = ResourceKey("Pod", "p", "ns")
        assert a == b
        c = ResourceKey("Pod", "p", "other")
        assert a != c


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFinding:
    def test_auto_id(self):
        f1 = Finding()
        f2 = Finding()
        assert f1.id != f2.id

    def test_to_dict(self):
        f = Finding(
            category=CheckCategory.PODS,
            severity=Severity.CRITICAL,
            resource=ResourceKey("Pod", "p", "ns"),
            message="test",
        )
        d = f.to_dict()
        assert d["category"] == "Pod Health"
        assert d["severity"] == "critical"
        assert d["resource"] == "Pod/ns/p"

    def test_defaults(self):
        f = Finding()
        assert f.details == {}
        assert f.related_resources == []
        assert f.evidence == []
        assert f.remediation == ""


# ---------------------------------------------------------------------------
# DependencyGraph
# ---------------------------------------------------------------------------


class TestDependencyGraph:
    def test_add_edge_and_lookup(self):
        g = DependencyGraph()
        pod = ResourceKey("Pod", "p", "ns")
        node = ResourceKey("Node", "n")
        edge = DependencyEdge(source=pod, target=node, dep_type=DependencyType.RUNS_ON)
        g.add_edge(edge)

        # Forward: pod depends on node
        assert g.dependencies_of(pod) == [edge]
        # Reverse: node has pod as dependent
        assert g.dependents_of(node) == [edge]

    def test_impact_radius(self):
        g = DependencyGraph()
        node = ResourceKey("Node", "n")
        pod1 = ResourceKey("Pod", "p1", "ns")
        pod2 = ResourceKey("Pod", "p2", "ns")
        g.add_edge(DependencyEdge(pod1, node, DependencyType.RUNS_ON))
        g.add_edge(DependencyEdge(pod2, node, DependencyType.RUNS_ON))

        # Impact of node failing includes itself + both pods
        impact = g.impact_radius(node)
        assert node in impact
        assert pod1 in impact
        assert pod2 in impact

    def test_dependency_chain(self):
        g = DependencyGraph()
        deploy = ResourceKey("Deployment", "d", "ns")
        rs = ResourceKey("ReplicaSet", "d-abc123", "ns")
        pod = ResourceKey("Pod", "d-abc123-xyz", "ns")
        g.add_edge(DependencyEdge(deploy, rs, DependencyType.OWNS))
        g.add_edge(DependencyEdge(rs, pod, DependencyType.OWNS))

        chain = g.dependency_chain(deploy)
        assert deploy in chain
        assert rs in chain
        assert pod in chain

    def test_empty_lookups(self):
        g = DependencyGraph()
        rk = ResourceKey("Pod", "x", "ns")
        assert g.dependencies_of(rk) == []
        assert g.dependents_of(rk) == []
        assert g.impact_radius(rk) == {rk}
        assert g.dependency_chain(rk) == {rk}


# ---------------------------------------------------------------------------
# CheckResult
# ---------------------------------------------------------------------------


class TestCheckResult:
    def test_empty_result(self):
        r = CheckResult(category=CheckCategory.PODS)
        assert r.critical_count == 0
        assert r.warning_count == 0
        assert r.worst_severity == Severity.OK

    def test_severity_counts(self):
        r = CheckResult(
            category=CheckCategory.PODS,
            findings=[
                Finding(severity=Severity.CRITICAL),
                Finding(severity=Severity.WARNING),
                Finding(severity=Severity.WARNING),
                Finding(severity=Severity.INFO),
            ],
        )
        assert r.critical_count == 1
        assert r.warning_count == 2
        assert r.worst_severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# CorrelationGroup
# ---------------------------------------------------------------------------


class TestCorrelationGroup:
    def test_severity_from_root_cause(self):
        g = CorrelationGroup(
            root_cause=Finding(severity=Severity.WARNING),
            symptoms=[Finding(severity=Severity.CRITICAL)],
        )
        # Severity comes from root cause, not symptoms
        assert g.severity == Severity.WARNING

    def test_severity_no_root_cause(self):
        g = CorrelationGroup(
            symptoms=[
                Finding(severity=Severity.INFO),
                Finding(severity=Severity.WARNING),
            ]
        )
        assert g.severity == Severity.WARNING

    def test_all_findings(self):
        root = Finding(severity=Severity.CRITICAL)
        s1 = Finding(severity=Severity.WARNING)
        g = CorrelationGroup(root_cause=root, symptoms=[s1])
        assert len(g.all_findings) == 2
        assert g.all_findings[0] is root


# ---------------------------------------------------------------------------
# InvestigationReport
# ---------------------------------------------------------------------------


class TestInvestigationReport:
    def test_total_findings(self):
        r = InvestigationReport(
            cluster_name="test",
            context="test-ctx",
            check_results=[
                CheckResult(category=CheckCategory.PODS, findings=[Finding(), Finding()]),
                CheckResult(category=CheckCategory.NODES, findings=[Finding()]),
            ],
        )
        assert r.total_findings == 3

    def test_overall_health_empty(self):
        r = InvestigationReport(cluster_name="test", context="test-ctx")
        assert r.overall_health == Severity.OK

    def test_overall_health_critical(self):
        r = InvestigationReport(
            cluster_name="test",
            context="test-ctx",
            check_results=[
                CheckResult(
                    category=CheckCategory.PODS,
                    findings=[Finding(severity=Severity.CRITICAL)],
                ),
                CheckResult(
                    category=CheckCategory.NODES,
                    findings=[Finding(severity=Severity.INFO)],
                ),
            ],
        )
        assert r.overall_health == Severity.CRITICAL

    def test_findings_summary_text_not_empty(self):
        r = InvestigationReport(
            cluster_name="my-cluster",
            context="admin@my-cluster",
            check_results=[
                CheckResult(
                    category=CheckCategory.PODS,
                    findings=[
                        Finding(
                            severity=Severity.CRITICAL,
                            resource=ResourceKey("Pod", "crash-pod", "default"),
                            message="CrashLoopBackOff",
                        )
                    ],
                ),
            ],
        )
        text = r.findings_summary_text()
        assert "my-cluster" in text
        assert "CrashLoopBackOff" in text
        assert "crash-pod" in text

    def test_all_findings_sorted(self):
        r = InvestigationReport(
            cluster_name="test",
            context="ctx",
            check_results=[
                CheckResult(
                    category=CheckCategory.PODS,
                    findings=[
                        Finding(severity=Severity.INFO),
                        Finding(severity=Severity.CRITICAL),
                        Finding(severity=Severity.WARNING),
                    ],
                ),
            ],
        )
        sorted_findings = r.all_findings_sorted()
        assert sorted_findings[0].severity == Severity.CRITICAL
        assert sorted_findings[1].severity == Severity.WARNING
        assert sorted_findings[2].severity == Severity.INFO
