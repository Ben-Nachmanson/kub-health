"""Tests for pod health checks."""

from datetime import datetime, timedelta, timezone

from kub_health.checks.pods import check_pods
from kub_health.models import CheckCategory, ClusterSnapshot, Severity

from tests.conftest import K8sObj, make_pod


class TestCheckPodsCrashLoop:
    def test_crashloop_detected(self):
        pod = make_pod(
            "crash-pod",
            container_statuses=[
                K8sObj(
                    name="main",
                    state=K8sObj(
                        waiting=K8sObj(reason="CrashLoopBackOff", message="back-off 5m0s"),
                        running=None,
                        terminated=None,
                    ),
                    last_state=K8sObj(terminated=None),
                    restart_count=15,
                    image="app:latest",
                    ready=False,
                )
            ],
        )
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)

        assert result.category == CheckCategory.PODS
        crash_findings = [f for f in result.findings if "CrashLoopBackOff" in f.message]
        assert len(crash_findings) >= 1
        assert crash_findings[0].severity == Severity.CRITICAL

    def test_healthy_pod_no_findings(self):
        pod = make_pod(
            "healthy-pod",
            container_statuses=[
                K8sObj(
                    name="main",
                    state=K8sObj(running=K8sObj(started_at=datetime.now(timezone.utc)), waiting=None, terminated=None),
                    last_state=K8sObj(terminated=None),
                    restart_count=0,
                    image="app:v1",
                    ready=True,
                )
            ],
            conditions=[
                K8sObj(type="Ready", status="True", reason="", message="", last_transition_time=None),
            ],
        )
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)
        assert len(result.findings) == 0


class TestCheckPodsImagePull:
    def test_image_pull_backoff(self):
        pod = make_pod(
            "bad-image-pod",
            container_statuses=[
                K8sObj(
                    name="main",
                    state=K8sObj(
                        waiting=K8sObj(reason="ImagePullBackOff", message="image not found"),
                        running=None,
                        terminated=None,
                    ),
                    last_state=K8sObj(terminated=None),
                    restart_count=0,
                    image="nonexistent:latest",
                    ready=False,
                )
            ],
        )
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)

        image_findings = [f for f in result.findings if "image pull" in f.message.lower()]
        assert len(image_findings) >= 1
        assert image_findings[0].severity == Severity.CRITICAL


class TestCheckPodsPending:
    def test_long_pending_critical(self):
        creation = datetime.now(timezone.utc) - timedelta(minutes=20)
        pod = make_pod(
            "stuck-pod",
            phase="Pending",
            creation_timestamp=creation,
            conditions=[
                K8sObj(
                    type="PodScheduled",
                    status="False",
                    reason="Unschedulable",
                    message="0/3 nodes are available: insufficient cpu",
                )
            ],
        )
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)

        pending_findings = [f for f in result.findings if "Pending" in f.message]
        assert len(pending_findings) >= 1
        assert pending_findings[0].severity == Severity.CRITICAL

    def test_recently_pending_info(self):
        creation = datetime.now(timezone.utc) - timedelta(minutes=1)
        pod = make_pod(
            "new-pod",
            phase="Pending",
            creation_timestamp=creation,
        )
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)

        pending_findings = [f for f in result.findings if "Pending" in f.message]
        assert len(pending_findings) >= 1
        assert pending_findings[0].severity == Severity.INFO


class TestCheckPodsOOMKilled:
    def test_oom_killed(self):
        pod = make_pod(
            "oom-pod",
            container_statuses=[
                K8sObj(
                    name="main",
                    state=K8sObj(running=K8sObj(started_at=datetime.now(timezone.utc)), waiting=None, terminated=None),
                    last_state=K8sObj(
                        terminated=K8sObj(
                            reason="OOMKilled",
                            exit_code=137,
                            finished_at=datetime.now(timezone.utc) - timedelta(minutes=5),
                        )
                    ),
                    restart_count=3,
                    image="app:v1",
                    ready=True,
                )
            ],
        )
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)

        oom_findings = [f for f in result.findings if "OOMKilled" in f.message]
        assert len(oom_findings) >= 1
        assert oom_findings[0].severity == Severity.CRITICAL


class TestCheckPodsReadiness:
    def test_long_unready_warning(self):
        pod = make_pod(
            "unready-pod",
            container_statuses=[
                K8sObj(
                    name="main",
                    state=K8sObj(running=K8sObj(started_at=datetime.now(timezone.utc)), waiting=None, terminated=None),
                    last_state=K8sObj(terminated=None),
                    restart_count=0,
                    image="app:v1",
                    ready=False,
                )
            ],
            conditions=[
                K8sObj(
                    type="Ready",
                    status="False",
                    reason="ContainersNotReady",
                    message="containers with unready status: [main]",
                    last_transition_time=datetime.now(timezone.utc) - timedelta(minutes=10),
                ),
            ],
        )
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)

        ready_findings = [f for f in result.findings if "not Ready" in f.message]
        assert len(ready_findings) >= 1
        assert ready_findings[0].severity == Severity.WARNING


class TestCheckPodsHighRestarts:
    def test_high_restart_warning(self):
        pod = make_pod(
            "restart-pod",
            container_statuses=[
                K8sObj(
                    name="main",
                    state=K8sObj(running=K8sObj(started_at=datetime.now(timezone.utc)), waiting=None, terminated=None),
                    last_state=K8sObj(terminated=None),
                    restart_count=10,
                    image="app:v1",
                    ready=True,
                )
            ],
        )
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)

        restart_findings = [f for f in result.findings if "restarts" in f.message]
        assert len(restart_findings) >= 1
        assert restart_findings[0].severity == Severity.WARNING

    def test_critical_restart_threshold(self):
        pod = make_pod(
            "many-restart-pod",
            container_statuses=[
                K8sObj(
                    name="main",
                    state=K8sObj(running=K8sObj(started_at=datetime.now(timezone.utc)), waiting=None, terminated=None),
                    last_state=K8sObj(terminated=None),
                    restart_count=25,
                    image="app:v1",
                    ready=True,
                )
            ],
        )
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)

        restart_findings = [f for f in result.findings if "restarts" in f.message]
        assert len(restart_findings) >= 1
        assert restart_findings[0].severity == Severity.CRITICAL


class TestCheckPodsFailed:
    def test_failed_pod_detected(self):
        pod = make_pod("evicted-pod", phase="Failed")
        pod.status.reason = "Evicted"
        pod.status.message = "The node was low on resource: memory."
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)

        failed_findings = [f for f in result.findings if "Failed" in f.message]
        assert len(failed_findings) >= 1
        assert failed_findings[0].severity == Severity.CRITICAL


class TestCheckPodsCreateConfigError:
    def test_create_config_error(self):
        pod = make_pod(
            "config-err-pod",
            container_statuses=[
                K8sObj(
                    name="main",
                    state=K8sObj(
                        waiting=K8sObj(
                            reason="CreateContainerConfigError",
                            message='configmap "app-config" not found',
                        ),
                        running=None,
                        terminated=None,
                    ),
                    last_state=K8sObj(terminated=None),
                    restart_count=0,
                    image="app:v1",
                    ready=False,
                )
            ],
        )
        snap = ClusterSnapshot(pods=[pod])
        result = check_pods(snap)

        config_findings = [f for f in result.findings if "config error" in f.message.lower()]
        assert len(config_findings) >= 1
        assert config_findings[0].severity == Severity.CRITICAL
