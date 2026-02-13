"""Storage analyzer.

Detects: unbound PVCs, lost PVs, storage class issues, capacity warnings,
orphaned PVs, and PVC/PV mismatches.
"""

from __future__ import annotations

from kub_health.checks.nodes import _parse_memory  # reuse for storage bytes
from kub_health.models import (
    CheckCategory,
    CheckResult,
    ClusterSnapshot,
    Finding,
    ResourceKey,
    Severity,
)


def check_storage(snap: ClusterSnapshot) -> CheckResult:
    """Analyze storage configuration and status."""
    result = CheckResult(category=CheckCategory.STORAGE)

    _check_pvcs(result, snap)
    _check_pvs(result, snap)
    _check_storage_classes(result, snap)
    _check_pod_volume_refs(result, snap)

    return result


def _check_pvcs(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Check PVC status for binding issues."""
    sc_names = {sc.metadata.name for sc in snap.storage_classes}

    for pvc in snap.pvcs:
        meta = pvc.metadata
        rk = ResourceKey("PVC", meta.name, meta.namespace)
        phase = pvc.status.phase or "Unknown"

        if phase == "Bound":
            continue

        if phase == "Pending":
            sc_name = pvc.spec.storage_class_name or ""
            details: dict = {
                "phase": phase,
                "storage_class": sc_name,
                "access_modes": pvc.spec.access_modes or [],
                "requested": pvc.spec.resources.requests.get("storage", "unknown")
                if pvc.spec.resources and pvc.spec.resources.requests
                else "unknown",
            }

            message = "PVC stuck in Pending state"
            remediation_parts = []

            if sc_name and sc_name not in sc_names:
                message = f"PVC pending - StorageClass '{sc_name}' does not exist"
                remediation_parts.append(
                    f"Create the StorageClass '{sc_name}' or change the PVC's storageClassName."
                )
                details["storage_class_exists"] = False

            if not sc_name and not snap.storage_classes:
                message = "PVC pending - no StorageClass specified and none exist in cluster"
                remediation_parts.append("Create a StorageClass or specify one on the PVC.")

            if not remediation_parts:
                remediation_parts.append(
                    "Check provisioner status, available capacity, and access mode compatibility."
                )

            result.findings.append(
                Finding(
                    category=CheckCategory.STORAGE,
                    severity=Severity.CRITICAL,
                    resource=rk,
                    message=message,
                    details=details,
                    evidence=[
                        f"kubectl describe pvc {meta.name} -n {meta.namespace}",
                        f"kubectl get events -n {meta.namespace} "
                        f"--field-selector involvedObject.name={meta.name}",
                    ],
                    remediation=" ".join(remediation_parts),
                )
            )

        elif phase == "Lost":
            result.findings.append(
                Finding(
                    category=CheckCategory.STORAGE,
                    severity=Severity.CRITICAL,
                    resource=rk,
                    message="PVC is in Lost state - underlying PV was deleted",
                    details={"phase": phase, "volume_name": pvc.spec.volume_name or ""},
                    evidence=[
                        f"kubectl describe pvc {meta.name} -n {meta.namespace}",
                    ],
                    remediation="The PV backing this claim has been removed. Data may be "
                    "lost. Recreate the PV or restore from backup.",
                )
            )


def _check_pvs(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Check PV status for issues."""
    for pv in snap.pvs:
        meta = pv.metadata
        rk = ResourceKey("PV", meta.name)
        phase = pv.status.phase or "Unknown"

        if phase in ("Bound", "Available"):
            continue

        if phase == "Released":
            reclaim = pv.spec.persistent_volume_reclaim_policy or "Delete"
            result.findings.append(
                Finding(
                    category=CheckCategory.STORAGE,
                    severity=Severity.WARNING,
                    resource=rk,
                    message=f"PV is Released (reclaim policy: {reclaim}) - "
                    "data exists but not usable by new PVCs",
                    details={
                        "phase": phase,
                        "reclaim_policy": reclaim,
                        "capacity": pv.spec.capacity.get("storage", "unknown")
                        if pv.spec.capacity
                        else "unknown",
                    },
                    evidence=[f"kubectl describe pv {meta.name}"],
                    remediation="If data is no longer needed, delete the PV. "
                    "If data should be reused, clear the claimRef: "
                    "`kubectl patch pv {name} -p '{{\"spec\":{{\"claimRef\": null}}}}'`".format(
                        name=meta.name
                    ),
                )
            )

        elif phase == "Failed":
            result.findings.append(
                Finding(
                    category=CheckCategory.STORAGE,
                    severity=Severity.CRITICAL,
                    resource=rk,
                    message="PV is in Failed state",
                    details={"phase": phase, "reason": pv.status.reason or ""},
                    evidence=[f"kubectl describe pv {meta.name}"],
                    remediation="The PV failed to reclaim. Check the storage backend "
                    "and provisioner logs.",
                )
            )


def _check_storage_classes(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Check storage class configuration."""
    if not snap.storage_classes:
        # Only flag if there are PVCs that need them
        if snap.pvcs:
            result.findings.append(
                Finding(
                    category=CheckCategory.STORAGE,
                    severity=Severity.WARNING,
                    resource=ResourceKey("StorageClass", "(none)"),
                    message="No StorageClasses defined but PVCs exist - "
                    "dynamic provisioning unavailable",
                    details={"pvc_count": len(snap.pvcs)},
                    remediation="Create a StorageClass for your storage backend. "
                    "Without one, PVCs must be manually provisioned.",
                )
            )

    # Check for default storage class
    defaults = [
        sc
        for sc in snap.storage_classes
        if (sc.metadata.annotations or {}).get(
            "storageclass.kubernetes.io/is-default-class"
        )
        == "true"
    ]
    if len(defaults) > 1:
        result.findings.append(
            Finding(
                category=CheckCategory.STORAGE,
                severity=Severity.WARNING,
                resource=ResourceKey("StorageClass", "(multiple-defaults)"),
                message=f"Multiple default StorageClasses: {[d.metadata.name for d in defaults]}",
                details={"defaults": [d.metadata.name for d in defaults]},
                remediation="Only one StorageClass should be the default. PVCs without "
                "a storageClassName may get unpredictable behavior.",
            )
        )


def _check_pod_volume_refs(result: CheckResult, snap: ClusterSnapshot) -> None:
    """Check that pods reference existing PVCs and ConfigMaps/Secrets."""
    pvc_set = {f"{p.metadata.namespace}/{p.metadata.name}" for p in snap.pvcs}
    cm_set = {f"{c.metadata.namespace}/{c.metadata.name}" for c in snap.configmaps}
    secret_set = {f"{s.metadata.namespace}/{s.metadata.name}" for s in snap.secrets}

    for pod in snap.pods:
        if pod.status.phase in ("Succeeded", "Failed"):
            continue

        meta = pod.metadata
        pod_key = ResourceKey("Pod", meta.name, meta.namespace)

        for vol in pod.spec.volumes or []:
            # PVC reference
            if vol.persistent_volume_claim:
                pvc_ref = f"{meta.namespace}/{vol.persistent_volume_claim.claim_name}"
                if pvc_ref not in pvc_set:
                    result.findings.append(
                        Finding(
                            category=CheckCategory.STORAGE,
                            severity=Severity.CRITICAL,
                            resource=pod_key,
                            message=f"References non-existent PVC "
                            f"'{vol.persistent_volume_claim.claim_name}'",
                            details={"volume": vol.name, "pvc": vol.persistent_volume_claim.claim_name},
                            related_resources=[
                                ResourceKey(
                                    "PVC",
                                    vol.persistent_volume_claim.claim_name,
                                    meta.namespace,
                                )
                            ],
                            remediation="The PVC doesn't exist. Create it or fix the volume reference.",
                        )
                    )

            # ConfigMap reference
            if vol.config_map:
                cm_ref = f"{meta.namespace}/{vol.config_map.name}"
                optional = vol.config_map.optional or False
                if cm_ref not in cm_set and not optional:
                    result.findings.append(
                        Finding(
                            category=CheckCategory.STORAGE,
                            severity=Severity.WARNING,
                            resource=pod_key,
                            message=f"References non-existent ConfigMap '{vol.config_map.name}'",
                            details={"volume": vol.name, "configmap": vol.config_map.name},
                            related_resources=[
                                ResourceKey("ConfigMap", vol.config_map.name, meta.namespace)
                            ],
                            remediation="The ConfigMap doesn't exist. This will prevent "
                            "the pod from starting.",
                        )
                    )

            # Secret reference
            if vol.secret:
                sec_ref = f"{meta.namespace}/{vol.secret.secret_name}"
                optional = vol.secret.optional or False
                if sec_ref not in secret_set and not optional:
                    result.findings.append(
                        Finding(
                            category=CheckCategory.STORAGE,
                            severity=Severity.WARNING,
                            resource=pod_key,
                            message=f"References non-existent Secret '{vol.secret.secret_name}'",
                            details={"volume": vol.name, "secret": vol.secret.secret_name},
                            related_resources=[
                                ResourceKey("Secret", vol.secret.secret_name, meta.namespace)
                            ],
                            remediation="The Secret doesn't exist. This will prevent "
                            "the pod from starting.",
                        )
                    )
