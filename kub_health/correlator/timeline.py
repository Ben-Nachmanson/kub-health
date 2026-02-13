"""Event timeline builder.

Reconstructs a chronological timeline of cluster events, grouped by resource,
so the correlation engine can determine causality chains (e.g., "a taint was
added to the node, then 5 pods on that node failed scheduling").
"""

from __future__ import annotations

from datetime import datetime, timezone

from kub_health.models import ClusterSnapshot, ResourceKey, TimelineEvent


def build_timeline(snap: ClusterSnapshot) -> list[TimelineEvent]:
    """Build a sorted timeline of all cluster events."""
    timeline: list[TimelineEvent] = []

    for event in snap.events:
        obj = event.involved_object
        rk = ResourceKey(
            obj.kind or "Unknown",
            obj.name or "unknown",
            obj.namespace or "",
        )

        # Use last_timestamp if available, otherwise fall back
        ts = (
            event.last_timestamp
            or event.event_time
            or event.metadata.creation_timestamp
        )
        if ts is None:
            continue

        # Ensure timezone-aware
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        source_component = ""
        if event.source:
            source_component = event.source.component or ""

        timeline.append(
            TimelineEvent(
                timestamp=ts,
                resource=rk,
                event_type=event.type or "Normal",
                reason=event.reason or "",
                message=event.message or "",
                count=event.count or 1,
                source_component=source_component,
            )
        )

    timeline.sort()
    return timeline


def events_for_resource(
    timeline: list[TimelineEvent], key: ResourceKey
) -> list[TimelineEvent]:
    """Filter timeline to events involving a specific resource."""
    return [e for e in timeline if e.resource == key]


def warning_events_in_window(
    timeline: list[TimelineEvent],
    start: datetime,
    end: datetime,
) -> list[TimelineEvent]:
    """Get all warning events within a time window."""
    return [
        e
        for e in timeline
        if e.event_type == "Warning" and start <= e.timestamp <= end
    ]


def recent_events(
    timeline: list[TimelineEvent],
    minutes: int = 30,
) -> list[TimelineEvent]:
    """Get events from the last N minutes."""
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=minutes)
    return [e for e in timeline if e.timestamp >= cutoff]
