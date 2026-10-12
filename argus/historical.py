"""Read-only reconstruction shared by historical CLI views."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from argus.analysis import deduplicate_events, select_historical_event_window
from argus.events import crowdsec_events_from_evidence, linux_auth_events_from_evidence
from argus.models import CollectionRun, SecurityEvent
from argus.storage import EvidenceStore


@dataclass(frozen=True)
class HistoricalSelection:
    events: tuple[tuple[SecurityEvent, int], ...]
    collections: tuple[CollectionRun, ...]
    all_collection_count: int


def reconstruct_historical_events(
    store: EvidenceStore | None,
    *,
    source: str,
    now: datetime,
    window: timedelta | None,
) -> HistoricalSelection:
    """Retain first stored identities, then select and sort event timestamps."""
    if source not in ("all", "crowdsec", "linux-auth"):
        raise ValueError(f"unknown historical source: {source}")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if window is not None and window <= timedelta(0):
        raise ValueError("window must be positive")
    collections = tuple(reversed(store.list_collections())) if store is not None else ()
    candidates: list[tuple[SecurityEvent, int]] = []
    for collection in collections:
        evidence = store.list_collection_evidence(collection.id)
        if source in ("all", "crowdsec"):
            candidates.extend(
                (event, collection.id)
                for event in crowdsec_events_from_evidence(evidence)
            )
        if source in ("all", "linux-auth"):
            candidates.extend(
                (event, collection.id)
                for event in linux_auth_events_from_evidence(evidence)
            )

    retained = deduplicate_events(event for event, _ in candidates)
    # Equal-valued observations still have distinct event objects and provenance.
    collection_by_event = {id(event): collection_id for event, collection_id in candidates}
    attributed = tuple((event, collection_by_event[id(event)]) for event in retained)
    selected = (
        attributed
        if window is None
        else select_historical_event_window(attributed, now=now, window=window)
    )
    ordered = tuple(sorted(selected, key=lambda item: item[0].timestamp, reverse=True))
    coverage = tuple(
        collection
        for collection in collections
        if window is None or now - window <= collection.collected_at <= now
    )
    return HistoricalSelection(ordered, coverage, len(collections))
