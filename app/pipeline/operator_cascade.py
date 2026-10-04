"""Operator Cascade Dispatch Queue (Module #3)."""
import asyncio
from datetime import datetime, timezone
from typing import List
from app.models.incident import IncidentRecord

class OperatorCascadeQueue:
    def __init__(self):
        self._queue: asyncio.Queue[IncidentRecord] = asyncio.Queue()
        self.dispatched_log: List[dict] = []

    async def enqueue(self, incident: IncidentRecord) -> dict:
        """Enqueues and immediately prepares cascade notification."""
        await self._queue.put(incident)
        record = {
            "incident_id": incident.incident_id,
            "dispatched_at": datetime.now(timezone.utc).isoformat(),
            "status": "DISPATCHED_ZERO_DELAY",
            "entity": incident.compromised_entity_id,
            "severity": incident.severity.value,
        }
        self.dispatched_log.append(record)
        return record

cascade_queue = OperatorCascadeQueue()
