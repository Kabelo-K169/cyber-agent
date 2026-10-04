from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field


class NotificationStatus(str, Enum):
    PENDING = "pending"
    DISPATCHED = "dispatched"
    FAILED = "failed"


class NotificationInvariant(BaseModel):
    """Every incident must register a notification task — no materiality drop-filter."""
    incident_id: str
    requires_notification: bool = Field(default=True, frozen=True)
    status: NotificationStatus = NotificationStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def dispatch(self) -> None:
        self.status = NotificationStatus.DISPATCHED


class OperatorCascadeQueue:
    """Immediate operator dispatch queue. No drop-filtering at enqueue."""
    def __init__(self):
        self._queue: list[dict] = []

    def enqueue(self, incident: dict) -> None:
        self._queue.append({
            "enqueued_at": datetime.now(timezone.utc).isoformat(),
            "incident": incident,
            "status": "ready_for_operator",
        })

    def get_all(self) -> list[dict]:
        return list(self._queue)

    def __len__(self) -> int:
        return len(self._queue)
