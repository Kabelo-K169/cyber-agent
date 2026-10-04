from datetime import datetime, timezone
from pydantic import BaseModel, Field


class StatutoryClock(BaseModel):
    """Immutable reasonable_grounds_at timestamp and statutory elapsed-time calculation."""
    reasonable_grounds_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        frozen=True,
    )

    def elapsed_seconds(self, now: datetime | None = None) -> float:
        current = now or datetime.now(timezone.utc)
        return (current - self.reasonable_grounds_at).total_seconds()

    def is_within_statutory_window(self, max_hours: float = 72.0) -> bool:
        """Whether the incident is still inside the POPIA notification window."""
        return self.elapsed_seconds() <= (max_hours * 3600.0)
