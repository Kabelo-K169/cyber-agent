"""POPIA Statutory Clock (Module #1) and Strict Notification Invariant (Module #2)."""
from __future__ import annotations
import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

class BreachNature(str, enum.Enum):
    UNAUTHORIZED_ACCESS = "unauthorised_access"
    RANSOMWARE = "ransomware"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    MALWARE = "malware"
    ACCIDENTAL_DISCLOSURE = "accidental_disclosure"

class SeverityLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentRecord(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    source_system: str
    breach_nature: BreachNature
    compromised_entity_id: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    reasonable_grounds_at: datetime
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    requires_notification: bool = True
    dismissal_justification: Optional[str] = None
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)
    attested: bool = False

    @field_validator("reasonable_grounds_at")
    @classmethod
    def ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @model_validator(mode="after")
    def enforce_strict_notification_invariant(self) -> IncidentRecord:
        """Severity (LOW/MEDIUM/HIGH/CRITICAL) cannot drop statutory notification duty."""
        if not self.requires_notification and not self.dismissal_justification:
            raise ValueError(
                "POPIA S22(1) Invariant Violation: requires_notification cannot be False "
                "without a documented dismissal_justification."
            )
        return self

    @classmethod
    def create_breach_record(
        cls,
        source_system: str,
        breach_nature: BreachNature,
        compromised_entity_id: str,
        reasonable_grounds_at: Optional[datetime] = None,
        severity: SeverityLevel = SeverityLevel.MEDIUM,
        raw_metadata: Optional[Dict[str, Any]] = None,
    ) -> IncidentRecord:
        rg_time = reasonable_grounds_at or datetime.now(timezone.utc)
        return cls(
            source_system=source_system,
            breach_nature=breach_nature,
            compromised_entity_id=compromised_entity_id,
            severity=severity,
            reasonable_grounds_at=rg_time,
            raw_metadata=raw_metadata or {},
        )
