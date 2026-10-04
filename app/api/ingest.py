"""Telemetry Ingestion Endpoint (Module #5)."""
from datetime import datetime
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from app.models.incident import BreachNature, IncidentRecord, SeverityLevel
from app.pipeline.operator_cascade import cascade_queue

router = APIRouter(prefix="/v1/telemetry", tags=["telemetry"])

# In-memory store for incidents
incidents_db: Dict[str, IncidentRecord] = {}

class TelemetryPayload(BaseModel):
    source_system: str
    breach_nature: BreachNature
    compromised_entity_id: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    reasonable_grounds_at: Optional[datetime] = None
    requires_notification: bool = True
    dismissal_justification: Optional[str] = None
    raw_metadata: Dict[str, Any] = {}

@router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_telemetry(payload: TelemetryPayload):
    try:
        record = IncidentRecord(
            source_system=payload.source_system,
            breach_nature=payload.breach_nature,
            compromised_entity_id=payload.compromised_entity_id,
            severity=payload.severity,
            reasonable_grounds_at=payload.reasonable_grounds_at or datetime.now(),
            requires_notification=payload.requires_notification,
            dismissal_justification=payload.dismissal_justification,
            raw_metadata=payload.raw_metadata,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    incidents_db[record.incident_id] = record
    dispatch = await cascade_queue.enqueue(record)

    return {
        "status": "INGESTED_AND_DISPATCHED",
        "incident_id": record.incident_id,
        "reasonable_grounds_at": record.reasonable_grounds_at.isoformat(),
        "cascade": dispatch,
    }
