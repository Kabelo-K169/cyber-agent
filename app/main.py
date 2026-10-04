from datetime import datetime, timezone
from fastapi import FastAPI, status
from pydantic import BaseModel
from app.clock import StatutoryClock
from app.notifications import NotificationInvariant, OperatorCascadeQueue

app = FastAPI(title="cyber-agent", version="0.1.0")

operator_queue = OperatorCascadeQueue()
incidents_db: dict[str, dict] = {}


class TelemetryIngestPayload(BaseModel):
    source_system: str
    source_event_id: str
    raw_payload: dict
    incident_type: str
    severity: str


@app.post("/api/v1/telemetry", status_code=status.HTTP_201_CREATED)
async def ingest_telemetry(payload: TelemetryIngestPayload):
    composite_key = f"{payload.source_system}:{payload.source_event_id}"
    if composite_key in incidents_db:
        return {"status": "duplicate", "incident_id": composite_key}

    clock = StatutoryClock()
    invariant = NotificationInvariant(incident_id=composite_key)

    record = {
        "incident_id": composite_key,
        "discovery_time": clock.reasonable_grounds_at.isoformat(),
        "payload": payload.model_dump(),
        "notification_status": invariant.status,
    }

    incidents_db[composite_key] = record
    operator_queue.enqueue(record)

    return {
        "status": "ingested",
        "incident_id": composite_key,
        "reasonable_grounds_at": record["discovery_time"],
        "queued": True,
    }


@app.get("/health")
async def health_check():
    return {"status": "ok"}
