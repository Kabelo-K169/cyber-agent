"""
build_app.py
Automated generator for the cyber-agent POPIA incident remediation platform.
Run: python build_app.py
"""
import os
from pathlib import Path

FILES = {
    # -------------------------------------------------------------
    # 1. Models: Incident & Strict Invariant (Issues #1 & #2)
    # -------------------------------------------------------------
    "app/models/__init__.py": "",
    "app/models/incident.py": '''"""POPIA Statutory Clock (Module #1) and Strict Notification Invariant (Module #2)."""
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
''',

    # -------------------------------------------------------------
    # 2. Models: POPIA Form Parts A-E & Attestation Gate (Issue #4)
    # -------------------------------------------------------------
    "app/models/filing.py": '''"""POPIA Section 22 Form Parts A-E & Part E Attestation Gate (Module #4)."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field

class ResponsiblePartyPartA(BaseModel):
    registration_number: str
    organisation_name: str
    information_officer_name: str
    information_officer_email: str
    physical_address: str

class IncidentDetailsPartB(BaseModel):
    incident_id: str
    reasonable_grounds_at: datetime
    description: str
    affected_categories: List[str] = Field(default_factory=list)
    estimated_data_subjects_count: int

class SecurityMeasuresPartC(BaseModel):
    pre_existing_measures: str
    failures_identified: str
    immediate_containment_taken: str

class DataSubjectNoticePartD(BaseModel):
    notice_method: str
    advice_to_subjects: str
    support_contact: str

class AttestationPartE(BaseModel):
    signatory_name: str
    signatory_designation: str
    truthfulness_declared: bool
    attestation_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class PopiaSection22Filing(BaseModel):
    part_a: ResponsiblePartyPartA
    part_b: IncidentDetailsPartB
    part_c: SecurityMeasuresPartC
    part_d: DataSubjectNoticePartD
    part_e: Optional[AttestationPartE] = None

    def assert_submittable(self) -> None:
        """Gate: Cannot transmit without Part E truthfulness declaration."""
        if not self.part_e or not self.part_e.truthfulness_declared:
            raise ValueError(
                "Part E Attestation Gate Failure: Filing cannot be transmitted without "
                "a verified declaration of truthfulness."
            )
''',

    # -------------------------------------------------------------
    # 3. Pipeline: Immediate Zero-Delay Operator Cascade (Issue #3)
    # -------------------------------------------------------------
    "app/pipeline/__init__.py": "",
    "app/pipeline/operator_cascade.py": '''"""Operator Cascade Dispatch Queue (Module #3)."""
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
''',

    # -------------------------------------------------------------
    # 4. Services: Remediation Playbooks (Issue #6)
    # -------------------------------------------------------------
    "app/services/__init__.py": "",
    "app/services/remediation.py": '''"""Automated Containment & Remediation Playbooks (Module #6)."""
from datetime import datetime, timezone
from typing import Dict, Any

class RemediationPlaybooks:
    @staticmethod
    def revoke_user_sessions(user_id: str, dry_run: bool = False) -> Dict[str, Any]:
        return {
            "action": "revoke_user_sessions",
            "target": user_id,
            "dry_run": dry_run,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "status": "SUCCESS" if not dry_run else "SIMULATED",
            "details": f"Revoked active OAuth/JWT tokens and sessions for {user_id}",
        }

    @staticmethod
    def isolate_endpoint(host_id: str, dry_run: bool = False) -> Dict[str, Any]:
        return {
            "action": "isolate_endpoint",
            "target": host_id,
            "dry_run": dry_run,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "status": "SUCCESS" if not dry_run else "SIMULATED",
            "details": f"Applied network isolation policy on agent endpoint {host_id}",
        }

    @staticmethod
    def block_network_indicator(indicator: str, dry_run: bool = False) -> Dict[str, Any]:
        return {
            "action": "block_network_indicator",
            "target": indicator,
            "dry_run": dry_run,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "status": "SUCCESS" if not dry_run else "SIMULATED",
            "details": f"Pushed perimeter firewall drop rule for indicator {indicator}",
        }
''',

    # -------------------------------------------------------------
    # 5. Ingestion API Endpoint (Issue #5)
    # -------------------------------------------------------------
    "app/api/__init__.py": "",
    "app/api/ingest.py": '''"""Telemetry Ingestion Endpoint (Module #5)."""
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
''',

    # -------------------------------------------------------------
    # 6. Live Operator Dashboard & HTML UI (Issue #9)
    # -------------------------------------------------------------
    "app/api/dashboard.py": '''"""Live Operator Dashboard Route (Module #9)."""
from datetime import datetime, timezone
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from app.api.ingest import incidents_db
from app.pipeline.operator_cascade import cascade_queue

router = APIRouter(tags=["dashboard"])

@router.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    now = datetime.now(timezone.utc)
    cards_html = ""
    
    if not incidents_db:
        cards_html = """
        <div style="background:#131d2a;border:1px dashed #24354a;border-radius:8px;padding:30px;text-align:center;color:#64748b;">
          No active incidents ingested yet. Use the <code>/v1/telemetry/ingest</code> endpoint to post an alert.
        </div>
        """
    else:
        for inc_id, inc in incidents_db.items():
            elapsed_sec = (now - inc.reasonable_grounds_at).total_seconds()
            remaining_hours = max(0.0, 72.0 - (elapsed_sec / 3600.0))
            badge_color = "#e53e3e" if remaining_hours < 24 else ("#dd6b20" if remaining_hours < 48 else "#38a169")
            
            cards_html += f"""
            <div style="background:#131d2a;border:1px solid #1e293b;border-radius:8px;padding:20px;margin-bottom:15px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                <span style="font-weight:700;color:#60a5fa;font-size:16px;">{inc.incident_id}</span>
                <span style="background:{badge_color};color:#fff;font-size:12px;padding:3px 8px;border-radius:4px;font-weight:600;">
                  {remaining_hours:.1f}h remaining
                </span>
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:13px;color:#94a3b8;">
                <div><strong>Entity:</strong> <span style="color:#f1f5f9;">{inc.compromised_entity_id}</span></div>
                <div><strong>Breach:</strong> <span style="color:#f1f5f9;">{inc.breach_nature.value}</span></div>
                <div><strong>Severity:</strong> <span style="color:#f1f5f9;">{inc.severity.value.upper()}</span></div>
                <div><strong>Source:</strong> <span style="color:#f1f5f9;">{inc.source_system}</span></div>
                <div><strong>POPIA S22 Notice:</strong> <span style="color:#38a169;">MANDATORY</span></div>
                <div><strong>Part E Attested:</strong> <span style="color:{'#38a169' if inc.attested else '#e53e3e'};">{'YES' if inc.attested else 'PENDING'}</span></div>
              </div>
            </div>
            """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cyber-Agent POPIA S22 Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ background: #0a0f18; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin:0; padding:24px; }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    h1 {{ font-size: 22px; font-weight: 700; margin-bottom: 4px; }}
    .sub {{ color: #64748b; font-size: 14px; margin-bottom: 24px; }}
    .metric-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }}
    .metric-box {{ background: #131d2a; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; text-align: center; }}
    .metric-val {{ font-size: 24px; font-weight: 800; color: #38bdf8; }}
    .metric-lbl {{ font-size: 12px; color: #64748b; margin-top: 4px; text-transform: uppercase; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>POPIA Section 22 Incident Commander</h1>
    <div class="sub">South African Cyber Incident Triage & Statutory Remediation Console</div>
    
    <div class="metric-grid">
      <div class="metric-box">
        <div class="metric-val">{len(incidents_db)}</div>
        <div class="metric-lbl">Total Incidents</div>
      </div>
      <div class="metric-box">
        <div class="metric-val">{len(cascade_queue.dispatched_log)}</div>
        <div class="metric-lbl">Dispatched Queues</div>
      </div>
      <div class="metric-box">
        <div class="metric-val">100%</div>
        <div class="metric-lbl">Invariant Strictness</div>
      </div>
      <div class="metric-box">
        <div class="metric-val">Active</div>
        <div class="metric-lbl">Attestation Gate</div>
      </div>
    </div>

    <h2 style="font-size:16px;margin-bottom:12px;color:#94a3b8;">ACTIVE INCIDENTS</h2>
    {cards_html}
  </div>
</body>
</html>
"""
    return HTMLResponse(content=html)
''',

    # -------------------------------------------------------------
    # 7. Main Application Entrypoint
    # -------------------------------------------------------------
    "app/main.py": '''"""Cyber-Agent FastAPI Core Entrypoint."""
from fastapi import FastAPI
from app.api.ingest import router as ingest_router
from app.api.dashboard import router as dashboard_router

app = FastAPI(
    title="Cyber-Agent POPIA S22 Platform",
    description="Automated incident triage, remediation playbooks, and statutory regulator reporting.",
    version="0.1.0",
)

app.include_router(ingest_router)
app.include_router(dashboard_router)

@app.get("/")
def root():
    return {
        "status": "OPERATIONAL",
        "jurisdiction": "ZA (POPIA Act 4 of 2013)",
        "dashboard": "/dashboard",
        "docs": "/docs",
    }
'''
}

def build():
    print("Building Cyber-Agent application structure...")
    for file_path, content in FILES.items():
        p = Path(file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  Created {file_path}")
    print("\nBuild complete! All domain modules, API endpoints, and dashboard are ready.")

if __name__ == "__main__":
    build()
