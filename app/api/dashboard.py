"""Live Operator Dashboard Route (Module #9)."""
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
