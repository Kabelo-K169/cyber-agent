"""
tests/test_platform.py
Regression suite for the Cyber-Agent POPIA S22 platform.

Covers:
  * Module #2 - Strict Notification Invariant
  * Module #4 - Part E Attestation Gate
  * Module #3 - Zero-delay operator cascade
  * Module #5 - Telemetry ingestion API
  * Module #9 - Operator dashboard + 72-hour statutory clock

Run:  pytest -v
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.ingest import incidents_db
from app.main import app
from app.models.filing import (
    AttestationPartE,
    DataSubjectNoticePartD,
    IncidentDetailsPartB,
    PopiaSection22Filing,
    ResponsiblePartyPartA,
    SecurityMeasuresPartC,
)
from app.models.incident import BreachNature, IncidentRecord, SeverityLevel
from app.pipeline.operator_cascade import cascade_queue

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_state():
    """Every test starts with an empty incident store and dispatch log."""
    incidents_db.clear()
    cascade_queue.dispatched_log.clear()
    yield
    incidents_db.clear()
    cascade_queue.dispatched_log.clear()


def make_payload(**overrides):
    payload = {
        "source_system": "aws-guardduty",
        "breach_nature": "ransomware",
        "compromised_entity_id": "user-4471",
        "severity": "critical",
    }
    payload.update(overrides)
    return payload


def make_filing(attested=None):
    return PopiaSection22Filing(
        part_a=ResponsiblePartyPartA(
            registration_number="2019/123456/07",
            organisation_name="Ubuntu Fintech (Pty) Ltd",
            information_officer_name="Naledi Mokoena",
            information_officer_email="io@ubuntufintech.co.za",
            physical_address="12 Sandton Drive, Johannesburg, 2196",
        ),
        part_b=IncidentDetailsPartB(
            incident_id="INC-DEADBEEF",
            reasonable_grounds_at=datetime.now(timezone.utc),
            description="Ransomware encrypted the CRM database server.",
            affected_categories=["identity", "financial"],
            estimated_data_subjects_count=18422,
        ),
        part_c=SecurityMeasuresPartC(
            pre_existing_measures="EDR, MFA, weekly offline backups",
            failures_identified="Unpatched RDP endpoint exposed to the internet",
            immediate_containment_taken="Host isolated, credentials rotated",
        ),
        part_d=DataSubjectNoticePartD(
            notice_method="email",
            advice_to_subjects="Reset your password and monitor your accounts.",
            support_contact="breach@ubuntufintech.co.za",
        ),
        part_e=attested,
    )


# ---------------------------------------------------------------- Module #2
def test_invariant_blocks_silent_dismissal():
    with pytest.raises(ValueError) as exc:
        IncidentRecord(
            source_system="edr",
            breach_nature=BreachNature.RANSOMWARE,
            compromised_entity_id="host-01",
            reasonable_grounds_at=datetime.now(timezone.utc),
            requires_notification=False,
        )
    assert "Invariant Violation" in str(exc.value)


def test_invariant_permits_documented_dismissal():
    record = IncidentRecord(
        source_system="edr",
        breach_nature=BreachNature.MALWARE,
        compromised_entity_id="host-02",
        reasonable_grounds_at=datetime.now(timezone.utc),
        requires_notification=False,
        dismissal_justification="Contained before any personal data was accessed.",
    )
    assert record.requires_notification is False


@pytest.mark.parametrize("severity", list(SeverityLevel))
def test_severity_never_lowers_notification_duty(severity):
    record = IncidentRecord.create_breach_record(
        source_system="sentinel",
        breach_nature=BreachNature.CREDENTIAL_THEFT,
        compromised_entity_id="user-1",
        severity=severity,
    )
    assert record.requires_notification is True


def test_naive_timestamp_is_coerced_to_utc():
    record = IncidentRecord(
        source_system="edr",
        breach_nature=BreachNature.MALWARE,
        compromised_entity_id="host-03",
        reasonable_grounds_at=datetime(2026, 10, 1, 9, 0, 0),
    )
    assert record.reasonable_grounds_at.tzinfo is not None


# ---------------------------------------------------------------- Module #4
def test_attestation_gate_blocks_missing_part_e():
    with pytest.raises(ValueError) as exc:
        make_filing(attested=None).assert_submittable()
    assert "Attestation Gate Failure" in str(exc.value)


def test_attestation_gate_blocks_false_declaration():
    bad = AttestationPartE(
        signatory_name="Naledi Mokoena",
        signatory_designation="Information Officer",
        truthfulness_declared=False,
    )
    with pytest.raises(ValueError):
        make_filing(attested=bad).assert_submittable()


def test_attestation_gate_allows_declared_filing():
    good = AttestationPartE(
        signatory_name="Naledi Mokoena",
        signatory_designation="Information Officer",
        truthfulness_declared=True,
    )
    make_filing(attested=good).assert_submittable()  # must not raise


# ------------------------------------------------------- Modules #3, #5, #9
def test_root_reports_jurisdiction():
    body = client.get("/").json()
    assert body["status"] == "OPERATIONAL"
    assert "POPIA" in body["jurisdiction"]


def test_ingest_creates_incident_and_dispatches_cascade():
    response = client.post("/v1/telemetry/ingest", json=make_payload())
    assert response.status_code == 201
    body = response.json()
    assert body["incident_id"].startswith("INC-")
    assert body["cascade"]["status"] == "DISPATCHED_ZERO_DELAY"
    assert body["incident_id"] in incidents_db


def test_ingest_rejects_undocumented_dismissal():
    response = client.post(
        "/v1/telemetry/ingest",
        json=make_payload(requires_notification=False),
    )
    assert response.status_code == 422
    assert "Invariant Violation" in response.json()["detail"]


def test_ingest_accepts_documented_dismissal():
    response = client.post(
        "/v1/telemetry/ingest",
        json=make_payload(
            requires_notification=False,
            dismissal_justification="Sinkhole caught the C2 beacon pre-exfiltration.",
        ),
    )
    assert response.status_code == 201


def test_ingest_defaults_timestamp_to_utc_now():
    body = client.post("/v1/telemetry/ingest", json=make_payload()).json()
    stamped = datetime.fromisoformat(body["reasonable_grounds_at"])
    assert stamped.tzinfo is not None
    drift = abs((datetime.now(timezone.utc) - stamped).total_seconds())
    assert drift < 60, f"Statutory clock skewed by {drift:.0f}s from true UTC"


def test_dashboard_shows_empty_state():
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "No active incidents" in response.text


def test_dashboard_renders_active_incident_as_mandatory():
    incident_id = client.post("/v1/telemetry/ingest", json=make_payload()).json()["incident_id"]
    html = client.get("/dashboard").text
    assert incident_id in html
    assert "MANDATORY" in html
    assert "PENDING" in html  # Part E not yet attested


def test_dashboard_clock_counts_down_from_72_hours():
    discovered = datetime.now(timezone.utc) - timedelta(hours=60)
    client.post(
        "/v1/telemetry/ingest",
        json=make_payload(reasonable_grounds_at=discovered.isoformat()),
    )
    html = client.get("/dashboard").text
    assert "12.0h remaining" in html
