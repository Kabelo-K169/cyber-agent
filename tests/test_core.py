from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from app.clock import StatutoryClock
from app.notifications import NotificationInvariant, OperatorCascadeQueue
from app.popia_form import PopiaSection22Form
from app.main import app


def test_statutory_clock_immutable():
    clock = StatutoryClock()
    with pytest.raises(Exception):
        clock.reasonable_grounds_at = datetime.now(timezone.utc)
    assert clock.is_within_statutory_window(72.0) is True


def test_notification_invariant_and_queue():
    queue = OperatorCascadeQueue()
    assert len(queue) == 0

    record = {"id": "INC-001", "details": "ransomware alert"}
    queue.enqueue(record)
    assert len(queue) == 1

    invariant = NotificationInvariant(incident_id="INC-001")
    assert invariant.requires_notification is True
    assert invariant.status == "pending"

    invariant.dispatch()
    assert invariant.status == "dispatched"


def test_popia_form_attestation():
    form = PopiaSection22Form(
        incident_id="INC-100",
        part_a_responsible_party={"name": "Org A", "reg": "2020/123456/07"},
        part_b_incident_details={"date": "2026-10-04", "type": "unauthorized_access"},
        part_c_affected_data_subjects={"count": 150, "categories": ["employees"]},
        part_d_likely_consequences="Minimal risk of financial loss",
        part_e_measures_taken="Access tokens revoked, endpoints quarantined",
        attestation_signed_by="Kabelo Malatji",
    )
    assert form.attested is False
    with pytest.raises(ValueError):
        form.sign_attestation("Wrong Officer")

    form.sign_attestation("Kabelo Malatji")
    assert form.attested is True


def test_api_telemetry_endpoint():
    response = client.post(
        "/v1/telemetry/ingest",
        json={
            "source_system": "siem",
            "breach_nature": "credential_theft",
            "compromised_entity_id": "192.168.1.50",
            "severity": "high",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["incident_id"].startswith("INC-")
    assert "reasonable_grounds_at" in data
    assert data["cascade"]["status"] == "DISPATCHED_ZERO_DELAY"
