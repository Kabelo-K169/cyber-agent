"""POPIA Section 22 Form Parts A-E & Part E Attestation Gate (Module #4)."""
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
