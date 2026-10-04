from pydantic import BaseModel, Field


class PopiaSection22Form(BaseModel):
    incident_id: str
    part_a_responsible_party: dict = Field(..., description="Responsible party details")
    part_b_incident_details: dict = Field(..., description="Nature and date of breach")
    part_c_affected_data_subjects: dict = Field(..., description="Categories and count of data subjects")
    part_d_likely_consequences: str = Field(..., description="Anticipated consequences")
    part_e_measures_taken: str = Field(..., description="Mitigation and containment measures")
    attestation_signed_by: str = Field(..., description="Human officer gate")
    attested: bool = Field(default=False)

    def sign_attestation(self, officer_name: str) -> None:
        if officer_name == self.attestation_signed_by:
            self.attested = True
        else:
            raise ValueError("Signer identity does not match designated attestation officer")
