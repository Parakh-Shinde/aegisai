import pytest
from app.models.ai_system import AISystemProfileRequest
from app.services.coverage import build_coverage_plan
from pydantic import ValidationError


def test_text_assistant_has_current_available_coverage() -> None:
    plan = build_coverage_plan(
        input_modalities={"text"},
        capabilities=set(),
        deployment_exposure="internal",
        data_classification="internal",
    )

    assert plan.available_packs == 4
    assert plan.planned_packs == 0
    assert plan.automated_test_coverage_percent == 100.0
    assert {pack.pack_id for pack in plan.packs} == {
        "prompt-injection",
        "jailbreak",
        "sensitive-data",
        "release-governance",
    }


def test_multimodal_public_agent_surfaces_coverage_gaps() -> None:
    plan = build_coverage_plan(
        input_modalities={"text", "image", "document"},
        capabilities={"rag", "agent_tools", "browser", "customer_data"},
        deployment_exposure="public",
        data_classification="confidential",
    )

    planned_ids = {pack.pack_id for pack in plan.packs if pack.status == "planned"}

    assert plan.available_packs == 4
    assert plan.planned_packs == 7
    assert plan.automated_test_coverage_percent == 36.36
    assert planned_ids == {
        "multimodal-input",
        "document-security",
        "rag-injection",
        "agent-tool-safety",
        "browser-indirect-injection",
        "public-api-security",
        "privacy-assurance",
    }


def test_system_type_enforces_its_attack_surface() -> None:
    rag_profile = AISystemProfileRequest(
        name="Knowledge assistant",
        system_type="rag",
        deployment_exposure="internal",
        data_classification="internal",
    )

    assert "rag" in rag_profile.capabilities

    with pytest.raises(ValidationError):
        AISystemProfileRequest(
            name="Image model",
            system_type="multimodal",
            deployment_exposure="internal",
            data_classification="internal",
            input_modalities={"text"},
        )
