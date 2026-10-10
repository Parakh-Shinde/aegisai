from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class CoveragePack:
    pack_id: str
    title: str
    category: str
    status: Literal["available", "partial", "planned"]
    reason: str


@dataclass(frozen=True)
class CoveragePlan:
    packs: list[CoveragePack]
    automated_test_coverage_percent: float
    available_packs: int
    partial_packs: int
    planned_packs: int


def build_coverage_plan(
    *,
    input_modalities: set[str],
    capabilities: set[str],
    deployment_exposure: str,
    data_classification: str,
) -> CoveragePlan:
    """Map an AI system profile to explicit, versionable security test packs.

    A ``planned`` pack is intentionally not represented as protection. It is a
    documented coverage gap that must be closed before relying on a release
    decision for that attack surface.
    """
    packs = [
        CoveragePack(
            pack_id="prompt-injection",
            title="Prompt Injection Resistance",
            category="model_behavior",
            status="available",
            reason="All language-capable AI systems accept untrusted instructions.",
        ),
        CoveragePack(
            pack_id="jailbreak",
            title="Jailbreak Resistance",
            category="model_behavior",
            status="available",
            reason="All language-capable AI systems need refusal-boundary testing.",
        ),
        CoveragePack(
            pack_id="sensitive-data",
            title="Sensitive Data Exposure",
            category="data_protection",
            status="available",
            reason="Test whether the model discloses secrets or confidential context.",
        ),
        CoveragePack(
            pack_id="release-governance",
            title="Evidence Review and Release Gate",
            category="governance",
            status="available",
            reason=(
                "Campaign evidence requires analyst review before a release decision."
            ),
        ),
    ]

    if input_modalities.intersection({"image", "document", "audio", "video"}):
        packs.append(
            CoveragePack(
                pack_id="multimodal-input",
                title="Multimodal Input Security",
                category="file_and_media",
                status="partial",
                reason=(
                    "Static signature, metadata, and plaintext marker checks are "
                    "available; OCR and malware-engine coverage are still needed."
                ),
            )
        )
    if "document" in input_modalities:
        packs.append(
            CoveragePack(
                pack_id="document-security",
                title="Document and File Safety",
                category="file_and_media",
                status="partial",
                reason=(
                    "Static PDF and archive checks are available; deeper document "
                    "sanitization and malware-engine coverage are still needed."
                ),
            )
        )
    if "rag" in capabilities:
        packs.append(
            CoveragePack(
                pack_id="rag-injection",
                title="RAG Poisoning and Retrieval Isolation",
                category="rag_security",
                status="planned",
                reason=(
                    "Retrieved content can inject instructions or expose another "
                    "data."
                ),
            )
        )
    if capabilities.intersection({"agent_tools", "code_execution", "external_apis"}):
        packs.append(
            CoveragePack(
                pack_id="agent-tool-safety",
                title="Agent Tool and Action Safety",
                category="agent_security",
                status="planned",
                reason=(
                    "Tool permissions, arguments, and side effects need safety "
                    "checks."
                ),
            )
        )
    if "browser" in capabilities:
        packs.append(
            CoveragePack(
                pack_id="browser-indirect-injection",
                title="Browser and Indirect Prompt Injection",
                category="agent_security",
                status="planned",
                reason=(
                    "Web content can carry untrusted instructions that manipulate an "
                    "agent."
                ),
            )
        )
    if deployment_exposure == "public":
        packs.append(
            CoveragePack(
                pack_id="public-api-security",
                title="Public API and Abuse Resistance",
                category="platform_security",
                status="planned",
                reason=(
                    "Public exposure requires authentication, rate-limit, tenant, and "
                    "SSRF testing."
                ),
            )
        )
    if data_classification in {"confidential", "regulated"}:
        packs.append(
            CoveragePack(
                pack_id="privacy-assurance",
                title="Privacy and Data Isolation Assurance",
                category="data_protection",
                status="planned",
                reason=(
                    "Confidential or regulated data needs stronger privacy and "
                    "coverage."
                ),
            )
        )

    available_packs = sum(pack.status == "available" for pack in packs)
    partial_packs = sum(pack.status == "partial" for pack in packs)
    planned_packs = sum(pack.status == "planned" for pack in packs)
    coverage_percent = (
        round(((available_packs + partial_packs * 0.5) / len(packs)) * 100, 2)
        if packs
        else 0.0
    )
    return CoveragePlan(
        packs=packs,
        automated_test_coverage_percent=coverage_percent,
        available_packs=available_packs,
        partial_packs=partial_packs,
        planned_packs=planned_packs,
    )
