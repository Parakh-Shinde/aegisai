import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Literal

INSTRUCTION_OVERRIDE_PATTERNS = (
    r"\bignore (?:all |any )?previous instructions?\b",
    r"\bdisregard (?:all |any )?previous instructions?\b",
    r"\boverride (?:the )?(?:system|developer|security) instructions?\b",
    r"\bdo not follow (?:the )?(?:system|developer|security) instructions?\b",
)
SECRET_EXTRACTION_PATTERNS = (
    r"\breveal (?:the )?(?:hidden )?(?:system|developer) prompt\b",
    r"\bprint (?:the )?(?:api key|password|secret|token)\b",
    r"\bexfiltrat(?:e|ion)\b",
)
TOOL_ACTION_PATTERNS = (
    r"\bcall (?:the )?(?:tool|api|function)\b",
    r"\bsend (?:all |the )?(?:records|data|files) to\b",
    r"\bupload (?:all |the )?(?:records|data|files) to\b",
)
ROLE_IMPERSONATION_PATTERNS = (
    r"\b(?:system|developer)\s*:\s*",
    r"\byou are now\b",
    r"\bnew instructions?\s*:\s*",
)
INVISIBLE_CHARACTER_PATTERN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
HTML_COMMENT_PATTERN = re.compile(r"<!--.*?-->", re.DOTALL)
REMOTE_CONTENT_PATTERN = re.compile(r"https?://", re.IGNORECASE)


@dataclass(frozen=True)
class RAGSecuritySignal:
    code: str
    severity: Literal["low", "medium", "high"]
    message: str


@dataclass(frozen=True)
class RAGSourceAnalysis:
    content_sha256: str
    content_characters: int
    verdict: Literal["approved", "quarantined"]
    signals: list[RAGSecuritySignal]
    recommendation: str


def analyze_rag_source(content: str) -> RAGSourceAnalysis:
    """Inspect staged retrieved text without indexing or forwarding it.

    The caller retains the original source outside of AEGISAI. This function
    produces only a digest and structural risk signals; it neither retrieves
    URLs nor sends content to a model or vector database.
    """
    normalized = unicodedata.normalize("NFKC", content)
    lowered = normalized.lower()
    signals: list[RAGSecuritySignal] = []

    if _matches_any(lowered, INSTRUCTION_OVERRIDE_PATTERNS):
        signals.append(
            RAGSecuritySignal(
                code="instruction_hierarchy_override",
                severity="high",
                message=(
                    "Source contains language that attempts to override higher-"
                    "priority instructions."
                ),
            )
        )
    if _matches_any(lowered, SECRET_EXTRACTION_PATTERNS):
        signals.append(
            RAGSecuritySignal(
                code="sensitive_data_extraction",
                severity="high",
                message=(
                    "Source contains language requesting system context or "
                    "sensitive credentials."
                ),
            )
        )
    if _matches_any(lowered, TOOL_ACTION_PATTERNS):
        signals.append(
            RAGSecuritySignal(
                code="untrusted_tool_instruction",
                severity="high",
                message=(
                    "Source contains an instruction to trigger a tool, API, or "
                    "data transfer."
                ),
            )
        )
    if _matches_any(lowered, ROLE_IMPERSONATION_PATTERNS):
        signals.append(
            RAGSecuritySignal(
                code="role_impersonation_marker",
                severity="medium",
                message=(
                    "Source contains a system or developer role-impersonation "
                    "marker."
                ),
            )
        )
    if INVISIBLE_CHARACTER_PATTERN.search(content):
        signals.append(
            RAGSecuritySignal(
                code="invisible_text_control",
                severity="medium",
                message=(
                    "Source contains invisible or bidirectional Unicode controls "
                    "that can obscure instructions."
                ),
            )
        )
    if HTML_COMMENT_PATTERN.search(content):
        signals.append(
            RAGSecuritySignal(
                code="hidden_html_comment",
                severity="medium",
                message="Source contains hidden HTML comments that require review.",
            )
        )
    if REMOTE_CONTENT_PATTERN.search(content):
        signals.append(
            RAGSecuritySignal(
                code="remote_content_reference",
                severity="low",
                message=(
                    "Source references remote content. AEGISAI did not fetch or "
                    "follow that reference."
                ),
            )
        )

    verdict: Literal["approved", "quarantined"]
    if any(signal.severity in {"medium", "high"} for signal in signals):
        verdict = "quarantined"
    else:
        verdict = "approved"
    return RAGSourceAnalysis(
        content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        content_characters=len(content),
        verdict=verdict,
        signals=signals,
        recommendation=_recommendation_for_verdict(verdict),
    )


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, value, flags=re.IGNORECASE) for pattern in patterns)


def _recommendation_for_verdict(
    verdict: Literal["approved", "quarantined"],
) -> str:
    if verdict == "approved":
        return (
            "No configured indirect-injection marker was found. Index only through "
            "a retrieval path that treats all source text as untrusted context."
        )
    return (
        "Do not index this source automatically. Keep it quarantined until an "
        "authorized reviewer makes and records an exception decision."
    )
