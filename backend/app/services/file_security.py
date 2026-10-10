import hashlib
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePath
from typing import Literal

MAX_ARCHIVE_ENTRIES = 100
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 10 * 1024 * 1024
PROMPT_INJECTION_MARKERS = (
    b"ignore previous instructions",
    b"ignore all previous instructions",
    b"reveal your system prompt",
    b"reveal the system prompt",
    b"developer message",
)
EXTENSION_FAMILIES = {
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".png": "png",
    ".gif": "gif",
    ".webp": "webp",
    ".pdf": "pdf",
    ".zip": "zip",
    ".docx": "zip",
    ".xlsx": "zip",
    ".pptx": "zip",
    ".txt": "text",
    ".csv": "text",
    ".json": "text",
}


@dataclass(frozen=True)
class FileSecuritySignal:
    code: str
    severity: Literal["low", "medium", "high"]
    message: str


@dataclass(frozen=True)
class FileSecurityAnalysis:
    safe_filename: str
    sha256: str
    file_size_bytes: int
    detected_type: str
    verdict: Literal["allowed", "quarantined", "blocked"]
    signals: list[FileSecuritySignal]
    recommendation: str


def analyze_file_upload(
    *,
    filename: str | None,
    content: bytes,
) -> FileSecurityAnalysis:
    """Perform non-executing structural checks on a user-supplied file.

    This deliberately does not execute, render, unpack to disk, or forward a
    file to a model. It records enough information to make a quarantine
    decision while preserving the original content outside AEGISAI.
    """
    safe_filename = _safe_filename(filename)
    detected_type = _detect_file_type(content)
    expected_type = EXTENSION_FAMILIES.get(PurePath(safe_filename).suffix.lower())
    signals: list[FileSecuritySignal] = []

    if not content:
        signals.append(
            FileSecuritySignal(
                code="empty_file",
                severity="high",
                message="The upload is empty and cannot be inspected safely.",
            )
        )
    if expected_type is None:
        signals.append(
            FileSecuritySignal(
                code="unsupported_extension",
                severity="high",
                message="The filename extension is not allowed for model input.",
            )
        )
    elif detected_type != expected_type:
        signals.append(
            FileSecuritySignal(
                code="file_type_mismatch",
                severity="high",
                message=(
                    "The filename extension does not match the detected file "
                    "signature."
                ),
            )
        )
    if detected_type == "unknown":
        signals.append(
            FileSecuritySignal(
                code="unknown_file_signature",
                severity="high",
                message="The file does not have a supported, verifiable signature.",
            )
        )

    if detected_type == "pdf":
        signals.extend(_pdf_signals(content))
    if detected_type == "zip":
        signals.extend(_zip_signals(content))
    if detected_type in {"jpeg", "png", "gif", "webp"}:
        signals.extend(_image_metadata_signals(content))
    signals.extend(_embedded_instruction_signals(content))

    verdict = _verdict_for_signals(signals)
    return FileSecurityAnalysis(
        safe_filename=safe_filename,
        sha256=hashlib.sha256(content).hexdigest(),
        file_size_bytes=len(content),
        detected_type=detected_type,
        verdict=verdict,
        signals=signals,
        recommendation=_recommendation_for_verdict(verdict),
    )


def _safe_filename(filename: str | None) -> str:
    candidate = PurePath(filename or "upload").name.strip()
    normalized = "".join(
        character for character in candidate if character.isprintable()
    )
    return normalized[:255] or "upload"


def _detect_file_type(content: bytes) -> str:
    if content.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if content.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
        return "webp"
    if content.startswith(b"%PDF-"):
        return "pdf"
    if content.startswith(b"PK\x03\x04"):
        return "zip"
    if _looks_like_text(content):
        return "text"
    return "unknown"


def _looks_like_text(content: bytes) -> bool:
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return "\x00" not in decoded


def _pdf_signals(content: bytes) -> list[FileSecuritySignal]:
    lower_content = content.lower()
    suspicious_tokens = {
        b"/javascript": "PDF contains a JavaScript action marker.",
        b"/openaction": "PDF contains an automatic-open action marker.",
        b"/launch": "PDF contains a launch-action marker.",
        b"/embeddedfile": "PDF contains an embedded-file marker.",
    }
    return [
        FileSecuritySignal(
            code="pdf_active_content",
            severity="high",
            message=message,
        )
        for token, message in suspicious_tokens.items()
        if token in lower_content
    ]


def _zip_signals(content: bytes) -> list[FileSecuritySignal]:
    signals: list[FileSecuritySignal] = []
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_ENTRIES:
                signals.append(
                    FileSecuritySignal(
                        code="archive_entry_limit",
                        severity="high",
                        message="Archive contains too many entries for a safe scan.",
                    )
                )
            total_uncompressed_size = sum(member.file_size for member in members)
            if total_uncompressed_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                signals.append(
                    FileSecuritySignal(
                        code="archive_expansion_limit",
                        severity="high",
                        message="Archive expands beyond the allowed inspection limit.",
                    )
                )
            for member in members:
                path = PurePath(member.filename)
                if path.is_absolute() or ".." in path.parts:
                    signals.append(
                        FileSecuritySignal(
                            code="archive_path_traversal",
                            severity="high",
                            message="Archive contains a path-traversal entry.",
                        )
                    )
                    break
                if member.flag_bits & 0x1:
                    signals.append(
                        FileSecuritySignal(
                            code="encrypted_archive",
                            severity="medium",
                            message=(
                                "Archive contains encrypted content that cannot be "
                                "inspected."
                            ),
                        )
                    )
                    break
                if member.filename.lower().endswith("vbaProject.bin".lower()):
                    signals.append(
                        FileSecuritySignal(
                            code="office_macro",
                            severity="high",
                            message="Office document archive contains a macro project.",
                        )
                    )
                    break
    except zipfile.BadZipFile:
        signals.append(
            FileSecuritySignal(
                code="invalid_archive",
                severity="high",
                message="Archive signature is present but the archive is invalid.",
            )
        )
    return signals


def _image_metadata_signals(content: bytes) -> list[FileSecuritySignal]:
    lower_content = content[:65_536].lower()
    if b"exif" in lower_content or b"<x:xmpmeta" in lower_content:
        return [
            FileSecuritySignal(
                code="image_metadata_present",
                severity="low",
                message=(
                    "Image metadata is present and should be stripped before "
                    "model use."
                ),
            )
        ]
    return []


def _embedded_instruction_signals(content: bytes) -> list[FileSecuritySignal]:
    lower_content = content[:65_536].lower()
    matches = [marker for marker in PROMPT_INJECTION_MARKERS if marker in lower_content]
    if not matches:
        return []
    return [
        FileSecuritySignal(
            code="embedded_instruction_marker",
            severity="medium",
            message="File contains text matching a prompt-injection marker.",
        )
    ]


def _verdict_for_signals(
    signals: list[FileSecuritySignal],
) -> Literal["allowed", "quarantined", "blocked"]:
    blocking_codes = {
        "empty_file",
        "unsupported_extension",
        "file_type_mismatch",
        "unknown_file_signature",
    }
    if any(signal.code in blocking_codes for signal in signals):
        return "blocked"
    if any(signal.severity in {"high", "medium"} for signal in signals):
        return "quarantined"
    return "allowed"


def _recommendation_for_verdict(
    verdict: Literal["allowed", "quarantined", "blocked"],
) -> str:
    if verdict == "allowed":
        return (
            "Static checks passed. Forward only through a model-specific safe "
            "input path."
        )
    if verdict == "quarantined":
        return "Keep the file out of the model path until an analyst completes review."
    return "Reject the upload and request a supported, verifiable file type."
