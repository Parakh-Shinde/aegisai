import hashlib
import html
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePath
from typing import Literal

MAX_ARCHIVE_ENTRIES = 100
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 10 * 1024 * 1024
MAX_IMAGE_DIMENSION = 8_192
MAX_IMAGE_PIXELS = 40_000_000
MAX_EMBEDDED_TEXT_BYTES = 1_000_000
PROMPT_INJECTION_MARKERS = (
    b"ignore previous instructions",
    b"ignore all previous instructions",
    b"reveal your system prompt",
    b"reveal the system prompt",
    b"developer message",
    b"disregard previous instructions",
    b"system instructions",
    b"send confidential",
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
        signals.extend(_image_signals(content, detected_type))
    if detected_type == "text":
        signals.extend(_embedded_instruction_signals(content, "text"))
    elif detected_type == "pdf":
        signals.extend(_embedded_instruction_signals(content, "PDF"))

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
            signals.extend(_office_document_text_signals(archive, members))
    except zipfile.BadZipFile:
        signals.append(
            FileSecuritySignal(
                code="invalid_archive",
                severity="high",
                message="Archive signature is present but the archive is invalid.",
            )
        )
    return signals


def _office_document_text_signals(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
) -> list[FileSecuritySignal]:
    """Inspect Office XML text in memory without extracting an archive to disk."""
    office_members = [
        member
        for member in members
        if member.filename.startswith(("word/", "xl/", "ppt/"))
        and member.filename.lower().endswith(".xml")
    ]
    if not office_members:
        return []

    remaining = MAX_EMBEDDED_TEXT_BYTES
    snippets: list[str] = []
    for member in office_members:
        if remaining <= 0:
            break
        if member.file_size > MAX_EMBEDDED_TEXT_BYTES:
            continue
        data = archive.read(member, pwd=None)[:remaining]
        remaining -= len(data)
        text = html.unescape(
            re.sub(r"<[^>]{0,1024}>", " ", data.decode("utf-8", "ignore"))
        )
        snippets.append(text)

    if not snippets:
        return []
    return _text_instruction_signals(
        "\n".join(snippets),
        code="office_document_instruction_marker",
        source="Office document text",
        severity="high",
    )


def _image_signals(content: bytes, detected_type: str) -> list[FileSecuritySignal]:
    signals = _image_dimension_signals(content, detected_type)
    metadata = _image_metadata_text(content, detected_type)
    if metadata:
        signals.append(
            FileSecuritySignal(
                code="image_metadata_present",
                severity="low",
                message=(
                    "Image metadata is present and should be stripped before "
                    "model use."
                ),
            )
        )
        signals.extend(
            _text_instruction_signals(
                metadata,
                code="image_metadata_instruction_marker",
                source="Image metadata",
                severity="high",
            )
        )
    return signals


def _image_dimension_signals(
    content: bytes,
    detected_type: str,
) -> list[FileSecuritySignal]:
    dimensions = _image_dimensions(content, detected_type)
    if dimensions is None:
        return []
    width, height = dimensions
    if (
        width <= MAX_IMAGE_DIMENSION
        and height <= MAX_IMAGE_DIMENSION
        and width * height <= MAX_IMAGE_PIXELS
    ):
        return []
    return [
        FileSecuritySignal(
            code="image_dimension_limit",
            severity="high",
            message=(
                "Image dimensions exceed the safe preprocessing limit and may "
                "cause resource exhaustion."
            ),
        )
    ]


def _image_dimensions(content: bytes, detected_type: str) -> tuple[int, int] | None:
    if detected_type == "png" and len(content) >= 24:
        return struct.unpack(">II", content[16:24])
    if detected_type == "gif" and len(content) >= 10:
        return struct.unpack("<HH", content[6:10])
    if detected_type == "jpeg":
        return _jpeg_dimensions(content)
    if detected_type == "webp":
        return _webp_dimensions(content)
    return None


def _jpeg_dimensions(content: bytes) -> tuple[int, int] | None:
    offset = 2
    while offset + 9 < len(content):
        if content[offset] != 0xFF:
            offset += 1
            continue
        marker = content[offset + 1]
        offset += 2
        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        if offset + 2 > len(content):
            return None
        segment_length = int.from_bytes(content[offset : offset + 2], "big")
        if segment_length < 2 or offset + segment_length > len(content):
            return None
        if marker in {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        } and segment_length >= 7:
            height = int.from_bytes(content[offset + 3 : offset + 5], "big")
            width = int.from_bytes(content[offset + 5 : offset + 7], "big")
            return width, height
        offset += segment_length
    return None


def _webp_dimensions(content: bytes) -> tuple[int, int] | None:
    if len(content) < 30 or content[12:16] != b"VP8X":
        return None
    width = 1 + int.from_bytes(content[24:27], "little")
    height = 1 + int.from_bytes(content[27:30], "little")
    return width, height


def _image_metadata_text(content: bytes, detected_type: str) -> str:
    if detected_type == "png":
        return _png_metadata_text(content)
    sample = content[:65_536]
    if b"exif" in sample.lower() or b"<x:xmpmeta" in sample.lower():
        return sample.decode("utf-8", "ignore")
    return ""


def _png_metadata_text(content: bytes) -> str:
    offset = 8
    values: list[bytes] = []
    remaining = MAX_EMBEDDED_TEXT_BYTES
    while offset + 12 <= len(content) and remaining > 0:
        length = int.from_bytes(content[offset : offset + 4], "big")
        chunk_type = content[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        if data_end + 4 > len(content):
            break
        data = content[data_start:data_end]
        if chunk_type == b"tEXt" or chunk_type == b"iTXt":
            values.append(data[:remaining])
            remaining -= min(len(data), remaining)
        elif chunk_type == b"zTXt" and b"\x00" in data:
            compressed = data.split(b"\x00", 1)[1][1:]
            try:
                decoder = zlib.decompressobj()
                value = decoder.decompress(compressed, remaining)
                values.append(value)
                remaining -= len(value)
            except zlib.error:
                pass
        offset = data_end + 4
    return b"\n".join(values).decode("utf-8", "ignore")


def _embedded_instruction_signals(
    content: bytes,
    source: str,
) -> list[FileSecuritySignal]:
    return _text_instruction_signals(
        content[:65_536].decode("utf-8", "ignore"),
        code="embedded_instruction_marker",
        source=source,
        severity="medium",
    )


def _text_instruction_signals(
    content: str,
    *,
    code: str,
    source: str,
    severity: Literal["medium", "high"],
) -> list[FileSecuritySignal]:
    lower_content = content.lower()
    matches = [
        marker
        for marker in PROMPT_INJECTION_MARKERS
        if marker.decode() in lower_content
    ]
    if not matches:
        return []
    return [
        FileSecuritySignal(
            code=code,
            severity=severity,
            message=f"{source} contains text matching a prompt-injection marker.",
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
