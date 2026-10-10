from io import BytesIO
from zipfile import ZipFile

from app.services.file_security import analyze_file_upload


def test_blocks_filename_and_signature_mismatch() -> None:
    result = analyze_file_upload(
        filename="invoice.jpg",
        content=b"%PDF-1.7\nexample",
    )

    assert result.detected_type == "pdf"
    assert result.verdict == "blocked"
    assert any(signal.code == "file_type_mismatch" for signal in result.signals)


def test_quarantines_pdf_with_active_content_marker() -> None:
    result = analyze_file_upload(
        filename="document.pdf",
        content=b"%PDF-1.7\n/OpenAction /JavaScript\n",
    )

    assert result.verdict == "quarantined"
    assert any(signal.code == "pdf_active_content" for signal in result.signals)


def test_quarantines_office_macro_archive_without_extracting_it() -> None:
    archive_bytes = BytesIO()
    with ZipFile(archive_bytes, "w") as archive:
        archive.writestr("word/vbaProject.bin", b"not-executed")

    result = analyze_file_upload(
        filename="report.docx",
        content=archive_bytes.getvalue(),
    )

    assert result.detected_type == "zip"
    assert result.verdict == "quarantined"
    assert any(signal.code == "office_macro" for signal in result.signals)


def test_allows_safe_text_without_persisting_content() -> None:
    result = analyze_file_upload(
        filename="notes.txt",
        content=b"This is an ordinary test document.",
    )

    assert result.verdict == "allowed"
    assert result.file_size_bytes == len(b"This is an ordinary test document.")
