import hashlib

import httpx
import pytest
from app.services.ocr_security import OCRRunnerError, extract_text_in_sandbox


def test_ocr_runner_client_uses_fixed_runner_and_preserves_text_digest() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://ocr-runner:8090/extract"
        assert request.headers["X-AEGISAI-OCR-Token"] == "local-runner-token"
        assert request.headers["X-AEGISAI-Detected-Type"] == "png"
        return httpx.Response(200, json={"text": "Visible safe text"})

    result = extract_text_in_sandbox(
        content=b"fake-png-content",
        filename="test.png",
        detected_type="png",
        runner_url="http://ocr-runner:8090",
        runner_token="local-runner-token",
        timeout_seconds=10,
        transport=httpx.MockTransport(handler),
    )

    assert result.text == "Visible safe text"
    assert result.characters == 17
    assert result.sha256 == hashlib.sha256(b"Visible safe text").hexdigest()


def test_ocr_runner_client_rejects_unsupported_input_type() -> None:
    with pytest.raises(OCRRunnerError, match="PNG and JPEG"):
        extract_text_in_sandbox(
            content=b"not-an-image",
            filename="test.gif",
            detected_type="gif",
            runner_url="http://ocr-runner:8090",
            runner_token=None,
            timeout_seconds=10,
        )


def test_ocr_runner_client_rejects_invalid_response() -> None:
    with pytest.raises(OCRRunnerError, match="invalid response"):
        extract_text_in_sandbox(
            content=b"fake-png-content",
            filename="test.png",
            detected_type="png",
            runner_url="http://ocr-runner:8090",
            runner_token=None,
            timeout_seconds=10,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"unexpected": "value"})
            ),
        )
