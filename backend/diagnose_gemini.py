"""One-shot, secret-safe Gemini connectivity diagnostic.

Run from the backend directory with the project's Python environment. Each
selected model receives exactly one request; neither prompt nor response is
printed.
"""

from __future__ import annotations

import json
import logging
import time

import httpx
from google import genai
from google.genai import types

from app.config import get_settings


ALTERNATE_FAST_MODEL = "gemini-3.5-flash-lite"
DIAGNOSTIC_PROMPT = "Reply with exactly OK."


def _safe_status_code(exc: Exception) -> int | None:
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    if isinstance(code, int):
        return code
    if isinstance(code, str) and code.isdigit():
        return int(code)
    return None


def _error_category(exc: Exception, status_code: int | None) -> str:
    if isinstance(exc, (httpx.TimeoutException, TimeoutError)) or "timeout" in type(exc).__name__.lower():
        return "timeout"
    if isinstance(exc, httpx.NetworkError):
        return "network"
    return {
        400: "invalid_request",
        401: "authentication",
        402: "billing",
        403: "permission",
        404: "model_not_found",
        429: "quota_or_rate_limit",
        504: "deadline_exceeded",
    }.get(status_code, "upstream_service_error" if status_code is not None and status_code >= 500 else "provider_error")


def main() -> None:
    # Suppress SDK logging so no request metadata or provider text can leak to this diagnostic output.
    logging.disable(logging.CRITICAL)
    settings = get_settings()
    models = [settings.ai_model]
    if ALTERNATE_FAST_MODEL != settings.ai_model:
        models.append(ALTERNATE_FAST_MODEL)

    if settings.ai_provider.strip().lower() != "gemini" or not settings.gemini_api_key:
        for model in models:
            print(json.dumps({"model": model, "success": False, "elapsed_seconds": 0, "http_status": None, "error_category": "configuration"}))
        return

    try:
        client = genai.Client(
            api_key=settings.gemini_api_key,
            http_options=types.HttpOptions(
                timeout=max(1, int(settings.ai_timeout_seconds * 1000)),
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )
    except Exception as exc:
        category = _error_category(exc, _safe_status_code(exc))
        for model in models:
            print(json.dumps({"model": model, "success": False, "elapsed_seconds": 0, "http_status": _safe_status_code(exc), "error_category": category}))
        return

    try:
        for model in models:
            started = time.perf_counter()
            status_code = None
            category = None
            success = False
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=DIAGNOSTIC_PROMPT,
                    config=types.GenerateContentConfig(max_output_tokens=8),
                )
                success = isinstance(getattr(response, "text", None), str) and bool(response.text.strip())
                status_code = 200
                if not success:
                    category = "empty_response"
            except Exception as exc:
                status_code = _safe_status_code(exc)
                category = _error_category(exc, status_code)

            print(json.dumps({
                "model": model,
                "success": success,
                "elapsed_seconds": round(time.perf_counter() - started, 2),
                "http_status": status_code,
                "error_category": category,
            }))
    finally:
        try:
            client.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
