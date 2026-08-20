from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ModelResponse:
    text: str
    input_tokens: int
    output_tokens: int


class ModelAdapter(Protocol):
    endpoint_class: str
    model_id: str

    def complete(self, *, prompt: str, timeout_seconds: float) -> ModelResponse: ...


class OfflineFakeAdapter:
    """Deterministic CI adapter. Its results are never labeled as live evidence."""

    endpoint_class = "offline_fake"
    model_id = "aegis-offline-fake-v1"

    def complete(self, *, prompt: str, timeout_seconds: float) -> ModelResponse:
        del timeout_seconds
        text = "ABSTAIN" if "insufficient evidence" in prompt.casefold() else "SAFE_RESPONSE"
        return ModelResponse(text=text, input_tokens=len(prompt.split()), output_tokens=1)


class OpenAICompatibleAdapter:
    endpoint_class = "openai_compatible_http"

    def __init__(self, *, endpoint: str, model_id: str, api_key: str) -> None:
        if not endpoint.startswith(("http://127.0.0.1", "http://localhost", "https://")):
            raise ValueError("endpoint must be HTTPS or an explicit loopback URL")
        self._endpoint = endpoint.rstrip("/")
        self.model_id = model_id
        self._api_key = api_key

    def complete(self, *, prompt: str, timeout_seconds: float) -> ModelResponse:
        body = json.dumps(
            {
                "model": self.model_id,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
                "seed": 7,
                "max_tokens": 128,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self._endpoint}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            # The constructor rejects non-HTTPS/non-loopback endpoints; redirects remain HTTP(S).
            with urllib.request.urlopen(  # nosec B310
                request, timeout=timeout_seconds
            ) as response:
                payload = json.load(response)
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise RuntimeError("configured model request failed") from exc
        usage = payload.get("usage", {})
        return ModelResponse(
            text=str(payload["choices"][0]["message"]["content"]),
            input_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
        )
