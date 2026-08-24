from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

_MAX_RESPONSE_BYTES = 1_000_000


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
    def __init__(
        self,
        *,
        endpoint: str,
        model_id: str,
        api_key: str,
        temperature: float = 0.0,
        seed: int = 7,
        max_output_tokens: int = 128,
    ) -> None:
        parsed = urllib.parse.urlsplit(endpoint)
        loopback = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("endpoint must not contain credentials, a query, or a fragment")
        if parsed.scheme != "https" and not loopback:
            raise ValueError("endpoint must be HTTPS or an explicit loopback HTTP URL")
        if not parsed.hostname:
            raise ValueError("endpoint must contain a hostname")
        if parsed.scheme == "https" and not api_key:
            raise ValueError("a non-empty API key is required for a remote HTTPS endpoint")
        if max_output_tokens < 1:
            raise ValueError("max_output_tokens must be positive")
        self._endpoint = endpoint.rstrip("/")
        self.model_id = model_id
        self._api_key = api_key
        self._temperature = temperature
        self._seed = seed
        self._max_output_tokens = max_output_tokens
        self.endpoint_class = (
            "openai_compatible_loopback" if loopback else "openai_compatible_https"
        )

    def complete(self, *, prompt: str, timeout_seconds: float) -> ModelResponse:
        body = json.dumps(
            {
                "model": self.model_id,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self._temperature,
                "seed": self._seed,
                "max_tokens": self._max_output_tokens,
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        request = urllib.request.Request(
            f"{self._endpoint}/chat/completions",
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            opener = urllib.request.build_opener(_NoRedirectHandler())
            with opener.open(request, timeout=timeout_seconds) as response:  # nosec B310
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise ValueError("configured model response exceeded the byte limit")
                payload = _CompletionPayload.model_validate_json(raw)
        except (urllib.error.URLError, TimeoutError, ValueError, ValidationError) as exc:
            raise RuntimeError("configured model request failed") from exc
        return ModelResponse(
            text=payload.choices[0].message.content,
            input_tokens=payload.usage.prompt_tokens,
            output_tokens=payload.usage.completion_tokens,
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent bearer credentials from following an endpoint redirect."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        return None


class _Message(BaseModel):
    model_config = ConfigDict(extra="ignore")

    content: str


class _Choice(BaseModel):
    model_config = ConfigDict(extra="ignore")

    message: _Message


class _Usage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)


class _CompletionPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    choices: tuple[_Choice, ...] = Field(min_length=1)
    usage: _Usage = _Usage()
