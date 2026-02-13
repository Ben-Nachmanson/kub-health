"""AI analysis layer with configurable LLM providers.

Supports: OpenAI, Anthropic, and Ollama (local / air-gapped).

The analyzer takes the full investigation report text and produces an
SRE-quality analysis with root cause reasoning and action items.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a senior Kubernetes SRE engineer performing a cluster health investigation.
You have been given a structured report of findings from an automated cluster scan,
including detected issues, root cause correlation groups, dependency relationships,
and event timelines.

Your job is to:
1. Provide a concise executive summary of the cluster's health status.
2. For each root cause group, explain the causal chain in plain language -
   what happened, why, and what the blast radius is.
3. Identify any cross-cutting concerns (e.g., "3 different issues all stem from
   node-7 running out of memory").
4. Prioritize the issues by business impact and urgency.
5. Provide specific, actionable remediation steps with exact kubectl commands
   where applicable.
6. Call out any non-obvious risks (e.g., "the cluster appears stable but is one
   node failure away from cascading pod evictions").

Be direct, specific, and technical. Avoid generic advice. Reference specific
resource names from the report. Format your response in markdown.
"""


@dataclass
class AIConfig:
    """Configuration for the AI provider."""

    provider: str = "ollama"  # "openai", "anthropic", "ollama"
    model: str = ""  # Provider-specific model name
    api_key: str = ""
    base_url: str = ""  # For Ollama or custom endpoints
    temperature: float = 0.3
    max_tokens: int = 4096

    def __post_init__(self) -> None:
        # Set defaults per provider
        if not self.model:
            self.model = {
                "openai": "gpt-4o",
                "anthropic": "claude-sonnet-4-20250514",
                "ollama": "llama3.1",
            }.get(self.provider, "llama3.1")

        if not self.base_url and self.provider == "ollama":
            self.base_url = "http://localhost:11434"


class AIProvider(ABC):
    """Base class for AI providers."""

    @abstractmethod
    def analyze(self, report_text: str) -> str:
        """Send the report to the LLM and return the analysis."""
        ...


class OpenAIProvider(AIProvider):
    """OpenAI API provider (also works with Azure OpenAI)."""

    def __init__(self, config: AIConfig):
        self.config = config

    def analyze(self, report_text: str) -> str:
        try:
            from openai import OpenAI

            client_kwargs: dict = {"api_key": self.config.api_key}
            if self.config.base_url:
                client_kwargs["base_url"] = self.config.base_url

            client = OpenAI(**client_kwargs)
            response = client.chat.completions.create(
                model=self.config.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": report_text},
                ],
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
            return response.choices[0].message.content or ""
        except ImportError:
            return "[Error: openai package not installed. Run: pip install openai]"
        except Exception as exc:
            logger.error("OpenAI analysis failed: %s", exc)
            return f"[AI analysis failed: {exc}]"


class AnthropicProvider(AIProvider):
    """Anthropic Claude API provider."""

    def __init__(self, config: AIConfig):
        self.config = config

    def analyze(self, report_text: str) -> str:
        try:
            from anthropic import Anthropic

            client_kwargs: dict = {"api_key": self.config.api_key}
            if self.config.base_url:
                client_kwargs["base_url"] = self.config.base_url

            client = Anthropic(**client_kwargs)
            response = client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": report_text},
                ],
                temperature=self.config.temperature,
            )
            return response.content[0].text if response.content else ""
        except ImportError:
            return "[Error: anthropic package not installed. Run: pip install anthropic]"
        except Exception as exc:
            logger.error("Anthropic analysis failed: %s", exc)
            return f"[AI analysis failed: {exc}]"


class OllamaProvider(AIProvider):
    """Ollama local LLM provider (air-gapped friendly)."""

    def __init__(self, config: AIConfig):
        self.config = config

    def analyze(self, report_text: str) -> str:
        try:
            url = f"{self.config.base_url}/api/chat"
            payload = {
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": report_text},
                ],
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens,
                },
            }

            with httpx.Client(timeout=300) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                return data.get("message", {}).get("content", "")

        except httpx.ConnectError:
            return (
                "[Error: Cannot connect to Ollama at "
                f"{self.config.base_url}. Is Ollama running? "
                "Start it with: ollama serve]"
            )
        except Exception as exc:
            logger.error("Ollama analysis failed: %s", exc)
            return f"[AI analysis failed: {exc}]"


def get_provider(config: AIConfig) -> AIProvider:
    """Factory function to get the appropriate AI provider."""
    providers = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "ollama": OllamaProvider,
    }

    provider_class = providers.get(config.provider)
    if not provider_class:
        raise ValueError(
            f"Unknown AI provider: {config.provider}. "
            f"Supported: {', '.join(providers.keys())}"
        )

    return provider_class(config)


def run_analysis(config: AIConfig, report_text: str) -> str:
    """Run AI analysis on the investigation report."""
    provider = get_provider(config)
    return provider.analyze(report_text)
