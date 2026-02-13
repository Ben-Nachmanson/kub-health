"""Configuration management for kub-health."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from kub_health.ai.analyzer import AIConfig

CONFIG_FILENAME = ".kub-health.yaml"
DEFAULT_PATHS = [
    Path.cwd() / CONFIG_FILENAME,
    Path.home() / CONFIG_FILENAME,
    Path.home() / ".config" / "kub-health" / "config.yaml",
]


@dataclass
class Config:
    """Application configuration."""

    # Kubernetes
    kubeconfig: str = ""
    context: str = ""
    namespace: str = ""  # Empty = all namespaces

    # AI
    ai: AIConfig = field(default_factory=AIConfig)

    # Checks
    skip_checks: list[str] = field(default_factory=list)  # e.g., ["rbac", "events"]
    skip_namespaces: list[str] = field(
        default_factory=lambda: ["kube-system", "kube-public", "kube-node-lease"]
    )

    # Output
    show_ok: bool = False  # Show OK (no issue) findings
    severity_filter: str = ""  # "critical", "warning", etc.
    no_ai: bool = False  # Skip AI analysis

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Create config from a dictionary (e.g., parsed YAML)."""
        ai_data = data.pop("ai", {})
        ai_config = AIConfig(
            provider=ai_data.get("provider", "ollama"),
            model=ai_data.get("model", ""),
            api_key=ai_data.get("api_key", ""),
            base_url=ai_data.get("base_url", ""),
            temperature=ai_data.get("temperature", 0.3),
            max_tokens=ai_data.get("max_tokens", 4096),
        )

        return cls(
            kubeconfig=data.get("kubeconfig", ""),
            context=data.get("context", ""),
            namespace=data.get("namespace", ""),
            ai=ai_config,
            skip_checks=data.get("skip_checks", []),
            skip_namespaces=data.get(
                "skip_namespaces",
                ["kube-system", "kube-public", "kube-node-lease"],
            ),
            show_ok=data.get("show_ok", False),
            severity_filter=data.get("severity_filter", ""),
            no_ai=data.get("no_ai", False),
        )

    @classmethod
    def load(cls, path: str | None = None) -> Config:
        """Load config from file, with env var overrides."""
        config_data: dict[str, Any] = {}

        # Find config file
        if path:
            config_path = Path(path)
        else:
            config_path = None
            for p in DEFAULT_PATHS:
                if p.exists():
                    config_path = p
                    break

        if config_path and config_path.exists():
            with open(config_path) as f:
                config_data = yaml.safe_load(f) or {}

        config = cls.from_dict(config_data)

        # Environment variable overrides
        if env_key := os.environ.get("OPENAI_API_KEY"):
            if not config.ai.api_key:
                config.ai.api_key = env_key
                if config.ai.provider == "ollama":
                    config.ai.provider = "openai"

        if env_key := os.environ.get("ANTHROPIC_API_KEY"):
            if not config.ai.api_key:
                config.ai.api_key = env_key
                if config.ai.provider == "ollama":
                    config.ai.provider = "anthropic"

        if env_url := os.environ.get("OLLAMA_HOST"):
            config.ai.base_url = env_url

        if env_model := os.environ.get("KUB_HEALTH_MODEL"):
            config.ai.model = env_model

        if env_provider := os.environ.get("KUB_HEALTH_AI_PROVIDER"):
            config.ai.provider = env_provider

        return config
