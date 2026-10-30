from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.9/3.10 compatibility
    import tomli as tomllib

from .utils import load_env_file


@dataclass(frozen=True)
class EnvValue:
    name: str | None
    value: str


@dataclass(frozen=True)
class LlmRuntimeConfig:
    stage: str
    enabled: bool
    requested_mode: str
    backend: str
    model: str
    timeout_sec: int
    codex_cli: str
    claude_cli: str
    codex_cli_path: str
    claude_cli_path: str
    base_url: str
    api_key: str
    api_provider: str
    resolved_env: dict[str, str | None]
    reasoning_effort: str = ""
    enable_thinking: bool | None = None
    config_path: str = ""


DEFAULT_OPENAI_MODEL = "gpt-5.6-luna"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5"
DEFAULT_CODEX_REASONING_EFFORT = "low"
DEFAULT_TIMEOUT_SEC = 300
LLM_RUNTIME_PROTOCOL_VERSION = "2026-08-04-v2"
LLM_CONFIG_FILENAME = "malskills.toml"
LLM_STAGES = (
    "sso_extraction",
    "object_analysis",
    "pattern_reasoning",
    "rule_feedback",
)
LLM_CONFIG_KEYS = {
    "enabled",
    "mode",
    "model",
    "timeout_sec",
    "reasoning_effort",
    "enable_thinking",
    "base_url",
    "codex_cli",
    "claude_cli",
}
DEFAULT_LLM_STAGE_ENABLED = {
    "sso_extraction": True,
    "object_analysis": True,
    "pattern_reasoning": True,
    "rule_feedback": False,
}


def build_llm_runtime_config(stage: str = "general") -> LlmRuntimeConfig:
    if stage != "general" and stage not in LLM_STAGES:
        raise ValueError(f"unknown LLM stage: {stage}")

    load_env_file(Path(__file__).resolve().parents[1])
    config_path, file_config = _load_llm_file_config()
    global_config, stage_config = _llm_stage_config(file_config, stage)

    stage_prefix = f"MALSKILLS_LLM_{stage.upper()}" if stage != "general" else ""
    enabled = (
        True
        if stage == "general"
        else resolve_llm_stage_enabled(
            stage,
            global_config=global_config,
            stage_config=stage_config,
        )
    )
    mode_env = _first_env(
        *([f"{stage_prefix}_MODE"] if stage_prefix else []),
        "MALSKILLS_LLM_MODE",
    )
    requested_mode = (mode_env.value or _config_text(stage_config, global_config, "mode") or "auto").lower()
    model_env = _first_env(
        *([f"{stage_prefix}_MODEL"] if stage_prefix else []),
        "MALSKILLS_LLM_MODEL",
        "OPENAI_MODEL",
        "ANTHROPIC_MODEL",
        "LLM_MODEL",
    )
    base_url_env = _first_env("MALSKILLS_LLM_BASE_URL", "OPENAI_BASE_URL", "PACKY_API_URL", "ANTHROPIC_BASE_URL")
    api_key_env = _first_env(
        "MALSKILLS_LLM_API_KEY",
        "OPENAI_API_KEY",
        "PACKY_API_KEY",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
    )
    codex_cli_env = _first_env("MALSKILLS_CODEX_CLI")
    claude_cli_env = _first_env("MALSKILLS_CLAUDE_CLI")
    timeout_env = _first_env(
        *([f"{stage_prefix}_TIMEOUT_SEC"] if stage_prefix else []),
        "MALSKILLS_LLM_TIMEOUT_SEC",
    )
    reasoning_effort_env = _first_env(
        *([f"{stage_prefix}_REASONING_EFFORT"] if stage_prefix else []),
        "MALSKILLS_LLM_REASONING_EFFORT",
    )

    codex_cli = codex_cli_env.value or _config_text(stage_config, global_config, "codex_cli") or "codex"
    claude_cli = claude_cli_env.value or _config_text(stage_config, global_config, "claude_cli") or "claude"
    codex_cli_path = shutil.which(codex_cli) or ""
    claude_cli_path = shutil.which(claude_cli) or ""

    configured_model = model_env.value or _config_text(stage_config, global_config, "model")
    configured_base_url = base_url_env.value or _config_text(stage_config, global_config, "base_url")
    api_provider = _infer_api_provider(requested_mode, configured_model, configured_base_url, api_key_env.name)
    default_model = DEFAULT_ANTHROPIC_MODEL if api_provider == "anthropic" else DEFAULT_OPENAI_MODEL
    model = configured_model or default_model

    backend = _resolve_backend(
        requested_mode=requested_mode,
        codex_available=bool(codex_cli_path),
        claude_available=bool(claude_cli_path),
        api_available=bool(api_key_env.value and configured_base_url),
        api_provider=api_provider,
    )
    configured_effort = reasoning_effort_env.value or _config_text(
        stage_config,
        global_config,
        "reasoning_effort",
    )
    reasoning_effort = _parse_reasoning_effort(configured_effort)
    if backend == "codex_cli" and not reasoning_effort:
        reasoning_effort = DEFAULT_CODEX_REASONING_EFFORT

    configured_timeout = timeout_env.value or _config_value(
        stage_config,
        global_config,
        "timeout_sec",
    )
    configured_thinking = _config_value(stage_config, global_config, "enable_thinking")
    enable_thinking = (
        None
        if configured_thinking == ""
        else _parse_bool(configured_thinking, "malskills.toml LLM setting 'enable_thinking'")
    )

    return LlmRuntimeConfig(
        stage=stage,
        enabled=enabled,
        requested_mode=requested_mode,
        backend=backend,
        model=model,
        timeout_sec=_parse_timeout(configured_timeout),
        codex_cli=codex_cli,
        claude_cli=claude_cli,
        codex_cli_path=codex_cli_path,
        claude_cli_path=claude_cli_path,
        base_url=configured_base_url,
        api_key=api_key_env.value,
        api_provider=api_provider,
        resolved_env={
            "mode": mode_env.name,
            "model": model_env.name,
            "base_url": base_url_env.name,
            "api_key": api_key_env.name,
            "codex_cli": codex_cli_env.name,
            "claude_cli": claude_cli_env.name,
            "timeout_sec": timeout_env.name,
            "reasoning_effort": reasoning_effort_env.name,
        },
        reasoning_effort=reasoning_effort,
        enable_thinking=enable_thinking,
        config_path=str(config_path) if config_path is not None else "",
    )


def describe_llm_runtime(config: LlmRuntimeConfig | None = None) -> dict[str, Any]:
    if config is not None:
        return _describe_runtime(config)
    runtimes = {stage: build_llm_runtime_config(stage) for stage in LLM_STAGES}
    config_paths = {runtime.config_path for runtime in runtimes.values() if runtime.config_path}
    return {
        "config_file": next(iter(config_paths), None),
        "stages": {
            stage: _describe_runtime(runtime)
            for stage, runtime in runtimes.items()
        },
        "environment_variables": {
            "config": ["MALSKILLS_CONFIG"],
            "global_selection": [
                "MALSKILLS_LLM_ENABLED",
                "MALSKILLS_LLM_MODE",
                "MALSKILLS_LLM_MODEL",
                "MALSKILLS_LLM_TIMEOUT_SEC",
                "MALSKILLS_LLM_REASONING_EFFORT",
            ],
            "stage_selection": [
                f"MALSKILLS_LLM_{stage.upper()}_{suffix}"
                for stage in LLM_STAGES
                for suffix in (
                    "ENABLED",
                    "MODE",
                    "MODEL",
                    "TIMEOUT_SEC",
                    "REASONING_EFFORT",
                )
            ],
            "local_cli": ["MALSKILLS_CODEX_CLI", "MALSKILLS_CLAUDE_CLI"],
            "online_api": [
                "MALSKILLS_LLM_BASE_URL",
                "MALSKILLS_LLM_API_KEY",
                "OPENAI_BASE_URL",
                "OPENAI_API_KEY",
                "OPENAI_MODEL",
                "PACKY_API_URL",
                "PACKY_API_KEY",
                "ANTHROPIC_BASE_URL",
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_MODEL",
            ],
            "cache": [
                "MALSKILLS_LLM_CACHE",
                "MALSKILLS_LLM_OBJECT_CACHE",
                "MALSKILLS_LLM_REASONING_CACHE",
                "MALSKILLS_LLM_FEEDBACK_CACHE",
            ],
        },
    }


def _describe_runtime(runtime: LlmRuntimeConfig) -> dict[str, Any]:
    return {
        "stage": runtime.stage,
        "enabled": runtime.enabled,
        "requested_mode": runtime.requested_mode,
        "resolved_backend": runtime.backend,
        "model": runtime.model,
        "timeout_sec": runtime.timeout_sec,
        "reasoning_effort": runtime.reasoning_effort or None,
        "enable_thinking": runtime.enable_thinking,
        "local_cli": {
            "codex_cli": runtime.codex_cli,
            "codex_cli_path": runtime.codex_cli_path or None,
            "claude_cli": runtime.claude_cli,
            "claude_cli_path": runtime.claude_cli_path or None,
        },
        "online_api": {
            "provider": runtime.api_provider,
            "base_url": runtime.base_url or None,
            "api_key_configured": bool(runtime.api_key),
        },
        "resolved_env": runtime.resolved_env,
        "config_file": runtime.config_path or None,
    }


def resolve_llm_stage_enabled(
    stage: str,
    *,
    global_config: dict[str, Any] | None = None,
    stage_config: dict[str, Any] | None = None,
) -> bool:
    if stage not in LLM_STAGES:
        raise ValueError(f"unknown LLM stage: {stage}")
    if global_config is None or stage_config is None:
        load_env_file(Path(__file__).resolve().parents[1])
        _, file_config = _load_llm_file_config()
        global_config, stage_config = _llm_stage_config(file_config, stage)
    stage_env = _env_value(f"MALSKILLS_LLM_{stage.upper()}_ENABLED")
    global_env = _env_value("MALSKILLS_LLM_ENABLED")
    if stage_env.value:
        return _parse_bool(stage_env.value, f"{stage_env.name}")
    if global_env.value:
        return _parse_bool(global_env.value, f"{global_env.name}")
    configured = _config_value(stage_config, global_config, "enabled")
    if configured != "":
        return _parse_bool(configured, f"[llm.{stage}].enabled")
    return DEFAULT_LLM_STAGE_ENABLED[stage]


def _load_llm_file_config() -> tuple[Path | None, dict[str, Any]]:
    explicit = os.environ.get("MALSKILLS_CONFIG", "").strip()
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"MalSkills config file does not exist: {path}")
        return path, _read_toml(path)

    candidates = [
        Path.cwd() / LLM_CONFIG_FILENAME,
        Path(__file__).resolve().parents[1] / LLM_CONFIG_FILENAME,
    ]
    seen: set[Path] = set()
    for candidate in candidates:
        path = candidate.resolve()
        if path in seen:
            continue
        seen.add(path)
        if path.is_file():
            return path, _read_toml(path)
    return None, {}


def _read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        payload = tomllib.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"MalSkills config must be a TOML table: {path}")
    return payload


def _llm_stage_config(
    config: dict[str, Any],
    stage: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    llm = config.get("llm", {})
    if not isinstance(llm, dict):
        raise ValueError("malskills.toml [llm] must be a table")
    unknown = set(llm) - LLM_CONFIG_KEYS - set(LLM_STAGES)
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ValueError(f"unknown keys in malskills.toml [llm]: {names}")
    global_config = {key: value for key, value in llm.items() if key in LLM_CONFIG_KEYS}
    if stage == "general":
        return global_config, {}
    selected = llm.get(stage, {})
    if not isinstance(selected, dict):
        raise ValueError(f"malskills.toml [llm.{stage}] must be a table")
    unknown_stage = set(selected) - LLM_CONFIG_KEYS
    if unknown_stage:
        names = ", ".join(sorted(unknown_stage))
        raise ValueError(f"unknown keys in malskills.toml [llm.{stage}]: {names}")
    return global_config, selected


def _config_value(
    stage_config: dict[str, Any],
    global_config: dict[str, Any],
    key: str,
) -> Any:
    if key in stage_config:
        return stage_config[key]
    return global_config.get(key, "")


def _config_text(
    stage_config: dict[str, Any],
    global_config: dict[str, Any],
    key: str,
) -> str:
    value = _config_value(stage_config, global_config, key)
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise ValueError(f"malskills.toml LLM setting '{key}' must be a string")
    return value.strip()


def invoke_structured_json(
    *,
    prompt: str,
    schema: dict[str, Any],
    system_prompt: str,
    cwd: str | Path | None = None,
    config: LlmRuntimeConfig | None = None,
) -> dict[str, Any] | None:
    runtime = config or build_llm_runtime_config()
    if runtime.backend == "codex_cli":
        return _invoke_codex_cli(
            runtime,
            prompt=prompt,
            schema=schema,
            system_prompt=system_prompt,
            cwd=cwd,
        )
    if runtime.backend == "claude_cli":
        return _invoke_claude_cli(runtime, prompt=prompt, schema=schema, system_prompt=system_prompt, cwd=cwd)
    if runtime.backend == "anthropic_api":
        return _invoke_anthropic_api(runtime, prompt=prompt, system_prompt=system_prompt)
    if runtime.backend == "openai_api":
        return _invoke_openai_api(runtime, prompt=prompt, schema=schema, system_prompt=system_prompt)
    if runtime.backend == "unavailable" and runtime.requested_mode != "auto":
        if runtime.requested_mode in {"api", "openai_api", "anthropic", "anthropic_api"}:
            raise RuntimeError(
                "LLM API mode requires MALSKILLS_LLM_BASE_URL and "
                "MALSKILLS_LLM_API_KEY in the environment"
            )
        raise RuntimeError(f"requested LLM mode is unavailable: {runtime.requested_mode}")
    return None


def _invoke_codex_cli(
    runtime: LlmRuntimeConfig,
    *,
    prompt: str,
    schema: dict[str, Any],
    system_prompt: str,
    cwd: str | Path | None,
) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory(prefix="malskills-codex-") as tmp_dir:
        schema_path = Path(tmp_dir) / "schema.json"
        output_path = Path(tmp_dir) / "result.json"
        schema_path.write_text(json.dumps(schema, indent=2, sort_keys=True), encoding="utf-8")
        command = [runtime.codex_cli_path]
        trusted_instructions = system_prompt.strip()
        if trusted_instructions:
            command.extend(
                ["--config", f"developer_instructions={json.dumps(trusted_instructions)}"]
            )
        if runtime.reasoning_effort:
            command.extend(
                ["--config", f"model_reasoning_effort={json.dumps(runtime.reasoning_effort)}"]
            )
        command.extend([
            "exec",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--color",
            "never",
            "--model",
            runtime.model,
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(output_path),
            "-",
        ])
        try:
            subprocess.run(
                command,
                cwd=str(Path(cwd).resolve()) if cwd else None,
                check=True,
                capture_output=True,
                text=True,
                input=prompt,
                timeout=runtime.timeout_sec,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        try:
            return _coerce_json_payload(output_path.read_text(encoding="utf-8"))
        except OSError:
            return None


def _invoke_claude_cli(
    runtime: LlmRuntimeConfig,
    *,
    prompt: str,
    schema: dict[str, Any],
    system_prompt: str,
    cwd: str | Path | None,
) -> dict[str, Any] | None:
    command = [
        runtime.claude_cli_path,
        "--print",
        "--output-format",
        "json",
        "--permission-mode",
        "dontAsk",
        "--tools",
        "",
        "--model",
        runtime.model,
        "--system-prompt",
        system_prompt,
        "--json-schema",
        json.dumps(schema, sort_keys=True),
        prompt,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(Path(cwd).resolve()) if cwd else None,
            check=True,
            capture_output=True,
            text=True,
            timeout=runtime.timeout_sec,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return _coerce_json_payload(completed.stdout)


def _invoke_openai_api(
    runtime: LlmRuntimeConfig,
    *,
    prompt: str,
    schema: dict[str, Any],
    system_prompt: str,
) -> dict[str, Any] | None:
    if not runtime.api_key:
        return None
    endpoint = _resolve_openai_endpoint(runtime.base_url or "https://api.openai.com/v1")
    payload = {
        "model": runtime.model,
        "temperature": 0,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "malskills_structured_output",
                "schema": schema,
            },
        },
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    }
    if runtime.reasoning_effort:
        payload["reasoning_effort"] = runtime.reasoning_effort
    if runtime.enable_thinking is not None:
        payload["enable_thinking"] = runtime.enable_thinking
    try:
        response_payload = _post_json(
            endpoint,
            payload,
            {
                "Authorization": f"Bearer {runtime.api_key}",
                "Content-Type": "application/json",
            },
            timeout_sec=runtime.timeout_sec,
        )
        content = response_payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    return _coerce_json_payload(content)


def _resolve_openai_endpoint(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return normalized + "/chat/completions"


def _invoke_anthropic_api(
    runtime: LlmRuntimeConfig,
    *,
    prompt: str,
    system_prompt: str,
) -> dict[str, Any] | None:
    if not runtime.api_key:
        return None
    endpoint = _resolve_anthropic_endpoint(runtime.base_url or "https://api.anthropic.com")
    payload = {
        "model": runtime.model,
        "max_tokens": 1200,
        "temperature": 0,
        "system": system_prompt,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        response_payload = _post_json(
            endpoint,
            payload,
            {
                "x-api-key": runtime.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            timeout_sec=runtime.timeout_sec,
        )
        blocks = response_payload["content"]
        text_blocks = [block.get("text", "") for block in blocks if isinstance(block, dict) and block.get("type") == "text"]
    except (KeyError, TypeError, ValueError):
        return None
    return _coerce_json_payload("\n".join(text_blocks))


def _resolve_anthropic_endpoint(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/messages"):
        return normalized
    if normalized.endswith("/v1"):
        return normalized + "/messages"
    return normalized + "/v1/messages"


def _post_json(endpoint: str, payload: dict[str, Any], headers: dict[str, str], *, timeout_sec: int) -> dict[str, Any]:
    http_request = request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with request.urlopen(http_request, timeout=timeout_sec) as response:
            return json.loads(response.read().decode("utf-8"))
    except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
        raise ValueError("request failed") from exc


def _coerce_json_payload(payload: str) -> dict[str, Any] | None:
    text = payload.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            parsed = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    if isinstance(parsed, dict) and isinstance(parsed.get("result"), str):
        return _coerce_json_payload(parsed["result"])
    return parsed if isinstance(parsed, dict) else None


def _infer_api_provider(requested_mode: str, model: str, base_url: str, api_key_name: str | None) -> str:
    if requested_mode in {"anthropic", "anthropic_api"}:
        return "anthropic"
    if requested_mode == "openai_api":
        return "openai"
    if "anthropic" in base_url.lower() or model.lower().startswith("claude"):
        return "anthropic"
    if api_key_name in {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"}:
        return "anthropic"
    return "openai"


def _resolve_backend(
    *,
    requested_mode: str,
    codex_available: bool,
    claude_available: bool,
    api_available: bool,
    api_provider: str,
) -> str:
    explicit_map = {
        "codex": "codex_cli",
        "codex_cli": "codex_cli",
        "claude": "claude_cli",
        "claude_cli": "claude_cli",
        "api": f"{api_provider}_api",
        "openai_api": "openai_api",
        "anthropic_api": "anthropic_api",
    }
    explicit_backend = explicit_map.get(requested_mode, "")
    if explicit_backend:
        available = {
            "codex_cli": codex_available,
            "claude_cli": claude_available,
            "openai_api": api_available,
            "anthropic_api": api_available,
        }
        return explicit_backend if available[explicit_backend] else "unavailable"
    if codex_available:
        return "codex_cli"
    if claude_available:
        return "claude_cli"
    if api_available:
        return f"{api_provider}_api"
    return "unavailable"


def _first_env(*names: str) -> EnvValue:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip():
            return EnvValue(name=name, value=value.strip())
    return EnvValue(name=None, value="")


def _env_value(name: str) -> EnvValue:
    value = os.environ.get(name)
    return EnvValue(name=name if value is not None else None, value=(value or "").strip())


def _parse_timeout(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SEC
    return max(1, parsed)


def _parse_bool(value: Any, source: str) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{source} must be a boolean")


def _parse_reasoning_effort(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"minimal", "low", "medium", "high", "xhigh", "max", "ultra"}:
        return normalized
    return ""
