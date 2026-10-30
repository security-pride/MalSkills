from __future__ import annotations

"""YASA adapter for SDG operand resolution."""

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..models import ArtifactRecord, SSOFinding, OperandBinding, Span
from ..utils import iter_code_fences


@dataclass(frozen=True)
class AnalysisTarget:
    artifact_id: str
    artifact_path: str
    language: str
    source_path: str
    content: str
    line_offset: int = 0


class YasaAdapter:
    SUPPORTED_CODE_LANGUAGES = frozenset({"python", "javascript", "go", "java"})
    LANGUAGE_SUFFIXES = {
        "python": frozenset({".py"}),
        "javascript": frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}),
        "go": frozenset({".go"}),
        "java": frozenset({".java"}),
    }
    CHECKER_CONFIG = {
        "javascript": ("taint_flow_js_input", None),
        "python": ("taint_flow_python_input", "MALSKILLS_YASA_UAST_SDK"),
        "go": ("taint_flow_go_input", None),
        "java": ("taint_flow_java_input", None),
    }
    FENCE_LANGUAGE_ALIASES = {
        "py": "python",
        "python": "python",
        "js": "javascript",
        "jsx": "javascript",
        "mjs": "javascript",
        "cjs": "javascript",
        "ts": "javascript",
        "tsx": "javascript",
        "typescript": "javascript",
        "javascript": "javascript",
        "node": "javascript",
        "go": "go",
        "golang": "go",
        "java": "java",
    }

    def __init__(self, yasa_root: str | Path | None = None) -> None:
        self.yasa_root = Path(yasa_root) if yasa_root else Path(__file__).resolve().parents[2] / "vendor" / "yasa"
        self.rules_dir = Path(__file__).resolve().parents[1] / "rules" / "yasa"
        self._counter = 0

    def available(self) -> bool:
        return shutil.which("node") is not None and self.yasa_root.exists() and (self.yasa_root / "dist" / "main.js").exists()

    def extract(self, skill_root: str | Path, artifacts: list[ArtifactRecord]) -> list[OperandBinding]:
        if not self.available():
            return []
        root = Path(skill_root).resolve()
        targets = self._build_targets(artifacts)
        bindings: list[OperandBinding] = []
        for language in self._planned_languages(targets):
            checker_id, sdk_env = self.CHECKER_CONFIG[language]
            bindings.extend(
                self._run_yasa(
                    root,
                    [target for target in targets if target.language == language],
                    language=language,
                    checker_id=checker_id,
                    rule_config=self._rule_config_for(language),
                    uast_sdk=self._uast_sdk_path(sdk_env),
                )
            )
        return self._dedupe_findings(bindings)

    def _uast_sdk_path(self, sdk_env: str | None) -> str | None:
        """Resolve the UAST SDK directory for a checker that needs one.

        The environment variable wins when it is set. Otherwise fall back to
        the directory install_deps.sh writes the binaries into, so a checkout
        that ran it analyses Python without any further configuration.
        """
        if not sdk_env:
            return None
        configured = os.environ.get(sdk_env)
        if configured:
            return configured
        vendored = self.yasa_root / "deps"
        return str(vendored) if vendored.is_dir() else None

    def _planned_languages(self, targets: list[AnalysisTarget]) -> list[str]:
        artifact_types = {target.language for target in targets}
        planned: list[str] = []
        for language in sorted(item for item in artifact_types if item):
            _, sdk_env = self.CHECKER_CONFIG[language]
            if sdk_env and not self._uast_sdk_path(sdk_env):
                continue
            planned.append(language)
        return planned

    def language_for_artifact(self, artifact: ArtifactRecord) -> str | None:
        if artifact.artifact_type in self.SUPPORTED_CODE_LANGUAGES:
            return artifact.artifact_type
        suffix = Path(artifact.relative_path).suffix.lower()
        for language, suffixes in self.LANGUAGE_SUFFIXES.items():
            if suffix in suffixes:
                return language
        return None

    def language_for_finding(self, artifact: ArtifactRecord, findings: SSOFinding) -> str | None:
        language = self.language_for_artifact(artifact)
        if language:
            return language
        if artifact.artifact_type not in {"markdown", "prompt"}:
            return None
        if findings.span is None or not artifact.content:
            return None
        for target in self._fenced_code_targets(artifact):
            start_line = target.line_offset + 1
            end_line = target.line_offset + target.content.count("\n") + 1
            if start_line <= findings.span.start_line <= end_line:
                return target.language
        return None

    def _build_targets(self, artifacts: list[ArtifactRecord]) -> list[AnalysisTarget]:
        targets: list[AnalysisTarget] = []
        for artifact in artifacts:
            language = self.language_for_artifact(artifact)
            if language and artifact.content:
                targets.append(
                    AnalysisTarget(
                        artifact_id=artifact.artifact_id,
                        artifact_path=artifact.relative_path,
                        language=language,
                        source_path=artifact.relative_path,
                        content=artifact.content,
                    )
                )
        return targets

    def _fenced_code_targets(self, artifact: ArtifactRecord) -> list[AnalysisTarget]:
        targets: list[AnalysisTarget] = []
        stem = Path(artifact.relative_path).stem or "artifact"
        parent = Path(artifact.relative_path).parent
        for index, (language_name, body, start_line, _) in enumerate(iter_code_fences(artifact.content or "")):
            language = self._normalize_fence_language(language_name)
            if language is None or not body.strip():
                continue
            suffix = next(iter(sorted(self.LANGUAGE_SUFFIXES[language])))
            source_name = f"{stem}__snippet_{index}{suffix}"
            source_path = (parent / ".malskills_yasa" / source_name).as_posix()
            targets.append(
                AnalysisTarget(
                    artifact_id=artifact.artifact_id,
                    artifact_path=artifact.relative_path,
                    language=language,
                    source_path=source_path,
                    content=body,
                    line_offset=start_line,
                )
            )
        return targets

    def _normalize_fence_language(self, language_name: str) -> str | None:
        return self.FENCE_LANGUAGE_ALIASES.get(language_name.strip().lower())

    def _run_yasa(
        self,
        root: Path,
        targets: list[AnalysisTarget],
        language: str,
        checker_id: str,
        rule_config: str,
        uast_sdk: str | None = None,
    ) -> list[OperandBinding]:
        with tempfile.TemporaryDirectory(prefix="malskills-yasa-") as tmpdir:
            source_root = Path(tmpdir) / "source"
            report_dir = Path(tmpdir) / "report"
            self._materialize_targets(source_root, targets)
            cmd = [
                "node",
                "dist/main.js",
                "--sourcePath",
                str(source_root),
                "--language",
                language,
                "--report",
                str(report_dir),
                "--checkerIds",
                checker_id,
                "--ruleConfigFile",
                rule_config,
            ]
            if uast_sdk:
                cmd.extend(["--uastSDKPath", uast_sdk])
            try:
                proc = subprocess.run(cmd, cwd=self.yasa_root, capture_output=True, text=True, check=False, timeout=90)
            except subprocess.TimeoutExpired:
                return []
            sarif = report_dir / "report.sarif"
            if proc.returncode != 0 or not sarif.exists():
                return []
            try:
                payload = json.loads(sarif.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return []

        target_map = {target.source_path: target for target in targets}
        bindings: list[OperandBinding] = []
        for run in payload.get("runs", []):
            for result in run.get("results", []):
                target, start_line, end_line = self._extract_location(result, source_root, target_map)
                if target is None:
                    continue
                flow_steps = self._extract_flow_steps(result, source_root, target_map)
                finding = self._extract_yasa_finding(result, target, start_line, end_line, language, checker_id, flow_steps)
                if finding is not None:
                    bindings.append(finding)
                self._counter += 1
        return bindings

    def _dedupe_findings(self, bindings: list[OperandBinding]) -> list[OperandBinding]:
        deduped: list[OperandBinding] = []
        seen: set[str] = set()
        for item in bindings:
            key = json.dumps(
                {
                    "artifact_id": item.artifact_id,
                    "artifact_path": item.artifact_path,
                    "sink_api": item.sink_api,
                    "sink_subtype": item.sink_subtype,
                    "role": item.role,
                    "value": item.value,
                    "span": {
                        "start_line": item.span.start_line if item.span else None,
                        "end_line": item.span.end_line if item.span else None,
                    },
                    "object_kind": item.object_kind,
                    "identity_key": item.identity_key,
                },
                sort_keys=True,
                ensure_ascii=True,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def _extract_yasa_finding(
        self,
        result: dict[str, object],
        target: AnalysisTarget,
        start_line: int,
        end_line: int,
        language: str,
        checker_id: str,
        flow_steps: list[dict[str, object]] | None = None,
    ) -> OperandBinding | None:
        sink_info = result.get("sinkInfo", {}) if isinstance(result.get("sinkInfo", {}), dict) else {}
        resolved_flow_steps = list(flow_steps or [])
        sink_api = str(sink_info.get("sinkRule", "")).strip()
        sink_subtype = self._map_sink_subtype(sink_api, sink_info.get("sinkAttribute", ""))
        parameter_role = self._parameter_role_for(sink_subtype)
        if not sink_api or not sink_subtype or not parameter_role:
            return None
        value, binding = self._binding_from_flow(target, resolved_flow_steps, parameter_role)
        if not value:
            return None
        return OperandBinding(
            binding_id=f"yasa_{self._counter:05d}",
            producer="yasa",
            artifact_id=target.artifact_id,
            artifact_path=target.artifact_path,
            sink_api=sink_api,
            sink_subtype=sink_subtype,
            role=parameter_role,
            value=value,
            confidence=0.94,
            span=Span(start_line, end_line),
            object_kind=str(binding.get("object_kind", "unknown")),
            identity_key=str(binding.get("identity_key", "")),
            flow_steps=resolved_flow_steps,
        )

    def _materialize_targets(self, source_root: Path, targets: list[AnalysisTarget]) -> None:
        for target in targets:
            path = source_root / target.source_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(target.content, encoding="utf-8")

    def _rule_config_for(self, language: str) -> str:
        if language == "javascript":
            return "resource/example-rule-config/rule_config_js.json"
        if language == "go":
            return "resource/example-rule-config/rule_config_go.json"
        if language == "java":
            return "resource/example-rule-config/rule_config_java.json"
        candidate = self.rules_dir / f"{language}.json"
        if candidate.exists():
            return str(candidate.resolve())
        fallback = {
            "python": "resource/example-rule-config/rule_config_python.json",
        }
        return fallback[language]

    def _extract_location(
        self,
        result: dict[str, object],
        root: Path,
        target_map: dict[str, AnalysisTarget],
    ) -> tuple[AnalysisTarget | None, int, int]:
        physical = self._pick_physical_location(result)
        target = self._resolve_target(physical, root, target_map)
        region = physical.get("region", {}) if isinstance(physical, dict) else {}
        start = int(region.get("startLine", 1) or 1)
        end = int(region.get("endLine", start) or start)
        if target is None:
            return None, start, end
        return target, start + target.line_offset, end + target.line_offset

    def _pick_physical_location(self, result: dict[str, object]) -> dict[str, object]:
        locations = result.get("locations", [])
        if isinstance(locations, list) and locations:
            first = locations[0]
            if isinstance(first, dict):
                return first.get("physicalLocation", {})
        flow_steps = self._extract_flow_locations(result)
        if flow_steps:
            return flow_steps[-1]
        return {}

    def _extract_flow_steps(
        self,
        result: dict[str, object],
        root: Path,
        target_map: dict[str, AnalysisTarget],
    ) -> list[dict[str, object]]:
        steps: list[dict[str, object]] = []
        for physical in self._extract_flow_locations(result):
            target = self._resolve_target(physical, root, target_map)
            if target is None:
                continue
            region = physical.get("region", {}) if isinstance(physical, dict) else {}
            snippet = region.get("snippet", {}) if isinstance(region.get("snippet", {}), dict) else {}
            text = snippet.get("text", "")
            affected = snippet.get("affectedNodeName", "")
            steps.append(
                {
                    "artifact_path": target.artifact_path,
                    "start_line": int(region.get("startLine", 1) or 1) + target.line_offset,
                    "end_line": int(region.get("endLine", region.get("startLine", 1) or 1) or 1) + target.line_offset,
                    "affected_node": affected,
                    "snippet": text,
                }
            )
        return steps

    def _extract_flow_locations(self, result: dict[str, object]) -> list[dict[str, object]]:
        physical_locations: list[dict[str, object]] = []
        code_flows = result.get("codeFlows", [])
        if not isinstance(code_flows, list):
            return physical_locations
        for code_flow in code_flows:
            if not isinstance(code_flow, dict):
                continue
            for thread_flow in code_flow.get("threadFlows", []):
                if not isinstance(thread_flow, dict):
                    continue
                for location in thread_flow.get("locations", []):
                    if not isinstance(location, dict):
                        continue
                    physical = (location.get("location") or {}).get("physicalLocation", {})
                    if isinstance(physical, dict):
                        physical_locations.append(physical)
        return physical_locations

    def _resolve_target(
        self,
        physical: dict[str, object],
        root: Path,
        target_map: dict[str, AnalysisTarget],
    ) -> AnalysisTarget | None:
        artifact_location = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
        uri = artifact_location.get("uri", "") if isinstance(artifact_location, dict) else ""
        if not isinstance(uri, str) or not uri:
            return None
        if uri.startswith("file://"):
            candidate = Path(uri[len("file://"):])
            if candidate.exists():
                resolved = candidate.resolve()
            else:
                resolved = (root / candidate.as_posix().lstrip("/")).resolve()
        else:
            candidate = Path(uri)
            resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
        try:
            return target_map.get(str(resolved.relative_to(root)))
        except ValueError:
            return target_map.get(candidate.as_posix().lstrip("/"))

    def _map_sink_subtype(self, sink_api: str, sink_attribute: object) -> str:
        sink_attr = str(sink_attribute or "").strip()
        lowered_api = sink_api.lower()
        attr_mapping = {
            "NodejsSSRF": "connection_create",
            "PythonSSRF": "connection_create",
            "NodejsCommandInjection": "system_command_execution",
            "PythonCommandInjection": "system_command_execution",
            "NodejsExec": "system_command_execution",
            "PythonCommandExec": "system_command_execution",
        }
        if sink_attr in attr_mapping:
            return attr_mapping[sink_attr]
        if any(token in lowered_api for token in ("requests.", "httpx.", "axios.", "fetch", "http.request", "https.request")):
            return "connection_create"
        if any(token in lowered_api for token in ("subprocess.", "os.system", "child_process.exec", "child_process.spawn")):
            return "system_command_execution"
        return ""

    def _parameter_role_for(self, sink_subtype: str) -> str:
        if sink_subtype in {"connection_create", "data_send", "data_receive"}:
            return "endpoint"
        if sink_subtype in {
            "system_command_execution",
            "dynamic_code_execution",
            "external_file_execution",
        }:
            return "command"
        return ""

    def _binding_from_flow(
        self,
        target: AnalysisTarget,
        flow_steps: list[dict[str, object]],
        parameter_role: str,
    ) -> tuple[str, dict[str, object]]:
        sink_value = self._value_from_sink_step(flow_steps, parameter_role)
        if sink_value:
            object_kind = self._infer_object_kind(sink_value, parameter_role)
            identity_key = self._infer_identity_key(sink_value, object_kind, target.artifact_path, parameter_role)
            binding: dict[str, object] = {"value": sink_value}
            if object_kind:
                binding["object_kind"] = object_kind
            if identity_key:
                binding["identity_key"] = identity_key
            return sink_value, binding
        if not flow_steps:
            return "", {}
        source_step = flow_steps[0]
        affected = str(source_step.get("affected_node", "")).strip()
        snippet = str(source_step.get("snippet", "")).strip()
        value = affected or snippet
        if not value:
            return "", {}
        object_kind = self._infer_object_kind(value, parameter_role)
        identity_key = self._infer_identity_key(value, object_kind, target.artifact_path, parameter_role)
        binding: dict[str, object] = {"value": value}
        if object_kind:
            binding["object_kind"] = object_kind
        if identity_key:
            binding["identity_key"] = identity_key
        return value, binding

    def _value_from_sink_step(self, flow_steps: list[dict[str, object]], parameter_role: str) -> str:
        if not flow_steps:
            return ""
        sink_snippet = str(flow_steps[-1].get("snippet", "")).strip()
        if not sink_snippet:
            return ""
        if parameter_role == "command":
            for pattern in (
                r"child_process\.spawn\(([^,\n]+)",
                r"child_process\.exec\(([^)\n]+)\)",
                r"subprocess\.run\(([^,\n]+)",
                r"subprocess\.check_output\(([^,\n]+)",
            ):
                match = re.search(pattern, sink_snippet)
                if match:
                    return match.group(1).strip()
        if parameter_role == "endpoint":
            for pattern in (
                r"axios\.post\(([^,\n]+)",
                r"requests\.post\(([^,\n]+)",
                r"fetch\(([^,\n]+)",
            ):
                match = re.search(pattern, sink_snippet)
                if match:
                    value = match.group(1).strip()
                    if "||" in value:
                        value = value.split("||", 1)[0].strip()
                    return value
        return ""

    def _matched_text_for_flow(self, value: str, flow_steps: list[dict[str, object]]) -> str:
        for step in flow_steps:
            snippet = str(step.get("snippet", "")).strip()
            if snippet:
                return snippet
        return value

    def _infer_object_kind(self, value: str, parameter_role: str) -> str:
        stripped = value.strip()
        if parameter_role == "endpoint" and ("[" in stripped or "." in stripped):
            return "config_key"
        if parameter_role == "endpoint" and (stripped.startswith("http://") or stripped.startswith("https://")):
            return "endpoint"
        if parameter_role == "command" and ("[" in stripped or "." in stripped):
            return "config_key"
        if parameter_role == "command":
            return "command"
        return "symbolic_reference"

    def _infer_identity_key(self, value: str, object_kind: str, artifact_path: str, parameter_role: str) -> str:
        stripped = value.strip()
        if object_kind == "config_key":
            if "." in stripped:
                return stripped.split(".")[-1].strip("[]'\"` ")
            if "[" in stripped and "]" in stripped:
                inner = stripped.split("[", 1)[1].split("]", 1)[0]
                return inner.strip("'\"` ")
        if object_kind == "endpoint":
            return stripped
        return f"{artifact_path}::{parameter_role}::{stripped}"
