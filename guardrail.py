from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

from aicomp_sdk.guardrails.base import Decision, GuardrailBase

class Guardrail(GuardrailBase):
    """
    Advanced Defensive Model: Stateful, Context-Aware Guardrail.
    - Persistent Taint Tracking (across turns)
    - Anti-Washing Logic (detects untrusted -> local file -> dangerous tool)
    - Sensitive Pattern Detection (Secrets, Credentials)
    - Anomaly Detection for Tool Sequences
    """

    DANGEROUS_TOOLS: Final[set[str]] = {
        "fs.delete",
        "fs.write",
        "shell.run",
        "http.post",
        "email.send",
    }

    SENSITIVE_PATTERNS: Final[set[str]] = {
        "secret", "password", "token", "key", "credential",
        "private", "confidential", "api_key", "admin", "root",
    }

    UNTRUSTED_SOURCES: Final[set[str]] = {"web", "email"}

    def __init__(self) -> None:
        super().__init__()
        self.tainted_files: set[str] = set()
        self.is_session_tainted: bool = False
        self.tool_history: list[str] = []

    def decide(
        self, tool_name: str, tool_args: Mapping[str, Any], context: Mapping[str, Any]
    ) -> Decision:
        self.tool_history.append(tool_name)
        recent_sources = context.get("recent_sources", [])
        target = self._extract_target(tool_args)

        is_op_from_untrusted = any(src in self.UNTRUSTED_SOURCES for src in recent_sources)

        # 1. Update Taint State
        if tool_name == "fs.write" and is_op_from_untrusted:
            if "path" in tool_args:
                self.tainted_files.add(str(tool_args["path"]).lower())

        # 2. Block Direct Access to Ultra-Sensitive Patterns
        if self._is_sensitive(target):
            if tool_name != "fs.read" or self.is_session_tainted or is_op_from_untrusted:
                 return Decision.deny(f"Blocked {tool_name} targeting sensitive resource: {target}")

        # 3. Anti-Washing Logic
        # Does the target contain a previously tainted filename?
        for tainted in self.tainted_files:
            if tainted in target:
                return Decision.deny(f"Security Policy: Blocked {tool_name} on tainted file {tainted}.")

        # 4. Global Taint Enforcement
        if (self.is_session_tainted or is_op_from_untrusted) and tool_name in self.DANGEROUS_TOOLS:
             return Decision.deny(f"Security Policy: Blocked dangerous tool {tool_name} in untrusted context.")

        # Update global taint AFTER checking current op
        if is_op_from_untrusted:
            self.is_session_tainted = True

        # 5. Anomaly Detection
        if tool_name == "shell.run" and "fs.read" in self.tool_history[-3:-1]:
             return Decision.deny("Anomalous tool sequence detected: shell execution following file read.")

        return Decision.allow("Validated Safe")

    def _extract_target(self, tool_args: Mapping[str, Any]) -> str:
        for key in ["path", "url", "cmd", "data", "body", "content", "id"]:
            if key in tool_args:
                return str(tool_args[key]).lower()
        return ""

    def _is_sensitive(self, target: str) -> bool:
        if not target: return False
        return any(pattern in target for pattern in self.SENSITIVE_PATTERNS)

    def snapshot_state(self) -> Any:
        return {
            "tainted_files": list(self.tainted_files),
            "is_session_tainted": self.is_session_tainted,
            "tool_history": self.tool_history[:],
        }

    def restore_state(self, snapshot: Any) -> None:
        if snapshot:
            self.tainted_files = set(snapshot.get("tainted_files", []))
            self.is_session_tainted = bool(snapshot.get("is_session_tainted", False))
            self.tool_history = list(snapshot.get("tool_history", []))

    def track_untrusted_content(self, content: str) -> None:
        if not content: return
        file_patterns = re.findall(r"[\w/]+\.[\w]+", content)
        for path in file_patterns:
            self.tainted_files.add(path.lower())
        if self._is_sensitive(content.lower()):
            self.is_session_tainted = True
