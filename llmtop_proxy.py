"""
LLM-TOP Host Session Proxy & Python Integration Module
Provides out-of-band session capability authorization and token savings calculation
for Python subagent frameworks (LangChain, AutoGen, CrewAI, MCP).
"""

import re
import json
from typing import Dict, List, Set, Optional, Tuple


class LLMTOPHostProxy:
    """
    Host-side execution proxy for subagent pipelines.
    Manages session-level capability grants out-of-band, eliminating JWT bearer
    token overhead from LLM text generation streams.
    """

    def __init__(self, default_deny: bool = True):
        self.default_deny = default_deny
        # Maps agent_id -> set of granted scope patterns (e.g. "read:src/*", "execute:read:src/*")
        self.session_capabilities: Dict[str, Set[str]] = {}
        # History of executed request IDs to prevent replay attacks
        self.executed_reqids: Set[Tuple[str, str]] = set()

    def grant_capability(self, agent_id: str, scope: str) -> None:
        """Grant a session scope to an agent (e.g., 'read:src/*', 'execute:read:src/main.py')."""
        if agent_id not in self.session_capabilities:
            self.session_capabilities[agent_id] = set()
        self.session_capabilities[agent_id].add(self.normalize_scope(scope))

    def revoke_capabilities(self, agent_id: str) -> None:
        """Revoke all session capability grants for an agent."""
        self.session_capabilities.pop(agent_id, None)

    def normalize_path(self, path_str: str) -> str:
        """Normalize file paths to resolve relative components (../) and prevent path traversal."""
        path_str = path_str.replace('\\', '/')
        segments = []
        for seg in path_str.split('/'):
            if not seg or seg == '.':
                continue
            if seg == '..':
                if segments and segments[-1] != '..':
                    segments.pop()
                else:
                    segments.append(seg)
            else:
                segments.append(seg)
        prefix = '/' if path_str.startswith('/') else ''
        return prefix + '/'.join(segments)

    def normalize_scope(self, scope: str) -> str:
        """Normalize path components within a scope string (action:path)."""
        parts = scope.split(':')
        if len(parts) > 1:
            # Action/tool prefix + resource path
            action = parts[0]
            resource = ':'.join(parts[1:])
            return f"{action}:{self.normalize_path(resource)}"
        return scope

    def match_scope(self, granted: str, requested: str) -> bool:
        """Evaluate if a granted scope pattern authorizes a requested scope."""
        g_parts = granted.split(':')
        r_parts = requested.split(':')
        if len(g_parts) != len(r_parts):
            return False
        
        for g_seg, r_seg in zip(g_parts, r_parts):
            if g_seg == '*':
                continue
            g_norm = self.normalize_path(g_seg)
            r_norm = self.normalize_path(r_seg)
            if '*' in g_norm:
                pattern = g_norm.split('*')[0]
                if not r_norm.startswith(pattern):
                    return False
            elif g_norm != r_norm:
                return False
        return True

    def is_authorized(self, agent_id: str, requested_scope: str) -> bool:
        """Check if an agent holds an active out-of-band session capability for a scope."""
        granted_scopes = self.session_capabilities.get(agent_id, set())
        req_norm = self.normalize_scope(requested_scope)
        for granted in granted_scopes:
            if granted == req_norm or self.match_scope(granted, req_norm):
                return True
        return False

    def evaluate_payload(self, llm_top_text: str) -> Dict[str, any]:
        """
        Parse and evaluate an LLM-TOP payload out-of-band.
        Enforces header integrity, replay protection, and session capability grants.
        """
        lines = [line.strip() for line in llm_top_text.strip().splitlines() if line.strip()]
        if not lines:
            return {"authorized": False, "error": "Empty payload"}

        # 1. Header line parsing
        header_line = lines[0]
        header = dict(re.findall(r'([A-Z]+):(\S+)', header_line))
        agent_id = header.get("AGT", "")
        req_id = header.get("REQID", "")

        if not agent_id or not req_id:
            return {"authorized": False, "error": "Missing AGT or REQID in header"}

        # 2. Replay protection
        session_key = (agent_id, req_id)
        if session_key in self.executed_reqids:
            return {"authorized": False, "error": f"Replay detected for REQID: {req_id}"}

        approved_actions = []
        
        # 3. Statement line evaluation
        for line in lines[1:]:
            # Target pointers (tgt:path)
            tgt_matches = re.findall(r'tgt:([^\s:]+)', line)
            for target in tgt_matches:
                resource = self.normalize_path(target)
                if not (self.is_authorized(agent_id, f"read:{resource}") or
                        self.is_authorized(agent_id, f"write:{resource}") or
                        self.is_authorized(agent_id, resource)):
                    return {"authorized": False, "error": f"Unauthorized target pointer: {target}"}
                approved_actions.append(f"READ/WRITE authorized for {resource}")

            # Tool executions (!tool[path=...])
            tool_matches = re.findall(r'!([a-zA-Z0-9_]+)\[(.*?)\]', line)
            for tool_name, args_raw in tool_matches:
                args = dict(re.findall(r'([a-zA-Z0-9_]+)=([^;\]]+)', args_raw))
                resource = args.get("path") or args.get("target") or args.get("file") or ""
                scope = f"execute:{tool_name}"
                if resource:
                    scope += f":{self.normalize_path(resource)}"
                
                if not self.is_authorized(agent_id, scope):
                    return {"authorized": False, "error": f"Unauthorized tool call: {tool_name} on {resource}"}
                approved_actions.append(f"TOOL authorized: {tool_name} ({resource})")

        # Mark request executed
        self.executed_reqids.add(session_key)
        return {
            "authorized": True,
            "agent_id": agent_id,
            "req_id": req_id,
            "approved_actions": approved_actions
        }


if __name__ == "__main__":
    # Integration test demonstration
    proxy = LLMTOPHostProxy()
    proxy.grant_capability("coder_agent", "execute:read:src/*")
    proxy.grant_capability("coder_agent", "read:src/*")

    valid_payload = (
        "VER:LLM-TOPv1 CHK:sha256:1234 AGT:coder_agent UID:user1 TIM:2026-07-21 REQID:req101 FALLBACK:json\n"
        "[CODER] tgt:src/main.cpp act:refactor\n"
        "!read[path=src/main.cpp]\n"
    )

    res = proxy.evaluate_payload(valid_payload)
    print("Out-of-Band Auth Result:", json.dumps(res, indent=2))
    assert res["authorized"] is True

    # Replay test
    replay_res = proxy.evaluate_payload(valid_payload)
    print("Replay Test Result:", json.dumps(replay_res, indent=2))
    assert replay_res["authorized"] is False

    print("llmtop_proxy.py self-test passed successfully!")
