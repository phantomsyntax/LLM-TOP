"""
LLM-TOP Dual-Model Live API Empirical Evaluation via System Curl Engine
Models: meta/llama-3.3-70b-instruct AND minimaxai/minimax-m3 (NVIDIA NIM)
Privacy Compliance: Strict (Zero PII, Machine IDs, Absolute Paths, or Secrets in Prompts)
"""

import os
import sys
import json
import time
import subprocess
import re
from typing import Dict, List, Tuple

try:
    from llmtop_proxy import LLMTOPHostProxy
except ImportError:
    sys.path.append(os.path.dirname(__file__))
    from llmtop_proxy import LLMTOPHostProxy

NV_TOKEN = os.getenv("NV_TOKEN")
if not NV_TOKEN:
    try:
        cmd = '[System.Environment]::GetEnvironmentVariable("NV_TOKEN", "User")'
        res = subprocess.check_output(["powershell", "-Command", cmd], text=True).strip()
        if res:
            NV_TOKEN = res
    except Exception:
        pass

if not NV_TOKEN:
    print("ERR: NV_TOKEN environment variable not found.")
    sys.exit(1)

NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
MODELS = [
    "meta/llama-3.3-70b-instruct",
    "minimaxai/minimax-m3"
]

TASKS = [
    {
        "name": "Task 1: Read Spec File",
        "desc": "Read requirements from relative file src/auth_spec.txt",
        "tgt": "src/auth_spec.txt",
        "act": "read",
        "tool": "read"
    },
    {
        "name": "Task 2: Refactor DB Pool",
        "desc": "Refactor connection pool logic in src/db/pool.cpp",
        "tgt": "src/db/pool.cpp",
        "act": "refactor",
        "tool": "read"
    }
]

SYS_LLMTOP = """You are an autonomous subagent command planner.
Respond ONLY with an LLM-TOP protocol payload. Do not include introductory text or markdown code blocks.

Format Specification:
VER:LLM-TOPv1 CHK:sha256:0000 AGT:coder_agent UID:user1 TIM:2026-07-21 REQID:<REQID> FALLBACK:json
[CODER] tgt:<TARGET_PATH> act:<ACTION> GL:<GOAL>
!<TOOL_NAME>[path=<TARGET_PATH>]
"""

SYS_JSON = """You are an autonomous subagent command planner.
Respond ONLY with a minified JSON object matching:
{"h":{"v":"v1","a":"coder_agent","u":"user1","t":"2026-07-21","r":"<REQID>"},"s":[{"r":"CODER","tgt":"<TARGET_PATH>","act":"<ACTION>","tc":[{"n":"<TOOL_NAME>","a":{"path":"<TARGET_PATH>"}}]}]}
Do not include formatting whitespace or markdown code blocks.
"""


def query_model(model_name: str, system_prompt: str, user_prompt: str) -> str:
    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 100
    }
    
    payload_json = json.dumps(payload)
    cmd = [
        "curl.exe", "-s", "-m", "150", "-X", "POST", NVIDIA_URL,
        "-H", f"Authorization: Bearer {NV_TOKEN}",
        "-H", "Content-Type: application/json",
        "-d", payload_json
    ]
    
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=160)
    if res.returncode != 0:
        raise RuntimeError(f"Curl failed with code {res.returncode}: {res.stderr}")
    
    data = json.loads(res.stdout)
    if "choices" in data and len(data["choices"]) > 0:
        return data["choices"][0]["message"]["content"].strip()
    elif "error" in data:
        raise RuntimeError(f"API Error ({model_name}): {data['error']}")
    else:
        raise RuntimeError(f"Unexpected response: {res.stdout[:200]}")


def run_eval():
    print("=" * 85)
    print("         LLM-TOP DUAL-MODEL LIVE EVALUATION (NVIDIA NIM)          ")
    print("=" * 85)
    print(f"Models Target: {', '.join(MODELS)}")
    print(f"Privacy Compliance: Active (Zero PII / Machine IDs / Non-Relative Paths)\n")

    proxy = LLMTOPHostProxy()

    for model in MODELS:
        print("=" * 85)
        print(f"                       EVALUATING MODEL: {model}")
        print("=" * 85)
        results = []

        for idx, t in enumerate(TASKS, 1):
            user_msg = f"Plan command for task: {t['desc']}. Target: {t['tgt']}, Action: {t['act']}, Tool: {t['tool']}."

            proxy.grant_capability("coder_agent", f"read:{t['tgt']}")
            proxy.grant_capability("coder_agent", f"write:{t['tgt']}")
            proxy.grant_capability("coder_agent", f"execute:{t['tool']}:{t['tgt']}")

            print(f"[{idx}/{len(TASKS)}] Querying {model} for '{t['name']}'...")

            try:
                # 1. LLM-TOP Call
                start_t = time.time()
                llmtop_raw = query_model(model, SYS_LLMTOP, user_msg)
                llmtop_time = time.time() - start_t
                clean_llmtop = re.sub(r'```[a-zA-Z]*', '', llmtop_raw).strip('` \n\r')

                # 2. Minified JSON Call
                start_t = time.time()
                json_raw = query_model(model, SYS_JSON, user_msg)
                json_time = time.time() - start_t
                clean_json = re.sub(r'```[a-zA-Z]*', '', json_raw).strip('` \n\r')

                # Validate syntax
                eval_res = proxy.evaluate_payload(clean_llmtop)
                llmtop_valid = eval_res.get("authorized", False)
                
                try:
                    json.loads(clean_json)
                    json_valid = True
                except Exception:
                    json_valid = False

                len_llmtop = len(clean_llmtop)
                len_json = len(clean_json)
                savings = (1.0 - (len_llmtop / float(len_json))) * 100.0 if len_json > 0 else 0.0

                results.append({
                    "task": t["name"],
                    "llmtop_valid": llmtop_valid,
                    "json_valid": json_valid,
                    "llmtop_len": len_llmtop,
                    "json_len": len_json,
                    "savings": savings,
                    "llmtop_time": llmtop_time,
                    "json_time": json_time,
                    "llmtop_text": clean_llmtop,
                    "json_text": clean_json
                })

                print(f"    - LLM-TOP Output ({len_llmtop} chars, {llmtop_time:.1f}s): {clean_llmtop}")
                print(f"    - Min JSON Output ({len_json} chars, {json_time:.1f}s): {clean_json}")
                print(f"    - LLM-TOP Valid: {llmtop_valid} | Min JSON Valid: {json_valid}")
                print(f"    - Payload Reduction: {savings:+.1f}%\n")
            except Exception as e:
                print(f"    - Error querying {model}: {e}\n")

        if results:
            print(f"RESULTS FOR {model}:")
            for r in results:
                v_str = "VALID" if r["llmtop_valid"] else "INVALID"
                j_str = "VALID" if r["json_valid"] else "INVALID"
                print(f"  {r['task']:<25} | LLM-TOP: {v_str} ({r['llmtop_len']} chars) | JSON: {j_str} ({r['json_len']} chars) | Savings: {r['savings']:+.1f}%")
            print()


if __name__ == "__main__":
    run_eval()
