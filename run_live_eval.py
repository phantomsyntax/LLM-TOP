"""
LLM-TOP Live API Empirical Evaluation Harness for NVIDIA NIM
Model: meta/llama-3.3-70b-instruct
Strict Privacy Compliance: Zero PII, Machine IDs, Absolute Paths, or Secrets in Prompts.
"""

import os
import sys
import json
import time
import ssl
import urllib.request
import urllib.error
from typing import Dict, List, Tuple

try:
    from llmtop_proxy import LLMTOPHostProxy
except ImportError:
    sys.path.append(os.path.dirname(__file__))
    from llmtop_proxy import LLMTOPHostProxy

NV_TOKEN = os.getenv("NV_TOKEN")
if not NV_TOKEN:
    import subprocess
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
MODEL_NAME = "meta/llama-3.3-70b-instruct"

BENCHMARK_PROMPTS = [
    {
        "task_name": "Task 1: Read File Request",
        "description": "Read contents of target file src/main.cpp",
        "tgt": "src/main.cpp",
        "act": "read",
        "tool": "read"
    },
    {
        "task_name": "Task 2: Refactor Request",
        "description": "Refactor database pool logic in src/db/pool.cpp",
        "tgt": "src/db/pool.cpp",
        "act": "refactor",
        "tool": "read"
    },
    {
        "task_name": "Task 3: Test Execution",
        "description": "Run test suite target tests/test_main.cpp",
        "tgt": "tests/test_main.cpp",
        "act": "test",
        "tool": "run"
    },
    {
        "task_name": "Task 4: Build Target",
        "description": "Compile release target in CMakeLists.txt",
        "tgt": "CMakeLists.txt",
        "act": "build",
        "tool": "compile"
    },
    {
        "task_name": "Task 5: Search and Replace",
        "description": "Update API route definitions in src/api/routes.ts",
        "tgt": "src/api/routes.ts",
        "act": "replace",
        "tool": "edit"
    }
]

SYSTEM_PROMPT_LLMTOP = """You are an autonomous subagent command planner.
Respond ONLY with an LLM-TOP protocol payload. Do not include introductory text, explanations, or markdown code blocks.

Format Specification:
VER:LLM-TOPv1 CHK:sha256:0000 AGT:coder_agent UID:user1 TIM:2026-07-21 REQID:<REQID> FALLBACK:json
[CODER] tgt:<TARGET_PATH> act:<ACTION> GL:<GOAL>
!<TOOL_NAME>[path=<TARGET_PATH>]
"""

SYSTEM_PROMPT_JSON = """You are an autonomous subagent command planner.
Respond ONLY with a minified JSON object matching this structure:
{"h":{"v":"v1","a":"coder_agent","u":"user1","t":"2026-07-21","r":"<REQID>"},"s":[{"r":"CODER","tgt":"<TARGET_PATH>","act":"<ACTION>","tc":[{"n":"<TOOL_NAME>","a":{"path":"<TARGET_PATH>"}}]}]}
Do not include formatting whitespace, introductory text, or markdown code blocks.
"""


def call_nvidia_api(system_prompt: str, user_prompt: str, max_tokens: int = 150) -> Tuple[str, float]:
    headers = {
        "Authorization": f"Bearer {NV_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": "LLMTOP-Eval/1.0"
    }
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
        "max_tokens": max_tokens
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(NVIDIA_URL, data=json.dumps(payload).encode('utf-8'), headers=headers)
    start_time = time.time()
    
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
                elapsed = time.time() - start_time
                body = json.loads(resp.read().decode('utf-8'))
                content = body["choices"][0]["message"]["content"].strip()
                return content, elapsed
        except Exception as e:
            if attempt == 2:
                raise e
            time.sleep(1)
    return "", 0.0


def run_live_evaluation():
    print("=" * 85)
    print("         LLM-TOP LIVE MODEL EMPIRICAL EVALUATION (NVIDIA NIM)          ")
    print("=" * 85)
    print(f"Model Endpoint: {MODEL_NAME}")
    print(f"Privacy Compliance: Active (Zero PII / Machine IDs / Non-Relative Paths)\n")

    proxy = LLMTOPHostProxy()
    results = []

    for idx, prompt_info in enumerate(BENCHMARK_PROMPTS, 1):
        user_msg = f"Plan command for task: {prompt_info['description']}. Target: {prompt_info['tgt']}, Action: {prompt_info['act']}, Tool: {prompt_info['tool']}."

        proxy.grant_capability("coder_agent", f"read:{prompt_info['tgt']}")
        proxy.grant_capability("coder_agent", f"write:{prompt_info['tgt']}")
        proxy.grant_capability("coder_agent", f"execute:{prompt_info['tool']}:{prompt_info['tgt']}")

        print(f"[{idx}/{len(BENCHMARK_PROMPTS)}] Querying {MODEL_NAME} for {prompt_info['task_name']}...")

        # 1. Fetch LLM-TOP Response
        llmtop_out, llmtop_time = call_nvidia_api(SYSTEM_PROMPT_LLMTOP, user_msg)
        clean_llmtop = re.sub(r'```[a-zA-Z]*', '', llmtop_out).strip('` \n\r')

        # 2. Fetch Minified JSON Response
        json_out, json_time = call_nvidia_api(SYSTEM_PROMPT_JSON, user_msg)
        clean_json = re.sub(r'```[a-zA-Z]*', '', json_out).strip('` \n\r')

        # Validate LLM-TOP syntax via Host Proxy
        eval_res = proxy.evaluate_payload(clean_llmtop)
        llmtop_valid = eval_res.get("authorized", False)

        # Validate JSON syntax
        try:
            json.loads(clean_json)
            json_valid = True
        except Exception:
            json_valid = False

        llmtop_len = len(clean_llmtop)
        json_len = len(clean_json)
        savings = (1.0 - (llmtop_len / float(json_len))) * 100.0 if json_len > 0 else 0.0

        results.append({
            "task": prompt_info["task_name"],
            "llmtop_valid": llmtop_valid,
            "json_valid": json_valid,
            "llmtop_bytes": llmtop_len,
            "json_bytes": json_len,
            "savings": savings,
            "llmtop_time": llmtop_time,
            "json_time": json_time,
            "llmtop_text": clean_llmtop,
            "json_text": clean_json
        })

        print(f"    - LLM-TOP Output ({llmtop_len} chars, {llmtop_time:.2f}s): {clean_llmtop[:60]}...")
        print(f"    - Min JSON Output ({json_len} chars, {json_time:.2f}s): {clean_json[:60]}...")
        print(f"    - LLM-TOP Syntax Valid: {llmtop_valid} | Min JSON Valid: {json_valid}")
        print(f"    - Payload Reduction: {savings:+.1f}%\n")

    print("=" * 85)
    print("                         LIVE EVALUATION SUMMARY TABLE                         ")
    print("=" * 85)
    print(f"{'Task':<28} | {'LLM-TOP Syntax':<15} | {'JSON Syntax':<12} | {'LLM-TOP Size':<12} | {'Savings':<10}")
    print("-" * 85)

    total_llmtop_bytes = 0
    total_json_bytes = 0
    valid_llmtop_count = 0
    valid_json_count = 0

    for r in results:
        total_llmtop_bytes += r["llmtop_bytes"]
        total_json_bytes += r["json_bytes"]
        if r["llmtop_valid"]: valid_llmtop_count += 1
        if r["json_valid"]: valid_json_count += 1

        v_str = "VALID" if r["llmtop_valid"] else "INVALID"
        j_str = "VALID" if r["json_valid"] else "INVALID"
        print(f"{r['task']:<28} | {v_str:<15} | {j_str:<12} | {r['llmtop_bytes']:>5} bytes   | {r['savings']:>+7.1f}%")

    print("-" * 85)
    total_savings = (1.0 - (total_llmtop_bytes / float(total_json_bytes))) * 100.0 if total_json_bytes > 0 else 0.0
    print(f"Overall LLM-TOP Syntax Pass Rate : {valid_llmtop_count}/{len(results)} ({valid_llmtop_count/len(results)*100:.0f}%)")
    print(f"Overall Min JSON Syntax Pass Rate: {valid_json_count}/{len(results)} ({valid_json_count/len(results)*100:.0f}%)")
    print(f"Total Character Reduction        : {total_savings:+.1f}%")
    print("=" * 85)


if __name__ == "__main__":
    run_live_evaluation()
