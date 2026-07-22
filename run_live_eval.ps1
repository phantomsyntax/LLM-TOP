# LLM-TOP Live API Evaluation Script via Native PowerShell HTTP Engine
# Model: meta/llama-3.3-70b-instruct on NVIDIA NIM
# Strict Privacy Compliance: Zero PII, Machine IDs, Absolute Paths, or Secrets in Prompts.

$token = [System.Environment]::GetEnvironmentVariable("NV_TOKEN", "User")
if (-not $token) {
    Write-Error "ERR: NV_TOKEN environment variable not found."
    exit 1
}

$url = "https://integrate.api.nvidia.com/v1/chat/completions"
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

$tasks = @(
    @{ name = "Task 1: Read File Request"; desc = "Read contents of target file src/main.cpp"; tgt = "src/main.cpp"; act = "read"; tool = "read" },
    @{ name = "Task 2: Refactor Request"; desc = "Refactor database pool logic in src/db/pool.cpp"; tgt = "src/db/pool.cpp"; act = "refactor"; tool = "read" }
)

$sys_llmtop = "You are an autonomous subagent command planner. Respond ONLY with an LLM-TOP protocol payload. Format: VER:LLM-TOPv1 CHK:sha256:0000 AGT:coder_agent UID:user1 TIM:2026-07-21 REQID:req1 FALLBACK:json`n[CODER] tgt:<PATH> act:<ACT> GL:goal`n!<TOOL>[path=<PATH>]"
$sys_json   = 'You are an autonomous subagent command planner. Respond ONLY with a minified JSON object matching: {"h":{"v":"v1","a":"coder_agent","u":"user1","t":"2026-07-21","r":"req1"},"s":[{"r":"CODER","tgt":"<PATH>","act":"<ACT>","tc":[{"n":"<TOOL>","a":{"path":"<PATH>"}}]}]}'

Write-Host "========================================================================="
Write-Host "         LLM-TOP LIVE MODEL EMPIRICAL EVALUATION (NVIDIA NIM)          "
Write-Host "========================================================================="
Write-Host "Model Endpoint: meta/llama-3.3-70b-instruct"
Write-Host "Privacy Compliance: Active (Zero PII / Machine IDs / Non-Relative Paths)`n"

$results = @()

foreach ($t in $tasks) {
    Write-Host "[$($t.name)] Querying Llama 3.3 70B (Server latency ~80s)..."
    
    $prompt = "Plan command for task: $($t.desc). Target: $($t.tgt), Action: $($t.act), Tool: $($t.tool)."

    # 1. LLM-TOP Call
    $body1 = @{
        model = "meta/llama-3.3-70b-instruct"
        messages = @(
            @{ role = "system"; content = $sys_llmtop },
            @{ role = "user"; content = $prompt }
        )
        temperature = 0.1
        max_tokens = 100
    } | ConvertTo-Json -Depth 5

    $r1 = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body1 -TimeoutSec 120
    $out1 = $r1.choices[0].message.content.Trim()
    $clean1 = $out1 -replace '```[a-zA-Z]*', '' -replace '`', ''

    # 2. Minified JSON Call
    $body2 = @{
        model = "meta/llama-3.3-70b-instruct"
        messages = @(
            @{ role = "system"; content = $sys_json },
            @{ role = "user"; content = $prompt }
        )
        temperature = 0.1
        max_tokens = 100
    } | ConvertTo-Json -Depth 5

    $r2 = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body2 -TimeoutSec 120
    $out2 = $r2.choices[0].message.content.Trim()
    $clean2 = $out2 -replace '```[a-zA-Z]*', '' -replace '`', ''

    $len1 = $clean1.Length
    $len2 = $clean2.Length
    $savings = [math]::Round((1.0 - ($len1 / [double]$len2)) * 100.0, 1)

    Write-Host "    - LLM-TOP Output ($len1 chars): $clean1"
    Write-Host "    - Min JSON Output ($len2 chars): $clean2"
    Write-Host "    - Character Reduction: $savings%`n"

    $results += [PSCustomObject]@{
        Task = $t.name
        LLMTOP_Size = $len1
        JSON_Size = $len2
        Savings_Pct = "$savings%"
    }
}

Write-Host "========================================================================="
Write-Host "                         LIVE EVALUATION RESULTS                         "
Write-Host "========================================================================="
$results | Format-Table -AutoSize
