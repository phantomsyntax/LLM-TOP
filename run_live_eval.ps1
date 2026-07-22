# LLM-TOP live model evaluation.
#
# Asks a model to answer the same task twice -- once as LLM-TOP, once as
# minified JSON -- and compares the two responses by *token* count, measured by
# llmtop_eval with the real cl100k_base BPE tokenizer. An earlier version of this
# script compared `.Length` (characters), which is not what anyone is billed for
# and systematically flatters a format that trades characters for punctuation.
#
# Validity is measured, not asserted: each LLM-TOP response is parsed and schema
# checked, and the summary reports how many actually passed.
#
# Privacy: prompts carry no PII, machine identifiers, or absolute paths. The API
# token is read from the environment and passed in-process, never on a command line.

[CmdletBinding()]
param(
    [string]$Model = "meta/llama-3.3-70b-instruct",
    [string]$Url = "https://integrate.api.nvidia.com/v1/chat/completions",
    [int]$TimeoutSec = 120,
    [string]$EvalBinary
)

$ErrorActionPreference = "Stop"

# --- locate llmtop_eval -------------------------------------------------------
if (-not $EvalBinary) {
    $candidates = @(
        "$PSScriptRoot\build\Release\llmtop_eval.exe",
        "$PSScriptRoot\build\Debug\llmtop_eval.exe",
        "$PSScriptRoot\build\llmtop_eval.exe",
        "$PSScriptRoot\build\llmtop_eval"
    )
    $EvalBinary = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $EvalBinary) {
    Write-Error "llmtop_eval not found. Build it first: cmake --build build --config Release --target llmtop_eval"
    exit 1
}

$token = [System.Environment]::GetEnvironmentVariable("NV_TOKEN", "User")
if (-not $token) {
    Write-Error "NV_TOKEN environment variable not found."
    exit 1
}

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

# Measure a response with the project's own tokenizer and validator.
# Returns the parsed JSON object from llmtop_eval, or $null if it could not measure.
function Measure-Payload {
    param(
        [Parameter(Mandatory)][string]$Text,
        [switch]$Validate
    )
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        # WriteAllText, not Set-Content: no trailing newline is appended and no
        # BOM is emitted, so the byte count is exactly what the model produced.
        [System.IO.File]::WriteAllText($tmp, $Text, [System.Text.UTF8Encoding]::new($false))
        $evalArgs = @()
        if ($Validate) { $evalArgs += "--validate" }
        $evalArgs += $tmp
        $out = & $EvalBinary @evalArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "llmtop_eval could not measure this response: $out"
            return $null
        }
        return $out | ConvertFrom-Json
    }
    finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

function Invoke-Model {
    param(
        [Parameter(Mandatory)][string]$System,
        [Parameter(Mandatory)][string]$UserPrompt
    )
    $body = @{
        model    = $Model
        messages = @(
            @{ role = "system"; content = $System },
            @{ role = "user";   content = $UserPrompt }
        )
        temperature = 0.1
        max_tokens  = 200
    } | ConvertTo-Json -Depth 5

    $started = Get-Date
    $resp = Invoke-RestMethod -Uri $Url -Method Post -Headers $headers -Body $body -TimeoutSec $TimeoutSec
    $elapsed = (Get-Date) - $started

    # Strip markdown fencing models add despite being told not to.
    $text = $resp.choices[0].message.content.Trim()
    $text = $text -replace '```[a-zA-Z]*', '' -replace '`', ''

    return [PSCustomObject]@{
        Text      = $text.Trim()
        LatencySec = [math]::Round($elapsed.TotalSeconds, 2)
    }
}

$tasks = @(
    @{ name = "Read File Request";  desc = "Read contents of target file src/main.cpp"; tgt = "src/main.cpp";    act = "read";     tool = "read" },
    @{ name = "Refactor Request";   desc = "Refactor database pool logic in src/db/pool.cpp"; tgt = "src/db/pool.cpp"; act = "refactor"; tool = "read" }
)

$sys_llmtop = "You are an autonomous subagent command planner. Respond ONLY with an LLM-TOP protocol payload. Format: VER:LLM-TOPv1 CHK:sha256:0000 AGT:coder_agent UID:user1 TIM:2026-07-21 REQID:req1 FALLBACK:json`n[CODER] tgt:<PATH> act:<ACT> GL:goal`n!<TOOL>[path=<PATH>]"
$sys_json   = 'You are an autonomous subagent command planner. Respond ONLY with a minified JSON object matching: {"h":{"v":"v1","a":"coder_agent","u":"user1","t":"2026-07-21","r":"req1"},"s":[{"r":"CODER","tgt":"<PATH>","act":"<ACT>","tc":[{"n":"<TOOL>","a":{"path":"<PATH>"}}]}]}'

Write-Host "========================================================================="
Write-Host "            LLM-TOP LIVE MODEL EVALUATION"
Write-Host "========================================================================="
Write-Host "Model:      $Model"
Write-Host "Measured by: $EvalBinary (real cl100k_base BPE token counts)"
Write-Host ""

$results = @()

foreach ($t in $tasks) {
    Write-Host "[$($t.name)] querying $Model ..."
    $prompt = "Plan command for task: $($t.desc). Target: $($t.tgt), Action: $($t.act), Tool: $($t.tool)."

    $r_top  = Invoke-Model -System $sys_llmtop -UserPrompt $prompt
    $r_json = Invoke-Model -System $sys_json   -UserPrompt $prompt

    $m_top  = Measure-Payload -Text $r_top.Text -Validate
    $m_json = Measure-Payload -Text $r_json.Text

    if (-not $m_top -or -not $m_json) {
        Write-Warning "Skipping '$($t.name)': a response could not be measured."
        continue
    }

    # Positive = LLM-TOP used fewer tokens. One sign convention everywhere.
    $savings = [math]::Round((1.0 - ($m_top.tokens / [double]$m_json.tokens)) * 100.0, 1)

    Write-Host "    LLM-TOP : $($m_top.tokens) tokens, valid=$($m_top.valid), $($r_top.LatencySec)s"
    if (-not $m_top.valid -and $m_top.errors) {
        Write-Host "              validation errors: $($m_top.errors -join '; ')"
    }
    Write-Host "    Min JSON: $($m_json.tokens) tokens, $($r_json.LatencySec)s"
    Write-Host "    Token reduction: $savings%`n"

    $results += [PSCustomObject]@{
        Task            = $t.name
        LLMTOP_Tokens   = $m_top.tokens
        JSON_Tokens     = $m_json.tokens
        Reduction_Pct   = $savings
        LLMTOP_Valid    = $m_top.valid
        LLMTOP_Latency  = $r_top.LatencySec
        JSON_Latency    = $r_json.LatencySec
    }
}

Write-Host "========================================================================="
Write-Host "                        RESULTS"
Write-Host "========================================================================="
if ($results.Count -eq 0) {
    Write-Host "No tasks produced a measurable result."
    exit 1
}

$results | Format-Table -AutoSize

$validCount = ($results | Where-Object { $_.LLMTOP_Valid }).Count
$median = ($results | Select-Object -ExpandProperty Reduction_Pct | Sort-Object)[[int]($results.Count / 2)]

Write-Host ""
Write-Host "Tasks measured:         $($results.Count)"
Write-Host "LLM-TOP responses valid: $validCount / $($results.Count)"
Write-Host "Median token reduction:  $median% (positive = LLM-TOP cheaper)"
Write-Host ""
Write-Host "n=$($results.Count). This is a sample size, not a benchmark. Report it as one."
