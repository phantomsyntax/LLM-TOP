# LLM-TOP format compliance experiment.
#
# The load-bearing question this project had never measured: when a model is
# asked to emit LLM-TOP, how often does it emit something that actually parses
# and validates? A token saving on tool-call turns is worthless if a meaningful
# fraction of turns have to be retried.
#
# Design notes, because the earlier harness got these wrong:
#
#  * There is a CONTROL. Free-text JSON is generated under an equivalent prompt
#    and held to an equivalent structural standard. "LLM-TOP is 96% valid" means
#    nothing on its own; it only means something next to what the alternative
#    scores under the same conditions.
#  * The two system prompts carry IDENTICAL information (same header fields,
#    same statement fields, same tool call). Otherwise the token comparison is
#    measuring prompt asymmetry, not format density.
#  * Validity is measured, never asserted. LLM-TOP goes through llmtop_eval
#    (real parse + schema validation); JSON goes through ConvertFrom-Json plus
#    an explicit field check of the same strictness.
#  * The system prompt cost is measured too, because savings on output turns are
#    only half the ledger -- a format you must teach on every request is not free.
#  * Proportions get a Wilson score interval. A raw percentage over n=30 invites
#    exactly the kind of overclaiming this project is recovering from.

[CmdletBinding()]
param(
    [string[]]$Models = @(
        "deepseek-ai/deepseek-v4-flash",
        "minimaxai/minimax-m3",
        "nvidia/llama-3.3-nemotron-super-49b-v1.5"
    ),
    [int]$Trials = 3,
    # Append an explicit "no spaces inside values" rule to the LLM-TOP system
    # prompt. Off by default so the baseline condition -- a model shown only the
    # structure -- stays reproducible. JSON needs no equivalent rule, and that
    # asymmetry is the finding, so the extra prompt tokens are charged to LLM-TOP
    # in the ledger below.
    [switch]$AntiSpaceRule,
    [string]$Url = "https://integrate.api.nvidia.com/v1/chat/completions",
    [int]$TimeoutSec = 90,
    [string]$OutCsv = "$PSScriptRoot\compliance_results.csv",
    [string]$EvalBinary
)

$ErrorActionPreference = "Stop"

if (-not $EvalBinary) {
    $EvalBinary = @(
        "$PSScriptRoot\build\Release\llmtop_eval.exe",
        "$PSScriptRoot\build\Debug\llmtop_eval.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $EvalBinary) { Write-Error "llmtop_eval not found; build it first."; exit 1 }

$token = [System.Environment]::GetEnvironmentVariable("NV_TOKEN", "User")
if (-not $token) { $token = $env:NV_TOKEN }
if (-not $token) { Write-Error "NV_TOKEN not set."; exit 1 }
$headers = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }

# --- the two formats, carrying identical information --------------------------

$sys_llmtop = @'
You are a command planner. Respond ONLY with an LLM-TOP payload. No prose, no explanation, no code fences.
Emit exactly this structure, substituting the angle-bracket values:
VER:LLM-TOPv1 CHK:sha256:0000 AGT:planner UID:user1 TIM:2026-07-22 REQID:<reqid> FALLBACK:json
[CODER] tgt:<path> act:<action> GL:<goal>
!<tool>[path=<path>]
'@

if ($AntiSpaceRule) {
    $sys_llmtop += @'
CRITICAL: never put a space inside a value. Fields are separated by spaces, so GL:fix the memory leak
is parsed as three separate fields and the payload is rejected. Use underscore slugs: GL:fix_memory_leak.
'@
}

$sys_json = @'
You are a command planner. Respond ONLY with a minified JSON object. No prose, no explanation, no code fences.
Emit exactly this structure, substituting the angle-bracket values:
{"h":{"v":"LLM-TOPv1","c":"sha256:0000","a":"planner","u":"user1","t":"2026-07-22","r":"<reqid>","f":"json"},"s":[{"o":"CODER","tgt":"<path>","act":"<action>","GL":"<goal>","tc":[{"n":"<tool>","a":{"path":"<path>"}}]}]}
'@

$tasks = @(
    @{ id = "t01"; desc = "Read the contents of src/main.cpp";                          path = "src/main.cpp";        action = "read";     tool = "read" },
    @{ id = "t02"; desc = "Refactor the database pool logic in src/db/pool.cpp";        path = "src/db/pool.cpp";     action = "refactor"; tool = "read" },
    @{ id = "t03"; desc = "Add a null check to src/net/socket.cpp";                     path = "src/net/socket.cpp";  action = "edit";     tool = "write" },
    @{ id = "t04"; desc = "Run the unit test suite in tests/run_all.sh";                path = "tests/run_all.sh";    action = "execute";  tool = "run" },
    @{ id = "t05"; desc = "Summarize the API surface in include/api.h";                 path = "include/api.h";       action = "analyze";  tool = "read" },
    @{ id = "t06"; desc = "Fix the memory leak in src/alloc/arena.cpp";                 path = "src/alloc/arena.cpp"; action = "fix";      tool = "write" },
    @{ id = "t07"; desc = "Rename the logger interface in src/log/logger.hpp";          path = "src/log/logger.hpp";  action = "refactor"; tool = "write" },
    @{ id = "t08"; desc = "Check formatting compliance of src/util/str.cpp";            path = "src/util/str.cpp";    action = "analyze";  tool = "read" },
    @{ id = "t09"; desc = "Generate bindings from schema/proto.def";                    path = "schema/proto.def";    action = "generate"; tool = "read" },
    @{ id = "t10"; desc = "Delete the deprecated shim in src/compat/legacy.cpp";        path = "src/compat/legacy.cpp"; action = "edit";   tool = "write" }
)

# --- measurement helpers ------------------------------------------------------

function Measure-Tokens {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [switch]$Validate)
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($tmp, $Text, [System.Text.UTF8Encoding]::new($false))
        $a = @(); if ($Validate) { $a += "--validate" }; $a += $tmp
        $out = & $EvalBinary @a 2>&1
        if ($LASTEXITCODE -ne 0) { return $null }
        return $out | ConvertFrom-Json
    } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
}

# Structural check for the JSON control, held to the same standard the schema
# validator applies to LLM-TOP: header identity fields present, at least one
# statement, statement carries role/target/action/goal, and a tool call with a
# name and a path argument.
function Test-JsonShape {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    try { $o = $Text | ConvertFrom-Json -ErrorAction Stop } catch { return $false }
    if (-not $o.h -or -not $o.s) { return $false }
    foreach ($f in @('v','a','u','t','r')) { if (-not $o.h.$f) { return $false } }
    if ($o.s.Count -lt 1) { return $false }
    $st = $o.s[0]
    foreach ($f in @('o','tgt','act','GL')) { if (-not $st.$f) { return $false } }
    if (-not $st.tc -or $st.tc.Count -lt 1) { return $false }
    if (-not $st.tc[0].n -or -not $st.tc[0].a.path) { return $false }
    return $true
}

function Invoke-Planner {
    param([string]$Model, [string]$System, [string]$UserPrompt)
    # Budget generously. Reasoning models spend completion tokens on hidden
    # reasoning before emitting any content: at max_tokens=300 one of them
    # returned 1467 characters of reasoning_content and an EMPTY content field,
    # which scored as 0/10 compliance for both formats. A response cut off by the
    # token limit says nothing about whether a model can emit a format.
    $body = @{
        model = $Model
        messages = @(@{role="system";content=$System}, @{role="user";content=$UserPrompt})
        temperature = 0.1
        max_tokens = 1500
    } | ConvertTo-Json -Depth 5

    # Retry transport failures with backoff. A 503 from a shared free-tier
    # endpoint says nothing about whether a model can emit this format, so it
    # must not be allowed to masquerade as a compliance failure. Exhausted
    # retries are reported as Transport=$true and excluded from the denominator.
    $maxAttempts = 4
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $r = Invoke-RestMethod -Uri $Url -Method Post -Headers $headers -Body $body -TimeoutSec $TimeoutSec
            $sw.Stop()
            $choice = $r.choices[0]
            $txt = $choice.message.content
            if ($null -eq $txt) { $txt = "" }

            # A truncated generation is a budget artifact, not a format failure.
            # Excluded from the denominator the same way a 503 is.
            $truncated = ($choice.finish_reason -eq 'length')
            $reasoned  = [bool]$choice.message.reasoning_content

            # Strip fences models add despite instructions. Their presence is
            # itself a compliance signal, but it is a wrapper, not a malformed
            # payload, so it is recorded rather than counted as a failure.
            $fenced = $txt -match '```'
            $txt = ($txt -replace '(?s)```[a-zA-Z]*', '').Trim()
            return [PSCustomObject]@{
                Text=$txt; Sec=[math]::Round($sw.Elapsed.TotalSeconds,2)
                Fenced=$fenced; Error=$(if ($truncated) { "truncated at max_tokens" } else { $null })
                Transport=$false; Truncated=$truncated; Reasoned=$reasoned; Attempts=$attempt
            }
        } catch {
            $msg = $_.Exception.Message
            $retryable = $msg -match '503|502|504|429|too many|timed out|Service Unavailable'
            if ($retryable -and $attempt -lt $maxAttempts) {
                Start-Sleep -Seconds ([math]::Pow(2, $attempt))   # 2s, 4s, 8s
                continue
            }
            $sw.Stop()
            return [PSCustomObject]@{
                Text=""; Sec=[math]::Round($sw.Elapsed.TotalSeconds,2)
                Fenced=$false; Error=$msg; Transport=$true
                Truncated=$false; Reasoned=$false; Attempts=$attempt
            }
        }
    }
}

# Wilson score interval -- the right interval for a proportion at these sample
# sizes. A normal approximation would put the upper bound above 100% at k=n.
function Get-WilsonInterval {
    param([int]$Successes, [int]$Total)
    if ($Total -eq 0) { return @{ Low=0.0; High=0.0; Point=0.0 } }
    $z = 1.96; $p = $Successes / [double]$Total; $n = [double]$Total
    $denom  = 1 + ($z*$z)/$n
    $center = ($p + ($z*$z)/(2*$n)) / $denom
    $half   = ($z / $denom) * [math]::Sqrt(($p*(1-$p))/$n + ($z*$z)/(4*$n*$n))
    # 0.0 / 1.0, not 0 / 1. With integer literals PowerShell binds the
    # [math]::Max(int,int) overload, truncating the double bound to an int: a
    # true interval of [0, 0.161] came out as [0, 0] and [0.839, 1.0] came out
    # as [1, 1]. Every interval silently collapsed to a point estimate, which is
    # the exact false precision the interval exists to prevent.
    return @{
        Point = [math]::Round($p*100,1)
        Low   = [math]::Round([math]::Max(0.0,($center-$half))*100,1)
        High  = [math]::Round([math]::Min(1.0,($center+$half))*100,1)
    }
}

# --- prompt-side cost, measured once ------------------------------------------

$sysTopTokens  = (Measure-Tokens -Text $sys_llmtop).tokens
$sysJsonTokens = (Measure-Tokens -Text $sys_json).tokens

Write-Host "========================================================================="
Write-Host "        LLM-TOP FORMAT COMPLIANCE EXPERIMENT"
Write-Host "========================================================================="
Write-Host "Models:  $($Models -join ', ')"
Write-Host "Design:  $($tasks.Count) tasks x $Trials trials x 2 formats x $($Models.Count) models = $($tasks.Count*$Trials*2*$Models.Count) requests"
Write-Host "System prompt cost: LLM-TOP $sysTopTokens tokens, JSON $sysJsonTokens tokens"
Write-Host ""

$rows = @()
$total = $tasks.Count * $Trials * 2 * $Models.Count
$done = 0

foreach ($model in $Models) {
    foreach ($task in $tasks) {
        for ($trial = 1; $trial -le $Trials; $trial++) {
            $prompt = "Task: $($task.desc). Target path: $($task.path). Action: $($task.action). Tool: $($task.tool). Request id: $($task.id)_$trial."

            foreach ($fmt in @("llmtop","json")) {
                $sys = if ($fmt -eq "llmtop") { $sys_llmtop } else { $sys_json }
                $resp = Invoke-Planner -Model $model -System $sys -UserPrompt $prompt

                $valid = $false; $tokens = $null; $errText = $resp.Error
                if (-not $resp.Error) {
                    if ($fmt -eq "llmtop") {
                        $m = Measure-Tokens -Text $resp.Text -Validate
                        if ($m) { $valid = [bool]$m.valid; $tokens = $m.tokens
                                  if (-not $valid -and $m.errors) { $errText = ($m.errors -join '; ') } }
                    } else {
                        $m = Measure-Tokens -Text $resp.Text
                        if ($m) { $tokens = $m.tokens }
                        $valid = Test-JsonShape -Text $resp.Text
                        if (-not $valid) { $errText = "json shape check failed" }
                    }
                }

                $rows += [PSCustomObject]@{
                    Model=$model; Task=$task.id; Trial=$trial; Format=$fmt
                    Valid=$valid; Transport=$resp.Transport; Truncated=$resp.Truncated
                    Reasoned=$resp.Reasoned; Tokens=$tokens
                    Sec=$resp.Sec; Attempts=$resp.Attempts; Fenced=$resp.Fenced
                    Note=$errText; Response=($resp.Text -replace '\r?\n','\n')
                }
                $done++
                if ($done % 10 -eq 0) { Write-Host "  ... $done / $total requests" }
                Start-Sleep -Milliseconds 400   # be a polite client on a shared endpoint
            }
        }
    }
}

$rows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding utf8
Write-Host "`nRaw results written to $OutCsv`n"

# --- report -------------------------------------------------------------------

Write-Host "========================================================================="
Write-Host "                 COMPLIANCE (valid / attempted)"
Write-Host "========================================================================="
Write-Host ("{0,-45} {1,-9} {2,8} {3,22} {4,9}" -f "Model","Format","Rate","95% Wilson CI","Excluded")
Write-Host ("-" * 99)

# Transport failures are excluded from the denominator: a 503 is a fact about a
# shared endpoint, not about whether a model can emit a format.
foreach ($model in $Models) {
    foreach ($fmt in @("llmtop","json")) {
        $all     = @($rows | Where-Object { $_.Model -eq $model -and $_.Format -eq $fmt })
        $scored  = @($all | Where-Object { -not $_.Transport -and -not $_.Truncated })
        $dropped = $all.Count - $scored.Count
        $n = $scored.Count
        $k = @($scored | Where-Object { $_.Valid }).Count
        $ci = Get-WilsonInterval -Successes $k -Total $n
        Write-Host ("{0,-45} {1,-9} {2,8} {3,22} {4,9}" -f $model, $fmt, "$k/$n", "$($ci.Point)% [$($ci.Low)-$($ci.High)]", $dropped)
    }
}

Write-Host "`n========================================================================="
Write-Host "                 OVERALL"
Write-Host "========================================================================="
foreach ($fmt in @("llmtop","json")) {
    $scored = @($rows | Where-Object { $_.Format -eq $fmt -and -not $_.Transport -and -not $_.Truncated })
    $n = $scored.Count
    $k = @($scored | Where-Object { $_.Valid }).Count
    $ci = Get-WilsonInterval -Successes $k -Total $n
    Write-Host ("{0,-9} {1,8}  {2}% [95% CI {3}-{4}]" -f $fmt, "$k/$n", $ci.Point, $ci.Low, $ci.High)
}

# Failure taxonomy: which failures are the format's fault is the whole question.
$badTop = @($rows | Where-Object { $_.Format -eq "llmtop" -and -not $_.Transport -and -not $_.Truncated -and -not $_.Valid })
if ($badTop.Count -gt 0) {
    Write-Host "`n--- LLM-TOP failure modes ---"
    $badTop | Group-Object Note | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  {0,3}x  {1}" -f $_.Count, $_.Name)
    }
}
$badJson = @($rows | Where-Object { $_.Format -eq "json" -and -not $_.Transport -and -not $_.Truncated -and -not $_.Valid })
if ($badJson.Count -gt 0) {
    Write-Host "`n--- JSON failure modes ---"
    $badJson | Group-Object Note | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  {0,3}x  {1}" -f $_.Count, $_.Name)
    }
}

# Token ledger, counting only valid responses -- an invalid response has to be
# retried, so its tokens are a cost with no output.
$topOk  = $rows | Where-Object { $_.Format -eq "llmtop" -and $_.Valid -and $_.Tokens }
$jsonOk = $rows | Where-Object { $_.Format -eq "json"   -and $_.Valid -and $_.Tokens }
if ($topOk -and $jsonOk) {
    $topMed  = ($topOk.Tokens  | Sort-Object)[[int](($topOk  | Measure-Object).Count/2)]
    $jsonMed = ($jsonOk.Tokens | Sort-Object)[[int](($jsonOk | Measure-Object).Count/2)]
    $perTurn = $jsonMed - $topMed
    Write-Host "`n--- Token ledger (median over valid responses) ---"
    Write-Host "  LLM-TOP output:      $topMed tokens"
    Write-Host "  JSON output:         $jsonMed tokens"
    Write-Host "  Saved per turn:      $perTurn tokens"
    Write-Host "  System prompt delta: $($sysTopTokens - $sysJsonTokens) tokens (LLM-TOP minus JSON, paid every request)"
    if ($perTurn -gt 0) {
        $breakeven = [math]::Ceiling(($sysTopTokens - $sysJsonTokens) / [double]$perTurn)
        if ($breakeven -gt 0) {
            Write-Host "  Break-even:          $breakeven tool-call turns per request before LLM-TOP is net cheaper"
        } else {
            Write-Host "  Break-even:          immediate (LLM-TOP's prompt is not more expensive)"
        }
    }
}

Write-Host "`nn per model per format = $($tasks.Count * $Trials). Report the interval, not the point."
