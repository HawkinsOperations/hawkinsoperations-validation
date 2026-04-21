Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$casePath = Join-Path $repoRoot "validation\\hero\\001-powershell-encoded-command\\validation-cases.json"
$reportDir = Join-Path $repoRoot "reports"
$jsonReportPath = Join-Path $reportDir "hero001-validation-report.json"
$mdReportPath = Join-Path $reportDir "hero001-validation-report.md"

if (-not (Test-Path -LiteralPath $casePath)) {
  throw "Validation case file missing: $casePath"
}

if (-not (Test-Path -LiteralPath $reportDir)) {
  New-Item -ItemType Directory -Path $reportDir | Out-Null
}

$cases = Get-Content -LiteralPath $casePath -Raw | ConvertFrom-Json

function Test-Rule001Match {
  param(
    [Parameter(Mandatory = $true)] [string] $Image,
    [Parameter(Mandatory = $true)] [string] $CommandLine
  )

  $img = $Image.ToLowerInvariant()
  $cli = $CommandLine.ToLowerInvariant()

  $imageMatch = $img.EndsWith("\powershell.exe") -or $img.EndsWith("\pwsh.exe")
  $cliMatch = $cli.Contains(" -enc ") -or $cli.Contains(" -encodedcommand ") -or $cli.Contains("frombase64string(")

  return ($imageMatch -and $cliMatch)
}

$positiveResults = @()
foreach ($item in $cases.positives) {
  $matched = Test-Rule001Match -Image $item.Image -CommandLine $item.CommandLine
  $positiveResults += [PSCustomObject]@{
    id = $item.id
    expected = $true
    matched = $matched
    pass = ($matched -eq $true)
  }
}

$negativeResults = @()
foreach ($item in $cases.negatives) {
  $matched = Test-Rule001Match -Image $item.Image -CommandLine $item.CommandLine
  $negativeResults += [PSCustomObject]@{
    id = $item.id
    expected = $false
    matched = $matched
    pass = ($matched -eq $false)
  }
}

$allResults = @($positiveResults + $negativeResults)
$total = $allResults.Count
$passCount = (@($allResults | Where-Object { $_.pass -eq $true })).Count
$failCount = $total - $passCount

$report = [PSCustomObject]@{
  rule_id = "HOD-001"
  rule_name = "PowerShell Encoded Command"
  executed_at = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
  totals = [PSCustomObject]@{
    total_cases = $total
    pass = $passCount
    fail = $failCount
  }
  positive = $positiveResults
  negative = $negativeResults
  status = if ($failCount -eq 0) { "pass" } else { "fail" }
}

$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonReportPath

$md = @()
$md += "# Hero001 Validation Report"
$md += ""
$md += "- Rule ID: HOD-001"
$md += ("- Executed: {0}" -f $report.executed_at)
$md += ("- Total: {0}" -f $report.totals.total_cases)
$md += ("- Pass: {0}" -f $report.totals.pass)
$md += ("- Fail: {0}" -f $report.totals.fail)
$md += ("- Status: {0}" -f $report.status)
$md += ""
$md += "## Failed Cases"
$failed = @($allResults | Where-Object { $_.pass -eq $false })
if ($failed.Count -eq 0) {
  $md += "- None"
} else {
  foreach ($f in $failed) {
    $md += ("- {0} expected={1} matched={2}" -f $f.id, $f.expected, $f.matched)
  }
}
$md -join [Environment]::NewLine | Set-Content -LiteralPath $mdReportPath

Write-Host "Report written: $jsonReportPath"
Write-Host "Report written: $mdReportPath"

if ($failCount -gt 0) {
  exit 1
}
