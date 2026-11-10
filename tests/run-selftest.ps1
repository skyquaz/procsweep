# Starts selftest.exe, scans it with procsweep, and checks that every planted
# artifact is reported with the expected type and severity. Run build.bat first.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$selftest = Join-Path $root 'build\selftest.exe'
$scanner = Join-Path $root 'build\procsweep.exe'
foreach ($exe in $selftest, $scanner) {
    if (-not (Test-Path $exe)) { throw "missing $exe - run build.bat first" }
}

# type/severity -> how many findings of that kind the planted artifacts must produce
$expected = [ordered]@{
    'UNBACKED_THREAD/high' = 1   # thread starting in the R-X trampoline
    'UNBACKED_PE/high'     = 1   # copied PE headers
    'PRIVATE_EXEC/high'    = 2   # trampoline (a thread starts there) + RWX page full of code
    'MAPPED_EXEC/high'     = 1   # RWX section view full of code
    'PRIVATE_EXEC/medium'  = 1   # RWX pool that is almost all zeros
    'PRIVATE_EXEC/low'     = 1   # R-X page with no other indicator
}

$proc = Start-Process -FilePath $selftest -ArgumentList 30 -PassThru -WindowStyle Hidden
try {
    Start-Sleep -Milliseconds 1500
    if ($proc.HasExited) { throw "selftest exited early (code $($proc.ExitCode))" }

    $report = (& $scanner --pid $proc.Id --all --json | Out-String) | ConvertFrom-Json
    $report.findings |
        Select-Object severity, type, address, memory, protection, detail |
        Format-Table -AutoSize | Out-String -Width 220 | Write-Host

    $actual = @{}
    foreach ($f in $report.findings) { $actual["$($f.type)/$($f.severity)"] += 1 }

    $failed = $false
    foreach ($key in $expected.Keys) {
        $got = [int]$actual[$key]
        if ($got -ne $expected[$key]) {
            Write-Host "FAIL: expected $($expected[$key]) x $key, got $got"
            $failed = $true
        }
    }
    foreach ($key in $actual.Keys) {
        if (-not $expected.Contains($key)) {
            Write-Host "FAIL: unexpected finding $key"
            $failed = $true
        }
    }
    if ($failed) { exit 1 }
    Write-Host "PASS: all $(($expected.Values | Measure-Object -Sum).Sum) planted artifacts detected with the expected severity"
    exit 0   # procsweep itself exits 1 when it reports findings; don't let that leak out
}
finally {
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
}
