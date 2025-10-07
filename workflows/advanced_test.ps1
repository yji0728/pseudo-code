# Advanced EDR Testing Workflow
# 고급 EDR 테스트 워크플로우
#
# This script provides comprehensive EDR testing with detailed logging
# and performance metrics collection

param(
    [string]$EDRVendor = "Generic",
    [string]$TestLevel = "Full",  # Basic, Intermediate, Full, Custom
    [switch]$GenerateReport,
    [string]$ReportPath = "EDR_Test_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [int]$DelayBetweenTests = 5
)

$ErrorActionPreference = "Continue"
$Script:TestStartTime = Get-Date
$Script:AllResults = @()

# Test result structure
class TestResult {
    [string]$TestName
    [string]$Category
    [DateTime]$StartTime
    [DateTime]$EndTime
    [double]$Duration
    [string]$Status
    [string]$Details
    [string]$EDRResponse
    [string]$Severity
}

function Write-Banner {
    param([string]$Text, [string]$Color = "Cyan")
    
    $banner = @"

================================================================
    $Text
================================================================
"@
    Write-Host $banner -ForegroundColor $Color
}

function Write-TestStep {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] $Message" -ForegroundColor Yellow
}

function Start-TestCase {
    param(
        [string]$Name,
        [string]$Category,
        [string]$Severity = "Medium"
    )
    
    Write-Banner "Test: $Name" "Cyan"
    Write-Host "Category: $Category" -ForegroundColor Gray
    Write-Host "Severity: $Severity" -ForegroundColor Gray
    Write-Host "Time: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    $result = [TestResult]::new()
    $result.TestName = $Name
    $result.Category = $Category
    $result.StartTime = Get-Date
    $result.Severity = $Severity
    
    return $result
}

function Complete-TestCase {
    param(
        [TestResult]$Result,
        [string]$Status,
        [string]$Details,
        [string]$EDRResponse = "Not checked"
    )
    
    $Result.EndTime = Get-Date
    $Result.Duration = ($Result.EndTime - $Result.StartTime).TotalSeconds
    $Result.Status = $Status
    $Result.Details = $Details
    $Result.EDRResponse = $EDRResponse
    
    $Script:AllResults += $Result
    
    $color = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "SKIP" { "Yellow" }
        "WARN" { "Magenta" }
        default { "White" }
    }
    
    Write-Host "`n[RESULT] $Status - Duration: $([math]::Round($Result.Duration, 2))s" -ForegroundColor $color
    Write-Host "Details: $Details" -ForegroundColor Gray
    
    if ($DelayBetweenTests -gt 0) {
        Write-Host "`nWaiting $DelayBetweenTests seconds before next test..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $DelayBetweenTests
    }
}

function Test-ProcessInjectionSuite {
    Write-Banner "PROCESS INJECTION TEST SUITE" "Magenta"
    
    # Test 1: DLL Injection
    $result = Start-TestCase -Name "DLL Injection" -Category "Process Injection" -Severity "High"
    try {
        if (Test-Path "samples\process_injection\dll_injection.exe") {
            Write-TestStep "1/3" "Executing DLL injection test..."
            $output = & "samples\process_injection\dll_injection.exe" test 2>&1
            Complete-TestCase -Result $result -Status "PASS" -Details "DLL injection test completed" -EDRResponse "Check EDR console"
        } else {
            Complete-TestCase -Result $result -Status "SKIP" -Details "Executable not found"
        }
    } catch {
        Complete-TestCase -Result $result -Status "FAIL" -Details $_.Exception.Message
    }
    
    # Test 2: Process Hollowing
    $result = Start-TestCase -Name "Process Hollowing" -Category "Process Injection" -Severity "High"
    try {
        if (Test-Path "samples\process_injection\process_hollowing.exe") {
            Write-TestStep "1/3" "Executing process hollowing test..."
            $output = & "samples\process_injection\process_hollowing.exe" 2>&1
            Complete-TestCase -Result $result -Status "PASS" -Details "Process hollowing test completed" -EDRResponse "Check EDR console"
        } else {
            Complete-TestCase -Result $result -Status "SKIP" -Details "Executable not found"
        }
    } catch {
        Complete-TestCase -Result $result -Status "FAIL" -Details $_.Exception.Message
    }
    
    # Test 3: APC Injection
    $result = Start-TestCase -Name "APC Injection" -Category "Process Injection" -Severity "High"
    try {
        if (Test-Path "samples\process_injection\apc_injection.exe") {
            Write-TestStep "1/3" "Executing APC injection test..."
            $output = & "samples\process_injection\apc_injection.exe" 2>&1
            Complete-TestCase -Result $result -Status "PASS" -Details "APC injection test completed" -EDRResponse "Check EDR console"
        } else {
            Complete-TestCase -Result $result -Status "SKIP" -Details "Executable not found"
        }
    } catch {
        Complete-TestCase -Result $result -Status "FAIL" -Details $_.Exception.Message
    }
}

function Test-FilelessSuite {
    Write-Banner "FILELESS TECHNIQUES TEST SUITE" "Magenta"
    
    # Test 1: PowerShell Memory Execution
    $result = Start-TestCase -Name "PowerShell Memory Execution" -Category "Fileless" -Severity "High"
    try {
        if (Test-Path "samples\fileless\memory_execution.ps1") {
            Write-TestStep "1/2" "Executing PowerShell fileless test..."
            $output = & powershell.exe -ExecutionPolicy Bypass -File "samples\fileless\memory_execution.ps1" 2>&1
            Complete-TestCase -Result $result -Status "PASS" -Details "PowerShell test completed" -EDRResponse "Check EDR console"
        } else {
            Complete-TestCase -Result $result -Status "SKIP" -Details "Script not found"
        }
    } catch {
        Complete-TestCase -Result $result -Status "FAIL" -Details $_.Exception.Message
    }
    
    # Test 2: WMI Execution
    $result = Start-TestCase -Name "WMI Execution" -Category "Fileless" -Severity "Medium"
    try {
        if (Test-Path "samples\fileless\wmi_execution.ps1") {
            Write-TestStep "1/2" "Executing WMI fileless test..."
            $output = & powershell.exe -ExecutionPolicy Bypass -File "samples\fileless\wmi_execution.ps1" 2>&1
            Complete-TestCase -Result $result -Status "PASS" -Details "WMI test completed" -EDRResponse "Check EDR console"
        } else {
            Complete-TestCase -Result $result -Status "SKIP" -Details "Script not found"
        }
    } catch {
        Complete-TestCase -Result $result -Status "FAIL" -Details $_.Exception.Message
    }
}

function Test-ShellcodeSuite {
    Write-Banner "SHELLCODE INJECTION TEST SUITE" "Magenta"
    
    $result = Start-TestCase -Name "Shellcode Injection" -Category "Shellcode" -Severity "High"
    try {
        if (Test-Path "samples\shellcode\shellcode_injection.exe") {
            Write-TestStep "1/1" "Executing shellcode injection test..."
            $output = & "samples\shellcode\shellcode_injection.exe" 2>&1
            Complete-TestCase -Result $result -Status "PASS" -Details "Shellcode injection test completed" -EDRResponse "Check EDR console"
        } else {
            Complete-TestCase -Result $result -Status "SKIP" -Details "Executable not found"
        }
    } catch {
        Complete-TestCase -Result $result -Status "FAIL" -Details $_.Exception.Message
    }
}

function Test-MultiStageSuite {
    Write-Banner "MULTI-STAGE ATTACK TEST SUITE" "Magenta"
    
    $result = Start-TestCase -Name "Multi-Stage Attack" -Category "Combined" -Severity "Critical"
    try {
        if (Test-Path "samples\combined\multi_stage_attack.exe") {
            Write-TestStep "1/1" "Executing multi-stage attack simulation..."
            $output = & "samples\combined\multi_stage_attack.exe" 2>&1
            Complete-TestCase -Result $result -Status "PASS" -Details "Multi-stage test completed" -EDRResponse "Check EDR console"
        } else {
            Complete-TestCase -Result $result -Status "SKIP" -Details "Executable not found"
        }
    } catch {
        Complete-TestCase -Result $result -Status "FAIL" -Details $_.Exception.Message
    }
}

function Generate-HTMLReport {
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>EDR Test Report - $EDRVendor</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .metric { display: inline-block; margin: 10px 20px; }
        .metric-label { font-weight: bold; color: #7f8c8d; }
        .metric-value { font-size: 24px; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; background-color: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th { background-color: #3498db; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .PASS { color: #27ae60; font-weight: bold; }
        .FAIL { color: #e74c3c; font-weight: bold; }
        .SKIP { color: #f39c12; font-weight: bold; }
        .severity-Critical { background-color: #e74c3c; color: white; padding: 3px 8px; border-radius: 3px; }
        .severity-High { background-color: #e67e22; color: white; padding: 3px 8px; border-radius: 3px; }
        .severity-Medium { background-color: #f39c12; color: white; padding: 3px 8px; border-radius: 3px; }
        .severity-Low { background-color: #95a5a6; color: white; padding: 3px 8px; border-radius: 3px; }
        .footer { margin-top: 30px; text-align: center; color: #7f8c8d; font-size: 12px; }
    </style>
</head>
<body>
    <h1>EDR Test Report</h1>
    <div class="summary">
        <div class="metric">
            <div class="metric-label">EDR Vendor</div>
            <div class="metric-value">$EDRVendor</div>
        </div>
        <div class="metric">
            <div class="metric-label">Test Date</div>
            <div class="metric-value">$(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>
        </div>
        <div class="metric">
            <div class="metric-label">Total Tests</div>
            <div class="metric-value">$($Script:AllResults.Count)</div>
        </div>
        <div class="metric">
            <div class="metric-label">Passed</div>
            <div class="metric-value" style="color: #27ae60;">$(($Script:AllResults | Where-Object {$_.Status -eq 'PASS'}).Count)</div>
        </div>
        <div class="metric">
            <div class="metric-label">Failed</div>
            <div class="metric-value" style="color: #e74c3c;">$(($Script:AllResults | Where-Object {$_.Status -eq 'FAIL'}).Count)</div>
        </div>
        <div class="metric">
            <div class="metric-label">Skipped</div>
            <div class="metric-value" style="color: #f39c12;">$(($Script:AllResults | Where-Object {$_.Status -eq 'SKIP'}).Count)</div>
        </div>
    </div>
    
    <h2>Test Results</h2>
    <table>
        <tr>
            <th>Test Name</th>
            <th>Category</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Duration (s)</th>
            <th>Details</th>
            <th>EDR Response</th>
        </tr>
"@

    foreach ($result in $Script:AllResults) {
        $html += @"
        <tr>
            <td>$($result.TestName)</td>
            <td>$($result.Category)</td>
            <td><span class="severity-$($result.Severity)">$($result.Severity)</span></td>
            <td class="$($result.Status)">$($result.Status)</td>
            <td>$([math]::Round($result.Duration, 2))</td>
            <td>$($result.Details)</td>
            <td>$($result.EDRResponse)</td>
        </tr>
"@
    }

    $html += @"
    </table>
    
    <div class="footer">
        <p>EDR Testing Tools - For legitimate security testing purposes only</p>
        <p>Report generated at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host "`n[+] HTML Report generated: $ReportPath" -ForegroundColor Green
}

# Main execution
Write-Banner "EDR TESTING WORKFLOW - ADVANCED" "Green"
Write-Host "EDR Vendor: $EDRVendor" -ForegroundColor Cyan
Write-Host "Test Level: $TestLevel" -ForegroundColor Cyan
Write-Host "Start Time: $Script:TestStartTime" -ForegroundColor Cyan
Write-Host ""

Write-Host "WARNING: This will execute multiple potentially suspicious activities!" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to cancel or any key to continue..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Execute test suites based on level
switch ($TestLevel) {
    "Basic" {
        Test-ProcessInjectionSuite
    }
    "Intermediate" {
        Test-ProcessInjectionSuite
        Test-FilelessSuite
    }
    "Full" {
        Test-ProcessInjectionSuite
        Test-FilelessSuite
        Test-ShellcodeSuite
        Test-MultiStageSuite
    }
}

# Generate report
Write-Banner "TEST EXECUTION COMPLETE" "Green"
$totalDuration = (Get-Date) - $Script:TestStartTime
Write-Host "Total Duration: $([math]::Round($totalDuration.TotalMinutes, 2)) minutes" -ForegroundColor Cyan
Write-Host "Total Tests: $($Script:AllResults.Count)" -ForegroundColor Cyan

if ($GenerateReport) {
    Generate-HTMLReport
}

Write-Host "`n[+] Please review your EDR console for detected activities." -ForegroundColor Green
Write-Host "[+] Compare results against expected detections." -ForegroundColor Green
