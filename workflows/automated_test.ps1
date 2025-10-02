# EDR Test Workflow - Automated Test Execution
#
# 목적: EDR 테스트를 자동화하고 결과를 수집
# Purpose: Automate EDR tests and collect results
#
# WARNING: For testing purposes only in isolated environments

param(
    [switch]$BasicOnly,
    [switch]$SkipCompilation,
    [string]$LogFile = "edr_test_results.log"
)

$ErrorActionPreference = "Continue"
$TestResults = @()

function Write-TestHeader {
    param([string]$Title)
    
    $header = @"

==============================================================
    $Title
    Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
==============================================================
"@
    Write-Host $header -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value $header
}

function Write-TestResult {
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Details
    )
    
    $result = "[$(Get-Date -Format 'HH:mm:ss')] $TestName - $Status - $Details"
    
    switch ($Status) {
        "PASS" { Write-Host $result -ForegroundColor Green }
        "FAIL" { Write-Host $result -ForegroundColor Red }
        "SKIP" { Write-Host $result -ForegroundColor Yellow }
        default { Write-Host $result -ForegroundColor White }
    }
    
    Add-Content -Path $LogFile -Value $result
    
    $global:TestResults += @{
        Name = $TestName
        Status = $Status
        Details = $Details
        Time = Get-Date
    }
}

function Test-Prerequisites {
    Write-TestHeader "Checking Prerequisites"
    
    # Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        Write-TestResult "Admin Rights" "PASS" "Running with administrator privileges"
    } else {
        Write-TestResult "Admin Rights" "WARN" "Not running as administrator - some tests may fail"
    }
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    Write-TestResult "PowerShell Version" "INFO" "Version $($psVersion.Major).$($psVersion.Minor)"
    
    # Check if compilation tools available
    if (-not $SkipCompilation) {
        $clExists = Get-Command cl.exe -ErrorAction SilentlyContinue
        if ($clExists) {
            Write-TestResult "C++ Compiler" "PASS" "cl.exe found"
        } else {
            Write-TestResult "C++ Compiler" "WARN" "cl.exe not found - C++ tests will be skipped"
        }
    }
    
    # Check test files
    $requiredDirs = @(
        "samples\process_injection",
        "samples\fileless",
        "samples\shellcode",
        "samples\combined"
    )
    
    foreach ($dir in $requiredDirs) {
        if (Test-Path $dir) {
            Write-TestResult "Directory Check" "PASS" "$dir exists"
        } else {
            Write-TestResult "Directory Check" "FAIL" "$dir not found"
        }
    }
}

function Compile-CppSamples {
    if ($SkipCompilation) {
        Write-TestResult "Compilation" "SKIP" "Skipped by user"
        return
    }
    
    Write-TestHeader "Compiling C++ Samples"
    
    $cppFiles = Get-ChildItem -Path "samples" -Recurse -Filter "*.cpp"
    
    foreach ($file in $cppFiles) {
        $outputName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name) + ".exe"
        $outputPath = Join-Path $file.DirectoryName $outputName
        
        Write-Host "`nCompiling $($file.Name)..." -ForegroundColor Yellow
        
        $compileCmd = "cl.exe /EHsc /W4 `"$($file.FullName)`" /Fe:`"$outputPath`" /link /SUBSYSTEM:CONSOLE"
        
        try {
            $result = Invoke-Expression $compileCmd 2>&1
            if (Test-Path $outputPath) {
                Write-TestResult "Compile" "PASS" "$($file.Name) compiled successfully"
            } else {
                Write-TestResult "Compile" "FAIL" "$($file.Name) compilation failed"
            }
        } catch {
            Write-TestResult "Compile" "FAIL" "$($file.Name) - $($_.Exception.Message)"
        }
    }
}

function Test-ProcessInjection {
    Write-TestHeader "Process Injection Tests"
    
    # Test 1: DLL Injection (test mode)
    if (Test-Path "samples\process_injection\dll_injection.exe") {
        try {
            Write-Host "`nRunning DLL Injection test..." -ForegroundColor Yellow
            $output = & "samples\process_injection\dll_injection.exe" test 2>&1
            Write-TestResult "DLL Injection" "PASS" "Test completed"
        } catch {
            Write-TestResult "DLL Injection" "FAIL" $_.Exception.Message
        }
    } else {
        Write-TestResult "DLL Injection" "SKIP" "Executable not found"
    }
    
    # Test 2: Process Hollowing
    if (Test-Path "samples\process_injection\process_hollowing.exe") {
        try {
            Write-Host "`nRunning Process Hollowing test..." -ForegroundColor Yellow
            $output = & "samples\process_injection\process_hollowing.exe" 2>&1
            Write-TestResult "Process Hollowing" "PASS" "Test completed"
        } catch {
            Write-TestResult "Process Hollowing" "FAIL" $_.Exception.Message
        }
    } else {
        Write-TestResult "Process Hollowing" "SKIP" "Executable not found"
    }
    
    # Test 3: APC Injection
    if (Test-Path "samples\process_injection\apc_injection.exe") {
        try {
            Write-Host "`nRunning APC Injection test..." -ForegroundColor Yellow
            $output = & "samples\process_injection\apc_injection.exe" 2>&1
            Write-TestResult "APC Injection" "PASS" "Test completed"
        } catch {
            Write-TestResult "APC Injection" "FAIL" $_.Exception.Message
        }
    } else {
        Write-TestResult "APC Injection" "SKIP" "Executable not found"
    }
}

function Test-Fileless {
    Write-TestHeader "Fileless Technique Tests"
    
    # Test 1: PowerShell Memory Execution
    if (Test-Path "samples\fileless\memory_execution.ps1") {
        try {
            Write-Host "`nRunning PowerShell Memory Execution test..." -ForegroundColor Yellow
            $output = & powershell.exe -ExecutionPolicy Bypass -File "samples\fileless\memory_execution.ps1" 2>&1
            Write-TestResult "PS Memory Execution" "PASS" "Test completed"
        } catch {
            Write-TestResult "PS Memory Execution" "FAIL" $_.Exception.Message
        }
    } else {
        Write-TestResult "PS Memory Execution" "SKIP" "Script not found"
    }
    
    # Test 2: WMI Execution
    if (Test-Path "samples\fileless\wmi_execution.ps1") {
        try {
            Write-Host "`nRunning WMI Execution test..." -ForegroundColor Yellow
            $output = & powershell.exe -ExecutionPolicy Bypass -File "samples\fileless\wmi_execution.ps1" 2>&1
            Write-TestResult "WMI Execution" "PASS" "Test completed"
        } catch {
            Write-TestResult "WMI Execution" "FAIL" $_.Exception.Message
        }
    } else {
        Write-TestResult "WMI Execution" "SKIP" "Script not found"
    }
}

function Test-Shellcode {
    Write-TestHeader "Shellcode Injection Tests"
    
    if (Test-Path "samples\shellcode\shellcode_injection.exe") {
        try {
            Write-Host "`nRunning Shellcode Injection test..." -ForegroundColor Yellow
            $output = & "samples\shellcode\shellcode_injection.exe" 2>&1
            Write-TestResult "Shellcode Injection" "PASS" "Test completed"
        } catch {
            Write-TestResult "Shellcode Injection" "FAIL" $_.Exception.Message
        }
    } else {
        Write-TestResult "Shellcode Injection" "SKIP" "Executable not found"
    }
}

function Test-Combined {
    Write-TestHeader "Combined/Multi-Stage Tests"
    
    if (Test-Path "samples\combined\multi_stage_attack.exe") {
        try {
            Write-Host "`nRunning Multi-Stage Attack test..." -ForegroundColor Yellow
            $output = & "samples\combined\multi_stage_attack.exe" 2>&1
            Write-TestResult "Multi-Stage Attack" "PASS" "Test completed"
        } catch {
            Write-TestResult "Multi-Stage Attack" "FAIL" $_.Exception.Message
        }
    } else {
        Write-TestResult "Multi-Stage Attack" "SKIP" "Executable not found"
    }
}

function Show-Summary {
    Write-TestHeader "Test Summary"
    
    $total = $TestResults.Count
    $passed = ($TestResults | Where-Object { $_.Status -eq "PASS" }).Count
    $failed = ($TestResults | Where-Object { $_.Status -eq "FAIL" }).Count
    $skipped = ($TestResults | Where-Object { $_.Status -eq "SKIP" }).Count
    
    Write-Host "`nTotal Tests: $total" -ForegroundColor White
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Skipped: $skipped" -ForegroundColor Yellow
    
    Write-Host "`nDetailed Results:" -ForegroundColor Cyan
    foreach ($result in $TestResults) {
        $color = switch ($result.Status) {
            "PASS" { "Green" }
            "FAIL" { "Red" }
            "SKIP" { "Yellow" }
            default { "White" }
        }
        Write-Host "  [$($result.Status)] $($result.Name)" -ForegroundColor $color
    }
    
    Write-Host "`n`nLog file: $LogFile" -ForegroundColor Cyan
    Write-Host "Check your EDR console for detected activities!" -ForegroundColor Yellow
}

# Main execution
Write-Host @"
==============================================================
    EDR Testing Workflow
    Automated Test Suite Execution
==============================================================
WARNING: This will execute multiple potentially suspicious
         activities for EDR testing purposes.
         
         Use only in isolated test environments!
==============================================================
"@ -ForegroundColor Yellow

Write-Host "`nPress any key to continue or Ctrl+C to cancel..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Initialize log file
"EDR Test Results - $(Get-Date)" | Out-File -FilePath $LogFile

# Run tests
Test-Prerequisites

if (-not $BasicOnly) {
    Compile-CppSamples
}

Test-ProcessInjection
Test-Fileless
Test-Shellcode

if (-not $BasicOnly) {
    Test-Combined
}

Show-Summary

Write-Host "`n[+] All tests completed!" -ForegroundColor Green
Write-Host "Review $LogFile for detailed results." -ForegroundColor Cyan
