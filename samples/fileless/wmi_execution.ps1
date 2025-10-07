# WMI-based Fileless Execution Test - EDR Detection Test
#
# 목적: WMI(Windows Management Instrumentation)를 통한 파일리스 실행 테스트
# Purpose: Test EDR's ability to detect WMI-based fileless execution
#
# 탐지 포인트 (Detection Points):
# - WMI command execution
# - WMI event subscriptions
# - WMI process creation
# - Persistence via WMI
#
# WARNING: For testing purposes only in isolated environments

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "    EDR Test: WMI Fileless Technique" -ForegroundColor Cyan
Write-Host "    WARNING: For testing purposes only!" -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: WMI Process Creation
Write-Host "[1] Testing WMI Process Creation..." -ForegroundColor Green
Write-Host "    (Creating process via WMI instead of direct API)" -ForegroundColor Gray

try {
    $processStartup = (Get-WmiObject -Class Win32_ProcessStartup -List).CreateInstance()
    $processStartup.ShowWindow = 1
    
    Write-Host "    Command: notepad.exe" -ForegroundColor Gray
    Write-Host "    Method: Win32_Process.Create() via WMI" -ForegroundColor Gray
    
    # Create process via WMI
    $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList @(
        "notepad.exe",
        $null,
        $processStartup
    )
    
    if ($result.ReturnValue -eq 0) {
        Write-Host "    [+] Process created via WMI (PID: $($result.ProcessId))" -ForegroundColor Green
        Start-Sleep -Seconds 2
        
        # Terminate the process
        $process = Get-WmiObject Win32_Process -Filter "ProcessId = $($result.ProcessId)"
        if ($process) {
            $process.Terminate() | Out-Null
            Write-Host "    [+] Process terminated" -ForegroundColor Green
        }
    } else {
        Write-Host "    [-] Failed to create process (Return: $($result.ReturnValue))" -ForegroundColor Yellow
    }
    
    Write-Host "[+] WMI process creation demonstrated" -ForegroundColor Green
} catch {
    Write-Host "    [-] Error: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Test 2: WMI Command Execution
Write-Host "`n[2] Testing WMI Command Execution..." -ForegroundColor Green
Write-Host "    (Executing commands via WMI)" -ForegroundColor Gray

try {
    # Execute a simple command
    $command = "cmd.exe /c echo EDR_TEST > %TEMP%\wmi_test.txt && type %TEMP%\wmi_test.txt && del %TEMP%\wmi_test.txt"
    Write-Host "    Command: $command" -ForegroundColor Gray
    
    $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $command
    
    if ($result.ReturnValue -eq 0) {
        Write-Host "    [+] Command executed via WMI (PID: $($result.ProcessId))" -ForegroundColor Green
        Start-Sleep -Seconds 1
    }
    
    Write-Host "[+] WMI command execution demonstrated" -ForegroundColor Green
} catch {
    Write-Host "    [-] Error: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Test 3: WMI Event Consumer (Persistence Simulation)
Write-Host "`n[3] Testing WMI Event Consumer (Persistence Pattern)..." -ForegroundColor Green
Write-Host "    (Demonstrating WMI persistence technique)" -ForegroundColor Gray

Write-Host "    Typical persistence pattern:" -ForegroundColor Gray
Write-Host "      1. Create EventFilter (trigger condition)" -ForegroundColor DarkGray
Write-Host "      2. Create EventConsumer (action to take)" -ForegroundColor DarkGray
Write-Host "      3. Create FilterToConsumerBinding (link them)" -ForegroundColor DarkGray
Write-Host ""

# Check for existing suspicious WMI subscriptions
Write-Host "    Checking for WMI event subscriptions..." -ForegroundColor Gray
try {
    $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    $consumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
    
    Write-Host "    Current EventFilters: $($filters.Count)" -ForegroundColor Gray
    Write-Host "    Current CommandLineConsumers: $($consumers.Count)" -ForegroundColor Gray
    
    # Note: Not actually creating persistence to avoid issues
    Write-Host "    [*] Not creating actual persistence (test environment safety)" -ForegroundColor Yellow
    
    Write-Host "[+] WMI event consumer pattern demonstrated" -ForegroundColor Green
} catch {
    Write-Host "    [-] Limited permissions for WMI subscription access" -ForegroundColor Yellow
}

# Test 4: WMI Query Execution
Write-Host "`n[4] Testing WMI Information Gathering..." -ForegroundColor Green
Write-Host "    (Common reconnaissance technique)" -ForegroundColor Gray

try {
    Write-Host "    Querying system information via WMI..." -ForegroundColor Gray
    
    # System information
    $os = Get-WmiObject Win32_OperatingSystem
    Write-Host "    OS: $($os.Caption)" -ForegroundColor Gray
    
    # Running processes
    $processes = Get-WmiObject Win32_Process | Select-Object -First 5
    Write-Host "    Sample processes via WMI:" -ForegroundColor Gray
    $processes | ForEach-Object {
        Write-Host "      - $($_.Name) (PID: $($_.ProcessId))" -ForegroundColor DarkGray
    }
    
    # Security products detection attempt
    Write-Host "    [*] Checking for security products..." -ForegroundColor Gray
    $av = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue
    if ($av) {
        Write-Host "    [+] Found $($av.Count) AV product(s)" -ForegroundColor Gray
    }
    
    Write-Host "[+] WMI information gathering demonstrated" -ForegroundColor Green
} catch {
    Write-Host "    [-] Error: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Test 5: Remote WMI Execution (Lateral Movement Pattern)
Write-Host "`n[5] Remote WMI Execution Pattern..." -ForegroundColor Green
Write-Host "    (Lateral movement technique)" -ForegroundColor Gray

Write-Host "    Typical remote WMI pattern:" -ForegroundColor Gray
Write-Host "      Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create" -ForegroundColor DarkGray
Write-Host "    [*] Not executing remote connection (local test only)" -ForegroundColor Yellow
Write-Host "[+] Remote WMI pattern awareness demonstrated" -ForegroundColor Green

# Summary
Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "EDR Detection Points for WMI Fileless:" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  - WMI Win32_Process.Create() calls" -ForegroundColor White
Write-Host "  - WMI event filter creation" -ForegroundColor White
Write-Host "  - WMI event consumer creation" -ForegroundColor White
Write-Host "  - FilterToConsumerBinding associations" -ForegroundColor White
Write-Host "  - WMI query execution patterns" -ForegroundColor White
Write-Host "  - Remote WMI connections" -ForegroundColor White
Write-Host "  - WmiPrvSE.exe suspicious activity" -ForegroundColor White
Write-Host "  - Unusual WMI namespace access" -ForegroundColor White
Write-Host "  - WMI-based persistence mechanisms" -ForegroundColor White
Write-Host "`n[+] Test completed successfully!" -ForegroundColor Green
