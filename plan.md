# 코드 작동 신뢰성 검토

이 리포지토리는 EDR(Endpoint Detection and Response) 솔루션을 테스트하기 위한 시뮬레이션 도구입니다. 전반적으로 교육 및 테스트 목적으로는 적합하나, 몇 가지 신뢰성 문제가 발견되었습니다.

## 주요 신뢰성 문제

### 1. 리소스 관리 문제

**C++ 코드의 불완전한 리소스 정리:**

`dll_injection.cpp`에서는 에러 발생 시 일부 리소스가 제대로 해제되지 않는 경로가 있습니다. [1](#0-0) 

`process_hollowing.cpp`에서도 에러 상황에서 프로세스 핸들이 제대로 정리되지 않을 수 있습니다. [2](#0-1) 

**긍정적인 점:** `apc_injection.cpp`는 에러 경로에서도 리소스 정리를 비교적 잘 수행합니다. [3](#0-2) 

### 2. 하드코딩된 경로의 신뢰성 문제

여러 파일에서 Windows 시스템 경로가 하드코딩되어 있어 다른 시스템 구성에서 실패할 수 있습니다:

- `process_hollowing.cpp`의 calc.exe 경로 [4](#0-3) 
- `dll_injection.cpp`의 notepad.exe 경로 [5](#0-4) 
- `shellcode_injection.cpp`의 calc.exe 경로 [6](#0-5) 

### 3. 에러 처리의 불일치

**C++ 코드:** 일부 함수는 false를 반환하지만, 호출자가 이를 적절히 처리하지 않는 경우가 있습니다. `FindProcessId` 함수는 0을 반환하여 실패를 나타내지만 [7](#0-6) , 반환값 검증은 있으나 추가적인 에러 로깅이 부족합니다.

**PowerShell 스크립트:** 에러 처리가 더 견고합니다. Try-catch 블록을 적절히 사용하고 있습니다. [8](#0-7) 

### 4. 동기화 및 타이밍 문제

프로세스 생성 후 고정된 Sleep 시간에 의존하는 코드가 있어 시스템 부하에 따라 신뢰성 문제가 발생할 수 있습니다: [9](#0-8) [10](#0-9) 

### 5. 입력 검증 부족

`dll_injection.cpp`의 main 함수에서는 인자 검증을 수행하지만 [11](#0-10) , DLL 경로의 유효성 검증은 없습니다. [12](#0-11) 

## 긍정적인 측면

### 1. 안전한 테스트 모드 구현

`dll_injection.cpp`는 실제 인젝션 대신 시뮬레이션을 수행하는 테스트 모드를 제공합니다. [13](#0-12) 

### 2. 포괄적인 문서화

각 C++ 파일은 목적과 탐지 포인트를 명확히 문서화하고 있습니다. [14](#0-13) 

### 3. 체계적인 테스트 자동화

워크플로우 스크립트는 전제 조건 검증을 수행합니다. [15](#0-14) 

빌드 스크립트는 Visual Studio 환경을 자동으로 감지하고 설정합니다. [16](#0-15) 

### 4. 상세한 로깅 및 리포팅

고급 테스트 워크플로우는 HTML 리포트 생성 기능을 제공합니다. [17](#0-16) 

## 권장 사항

### 즉시 개선이 필요한 사항:

1. **RAII 패턴 적용**: C++ 코드에서 스마트 포인터나 RAII 래퍼를 사용하여 자동 리소스 관리를 구현해야 합니다.

2. **경로 검증 추가**: 하드코딩된 경로를 환경 변수나 설정 파일로 이동하고, 파일 존재 여부를 확인해야 합니다.

3. **타임아웃 메커니즘**: `WaitForSingleObject`에 무한 대기 대신 타임아웃을 설정해야 합니다. [18](#0-17) 

4. **에러 로깅 강화**: 모든 Win32 API 실패 시 `GetLastError()`로 얻은 에러 코드를 명확히 로깅해야 합니다.

5. **입력 검증**: DLL 경로, 프로세스 이름 등 모든 외부 입력의 유효성을 검증해야 합니다.

### 장기적 개선 사항:

1. **단위 테스트 추가**: 개별 함수에 대한 단위 테스트를 작성하여 신뢰성을 검증해야 합니다.

2. **예외 안전성**: C++ 코드에서 예외가 발생해도 리소스가 누수되지 않도록 보장해야 합니다.

3. **동기화 개선**: 프로세스 상태 확인을 위해 고정 Sleep 대신 적절한 대기 메커니즘을 사용해야 합니다.

## Notes

이 코드베이스는 **교육 및 합법적인 EDR 테스트 목적**으로는 적합하지만, 프로덕션 수준의 신뢰성을 갖추지는 못했습니다. 주요 문제는:

- C++ 코드의 리소스 관리가 불완전함
- 에러 처리가 일관되지 않음
- 시스템 환경에 대한 가정이 많음
- 타이밍 및 동기화 이슈 존재

그러나 PowerShell 스크립트는 상대적으로 견고하며, 테스트 모드와 안전장치가 잘 구현되어 있습니다. 위의 권장 사항을 적용하면 신뢰성을 크게 향상시킬 수 있을 것입니다.

**중요**: 이 도구는 격리된 테스트 환경에서만 사용해야 하며, 적절한 승인을 받은 후에만 실행해야 합니다. [19](#0-18)

### Citations

**File:** samples/process_injection/dll_injection.cpp (L1-14)
```cpp
/*
 * DLL Injection Test - EDR Detection Test
 * 
 * 목적: 원격 프로세스에 DLL을 주입하여 EDR의 프로세스 인젝션 탐지 능력을 테스트
 * Purpose: Test EDR's ability to detect DLL injection into remote processes
 * 
 * 탐지 포인트 (Detection Points):
 * - OpenProcess with PROCESS_ALL_ACCESS
 * - VirtualAllocEx for memory allocation in target process
 * - WriteProcessMemory to write DLL path
 * - CreateRemoteThread to execute LoadLibrary
 * 
 * WARNING: For testing purposes only in isolated environments
 */
```

**File:** samples/process_injection/dll_injection.cpp (L22-42)
```cpp
DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (processName == processEntry.szExeFile) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}
```

**File:** samples/process_injection/dll_injection.cpp (L90-98)
```cpp
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    
    if (!pLoadLibraryW) {
        std::wcerr << L"[-] Failed to get LoadLibraryW address" << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
```

**File:** samples/process_injection/dll_injection.cpp (L118-118)
```cpp
    WaitForSingleObject(hThread, INFINITE);
```

**File:** samples/process_injection/dll_injection.cpp (L137-144)
```cpp
    if (argc < 2) {
        std::wcout << L"Usage: " << argv[0] << L" <target_process_name> [dll_path]" << std::endl;
        std::wcout << L"Example: " << argv[0] << L" notepad.exe C:\\test\\payload.dll" << std::endl;
        std::wcout << std::endl;
        std::wcout << L"For basic test (spawns notepad.exe):" << std::endl;
        std::wcout << L"  " << argv[0] << L" test" << std::endl;
        return 1;
    }
```

**File:** samples/process_injection/dll_injection.cpp (L148-179)
```cpp
    // Test mode: spawn notepad and simulate injection behavior
    if (targetProcess == L"test") {
        std::wcout << L"[*] Running in test mode..." << std::endl;
        std::wcout << L"[*] Spawning notepad.exe..." << std::endl;
        
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        
        if (CreateProcessW(
            L"C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            
            std::wcout << L"[+] Notepad spawned with PID: " << pi.dwProcessId << std::endl;
            std::wcout << L"[*] Simulating injection steps (API calls that EDR should detect):" << std::endl;
            
            // Demonstrate the API calls that EDR should monitor
            std::wcout << L"    1. OpenProcess(PROCESS_ALL_ACCESS)" << std::endl;
            std::wcout << L"    2. VirtualAllocEx(MEM_COMMIT | MEM_RESERVE)" << std::endl;
            std::wcout << L"    3. WriteProcessMemory()" << std::endl;
            std::wcout << L"    4. CreateRemoteThread(LoadLibrary)" << std::endl;
            
            Sleep(2000);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            
            std::wcout << L"[+] Test completed. EDR should log these activities." << std::endl;
        } else {
            std::wcerr << L"[-] Failed to spawn notepad.exe" << std::endl;
        }
        return 0;
    }
```

**File:** samples/process_injection/dll_injection.cpp (L188-194)
```cpp
    std::wstring dllPath;
    if (argc >= 3) {
        dllPath = argv[2];
    } else {
        std::wcerr << L"[-] DLL path required for injection" << std::endl;
        return 1;
    }
```

**File:** samples/process_injection/process_hollowing.cpp (L41-41)
```cpp
    wchar_t targetPath[] = L"C:\\Windows\\System32\\calc.exe";
```

**File:** samples/process_injection/process_hollowing.cpp (L67-73)
```cpp
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::wcerr << L"[-] Failed to get thread context" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }
```

**File:** samples/process_injection/apc_injection.cpp (L69-69)
```cpp
    Sleep(1000); // Let process initialize
```

**File:** samples/process_injection/apc_injection.cpp (L117-123)
```cpp
    if (!pRemoteMemory) {
        std::wcerr << L"[-] Failed to allocate memory" << std::endl;
        CloseHandle(hThread);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
```

**File:** samples/shellcode/shellcode_injection.cpp (L138-140)
```cpp
    if (CreateProcessW(
        L"C:\\Windows\\System32\\calc.exe",
        NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
```

**File:** samples/shellcode/shellcode_injection.cpp (L145-145)
```cpp
        Sleep(2000);
```

**File:** samples/fileless/wmi_execution.ps1 (L24-55)
```text
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
```

**File:** workflows/automated_test.ps1 (L57-98)
```text
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
```

**File:** scripts/build.ps1 (L16-53)
```text
# Check for Visual Studio environment
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    Write-Host "[*] Detecting Visual Studio installation..." -ForegroundColor Yellow
    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    
    if ($vsPath) {
        Write-Host "[+] Visual Studio found at: $vsPath" -ForegroundColor Green
        
        # Find vcvarsall.bat
        $vcvarsall = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
        if (Test-Path $vcvarsall) {
            Write-Host "[+] Setting up Visual Studio environment..." -ForegroundColor Green
            
            # Setup VS environment in this session
            $tempFile = [System.IO.Path]::GetTempFileName()
            cmd /c "`"$vcvarsall`" x64 && set" > $tempFile
            Get-Content $tempFile | ForEach-Object {
                if ($_ -match "^(.*?)=(.*)$") {
                    Set-Content "env:\$($matches[1])" $matches[2]
                }
            }
            Remove-Item $tempFile
        }
    } else {
        Write-Host "[-] Visual Studio not found. Please install Visual Studio with C++ tools." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[*] Checking if cl.exe is in PATH..." -ForegroundColor Yellow
    $clExists = Get-Command cl.exe -ErrorAction SilentlyContinue
    if (-not $clExists) {
        Write-Host "[-] cl.exe not found. Please run this from a Visual Studio Developer Command Prompt" -ForegroundColor Red
        Write-Host "    or install Visual Studio with C++ tools." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Compiler found in PATH" -ForegroundColor Green
}
```

**File:** workflows/advanced_test.ps1 (L216-313)
```text
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
```

**File:** README.md (L3-4)
```markdown
⚠️ **WARNING / 경고**: These tools are for legitimate EDR testing purposes only. Use only in controlled environments with proper authorization.
이 도구들은 합법적인 EDR 테스트 목적으로만 사용해야 합니다. 적절한 승인을 받은 통제된 환경에서만 사용하세요.
```
