# Fileless Technique Samples

이 디렉토리는 파일리스(Fileless) 악성코드 기법을 포함합니다.

## 샘플 목록

### 1. memory_execution.ps1
**기법:** PowerShell Memory-Only Execution
**설명:** 디스크에 파일을 쓰지 않고 메모리에서만 실행

**주요 기법:**
- Base64 인코딩된 명령 실행
- `Invoke-Expression (IEX)` 사용
- `Add-Type` - 메모리 내 .NET 컴파일
- Reflection 기반 어셈블리 로딩
- Download-Execute 패턴 (시뮬레이션)

**사용법:**
```powershell
powershell -ExecutionPolicy Bypass -File memory_execution.ps1
```

**MITRE ATT&CK:** T1059.001

---

### 2. wmi_execution.ps1
**기법:** WMI-based Execution
**설명:** WMI를 통한 파일리스 실행 및 지속성

**주요 기법:**
- `Win32_Process.Create()` - WMI를 통한 프로세스 생성
- WMI Event Filter 생성
- WMI Event Consumer 생성
- FilterToConsumerBinding - 지속성 메커니즘
- 원격 WMI 실행 패턴

**사용법:**
```powershell
powershell -ExecutionPolicy Bypass -File wmi_execution.ps1
```

**MITRE ATT&CK:** T1047

---

## 실행 방법

### 개별 실행
```powershell
# PowerShell 메모리 실행 테스트
.\memory_execution.ps1

# WMI 실행 테스트
.\wmi_execution.ps1
```

### 전체 실행
```powershell
Get-ChildItem *.ps1 | ForEach-Object {
    Write-Host "Running $($_.Name)..." -ForegroundColor Yellow
    & $_.FullName
}
```

## EDR 탐지 포인트

EDR 솔루션은 다음을 탐지해야 합니다:

### PowerShell 관련
- ✅ `powershell.exe` 실행 모니터링
- ✅ `-EncodedCommand` 파라미터 사용
- ✅ Script Block Logging 이벤트
- ✅ `Invoke-Expression (IEX)` 호출
- ✅ `Add-Type` 및 메모리 내 컴파일
- ✅ `Reflection.Assembly::Load()` 호출
- ✅ AMSI (Antimalware Scan Interface) 통합
- ✅ 서명되지 않은 스크립트 실행

### WMI 관련
- ✅ `Win32_Process.Create()` 호출
- ✅ WMI Event Filter 생성
- ✅ WMI Event Consumer 생성
- ✅ FilterToConsumerBinding 생성
- ✅ `WmiPrvSE.exe` 비정상 활동
- ✅ 원격 WMI 연결
- ✅ WMI 기반 지속성 메커니즘

## 로깅 활성화

EDR 테스트를 위해 PowerShell 로깅 활성화 권장:

```powershell
# Script Block Logging 활성화 (관리자 권한 필요)
$regPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1

# Module Logging 활성화
$regPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1
```

## 이벤트 로그 확인

```powershell
# PowerShell 스크립트 블록 로그 확인
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} -MaxEvents 10

# WMI 활동 로그 확인
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WMI-Activity/Operational'
} -MaxEvents 10
```

## 안전성 참고사항

- 모든 샘플은 무해한 작업만 수행합니다
- 실제 악성 페이로드를 다운로드하거나 실행하지 않습니다
- 주로 계산기(calc.exe) 또는 메모장(notepad.exe)을 실행합니다
- 지속성 메커니즘은 실제로 생성하지 않고 패턴만 시뮬레이션합니다
