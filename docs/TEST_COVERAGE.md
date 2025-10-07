# EDR Test Coverage Matrix
# EDR 테스트 범위 매트릭스

## 테스트 기법 전체 개요

이 문서는 제공된 모든 테스트 기법과 EDR이 탐지해야 하는 포인트를 정리합니다.

---

## 1. 프로세스 인젝션 (Process Injection) 테스트

### 1.1 DLL Injection (dll_injection.cpp)

| 항목 | 내용 |
|------|------|
| **파일** | `samples/process_injection/dll_injection.cpp` |
| **MITRE ATT&CK** | T1055.001 |
| **난이도** | Basic |
| **심각도** | High |

**탐지 포인트:**
```
✓ OpenProcess(PROCESS_ALL_ACCESS)
✓ VirtualAllocEx(target_process)
✓ WriteProcessMemory(target_process)
✓ CreateRemoteThread(LoadLibraryW)
```

**실행 방법:**
```bash
dll_injection.exe test
```

---

### 1.2 Process Hollowing (process_hollowing.cpp)

| 항목 | 내용 |
|------|------|
| **파일** | `samples/process_injection/process_hollowing.cpp` |
| **MITRE ATT&CK** | T1055.012 |
| **난이도** | Advanced |
| **심각도** | High |

**탐지 포인트:**
```
✓ CreateProcess(CREATE_SUSPENDED)
✓ NtUnmapViewOfSection()
✓ VirtualAllocEx() in suspended process
✓ WriteProcessMemory() to suspended
✓ SetThreadContext()
✓ ResumeThread()
```

**실행 방법:**
```bash
process_hollowing.exe
```

---

### 1.3 APC Injection (apc_injection.cpp)

| 항목 | 내용 |
|------|------|
| **파일** | `samples/process_injection/apc_injection.cpp` |
| **MITRE ATT&CK** | T1055.004 |
| **난이도** | Intermediate |
| **심각도** | High |

**탐지 포인트:**
```
✓ OpenProcess()
✓ OpenThread(THREAD_SET_CONTEXT)
✓ VirtualAllocEx(PAGE_EXECUTE_READWRITE)
✓ WriteProcessMemory() to executable region
✓ QueueUserAPC()
```

**실행 방법:**
```bash
apc_injection.exe
```

---

## 2. 파일리스 기법 (Fileless) 테스트

### 2.1 PowerShell Memory Execution (memory_execution.ps1)

| 항목 | 내용 |
|------|------|
| **파일** | `samples/fileless/memory_execution.ps1` |
| **MITRE ATT&CK** | T1059.001 |
| **난이도** | Intermediate |
| **심각도** | High |

**탐지 포인트:**
```
✓ Base64 encoded commands
✓ Invoke-Expression (IEX)
✓ Add-Type (in-memory compilation)
✓ Reflection-based assembly loading
✓ Script Block Logging events
✓ AMSI detections
```

**실행 방법:**
```powershell
powershell -ExecutionPolicy Bypass -File memory_execution.ps1
```

---

### 2.2 WMI Execution (wmi_execution.ps1)

| 항목 | 내용 |
|------|------|
| **파일** | `samples/fileless/wmi_execution.ps1` |
| **MITRE ATT&CK** | T1047 |
| **난이도** | Intermediate |
| **심각도** | Medium-High |

**탐지 포인트:**
```
✓ Win32_Process.Create()
✓ WMI Event Filter creation
✓ WMI Event Consumer creation
✓ FilterToConsumerBinding
✓ WmiPrvSE.exe suspicious activity
✓ Remote WMI connections
```

**실행 방법:**
```powershell
powershell -ExecutionPolicy Bypass -File wmi_execution.ps1
```

---

## 3. 쉘코드 인젝션 (Shellcode) 테스트

### 3.1 Shellcode Injection (shellcode_injection.cpp)

| 항목 | 내용 |
|------|------|
| **파일** | `samples/shellcode/shellcode_injection.cpp` |
| **MITRE ATT&CK** | T1055 |
| **난이도** | Intermediate |
| **심각도** | High |

**탐지 포인트:**
```
✓ VirtualAlloc(PAGE_EXECUTE_READWRITE)
✓ Memory with RWX permissions
✓ VirtualProtect() to RX
✓ CreateThread() on non-image memory
✓ Shellcode pattern detection
✓ Memory scanning
```

**실행 방법:**
```bash
shellcode_injection.exe
```

---

## 4. 복합 공격 (Combined) 테스트

### 4.1 Multi-Stage Attack (multi_stage_attack.cpp)

| 항목 | 내용 |
|------|------|
| **파일** | `samples/combined/multi_stage_attack.cpp` |
| **MITRE ATT&CK** | Multiple (T1055, T1082, T1518.001) |
| **난이도** | Advanced |
| **심각도** | Critical |

**공격 단계:**
```
Stage 1: Reconnaissance
  ✓ Process enumeration
  ✓ Security product detection
  ✓ System information gathering

Stage 2: Preparation
  ✓ Memory allocation
  ✓ Protection change (RW -> RX)
  ✓ Obfuscation simulation

Stage 3: Injection
  ✓ Process creation (suspended)
  ✓ Injection simulation
  ✓ Thread resumption

Stage 4: Execution
  ✓ Final payload (calc.exe)
  ✓ Process correlation

Stage 5: Evasion
  ✓ Anti-analysis techniques
  ✓ Timing manipulation
```

**실행 방법:**
```bash
multi_stage_attack.exe
```

---

## 테스트 워크플로우

### Automated Test (automated_test.ps1)

**기능:**
- 모든 테스트 자동 실행
- 결과 로깅
- 통계 수집

**사용법:**
```powershell
.\workflows\automated_test.ps1
```

**옵션:**
```powershell
# 기본 테스트만
.\workflows\automated_test.ps1 -BasicOnly

# 컴파일 스킵
.\workflows\automated_test.ps1 -SkipCompilation
```

---

### Advanced Test (advanced_test.ps1)

**기능:**
- 단계별 상세 실행
- HTML 리포트 생성
- 성능 메트릭 수집
- EDR 벤더별 커스터마이징

**사용법:**
```powershell
# 전체 테스트 + HTML 리포트
.\workflows\advanced_test.ps1 -TestLevel Full -GenerateReport

# 특정 EDR 벤더 테스트
.\workflows\advanced_test.ps1 -EDRVendor "CrowdStrike" -GenerateReport

# 중급 테스트만
.\workflows\advanced_test.ps1 -TestLevel Intermediate
```

---

## EDR 평가 체크리스트

### 필수 탐지 항목 (Must Detect)

#### High Priority
- [x] Process Injection API sequences
- [x] Suspended process creation
- [x] Remote thread creation
- [x] RWX memory allocation
- [x] PowerShell encoded commands
- [x] WMI process creation

#### Medium Priority
- [x] Process enumeration
- [x] Memory protection changes
- [x] Script block logging
- [x] WMI event subscriptions
- [x] Unusual parent-child relationships

#### Advanced Features
- [x] Attack chain correlation
- [x] Behavioral analysis
- [x] Memory scanning
- [x] Anomaly detection
- [x] Automated response

---

## 성능 평가 기준

### 탐지 성능

| 등급 | 탐지율 | 설명 |
|------|-------|------|
| **우수** | 95-100% | 거의 모든 기법 탐지 |
| **양호** | 80-94% | 주요 기법 탐지 |
| **보통** | 60-79% | 기본 기법 탐지 |
| **미흡** | < 60% | 많은 기법 누락 |

### 반응 속도

| 등급 | 시간 | 설명 |
|------|------|------|
| **우수** | < 1초 | 실시간 탐지 |
| **양호** | 1-5초 | 준실시간 탐지 |
| **보통** | 5-10초 | 지연된 탐지 |
| **미흡** | > 10초 | 느린 탐지 |

### False Positive

| 등급 | 비율 | 설명 |
|------|------|------|
| **우수** | < 1% | 거의 없음 |
| **양호** | 1-5% | 허용 가능 |
| **보통** | 5-10% | 관리 필요 |
| **미흡** | > 10% | 심각한 수준 |

---

## 빠른 테스트 시나리오

### 시나리오 A: 5분 Quick Test
```powershell
# 1. DLL Injection
.\samples\process_injection\dll_injection.exe test

# 2. PowerShell Fileless
.\samples\fileless\memory_execution.ps1
```

### 시나리오 B: 15분 Standard Test
```powershell
# 자동화 워크플로우 실행
.\workflows\automated_test.ps1 -BasicOnly
```

### 시나리오 C: 30분 Comprehensive Test
```powershell
# 전체 테스트 + 리포트
.\workflows\advanced_test.ps1 -TestLevel Full -GenerateReport
```

---

## MITRE ATT&CK 매핑

| 테스트 | 기법 ID | 기법 이름 |
|--------|---------|----------|
| DLL Injection | T1055.001 | Process Injection: DLL Injection |
| Process Hollowing | T1055.012 | Process Injection: Process Hollowing |
| APC Injection | T1055.004 | Process Injection: Asynchronous Procedure Call |
| PowerShell | T1059.001 | Command and Scripting Interpreter: PowerShell |
| WMI | T1047 | Windows Management Instrumentation |
| Shellcode | T1055 | Process Injection |
| Reconnaissance | T1082 | System Information Discovery |
| Security Product Discovery | T1518.001 | Software Discovery: Security Software |

---

## 문제 해결 가이드

### 컴파일 문제
```powershell
# Visual Studio 환경 설정
.\scripts\build.ps1

# 수동 컴파일
cl /EHsc /W4 sample.cpp
```

### 권한 문제
```powershell
# 관리자로 PowerShell 실행
# 실행 정책 변경
Set-ExecutionPolicy Bypass -Scope Process
```

### EDR이 테스트를 차단하는 경우
1. EDR을 일시적으로 학습 모드로 전환
2. 테스트 디렉토리를 예외 처리
3. 격리된 VM 환경 사용

---

## 결과 분석 팁

1. **EDR 콘솔 확인**
   - Alert 개수와 심각도
   - 탐지 시간
   - 제공되는 컨텍스트 정보

2. **로그 분석**
   - Windows Event Logs
   - PowerShell Logs
   - Sysmon Logs (있는 경우)

3. **행위 분석**
   - Attack chain reconstruction
   - Parent-child process relationship
   - Timeline analysis

4. **성능 평가**
   - 시스템 리소스 사용량
   - 탐지 지연 시간
   - False positive 비율

---

## 추가 리소스

- **문서**: `docs/detection_guide.md`
- **빠른 시작**: `docs/QUICKSTART.md`
- **MITRE ATT&CK**: https://attack.mitre.org/
- **Atomic Red Team**: https://github.com/redcanaryco/atomic-red-team

---

**마지막 업데이트**: 2024
**버전**: 1.0
