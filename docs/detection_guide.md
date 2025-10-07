# EDR 탐지 기법 가이드 (EDR Detection Techniques Guide)

## 목차 (Table of Contents)

1. [개요](#개요)
2. [탐지 포인트](#탐지-포인트)
3. [테스트 시나리오](#테스트-시나리오)
4. [기대되는 EDR 행동](#기대되는-edr-행동)
5. [결과 분석](#결과-분석)

---

## 개요

이 문서는 EDR 솔루션이 탐지해야 하는 주요 악성 행위 패턴과 기법들을 설명합니다.

### EDR이 탐지해야 하는 핵심 영역

1. **프로세스 활동 모니터링**
2. **메모리 조작 탐지**
3. **네트워크 활동 분석**
4. **파일 시스템 변경 추적**
5. **레지스트리 수정 감시**
6. **행위 기반 분석**

---

## 탐지 포인트

### 1. 프로세스 인젝션 (Process Injection)

#### DLL Injection
**탐지 포인트:**
- `OpenProcess()` with `PROCESS_ALL_ACCESS` or suspicious permissions
- `VirtualAllocEx()` 호출
- `WriteProcessMemory()` to remote process
- `CreateRemoteThread()` 호출
- Thread creation pointing to `LoadLibrary`

**MITRE ATT&CK:** T1055.001

**심각도:** High

**예상 로그:**
```
[ALERT] Suspicious API sequence detected
Process: test_program.exe (PID: 1234)
- OpenProcess(target_process, PROCESS_ALL_ACCESS)
- VirtualAllocEx(target_process, ...)
- WriteProcessMemory(target_process, ...)
- CreateRemoteThread(target_process, LoadLibraryW, ...)
```

#### Process Hollowing
**탐지 포인트:**
- `CreateProcess()` with `CREATE_SUSPENDED` flag
- `NtUnmapViewOfSection()` 호출
- `VirtualAllocEx()` in suspended process
- `WriteProcessMemory()` to suspended process
- `SetThreadContext()` 호출
- `ResumeThread()` 호출

**MITRE ATT&CK:** T1055.012

**심각도:** High

**예상 로그:**
```
[ALERT] Process Hollowing detected
Parent: suspicious.exe (PID: 1234)
Child: notepad.exe (PID: 5678) - SUSPENDED
- Image unmapped via NtUnmapViewOfSection
- New memory allocated and written
- Entry point modified
- Process resumed
```

#### APC Injection
**탐지 포인트:**
- `OpenThread()` 호출
- `VirtualAllocEx()` with `PAGE_EXECUTE_READWRITE`
- `WriteProcessMemory()` to executable memory
- `QueueUserAPC()` 호출
- APC queue에 비정상적인 항목

**MITRE ATT&CK:** T1055.004

**심각도:** High

---

### 2. 파일리스 기법 (Fileless Techniques)

#### PowerShell 기반 공격
**탐지 포인트:**
- PowerShell 실행 with `-EncodedCommand`
- `Invoke-Expression (IEX)` 사용
- `Add-Type` for in-memory compilation
- `Reflection.Assembly::Load()` 호출
- 스크립트 블록 로깅 이벤트
- AMSI 스캔 결과

**MITRE ATT&CK:** T1059.001

**심각도:** Medium to High

**예상 로그:**
```
[ALERT] Suspicious PowerShell activity
Process: powershell.exe (PID: 1234)
- Encoded command execution detected
- Script Block Logging: Invoke-Expression called
- AMSI: Potentially malicious content detected
```

#### WMI 기반 실행
**탐지 포인트:**
- `Win32_Process.Create()` 호출
- WMI Event Filter 생성
- WMI Event Consumer 생성
- `FilterToConsumerBinding` 생성
- `WmiPrvSE.exe` 비정상 활동

**MITRE ATT&CK:** T1047

**심각도:** Medium to High

---

### 3. 쉘코드 인젝션 (Shellcode Injection)

**탐지 포인트:**
- `VirtualAlloc()` with `PAGE_EXECUTE_READWRITE`
- Memory region with RWX permissions
- `VirtualProtect()` changing to executable
- `CreateThread()` pointing to heap memory
- Shellcode 패턴 signature
- 비-이미지 메모리에서의 실행

**MITRE ATT&CK:** T1055

**심각도:** High

**예상 로그:**
```
[ALERT] Shellcode execution detected
Process: malware.exe (PID: 1234)
- VirtualAlloc with PAGE_EXECUTE_READWRITE
- Suspicious instruction pattern in allocated memory
- Thread created pointing to heap address 0x12340000
```

---

### 4. 지속성 메커니즘 (Persistence Mechanisms)

**탐지 포인트:**
- 레지스트리 Run 키 수정
- Scheduled Task 생성
- WMI Event Subscription
- Service 생성
- Startup folder 수정

**MITRE ATT&CK:** T1547, T1053, T1543

**심각도:** Medium to High

---

## 테스트 시나리오

### 시나리오 1: 기본 프로세스 인젝션

**단계:**
1. 대상 프로세스 식별
2. 프로세스 핸들 획득
3. 메모리 할당
4. 페이로드 작성
5. 원격 스레드 생성

**예상 탐지:**
- 각 API 호출에서 alert
- 전체 공격 체인 correlation
- High severity alert

### 시나리오 2: 파일리스 공격

**단계:**
1. PowerShell 실행
2. 인코딩된 명령 실행
3. 메모리 상에서 .NET 어셈블리 로드
4. Reflection을 통한 실행

**예상 탐지:**
- PowerShell 스크립트 블록 로깅
- AMSI 탐지
- 비정상적인 .NET 로딩 패턴

### 시나리오 3: 다단계 공격

**단계:**
1. 정찰 (프로세스 열거)
2. 환경 확인 (보안 제품 탐지)
3. 페이로드 준비 (메모리 할당)
4. 인젝션 수행
5. 최종 페이로드 실행

**예상 탐지:**
- 각 단계별 개별 alert
- 행위 기반 correlation
- Attack chain reconstruction

---

## 기대되는 EDR 행동

### 1. 실시간 탐지 (Real-time Detection)

**우수한 EDR의 특징:**
- 의심스러운 API 호출 즉시 탐지
- 행위 패턴 실시간 분석
- 자동 차단 또는 격리 기능

### 2. 행위 분석 (Behavioral Analysis)

**평가 기준:**
- 개별 이벤트 탐지
- 이벤트 간 correlation
- Attack chain 재구성
- False positive 비율

### 3. 메모리 스캐닝 (Memory Scanning)

**평가 항목:**
- RWX 메모리 영역 탐지
- 쉘코드 시그니처 인식
- 메모리 내 악성 패턴 탐지

### 4. 로깅 및 리포팅 (Logging and Reporting)

**필수 정보:**
- Timestamp
- Process tree
- API sequence
- Memory operations
- Network connections
- File system changes

---

## 결과 분석

### 평가 매트릭스

| 테스트 항목 | 탐지 여부 | 탐지 시간 | False Positive | 심각도 평가 | 대응 조치 |
|-----------|---------|---------|---------------|-----------|---------|
| DLL Injection | Y/N | < 1초 | Y/N | High/Med/Low | Block/Alert |
| Process Hollowing | Y/N | < 1초 | Y/N | High/Med/Low | Block/Alert |
| APC Injection | Y/N | < 1초 | Y/N | High/Med/Low | Block/Alert |
| PS Memory Exec | Y/N | < 1초 | Y/N | High/Med/Low | Block/Alert |
| WMI Execution | Y/N | < 1초 | Y/N | High/Med/Low | Block/Alert |
| Shellcode Inject | Y/N | < 1초 | Y/N | High/Med/Low | Block/Alert |

### 점수 체계

**탐지 능력 (Detection Capability):**
- 100점: 모든 테스트 탐지
- 80-99점: 대부분 탐지, 일부 누락
- 60-79점: 주요 기법 탐지, 고급 기법 누락
- 60점 미만: 기본적인 탐지 능력 부족

**반응 속도 (Response Time):**
- Excellent: < 1초
- Good: 1-5초
- Acceptable: 5-10초
- Poor: > 10초

**False Positive Rate:**
- Excellent: < 1%
- Good: 1-5%
- Acceptable: 5-10%
- Poor: > 10%

---

## 권장 테스트 순서

1. **기본 테스트** (1단계)
   - DLL Injection
   - Simple shellcode execution
   - PowerShell basic test

2. **중급 테스트** (2단계)
   - Process Hollowing
   - APC Injection
   - WMI execution

3. **고급 테스트** (3단계)
   - Multi-stage attacks
   - Evasion techniques
   - Combined techniques

4. **스트레스 테스트** (4단계)
   - Multiple simultaneous attacks
   - Rapid-fire techniques
   - Resource exhaustion tests

---

## EDR 벤더 비교 시 고려사항

1. **탐지 범위:** 얼마나 많은 기법을 탐지하는가?
2. **탐지 속도:** 얼마나 빠르게 탐지하는가?
3. **정확도:** False positive/negative 비율
4. **가시성:** 얼마나 상세한 정보를 제공하는가?
5. **대응 능력:** 자동 차단/격리 기능
6. **성능 영향:** 시스템 리소스 사용량
7. **관리 편의성:** 콘솔 사용성, 리포팅

---

## 추가 참고 자료

- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **Atomic Red Team:** https://github.com/redcanaryco/atomic-red-team
- **Windows API Documentation:** https://docs.microsoft.com/en-us/windows/win32/api/

---

## 면책 조항

이 도구와 문서는 합법적인 보안 테스트 목적으로만 제공됩니다.
무단으로 시스템에 접근하거나 악의적인 목적으로 사용하는 것은 불법입니다.
