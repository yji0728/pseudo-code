# EDR Testing Tools (EDR 탐지 성능 테스트 도구)

⚠️ **WARNING / 경고**: These tools are for legitimate EDR testing purposes only. Use only in controlled environments with proper authorization.
이 도구들은 합법적인 EDR 테스트 목적으로만 사용해야 합니다. 적절한 승인을 받은 통제된 환경에서만 사용하세요.

## 개요 (Overview)

이 저장소는 EDR(Endpoint Detection and Response) 솔루션의 탐지 성능을 테스트하기 위한 시뮬레이션 도구를 포함하고 있습니다.
다양한 악성코드 기법을 시뮬레이션하여 EDR의 탐지 능력을 평가할 수 있습니다.

This repository contains simulation tools for testing EDR (Endpoint Detection and Response) solutions.
Various malware techniques are simulated to evaluate EDR detection capabilities.

## 주요 기능 (Key Features)

### 1. 프로세스 인젝션 기법 (Process Injection Techniques)
- **Classic DLL Injection**: 원격 프로세스에 DLL을 주입
- **Process Hollowing**: 정상 프로세스를 생성하고 악성 코드로 교체
- **APC Injection**: Asynchronous Procedure Call을 이용한 코드 실행
- **Thread Hijacking**: 기존 스레드의 실행 흐름을 변경

### 2. 파일리스 기법 (Fileless Techniques)
- **PowerShell 기반**: 메모리 상에서만 실행되는 스크립트
- **WMI 활용**: Windows Management Instrumentation을 통한 실행
- **Registry 기반**: 레지스트리에 페이로드 저장 및 실행

### 3. 쉘코드 실행 (Shellcode Execution)
- **Direct Memory Execution**: 메모리에 쉘코드 직접 실행
- **VirtualAlloc + CreateThread**: 동적 메모리 할당 후 실행
- **ROP Chain**: Return-Oriented Programming 기법

### 4. 테스트 시나리오 (Test Scenarios)
- **Notepad.exe 실행**: 계산기나 메모장 실행을 통한 탐지 테스트
- **Calc.exe 실행**: 무해한 애플리케이션을 통한 기법 검증
- **Multi-Stage Attack**: 다단계 공격 시뮬레이션

## 디렉토리 구조 (Directory Structure)

```
pseudo-code/
├── samples/                    # 테스트 샘플 코드
│   ├── process_injection/     # 프로세스 인젝션 샘플
│   ├── fileless/              # 파일리스 기법 샘플
│   ├── shellcode/             # 쉘코드 인젝션 샘플
│   └── combined/              # 복합 기법 샘플
├── workflows/                  # 테스트 워크플로우
├── docs/                       # 문서
└── scripts/                    # 실행 스크립트
```

## 사용 방법 (Usage)

### 전제 조건 (Prerequisites)
- Windows 10/11 or Windows Server
- Visual Studio 2019 or later (C/C++ samples)
- PowerShell 5.1 or later
- Administrator privileges
- Isolated test environment

### 컴파일 (Compilation)
```bash
# C/C++ 샘플 컴파일
cd samples/process_injection
cl /EHsc /W4 dll_injection.cpp /Fe:dll_injection.exe

# PowerShell 샘플은 컴파일 불필요
```

### 실행 (Execution)
```bash
# 개별 테스트 실행
.\samples\process_injection\dll_injection.exe

# PowerShell 테스트
powershell -ExecutionPolicy Bypass -File .\samples\fileless\memory_execution.ps1

# 전체 워크플로우 실행
.\scripts\run_all_tests.ps1
```

## 테스트 워크플로우 (Test Workflows)

### 기본 워크플로우 (Basic Workflow)
1. Process Injection 테스트
2. Fileless 기법 테스트
3. Shellcode Injection 테스트
4. 결과 분석

### 고급 워크플로우 (Advanced Workflow)
1. Multi-stage attack simulation
2. Evasion techniques
3. Persistence mechanisms
4. Lateral movement simulation

## EDR 탐지 포인트 (EDR Detection Points)

각 테스트는 다음과 같은 EDR 탐지 기능을 검증합니다:
- Process Creation Monitoring
- Memory Allocation Detection
- API Call Monitoring
- Thread Creation Detection
- Registry Modification Monitoring
- Network Activity Monitoring
- Behavioral Analysis

## 보안 주의사항 (Security Notes)

1. **격리된 환경에서만 실행**: 프로덕션 시스템에서 절대 실행하지 마세요
2. **네트워크 격리**: 외부 네트워크와 연결되지 않은 환경에서 테스트
3. **백업**: 테스트 전 시스템 백업 필수
4. **권한 관리**: 필요한 최소 권한만 사용
5. **로깅**: 모든 테스트 활동을 로깅하여 추적 가능하도록 유지

## 법적 고지 (Legal Disclaimer)

이 도구들은 교육 및 합법적인 보안 테스트 목적으로만 제공됩니다. 
무단으로 시스템에 접근하거나 악의적인 목적으로 사용하는 것은 불법이며, 
사용자는 모든 관련 법률과 규정을 준수할 책임이 있습니다.

These tools are provided for educational and legitimate security testing purposes only.
Unauthorized access to systems or malicious use is illegal, and users are responsible 
for complying with all applicable laws and regulations.

## 참고 자료 (References)

- MITRE ATT&CK Framework
- Windows API Documentation
- EDR Bypass Techniques (Academic Research)
- OWASP Testing Guide

## 라이선스 (License)

This project is for educational and legitimate security testing purposes only.
Use at your own risk and responsibility.

## 기여 (Contributing)

Pull requests are welcome for:
- New testing techniques
- Improved documentation
- Bug fixes
- Performance improvements

## 연락처 (Contact)

For legitimate security research inquiries only.