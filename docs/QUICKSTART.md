# EDR Testing Tools - Quick Start Guide
# 빠른 시작 가이드

## 🎯 목적 (Purpose)

이 도구는 EDR(Endpoint Detection and Response) 솔루션의 탐지 성능을 테스트하기 위한 것입니다.
다양한 악성코드 기법을 안전하게 시뮬레이션하여 EDR의 효과를 검증할 수 있습니다.

## ⚠️ 경고 (WARNING)

**반드시 격리된 테스트 환경에서만 실행하세요!**
- 프로덕션 시스템에서 실행 금지
- 네트워크 격리 환경 권장
- 승인된 테스트 환경에서만 사용

## 📋 전제 조건 (Prerequisites)

### 필수 요구사항
1. **Windows 10/11 or Windows Server 2016+**
2. **관리자 권한 (Administrator privileges)**
3. **Visual Studio 2019 or later** (C++ 빌드용)
   - 또는 Visual Studio Build Tools
   - C++ 데스크톱 개발 워크로드 필요
4. **PowerShell 5.1 or later**

### 선택 사항
- EDR 솔루션 설치됨 (테스트 대상)
- 격리된 VM 환경

## 🚀 빠른 시작 (Quick Start)

### 1단계: 저장소 클론

```powershell
git clone https://github.com/yji0728/pseudo-code.git
cd pseudo-code
```

### 2단계: 빌드

**Option A: Visual Studio Developer Command Prompt 사용**
```cmd
# Visual Studio Developer Command Prompt 실행
cd pseudo-code
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

**Option B: 일반 PowerShell (자동 VS 환경 설정)**
```powershell
# 관리자 권한으로 PowerShell 실행
Set-ExecutionPolicy Bypass -Scope Process
.\scripts\build.ps1
```

### 3단계: 테스트 실행

**전체 자동화 테스트:**
```powershell
.\workflows\automated_test.ps1
```

**개별 테스트 실행:**
```powershell
# Process Injection 테스트
.\samples\process_injection\dll_injection.exe test

# Fileless 테스트
powershell -ExecutionPolicy Bypass -File .\samples\fileless\memory_execution.ps1

# Shellcode 테스트
.\samples\shellcode\shellcode_injection.exe

# Multi-stage 테스트
.\samples\combined\multi_stage_attack.exe
```

## 📂 프로젝트 구조

```
pseudo-code/
├── samples/                          # 테스트 샘플 코드
│   ├── process_injection/           # 프로세스 인젝션 기법
│   │   ├── dll_injection.cpp        # DLL 인젝션
│   │   ├── process_hollowing.cpp    # 프로세스 할로잉
│   │   └── apc_injection.cpp        # APC 인젝션
│   ├── fileless/                    # 파일리스 기법
│   │   ├── memory_execution.ps1     # PowerShell 메모리 실행
│   │   └── wmi_execution.ps1        # WMI 기반 실행
│   ├── shellcode/                   # 쉘코드 인젝션
│   │   └── shellcode_injection.cpp  # 쉘코드 실행
│   └── combined/                    # 복합 기법
│       └── multi_stage_attack.cpp   # 다단계 공격
├── workflows/                        # 자동화 워크플로우
│   └── automated_test.ps1           # 전체 테스트 자동화
├── scripts/                         # 빌드 및 유틸리티 스크립트
│   └── build.ps1                    # 빌드 스크립트
├── docs/                            # 문서
│   └── detection_guide.md           # 탐지 기법 가이드
└── README.md                        # 프로젝트 개요
```

## 🧪 테스트 시나리오

### 시나리오 1: 기본 테스트 (약 5분)

```powershell
# 1. DLL Injection 테스트
.\samples\process_injection\dll_injection.exe test

# 2. PowerShell 파일리스 테스트
.\samples\fileless\memory_execution.ps1
```

**예상 결과:** EDR이 다음을 탐지해야 함
- 의심스러운 프로세스 활동
- 메모리 조작 시도
- PowerShell 스크립트 블록 실행

### 시나리오 2: 중급 테스트 (약 10분)

```powershell
# 전체 프로세스 인젝션 suite
Get-ChildItem .\samples\process_injection\*.exe | ForEach-Object { & $_.FullName }

# 전체 파일리스 suite
Get-ChildItem .\samples\fileless\*.ps1 | ForEach-Object { 
    powershell -ExecutionPolicy Bypass -File $_.FullName 
}
```

### 시나리오 3: 고급 테스트 (약 15분)

```powershell
# 자동화된 전체 테스트 suite
.\workflows\automated_test.ps1
```

## 📊 결과 확인

### EDR 콘솔 확인 항목

1. **Alert/Detection 개수**
   - 각 테스트마다 얼마나 많은 alert가 발생했는가?
   
2. **탐지 시간**
   - 실행 후 얼마나 빨리 탐지되었는가?

3. **탐지 상세 정보**
   - Process tree
   - API call sequence
   - Memory operations
   - Network activities

4. **대응 조치**
   - 자동 차단 여부
   - 격리 조치 여부
   - 경고 수준

### 로그 파일 확인

```powershell
# 테스트 결과 로그 확인
Get-Content .\edr_test_results.log
```

## 🔍 주요 탐지 포인트

### 1. Process Injection
- ✅ OpenProcess 호출
- ✅ VirtualAllocEx 호출
- ✅ WriteProcessMemory 호출
- ✅ CreateRemoteThread 호출

### 2. Fileless Techniques
- ✅ PowerShell 인코딩된 명령
- ✅ Invoke-Expression (IEX)
- ✅ WMI Process Creation
- ✅ In-memory assembly loading

### 3. Shellcode Injection
- ✅ RWX 메모리 할당
- ✅ 메모리 보호 속성 변경
- ✅ 비-이미지 메모리 실행

### 4. Multi-Stage Attack
- ✅ 프로세스 열거
- ✅ 보안 제품 탐지 시도
- ✅ 다단계 인젝션
- ✅ 최종 페이로드 실행

## 📈 평가 기준

### 우수한 EDR
- ✅ 모든 테스트 케이스 탐지
- ✅ 실시간 탐지 (< 1초)
- ✅ 상세한 컨텍스트 정보 제공
- ✅ 자동 대응 기능

### 보통 수준의 EDR
- ⚠️ 대부분의 테스트 케이스 탐지
- ⚠️ 탐지 지연 (1-5초)
- ⚠️ 기본적인 정보만 제공
- ⚠️ 수동 대응 필요

### 개선이 필요한 EDR
- ❌ 일부 테스트 케이스 미탐지
- ❌ 느린 탐지 (> 5초)
- ❌ 불충분한 정보
- ❌ 대응 기능 부족

## 🛠️ 문제 해결 (Troubleshooting)

### 빌드 오류

**문제:** "cl.exe를 찾을 수 없습니다"
```powershell
# 해결: Visual Studio Developer Command Prompt 사용
# 또는 Visual Studio 설치 확인
```

**문제:** "fatal error C1083: 파일을 열 수 없습니다"
```powershell
# 해결: Windows SDK 설치 확인
# Visual Studio Installer에서 "Windows 10 SDK" 선택
```

### 실행 권한 오류

**문제:** "스크립트 실행이 비활성화되어 있습니다"
```powershell
# 해결: 실행 정책 변경 (현재 세션만)
Set-ExecutionPolicy Bypass -Scope Process
```

**문제:** "관리자 권한이 필요합니다"
```powershell
# 해결: PowerShell을 관리자 권한으로 실행
# 시작 메뉴 > PowerShell > 우클릭 > 관리자 권한으로 실행
```

### 테스트 실패

**문제:** 프로세스 생성 실패
```powershell
# 확인: calc.exe, notepad.exe 경로 확인
Test-Path C:\Windows\System32\calc.exe
Test-Path C:\Windows\System32\notepad.exe
```

## 📚 추가 문서

- [탐지 기법 가이드](docs/detection_guide.md) - 상세한 탐지 포인트 설명
- [MITRE ATT&CK Mapping](docs/detection_guide.md#mitre-attck-mapping)

## 🤝 기여 (Contributing)

개선 사항이나 새로운 테스트 기법 제안을 환영합니다:
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 지원 (Support)

문제가 발생하거나 질문이 있으시면 GitHub Issues를 통해 문의해 주세요.

## ⚖️ 법적 고지 (Legal Notice)

이 도구들은 교육 및 합법적인 보안 테스트 목적으로만 제공됩니다.
무단으로 시스템에 접근하거나 악의적인 목적으로 사용하는 것은 불법이며,
사용자는 모든 관련 법률과 규정을 준수할 책임이 있습니다.

---

**마지막 업데이트:** 2024
**버전:** 1.0
