# Process Injection Samples

이 디렉토리는 다양한 프로세스 인젝션 기법을 포함합니다.

## 샘플 목록

### 1. dll_injection.cpp
**기법:** Classic DLL Injection
**설명:** 원격 프로세스에 DLL을 주입하는 전통적인 방법

**주요 API:**
- `OpenProcess()` - 대상 프로세스 핸들 획득
- `VirtualAllocEx()` - 원격 프로세스 메모리 할당
- `WriteProcessMemory()` - DLL 경로 작성
- `CreateRemoteThread()` - LoadLibrary 실행

**사용법:**
```cmd
dll_injection.exe test
```

**MITRE ATT&CK:** T1055.001

---

### 2. process_hollowing.cpp
**기법:** Process Hollowing
**설명:** 정상 프로세스를 생성 후 악성 코드로 교체

**주요 API:**
- `CreateProcess()` with `CREATE_SUSPENDED`
- `NtUnmapViewOfSection()` - 원본 이미지 언맵
- `VirtualAllocEx()` - 새 메모리 할당
- `WriteProcessMemory()` - 페이로드 작성
- `SetThreadContext()` - 진입점 수정
- `ResumeThread()` - 프로세스 재개

**사용법:**
```cmd
process_hollowing.exe
```

**MITRE ATT&CK:** T1055.012

---

### 3. apc_injection.cpp
**기법:** Asynchronous Procedure Call (APC) Injection
**설명:** APC 큐를 이용한 코드 실행

**주요 API:**
- `OpenProcess()` - 프로세스 핸들
- `OpenThread()` - 스레드 핸들
- `VirtualAllocEx()` - 메모리 할당
- `WriteProcessMemory()` - 쉘코드 작성
- `QueueUserAPC()` - APC 큐에 추가

**사용법:**
```cmd
apc_injection.exe
```

**MITRE ATT&CK:** T1055.004

---

## 컴파일 방법

```cmd
# Visual Studio Developer Command Prompt에서
cl /EHsc /W4 dll_injection.cpp /Fe:dll_injection.exe
cl /EHsc /W4 process_hollowing.cpp /Fe:process_hollowing.exe
cl /EHsc /W4 apc_injection.cpp /Fe:apc_injection.exe

# 또는 빌드 스크립트 사용
cd ..\..
.\scripts\build.ps1
```

## EDR 탐지 포인트

EDR 솔루션은 다음을 탐지해야 합니다:

- ✅ 의심스러운 권한으로 프로세스 오픈
- ✅ 원격 프로세스 메모리 조작
- ✅ 실행 가능한 메모리 할당
- ✅ 원격 스레드 생성
- ✅ 프로세스가 SUSPENDED 상태로 생성
- ✅ 프로세스 메모리 언맵
- ✅ 스레드 컨텍스트 수정
- ✅ APC 큐 조작

## 안전성 참고사항

모든 샘플은 실제 악성 페이로드를 실행하지 않고 기법만 시뮬레이션합니다.
대부분 notepad.exe 또는 calc.exe를 실행하여 EDR의 탐지 능력을 테스트합니다.
