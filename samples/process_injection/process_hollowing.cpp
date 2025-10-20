/*
 * Process Hollowing Test - EDR Detection Test
 * 
 * 목적: Process Hollowing 기법을 통해 정상 프로세스를 생성 후 악성 코드로 교체
 * Purpose: Test EDR's ability to detect process hollowing technique
 * 
 * 탐지 포인트 (Detection Points):
 * - CreateProcess with CREATE_SUSPENDED flag
 * - NtUnmapViewOfSection to unmap original executable
 * - VirtualAllocEx to allocate new memory
 * - WriteProcessMemory to write new code
 * - SetThreadContext to modify entry point
 * - ResumeThread to execute injected code
 * 
 * WARNING: For testing purposes only in isolated environments
 */

#include <windows.h>
#include <winternl.h>
#include <iostream>

// Function pointer types for NT APIs
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// RAII wrapper for HANDLE to ensure automatic cleanup
class HandleGuard {
private:
    HANDLE handle;
    
public:
    HandleGuard(HANDLE h) : handle(h) {}
    ~HandleGuard() {
        if (handle && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
    
    HANDLE get() const { return handle; }
    bool isValid() const { return handle && handle != INVALID_HANDLE_VALUE; }
    
    // Prevent copying
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
};

// Validate executable path
bool ValidateExecutablePath(const std::wstring& exePath) {
    DWORD fileAttributes = GetFileAttributesW(exePath.c_str());
    
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"[-] Executable not found at: " << exePath << std::endl;
        std::wcerr << L"    Error: " << GetLastError() << std::endl;
        return false;
    }
    
    return true;
}

void SimulateProcessHollowing() {
    std::wcout << L"==================================================" << std::endl;
    std::wcout << L"    EDR Test: Process Hollowing Technique" << std::endl;
    std::wcout << L"    WARNING: For testing purposes only!" << std::endl;
    std::wcout << L"==================================================" << std::endl;
    std::wcout << std::endl;

    // Step 1: Create target process in suspended state
    std::wcout << L"[1] Creating suspended process (calc.exe)..." << std::endl;
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    std::wstring targetPath = L"C:\\Windows\\System32\\calc.exe";
    
    // Validate path exists
    if (!ValidateExecutablePath(targetPath)) {
        std::wcerr << L"[-] Cannot proceed: calc.exe not found" << std::endl;
        return;
    }
    
    if (!CreateProcessW(
        targetPath.c_str(),
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,  // Critical: Process created in suspended state
        NULL,
        NULL,
        &si,
        &pi)) {
        std::wcerr << L"[-] Failed to create process. Error: " << GetLastError() << std::endl;
        return;
    }

    // Use RAII for automatic cleanup
    HandleGuard processGuard(pi.hProcess);
    HandleGuard threadGuard(pi.hThread);

    std::wcout << L"[+] Process created in suspended state" << std::endl;
    std::wcout << L"    PID: " << pi.dwProcessId << std::endl;
    std::wcout << L"    Thread ID: " << pi.dwThreadId << std::endl;

    // Step 2: Get process context
    std::wcout << L"\n[2] Getting thread context..." << std::endl;
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::wcerr << L"[-] Failed to get thread context. Error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return;
    }
    std::wcout << L"[+] Thread context retrieved" << std::endl;

    // Step 3: Simulate unmapping of original image
    std::wcout << L"\n[3] Demonstrating NtUnmapViewOfSection call..." << std::endl;
    std::wcout << L"    (This would unmap the original executable from memory)" << std::endl;
    std::wcout << L"    API: NtUnmapViewOfSection()" << std::endl;
    
    // Load ntdll for demonstration
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        pNtUnmapViewOfSection NtUnmapViewOfSection = 
            (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        if (NtUnmapViewOfSection) {
            std::wcout << L"[+] NtUnmapViewOfSection address: 0x" << std::hex 
                       << (DWORD_PTR)NtUnmapViewOfSection << std::dec << std::endl;
        } else {
            std::wcerr << L"[-] Failed to get NtUnmapViewOfSection address. Error: " << GetLastError() << std::endl;
        }
    } else {
        std::wcerr << L"[-] Failed to get ntdll.dll handle. Error: " << GetLastError() << std::endl;
    }

    // Step 4: Simulate memory allocation
    std::wcout << L"\n[4] Simulating VirtualAllocEx for new image..." << std::endl;
    std::wcout << L"    (This would allocate memory for malicious payload)" << std::endl;
    
    SIZE_T imageSize = 0x10000; // Example size
    LPVOID pRemoteImage = VirtualAllocEx(
        pi.hProcess,
        NULL,
        imageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (pRemoteImage) {
        std::wcout << L"[+] Memory allocated at: 0x" << std::hex 
                   << (DWORD_PTR)pRemoteImage << std::dec << std::endl;
        VirtualFreeEx(pi.hProcess, pRemoteImage, 0, MEM_RELEASE);
    } else {
        std::wcerr << L"[-] Failed to allocate memory. Error: " << GetLastError() << std::endl;
    }

    // Step 5: Demonstrate WriteProcessMemory
    std::wcout << L"\n[5] Demonstrating WriteProcessMemory..." << std::endl;
    std::wcout << L"    (This would write malicious code to process memory)" << std::endl;
    std::wcout << L"    API: WriteProcessMemory()" << std::endl;

    // Step 6: Demonstrate SetThreadContext
    std::wcout << L"\n[6] Demonstrating SetThreadContext..." << std::endl;
    std::wcout << L"    (This would modify entry point to malicious code)" << std::endl;
    std::wcout << L"    API: SetThreadContext()" << std::endl;

    // Step 7: Explain ResumeThread
    std::wcout << L"\n[7] ResumeThread would execute the hollowed process..." << std::endl;
    std::wcout << L"    (Not executing to prevent actual code injection)" << std::endl;

    // Cleanup
    std::wcout << L"\n[*] Cleaning up test process..." << std::endl;
    TerminateProcess(pi.hProcess, 0);

    std::wcout << L"\n[+] Test completed!" << std::endl;
    std::wcout << L"\nEDR Detection Points:" << std::endl;
    std::wcout << L"  - CreateProcess with CREATE_SUSPENDED flag" << std::endl;
    std::wcout << L"  - NtUnmapViewOfSection API call" << std::endl;
    std::wcout << L"  - VirtualAllocEx with PAGE_EXECUTE_READWRITE" << std::endl;
    std::wcout << L"  - WriteProcessMemory to suspended process" << std::endl;
    std::wcout << L"  - SetThreadContext modification" << std::endl;
    std::wcout << L"  - ResumeThread on modified process" << std::endl;
}

int main() {
    SimulateProcessHollowing();
    return 0;
}
