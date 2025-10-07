/*
 * APC Queue Injection Test - EDR Detection Test
 * 
 * 목적: Asynchronous Procedure Call을 이용한 코드 실행 테스트
 * Purpose: Test EDR's ability to detect APC injection technique
 * 
 * 탐지 포인트 (Detection Points):
 * - OpenProcess with specific access rights
 * - OpenThread to get thread handle
 * - VirtualAllocEx for shellcode allocation
 * - WriteProcessMemory to write shellcode
 * - QueueUserAPC to queue malicious APC
 * 
 * WARNING: For testing purposes only in isolated environments
 */

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

// Enumerate threads of a process
DWORD GetThreadId(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == processId) {
                CloseHandle(hSnapshot);
                return te.th32ThreadID;
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return 0;
}

void SimulateApcInjection() {
    std::wcout << L"==================================================" << std::endl;
    std::wcout << L"    EDR Test: APC Queue Injection Technique" << std::endl;
    std::wcout << L"    WARNING: For testing purposes only!" << std::endl;
    std::wcout << L"==================================================" << std::endl;
    std::wcout << std::endl;

    // Step 1: Create target process
    std::wcout << L"[1] Creating target process (notepad.exe)..." << std::endl;
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(
        L"C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::wcerr << L"[-] Failed to create process" << std::endl;
        return;
    }

    std::wcout << L"[+] Process created" << std::endl;
    std::wcout << L"    PID: " << pi.dwProcessId << std::endl;

    Sleep(1000); // Let process initialize

    // Step 2: Get thread handle
    std::wcout << L"\n[2] Getting thread ID..." << std::endl;
    DWORD threadId = GetThreadId(pi.dwProcessId);
    
    if (threadId == 0) {
        std::wcerr << L"[-] Failed to get thread ID" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    std::wcout << L"[+] Thread ID: " << threadId << std::endl;

    // Step 3: Open thread handle
    std::wcout << L"\n[3] Opening thread handle..." << std::endl;
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
    
    if (!hThread) {
        std::wcerr << L"[-] Failed to open thread" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    std::wcout << L"[+] Thread handle obtained" << std::endl;

    // Step 4: Allocate memory for shellcode
    std::wcout << L"\n[4] Allocating memory in target process..." << std::endl;
    
    // Example shellcode (non-functional, for demonstration)
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP sled
        0xC3                      // RET
    };
    SIZE_T shellcodeSize = sizeof(shellcode);

    LPVOID pRemoteMemory = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!pRemoteMemory) {
        std::wcerr << L"[-] Failed to allocate memory" << std::endl;
        CloseHandle(hThread);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    std::wcout << L"[+] Memory allocated at: 0x" << std::hex 
               << (DWORD_PTR)pRemoteMemory << std::dec << std::endl;

    // Step 5: Write shellcode
    std::wcout << L"\n[5] Writing shellcode to target process..." << std::endl;
    
    if (!WriteProcessMemory(pi.hProcess, pRemoteMemory, shellcode, shellcodeSize, NULL)) {
        std::wcerr << L"[-] Failed to write memory" << std::endl;
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hThread);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    std::wcout << L"[+] Shellcode written" << std::endl;

    // Step 6: Demonstrate QueueUserAPC
    std::wcout << L"\n[6] Demonstrating QueueUserAPC..." << std::endl;
    std::wcout << L"    (This would queue the shellcode for execution)" << std::endl;
    std::wcout << L"    API: QueueUserAPC((PAPCFUNC)shellcode_addr, hThread, 0)" << std::endl;
    
    // Note: Not actually queuing APC to avoid execution
    std::wcout << L"[+] APC queue simulation complete" << std::endl;

    // Cleanup
    std::wcout << L"\n[*] Cleaning up..." << std::endl;
    VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::wcout << L"\n[+] Test completed!" << std::endl;
    std::wcout << L"\nEDR Detection Points:" << std::endl;
    std::wcout << L"  - OpenProcess with write/execute permissions" << std::endl;
    std::wcout << L"  - OpenThread with THREAD_SET_CONTEXT" << std::endl;
    std::wcout << L"  - VirtualAllocEx with PAGE_EXECUTE_READWRITE" << std::endl;
    std::wcout << L"  - WriteProcessMemory to executable memory" << std::endl;
    std::wcout << L"  - QueueUserAPC call to inject code" << std::endl;
    std::wcout << L"  - Unusual APC queue behavior" << std::endl;
}

int main() {
    SimulateApcInjection();
    return 0;
}
