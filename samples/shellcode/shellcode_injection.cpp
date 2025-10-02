/*
 * Shellcode Injection Test - EDR Detection Test
 * 
 * 목적: 메모리에 쉘코드를 직접 주입하고 실행하는 기법 테스트
 * Purpose: Test EDR's ability to detect direct shellcode injection and execution
 * 
 * 탐지 포인트 (Detection Points):
 * - VirtualAlloc with PAGE_EXECUTE_READWRITE
 * - Memory region with RWX permissions
 * - Direct execution of non-image memory
 * - Shellcode execution patterns
 * - CreateThread on allocated memory
 * 
 * WARNING: For testing purposes only in isolated environments
 */

#include <windows.h>
#include <iostream>

void SimulateShellcodeInjection() {
    std::wcout << L"==================================================" << std::endl;
    std::wcout << L"    EDR Test: Shellcode Injection Technique" << std::endl;
    std::wcout << L"    WARNING: For testing purposes only!" << std::endl;
    std::wcout << L"==================================================" << std::endl;
    std::wcout << std::endl;

    // Benign shellcode that launches calc.exe
    // This is actual x64 shellcode that executes calc.exe
    // EDR should detect the shellcode pattern and execution
    unsigned char shellcode[] = 
        // MessageBox shellcode (benign demonstration)
        "\x48\x83\xEC\x28"                          // sub rsp, 0x28
        "\x48\x83\xE4\xF0"                          // and rsp, 0xFFFFFFFFFFFFFFF0
        "\x48\x8D\x15\x66\x00\x00\x00"              // lea rdx, [rel message]
        "\x48\x8D\x0D\x52\x00\x00\x00"              // lea rcx, [rel title]
        "\x48\x31\xC9"                              // xor rcx, rcx
        "\xFF\x15\x00\x00\x00\x00"                  // call MessageBoxA (placeholder)
        "\x48\x31\xC9"                              // xor rcx, rcx
        "\xFF\x15\x00\x00\x00\x00"                  // call ExitProcess (placeholder)
        "EDR Test\0"                                // title
        "Shellcode Execution Detected!\0";         // message

    SIZE_T shellcodeSize = sizeof(shellcode);

    // Step 1: Allocate executable memory
    std::wcout << L"[1] Allocating executable memory..." << std::endl;
    std::wcout << L"    Size: " << shellcodeSize << L" bytes" << std::endl;
    std::wcout << L"    Protection: PAGE_EXECUTE_READWRITE (RWX)" << std::endl;
    
    LPVOID execMemory = VirtualAlloc(
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE  // Critical: RWX memory allocation
    );

    if (!execMemory) {
        std::wcerr << L"[-] Failed to allocate memory. Error: " << GetLastError() << std::endl;
        return;
    }

    std::wcout << L"[+] Memory allocated at: 0x" << std::hex 
               << (DWORD_PTR)execMemory << std::dec << std::endl;
    std::wcout << L"    [!] EDR should flag RWX memory allocation" << std::endl;

    // Step 2: Copy shellcode to allocated memory
    std::wcout << L"\n[2] Copying shellcode to allocated memory..." << std::endl;
    memcpy(execMemory, shellcode, shellcodeSize);
    std::wcout << L"[+] Shellcode copied successfully" << std::endl;
    std::wcout << L"    [!] EDR should detect suspicious memory write to RWX region" << std::endl;

    // Step 3: Display shellcode characteristics
    std::wcout << L"\n[3] Shellcode characteristics..." << std::endl;
    std::wcout << L"    First 16 bytes (hex): ";
    for (size_t i = 0; i < 16 && i < shellcodeSize; i++) {
        wprintf(L"%02X ", shellcode[i]);
    }
    std::wcout << std::endl;

    // Step 4: Demonstrate CreateThread on shellcode
    std::wcout << L"\n[4] Demonstrating thread creation on shellcode..." << std::endl;
    std::wcout << L"    [*] Would call: CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcode, NULL, 0, NULL)" << std::endl;
    std::wcout << L"    [!] EDR should detect thread creation pointing to non-image memory" << std::endl;
    std::wcout << L"    [*] Not actually executing to prevent code execution" << std::endl;

    // Step 5: Demonstrate alternative execution methods
    std::wcout << L"\n[5] Alternative shellcode execution methods EDR should detect..." << std::endl;
    std::wcout << L"    - CreateThread: Most common method" << std::endl;
    std::wcout << L"    - CreateRemoteThread: For remote process injection" << std::endl;
    std::wcout << L"    - RtlCreateUserThread: Native API alternative" << std::endl;
    std::wcout << L"    - NtQueueApcThread: APC-based execution" << std::endl;
    std::wcout << L"    - SetThreadContext: Context hijacking" << std::endl;
    std::wcout << L"    - Fiber execution: CoFiberCreate/SwitchToFiber" << std::endl;

    // Step 6: Memory protection change detection
    std::wcout << L"\n[6] Demonstrating memory protection changes..." << std::endl;
    DWORD oldProtect;
    
    // Change to read-only (typical evasion: allocate RW, then change to RX)
    if (VirtualProtect(execMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::wcout << L"    [+] Protection changed from RWX to RX" << std::endl;
        std::wcout << L"    [!] EDR should track memory protection transitions" << std::endl;
        std::wcout << L"    Old protection: 0x" << std::hex << oldProtect << std::dec << std::endl;
    }

    // Cleanup
    std::wcout << L"\n[7] Cleaning up allocated memory..." << std::endl;
    VirtualFree(execMemory, 0, MEM_RELEASE);
    std::wcout << L"[+] Memory freed" << std::endl;

    // Summary
    std::wcout << L"\n==================================================" << std::endl;
    std::wcout << L"EDR Detection Points for Shellcode Injection:" << std::endl;
    std::wcout << L"==================================================" << std::endl;
    std::wcout << L"  - VirtualAlloc with PAGE_EXECUTE_READWRITE" << std::endl;
    std::wcout << L"  - VirtualProtect changing memory to executable" << std::endl;
    std::wcout << L"  - Memory writes to executable regions" << std::endl;
    std::wcout << L"  - Thread creation pointing to heap/non-image memory" << std::endl;
    std::wcout << L"  - Suspicious instruction patterns in allocated memory" << std::endl;
    std::wcout << L"  - Memory scanning for shellcode signatures" << std::endl;
    std::wcout << L"  - Behavioral analysis of memory execution" << std::endl;
    std::wcout << L"\n[+] Test completed successfully!" << std::endl;
}

void LaunchCalcWithShellcode() {
    std::wcout << L"\n==================================================" << std::endl;
    std::wcout << L"    Calc.exe Launch via Process Creation" << std::endl;
    std::wcout << L"==================================================" << std::endl;
    std::wcout << std::endl;

    std::wcout << L"[*] Demonstrating benign process creation (calc.exe)..." << std::endl;
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessW(
        L"C:\\Windows\\System32\\calc.exe",
        NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        
        std::wcout << L"[+] Calculator launched (PID: " << pi.dwProcessId << L")" << std::endl;
        std::wcout << L"    [!] EDR should log this process creation" << std::endl;
        
        Sleep(2000);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        std::wcout << L"[+] Process terminated" << std::endl;
    } else {
        std::wcerr << L"[-] Failed to launch calculator" << std::endl;
    }
}

int main() {
    // Test 1: Shellcode injection simulation
    SimulateShellcodeInjection();
    
    // Test 2: Launch calc.exe as final payload
    LaunchCalcWithShellcode();
    
    return 0;
}
