/*
 * Multi-Stage Attack Simulation - EDR Detection Test
 * 
 * 목적: 여러 악성 기법을 조합한 다단계 공격 시뮬레이션
 * Purpose: Test EDR's ability to detect multi-stage attacks combining various techniques
 * 
 * 이 샘플은 다음을 포함합니다:
 * This sample includes:
 * 1. Process enumeration and reconnaissance
 * 2. Memory allocation and shellcode preparation
 * 3. Process injection
 * 4. Final payload execution (notepad/calc)
 * 
 * WARNING: For testing purposes only in isolated environments
 */

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>

class EDRTestSuite {
private:
    struct ProcessInfo {
        DWORD pid;
        std::wstring name;
    };

    std::vector<ProcessInfo> processes;

    void PrintBanner() {
        std::wcout << L"===========================================================" << std::endl;
        std::wcout << L"    EDR Test: Multi-Stage Attack Simulation" << std::endl;
        std::wcout << L"    WARNING: Comprehensive EDR detection test!" << std::endl;
        std::wcout << L"===========================================================" << std::endl;
        std::wcout << std::endl;
    }

    // Stage 1: Reconnaissance
    void StageReconnaissance() {
        std::wcout << L"\n[STAGE 1] Reconnaissance and Environment Discovery" << std::endl;
        std::wcout << L"============================================" << std::endl;

        std::wcout << L"\n[1.1] Enumerating running processes..." << std::endl;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnapshot, &pe)) {
                int count = 0;
                do {
                    ProcessInfo info;
                    info.pid = pe.th32ProcessID;
                    info.name = pe.szExeFile;
                    processes.push_back(info);
                    count++;
                } while (Process32NextW(hSnapshot, &pe) && count < 10);
            }
            CloseHandle(hSnapshot);
            std::wcout << L"    [+] Found " << processes.size() << L" processes (showing first 10)" << std::endl;
        }

        std::wcout << L"\n[1.2] Checking for security products..." << std::endl;
        std::vector<std::wstring> securityProducts = {
            L"MsMpEng.exe",      // Windows Defender
            L"cb.exe",           // Carbon Black
            L"CylanceSvc.exe",   // Cylance
            L"CSFalconService.exe" // CrowdStrike
        };

        for (const auto& proc : processes) {
            for (const auto& secProd : securityProducts) {
                if (proc.name.find(secProd) != std::wstring::npos) {
                    std::wcout << L"    [!] Security product detected: " << secProd << std::endl;
                }
            }
        }
        std::wcout << L"    [+] Security product enumeration completed" << std::endl;

        std::wcout << L"\n[1.3] System information gathering..." << std::endl;
        wchar_t computerName[256];
        DWORD size = 256;
        if (GetComputerNameW(computerName, &size)) {
            std::wcout << L"    Computer Name: " << computerName << std::endl;
        }

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        std::wcout << L"    Processor Count: " << sysInfo.dwNumberOfProcessors << std::endl;
        std::wcout << L"    [!] EDR should log reconnaissance activities" << std::endl;
    }

    // Stage 2: Preparation
    void StagePreparation() {
        std::wcout << L"\n[STAGE 2] Attack Preparation" << std::endl;
        std::wcout << L"============================================" << std::endl;

        std::wcout << L"\n[2.1] Allocating memory for payload..." << std::endl;
        SIZE_T payloadSize = 4096;
        LPVOID memory = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (memory) {
            std::wcout << L"    [+] Memory allocated at: 0x" << std::hex << (DWORD_PTR)memory << std::dec << std::endl;
            
            std::wcout << L"\n[2.2] Changing memory protection to executable..." << std::endl;
            DWORD oldProtect;
            if (VirtualProtect(memory, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
                std::wcout << L"    [+] Memory protection changed to RX" << std::endl;
                std::wcout << L"    [!] EDR should detect RW->RX transition" << std::endl;
            }

            VirtualFree(memory, 0, MEM_RELEASE);
        }

        std::wcout << L"\n[2.3] Simulating obfuscation techniques..." << std::endl;
        std::wcout << L"    - XOR encoding" << std::endl;
        std::wcout << L"    - String encryption" << std::endl;
        std::wcout << L"    - API hashing" << std::endl;
        std::wcout << L"    [!] EDR should use behavioral analysis" << std::endl;
    }

    // Stage 3: Injection
    void StageInjection() {
        std::wcout << L"\n[STAGE 3] Process Injection Simulation" << std::endl;
        std::wcout << L"============================================" << std::endl;

        std::wcout << L"\n[3.1] Creating target process (notepad.exe)..." << std::endl;
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));

        if (!CreateProcessW(
            L"C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            std::wcerr << L"    [-] Failed to create process" << std::endl;
            return;
        }

        std::wcout << L"    [+] Process created in suspended state (PID: " << pi.dwProcessId << L")" << std::endl;
        std::wcout << L"    [!] EDR should flag CREATE_SUSPENDED" << std::endl;

        std::wcout << L"\n[3.2] Simulating injection steps..." << std::endl;
        std::wcout << L"    - OpenProcess with PROCESS_ALL_ACCESS" << std::endl;
        std::wcout << L"    - VirtualAllocEx in target process" << std::endl;
        std::wcout << L"    - WriteProcessMemory with payload" << std::endl;
        std::wcout << L"    - CreateRemoteThread to execute" << std::endl;
        std::wcout << L"    [!] Each API call should trigger EDR alerts" << std::endl;

        std::wcout << L"\n[3.3] Resuming process..." << std::endl;
        ResumeThread(pi.hThread);
        std::wcout << L"    [+] Process resumed" << std::endl;

        Sleep(2000);

        std::wcout << L"\n[3.4] Terminating test process..." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        std::wcout << L"    [+] Process terminated" << std::endl;
    }

    // Stage 4: Execution
    void StageExecution() {
        std::wcout << L"\n[STAGE 4] Payload Execution" << std::endl;
        std::wcout << L"============================================" << std::endl;

        std::wcout << L"\n[4.1] Launching final payload (calc.exe)..." << std::endl;
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));

        if (CreateProcessW(
            L"C:\\Windows\\System32\\calc.exe",
            NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            
            std::wcout << L"    [+] Calculator launched (PID: " << pi.dwProcessId << L")" << std::endl;
            std::wcout << L"    [!] EDR should correlate this with previous activities" << std::endl;
            
            Sleep(3000);
            
            std::wcout << L"\n[4.2] Cleaning up..." << std::endl;
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            std::wcout << L"    [+] Payload terminated" << std::endl;
        }
    }

    // Stage 5: Evasion Techniques
    void StageEvasion() {
        std::wcout << L"\n[STAGE 5] Evasion Techniques (Awareness)" << std::endl;
        std::wcout << L"============================================" << std::endl;

        std::wcout << L"\n[5.1] Common evasion techniques EDR should detect:" << std::endl;
        std::wcout << L"    - Sleep/delay to avoid sandboxing" << std::endl;
        std::wcout << L"    - Environment checks (VM detection)" << std::endl;
        std::wcout << L"    - API unhooking attempts" << std::endl;
        std::wcout << L"    - AMSI bypass attempts" << std::endl;
        std::wcout << L"    - ETW patching" << std::endl;
        std::wcout << L"    - Direct syscalls (bypassing hooks)" << std::endl;

        std::wcout << L"\n[5.2] Performing benign sleep..." << std::endl;
        std::wcout << L"    Sleeping for 2 seconds..." << std::endl;
        Sleep(2000);
        std::wcout << L"    [+] Sleep completed" << std::endl;
        std::wcout << L"    [!] Long sleeps may indicate anti-analysis behavior" << std::endl;
    }

public:
    void RunFullTest() {
        PrintBanner();
        StageReconnaissance();
        StagePreparation();
        StageInjection();
        StageExecution();
        StageEvasion();
        PrintSummary();
    }

    void PrintSummary() {
        std::wcout << L"\n===========================================================" << std::endl;
        std::wcout << L"    Test Summary and EDR Detection Points" << std::endl;
        std::wcout << L"===========================================================" << std::endl;
        std::wcout << L"\nA comprehensive EDR solution should have detected:" << std::endl;
        std::wcout << L"  1. Process enumeration (CreateToolhelp32Snapshot)" << std::endl;
        std::wcout << L"  2. Security product discovery attempts" << std::endl;
        std::wcout << L"  3. Suspicious memory allocations (RWX pages)" << std::endl;
        std::wcout << L"  4. Memory protection changes" << std::endl;
        std::wcout << L"  5. Process creation with CREATE_SUSPENDED" << std::endl;
        std::wcout << L"  6. Process injection API sequence" << std::endl;
        std::wcout << L"  7. Remote thread creation" << std::endl;
        std::wcout << L"  8. Child process spawning from suspicious parent" << std::endl;
        std::wcout << L"  9. Behavioral chains indicating attack pattern" << std::endl;
        std::wcout << L" 10. Evasion technique attempts" << std::endl;
        std::wcout << L"\n[+] Multi-stage test completed!" << std::endl;
        std::wcout << L"\nRecommendation: Review EDR logs for all detected events." << std::endl;
        std::wcout << L"===========================================================" << std::endl;
    }
};

int main() {
    EDRTestSuite testSuite;
    testSuite.RunFullTest();
    return 0;
}
