# Build Script for EDR Testing Tools
# Compiles all C++ samples

param(
    [switch]$Clean,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "    EDR Testing Tools - Build Script" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Check for Visual Studio environment
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    Write-Host "[*] Detecting Visual Studio installation..." -ForegroundColor Yellow
    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    
    if ($vsPath) {
        Write-Host "[+] Visual Studio found at: $vsPath" -ForegroundColor Green
        
        # Find vcvarsall.bat
        $vcvarsall = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
        if (Test-Path $vcvarsall) {
            Write-Host "[+] Setting up Visual Studio environment..." -ForegroundColor Green
            
            # Setup VS environment in this session
            $tempFile = [System.IO.Path]::GetTempFileName()
            cmd /c "`"$vcvarsall`" x64 && set" > $tempFile
            Get-Content $tempFile | ForEach-Object {
                if ($_ -match "^(.*?)=(.*)$") {
                    Set-Content "env:\$($matches[1])" $matches[2]
                }
            }
            Remove-Item $tempFile
        }
    } else {
        Write-Host "[-] Visual Studio not found. Please install Visual Studio with C++ tools." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[*] Checking if cl.exe is in PATH..." -ForegroundColor Yellow
    $clExists = Get-Command cl.exe -ErrorAction SilentlyContinue
    if (-not $clExists) {
        Write-Host "[-] cl.exe not found. Please run this from a Visual Studio Developer Command Prompt" -ForegroundColor Red
        Write-Host "    or install Visual Studio with C++ tools." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Compiler found in PATH" -ForegroundColor Green
}

# Clean if requested
if ($Clean) {
    Write-Host "`n[*] Cleaning previous builds..." -ForegroundColor Yellow
    Get-ChildItem -Path "samples" -Recurse -Include "*.exe", "*.obj", "*.pdb", "*.ilk" | Remove-Item -Force
    Write-Host "[+] Clean completed" -ForegroundColor Green
}

# Find all C++ source files
Write-Host "`n[*] Finding C++ source files..." -ForegroundColor Yellow
$cppFiles = Get-ChildItem -Path "samples" -Recurse -Filter "*.cpp"
Write-Host "[+] Found $($cppFiles.Count) C++ files" -ForegroundColor Green

# Compile each file
$successCount = 0
$failCount = 0

Write-Host "`n[*] Starting compilation..." -ForegroundColor Yellow
Write-Host "==================================================`n" -ForegroundColor Cyan

foreach ($file in $cppFiles) {
    $fileName = $file.Name
    $outputName = [System.IO.Path]::GetFileNameWithoutExtension($fileName) + ".exe"
    $outputPath = Join-Path $file.DirectoryName $outputName
    
    Write-Host "Compiling: $fileName" -ForegroundColor Cyan
    Write-Host "  Location: $($file.DirectoryName)" -ForegroundColor Gray
    Write-Host "  Output: $outputName" -ForegroundColor Gray
    
    # Compilation flags
    $flags = "/EHsc /W4 /std:c++17 /nologo"
    if ($Verbose) {
        $flags += " /Wall"
    } else {
        $flags += " /D_CRT_SECURE_NO_WARNINGS"
    }
    
    # Build command
    $compileCmd = "cl.exe $flags `"$($file.FullName)`" /Fe:`"$outputPath`" /link /SUBSYSTEM:CONSOLE"
    
    try {
        # Create a temp file for compilation output
        $tempOutput = [System.IO.Path]::GetTempFileName()
        
        # Execute compilation
        $result = Invoke-Expression "$compileCmd 2>&1" | Out-File $tempOutput
        
        # Check if exe was created
        if (Test-Path $outputPath) {
            Write-Host "  [SUCCESS] Compiled successfully" -ForegroundColor Green
            $successCount++
            
            # Get file size
            $fileSize = (Get-Item $outputPath).Length
            Write-Host "  Size: $([math]::Round($fileSize/1KB, 2)) KB" -ForegroundColor Gray
        } else {
            Write-Host "  [FAILED] Compilation failed" -ForegroundColor Red
            $failCount++
            
            if ($Verbose) {
                Write-Host "  Error details:" -ForegroundColor Red
                Get-Content $tempOutput | Write-Host -ForegroundColor DarkRed
            }
        }
        
        Remove-Item $tempOutput -ErrorAction SilentlyContinue
        
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
    }
    
    # Clean up intermediate files
    $objFile = Join-Path $file.DirectoryName ([System.IO.Path]::GetFileNameWithoutExtension($fileName) + ".obj")
    if (Test-Path $objFile) { Remove-Item $objFile -Force -ErrorAction SilentlyContinue }
    
    Write-Host ""
}

# Summary
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "    Build Summary" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Total files: $($cppFiles.Count)" -ForegroundColor White
Write-Host "Successful: $successCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host "==================================================" -ForegroundColor Cyan

if ($successCount -eq $cppFiles.Count) {
    Write-Host "`n[+] All files compiled successfully!" -ForegroundColor Green
    Write-Host "You can now run the workflow script to execute tests." -ForegroundColor Cyan
    exit 0
} else {
    Write-Host "`n[-] Some files failed to compile. Check errors above." -ForegroundColor Red
    exit 1
}
