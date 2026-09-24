@echo off
:: Step 1: Request Administrative Elevation if not running as Admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Step 2: Access network share directly via UNC path and run PowerShell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsProfileMaintenance.ps1"

pause