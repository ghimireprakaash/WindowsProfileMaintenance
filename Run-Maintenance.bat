@echo off
:: Self-elevate to Administrator if not already running as Admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Change directory to the folder where this batch file lives
cd /d "%~dp0"

:: Execute the PowerShell maintenance script
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WindowsProfileMaintenance.ps1"

pause