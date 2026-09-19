@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ensure-edge-controller.ps1"
if errorlevel 1 exit /b %errorlevel%
"%LOCALAPPDATA%\edge-platform\bin\edge-console.exe" menu
