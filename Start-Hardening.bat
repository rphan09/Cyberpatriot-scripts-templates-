@echo off
REM Right-click this file and choose "Run as administrator".
REM Any arguments are passed to Run-Hardening.ps1, for example:  Start-Hardening.bat -DryRun
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0' -Recurse -File | Unblock-File; & '%~dp0Run-Hardening.ps1' %*"
pause
