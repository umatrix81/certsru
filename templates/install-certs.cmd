@echo off
rem Double-clickable wrapper for install-certs.ps1.
rem
rem PowerShell's default execution policy on Windows client is Restricted, so a .ps1 cannot
rem be run by double-clicking it. A .cmd is not policy-gated, and invoking PowerShell with
rem -ExecutionPolicy Bypass affects only this one process -- the machine's policy is left
rem alone.
rem
rem With no arguments this shows the certificates and their thumbprints first, then asks
rem before installing anything. Check those thumbprints against a value you received
rem separately: this installs a trust anchor, and that is worth ten seconds.
rem
rem Any arguments given are passed straight through, so `install-certs.cmd -Machine` or
rem `install-certs.cmd -Uninstall` work as expected.

setlocal
set "PS1=%~dp0install-certs.ps1"

if not exist "%PS1%" (
    echo install-certs.ps1 не найден.
    echo Держите оба файла вместе.
    echo.
    pause
    exit /b 1
)

rem Files that arrived by browser, mail or network share carry a zone marker that blocks
rem them regardless of execution policy. Clearing it here is harmless if absent.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Unblock-File -LiteralPath '%PS1%'" >nul 2>&1

if not "%~1"=="" goto passthrough

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -ShowOnly
if errorlevel 1 goto finish

echo.
set "ANSWER="
set /p "ANSWER=Install these certificates? [y/N] "
if /i not "%ANSWER%"=="y" (
    echo Aborted. Nothing was installed.
    set "RC=1"
    goto finish
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
set "RC=%ERRORLEVEL%"
goto finish

:passthrough
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"

:finish
echo.
pause
exit /b %RC%
