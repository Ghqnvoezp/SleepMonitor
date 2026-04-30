@echo off
:: ============================================================
::  build.bat  -  SleepMonitor build script  (x64 only)
:: ============================================================
::
::  Prerequisites:
::    1. MinHook (https://github.com/TsudaKageyu/minhook)
::       Place MinHook.h in include\
::       Place MinHook.x64.lib (MSVC) in lib\
::         The lib ships under two names depending on version:
::           MinHook.x64.lib   (older releases)
::           libMinHook.x64.lib (newer releases / vcpkg)
::         Either works — this script tries both.
::    2. Run from an x64 Native Tools Command Prompt for VS 20xx
::       OR let this script invoke vcvars64 automatically.
::
::  Usage:
::    build.bat        -- auto-detect and build
::    build.bat mingw  -- force MinGW-w64
:: ============================================================

setlocal enabledelayedexpansion

:: ── Verify we are actually targeting x64 ──────────────────────────────────────
if /i "%VSCMD_ARG_TGT_ARCH%"=="x64" goto :ARCH_OK
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    if "%VSCMD_ARG_TGT_ARCH%"=="" (
        echo [*] Not in a VS prompt. Trying to locate vcvars64.bat...
        for /f "delims=" %%i in ('where /r "%ProgramFiles%\Microsoft Visual Studio" vcvars64.bat 2^>nul') do (
            call "%%i"
            goto :ARCH_OK
        )
        echo [ERROR] Could not find vcvars64.bat. Open an x64 Native Tools Command Prompt for VS.
        exit /b 1
    )
)
if /i not "%VSCMD_ARG_TGT_ARCH%"=="x64" (
    echo [ERROR] You are in a %VSCMD_ARG_TGT_ARCH% prompt. Please open:
    echo         "x64 Native Tools Command Prompt for VS 20xx"
    echo         Start menu ^> search "x64 Native Tools"
    exit /b 1
)
:ARCH_OK
echo [*] Target arch: x64

:: ── Locate MinHook lib (handle both naming conventions) ───────────────────────
set MINHOOK_LIB=
if exist "lib\MinHook.x64.lib"    set MINHOOK_LIB=lib\MinHook.x64.lib
if exist "lib\libMinHook.x64.lib" set MINHOOK_LIB=lib\libMinHook.x64.lib

if "%MINHOOK_LIB%"=="" (
    echo [ERROR] MinHook lib not found. Place one of these in lib\:
    echo           lib\MinHook.x64.lib
    echo           lib\libMinHook.x64.lib
    echo         Download from: https://github.com/TsudaKageyu/minhook/releases
    exit /b 1
)
echo [*] Using MinHook lib: %MINHOOK_LIB%

:: ── Check MinHook header ──────────────────────────────────────────────────────
if not exist "include\MinHook.h" (
    echo [ERROR] include\MinHook.h not found.
    echo         Download from: https://github.com/TsudaKageyu/minhook/releases
    exit /b 1
)

:: ── Create output dirs ────────────────────────────────────────────────────────
if not exist bin mkdir bin

set COMPILER=%1
if /i "%COMPILER%"=="mingw" goto :MINGW

:: ── MSVC ──────────────────────────────────────────────────────────────────────
:MSVC
echo [Build] Using MSVC (x64)...

:: Hook DLL — /LD = build DLL, /Fe sets output name
cl /LD /EHsc /O2 /W3 ^
   /I "include" ^
   "src\hook_dll.cpp" ^
   /Fe"bin\SleepMonitorHook.dll" ^
   /link /MACHINE:X64 ^
   "%MINHOOK_LIB%" ^
   psapi.lib shlwapi.lib advapi32.lib
if errorlevel 1 ( echo [FAIL] Hook DLL & exit /b 1 )

:: Monitor EXE
cl /EHsc /O2 /W3 ^
   /I "include" ^
   "src\monitor.cpp" ^
   /Fe"bin\SleepMonitor.exe" ^
   /link /MACHINE:X64 ^
    psapi.lib shlwapi.lib advapi32.lib
if errorlevel 1 ( echo [FAIL] Monitor EXE & exit /b 1 )

goto :DONE

:: ── MinGW ─────────────────────────────────────────────────────────────────────
:MINGW
echo [Build] Using MinGW-w64 (x64)...

g++ -shared -O2 -m64 ^
    -I include ^
    src\hook_dll.cpp ^
    -o bin\SleepMonitorHook.dll ^
    -L lib -lMinHook.x64 ^
    -lpsapi -lshlwapi ^
    -static-libgcc -static-libstdc++
if errorlevel 1 ( echo [FAIL] Hook DLL & exit /b 1 )

g++ -O2 -m64 ^
    -I include ^
    src\monitor.cpp ^
    -o bin\SleepMonitor.exe ^
    -lpsapi -lshlwapi ^
    -static-libgcc -static-libstdc++
if errorlevel 1 ( echo [FAIL] Monitor EXE & exit /b 1 )

goto :DONE

:DONE
echo.
echo [OK] Build complete.
echo      bin\SleepMonitorHook.dll   -- injected into target processes
echo      bin\SleepMonitor.exe       -- run as Administrator
echo.
echo [*] Copy config\allowlist.json next to SleepMonitor.exe before running.
