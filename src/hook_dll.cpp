/*
 * SleepMonitor Hook DLL
 * =====================
 * Injects into target processes and hooks Sleep / SleepEx via MinHook.
 * Communicates alerts to SleepMonitor.exe via named pipe.
 *
 * Build (x64 Native Tools Command Prompt):
 *   cl /LD /EHsc /O2 /I"include" src\hook_dll.cpp /Fe"bin\SleepMonitorHook.dll"
 *      /link /MACHINE:X64 lib\MinHook.x64.lib psapi.lib shlwapi.lib
 *
 * Debug log: R:\SleepMonitorHook.log  (delete file to disable logging)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include "MinHook.h"
#include <winternl.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// ── Configuration ─────────────────────────────────────────────────────────────
static constexpr DWORD THRESHOLD_MS    = 1000;   // flag sleeps >= 3 second
static constexpr DWORD PIPE_TIMEOUT_MS = 500;    // WaitNamedPipe timeout per attempt
static constexpr int   PIPE_RETRIES    = 5;      // attempts before dropping alert
static const wchar_t*  PIPE_NAME       = L"\\\\.\\pipe\\SleepMonitorPipe";
static const wchar_t*  LOG_PATH        = L"R:\\SleepMonitorHook.log";

// ── Original function pointers ────────────────────────────────────────────────
typedef VOID  (WINAPI *FnSleep)         (DWORD);
typedef DWORD (WINAPI *FnSleepEx)       (DWORD, BOOL);
// NtDelayExecution(Alertable, DelayInterval)
// DelayInterval is a LARGE_INTEGER in 100-nanosecond units; negative = relative.
typedef NTSTATUS (NTAPI *FnNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);

static FnSleep           g_origSleep           = nullptr;
static FnSleepEx         g_origSleepEx         = nullptr;
static FnNtDelayExecution g_origNtDelayExecution = nullptr;

// ── Debug log ─────────────────────────────────────────────────────────────────
// Writes timestamped lines to C:\SleepMonitorHook.log so you can confirm the
// hook fired even when the pipe isn't reachable.
static void DebugLog(const char* fmt, ...)
{
    FILE* f = nullptr;
    if (_wfopen_s(&f, LOG_PATH, L"a") != 0 || !f) return;

    SYSTEMTIME st = {};
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] PID%-5lu  ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            (unsigned long)GetCurrentProcessId());

    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);

    fputc('\n', f);
    fclose(f);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
static std::wstring GetCurrentProcessName()
{
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return PathFindFileNameW(buf);
}

// ── Pipe sender ───────────────────────────────────────────────────────────────
// The pipe server in monitor.exe spawns a thread per client but there is still
// a brief window between ConnectNamedPipe calls where the server is "full".
// When that happens CreateFileW fails with ERROR_PIPE_BUSY.
// WaitNamedPipeW blocks until a server slot is free, then we retry.
static void SendAlert(DWORD pid, const std::wstring& procName, DWORD ms, const char* fn)
{
    char narrow[MAX_PATH] = {};
    WideCharToMultiByte(CP_UTF8, 0, procName.c_str(), -1,
                        narrow, MAX_PATH, nullptr, nullptr);

    std::ostringstream js;
    js << "{\"pid\":"       << pid
       << ",\"process\":\"" << narrow << "\""
       << ",\"fn\":\""      << fn     << "\""
       << ",\"ms\":"        << ms     << "}\n";
    std::string msg = js.str();

    DebugLog("SendAlert -> %s", msg.c_str());

    for (int attempt = 0; attempt < PIPE_RETRIES; ++attempt)
    {
        HANDLE hPipe = CreateFileW(PIPE_NAME, GENERIC_WRITE,
                                   0, nullptr, OPEN_EXISTING, 0, nullptr);

        if (hPipe != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            BOOL  ok      = WriteFile(hPipe, msg.c_str(), (DWORD)msg.size(),
                                      &written, nullptr);
            CloseHandle(hPipe);
            DebugLog("WriteFile %s wrote=%lu", ok ? "OK" : "FAIL",
                     (unsigned long)written);
            return;
        }

        DWORD err = GetLastError();
        DebugLog("CreateFileW attempt %d err=%lu", attempt + 1, (unsigned long)err);

        if (err == ERROR_PIPE_BUSY)
            WaitNamedPipeW(PIPE_NAME, PIPE_TIMEOUT_MS);
        else
            return; // pipe doesn't exist (monitor not running)
    }

    DebugLog("All %d attempts failed, alert dropped.", PIPE_RETRIES);
}

// ── Hook stubs ────────────────────────────────────────────────────────────────
static VOID WINAPI HookedSleep(DWORD dwMilliseconds)
{
    DebugLog("HookedSleep %lu ms", (unsigned long)dwMilliseconds);
    if (dwMilliseconds >= THRESHOLD_MS)
        SendAlert(GetCurrentProcessId(), GetCurrentProcessName(),
                  dwMilliseconds, "Sleep");
    g_origSleep(dwMilliseconds);
}

static DWORD WINAPI HookedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    DebugLog("HookedSleepEx %lu ms alertable=%d",
             (unsigned long)dwMilliseconds, (int)bAlertable);
    if (dwMilliseconds >= THRESHOLD_MS)
        SendAlert(GetCurrentProcessId(), GetCurrentProcessName(),
                  dwMilliseconds, "SleepEx");
    return g_origSleepEx(dwMilliseconds, bAlertable);
}

// Converts a negative LARGE_INTEGER (100-ns units) to milliseconds.
// NtDelayExecution uses negative values for relative delays.
static DWORD LargeIntToMs(PLARGE_INTEGER li)
{
    if (!li || li->QuadPart >= 0) return 0; // absolute time or zero — ignore
    // QuadPart is negative; negate and convert 100-ns units -> ms
    return (DWORD)((-li->QuadPart) / 10000);
}

static NTSTATUS NTAPI HookedNtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER interval)
{
    DWORD ms = LargeIntToMs(interval);
    DebugLog("HookedNtDelayExecution %lu ms alertable=%d", (unsigned long)ms, (int)alertable);
    if (ms >= THRESHOLD_MS)
        SendAlert(GetCurrentProcessId(), GetCurrentProcessName(), ms, "NtDelayExecution");
    return g_origNtDelayExecution(alertable, interval);
}

// ── DLL entry point ───────────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        DebugLog("DLL_PROCESS_ATTACH");

        if (MH_Initialize() != MH_OK)
        {
            DebugLog("MH_Initialize FAILED");
            return FALSE;
        }

        MH_STATUS s1 = MH_CreateHookApi(L"kernel32", "Sleep",
                                         (LPVOID)HookedSleep,
                                         (LPVOID*)&g_origSleep);
        MH_STATUS s2 = MH_CreateHookApi(L"kernel32", "SleepEx",
                                         (LPVOID)HookedSleepEx,
                                         (LPVOID*)&g_origSleepEx);
        // NtDelayExecution lives in ntdll — hooking it catches callers that
        // bypass kernel32 entirely (e.g. .NET ThreadSleep, direct syscall wrappers).
        MH_STATUS s3 = MH_CreateHookApi(L"ntdll", "NtDelayExecution",
                                         (LPVOID)HookedNtDelayExecution,
                                         (LPVOID*)&g_origNtDelayExecution);
        DebugLog("CreateHookApi Sleep=%d SleepEx=%d NtDelayExecution=%d (0=OK)",
                 (int)s1, (int)s2, (int)s3);

        if (s1 != MH_OK || s2 != MH_OK || s3 != MH_OK)
            return FALSE;

        MH_STATUS se = MH_EnableHook(MH_ALL_HOOKS);
        DebugLog("EnableHook=%d (0=OK)", (int)se);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        DebugLog("DLL_PROCESS_DETACH");
    }
    return TRUE;
}
