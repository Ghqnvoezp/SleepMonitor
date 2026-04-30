/*
 * SleepMonitor Hook DLL
 * =====================
 * This DLL is injected into target processes by SleepMonitor.exe.
 * Once inside a target process it uses MinHook to intercept (hook) three
 * Windows sleep functions:
 *
 *   - Sleep()            in kernel32.dll
 *   - SleepEx()          in kernel32.dll
 *   - NtDelayExecution() in ntdll.dll  (catches bypasses of the above two)
 *
 * When any of those functions is called with a delay >= THRESHOLD_MS, the DLL
 * sends a JSON alert to SleepMonitor.exe over a named pipe.
 *
 * Build (x64 Native Tools Command Prompt):
 *   cl /LD /EHsc /O2 /MT /I"include" /I"C:\minhook\include" src\hook_dll.cpp
 *      /Fe"bin\SleepMonitorHook.dll"
 *      /link /MACHINE:X64 lib\MinHook_static.lib psapi.lib shlwapi.lib
 *
 * Debug log written to: R:\SleepMonitorHook.log
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>   // core Win32 types and API
#include <psapi.h>     // GetModuleFileNameExW - needed to get current process name
#include <shlwapi.h>   // PathFindFileNameW - strips directory from a path
#include <stdio.h>     // fprintf, fopen etc for the debug log
#include <string>      // std::wstring, std::string
#include <sstream>     // std::ostringstream - used to build JSON alert strings
#include "MinHook.h"   // MinHook API - MH_Initialize, MH_CreateHookApi etc
#include <winternl.h>  // NTSTATUS type used by NtDelayExecution

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// ── Configuration ─────────────────────────────────────────────────────────────
// Sleep calls with a delay at or above this value trigger an alert.
// Note: this is the DLL-side hardcoded fallback. The monitor broadcasts the
// real threshold via shared memory (see LoadThresholdFromSharedMemory).
static constexpr DWORD THRESHOLD_MS    = 1000;  // flag sleeps >= 1 second
// How long (ms) to wait for the pipe server to free up before retrying.
static constexpr DWORD PIPE_TIMEOUT_MS = 500;
// How many times to retry connecting to the pipe before giving up on an alert.
static constexpr int   PIPE_RETRIES    = 5;
// Named pipe path - must match the name used in monitor.exe's PipeServerThread.
static const wchar_t*  PIPE_NAME       = L"\\\\.\\pipe\\SleepMonitorPipe";
// Debug log file path. Every hook event is written here so you can diagnose
// problems even when the pipe isn't reachable.
static const wchar_t*  LOG_PATH        = L"R:\\SleepMonitorHook.log";

// ── Original function pointer typedefs ───────────────────────────────────────
// Before MinHook patches the real functions, it saves their original addresses
// into these pointers via the ppOriginal argument of MH_CreateHookApi.
// Our hook stubs call through these pointers so the target process still
// executes the real sleep - we're intercepting, not blocking.
typedef VOID     (WINAPI *FnSleep)           (DWORD);
typedef DWORD    (WINAPI *FnSleepEx)         (DWORD, BOOL);
// NtDelayExecution signature: Alertable flag + pointer to 100-ns delay interval
// (negative value = relative time, positive = absolute time).
typedef NTSTATUS (NTAPI  *FnNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);

// Populated by MH_CreateHookApi - point to trampolines that call the real functions.
static FnSleep            g_origSleep            = nullptr;
static FnSleepEx          g_origSleepEx          = nullptr;
static FnNtDelayExecution g_origNtDelayExecution = nullptr;

// ── Debug log ─────────────────────────────────────────────────────────────────
// Appends a timestamped, PID-prefixed line to the log file.
// Called at every significant event: DLL attach, hook setup results,
// every sleep interception, and every pipe send attempt.
// If the log file can't be opened (e.g. drive R: doesn't exist) the call
// silently does nothing - it will not crash the target process.
static void DebugLog(const char* fmt, ...)
{
    FILE* f = nullptr;
    // Open in append mode so entries accumulate across multiple injected processes
    if (_wfopen_s(&f, LOG_PATH, L"a") != 0 || !f) return;

    SYSTEMTIME st = {};
    GetLocalTime(&st);
    // Format: [HH:MM:SS.mmm] PIDxxxxx  <message>
    fprintf(f, "[%02d:%02d:%02d.%03d] PID%-5lu  ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            (unsigned long)GetCurrentProcessId());

    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);

    fputc('\n', f);
    fclose(f); // close immediately - keeps the file consistent across processes
}

// ── Process name helper ───────────────────────────────────────────────────────
// Returns just the filename portion of the current process's image path,
// e.g. "sleeper.exe" rather than "C:\Users\...\sleeper.exe".
// Used when building the JSON alert payload.
static std::wstring GetCurrentProcessName()
{
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH); // nullptr = current process module
    return PathFindFileNameW(buf);              // strips directory component
}

// ── Pipe sender ───────────────────────────────────────────────────────────────
// Serialises an alert as a JSON line and writes it to the named pipe that
// SleepMonitor.exe's PipeServerThread is listening on.
//
// Why the retry loop?
// The pipe server in monitor.exe hands each connection off to a worker thread
// and immediately creates the next waiting instance. But there is still a tiny
// window between ConnectNamedPipe returning and CreateNamedPipeW being called
// where no server instance exists. If we hit that window, CreateFileW returns
// INVALID_HANDLE_VALUE with ERROR_PIPE_BUSY. WaitNamedPipeW blocks until a
// server slot is available, then we try again.
static void SendAlert(DWORD pid, const std::wstring& procName, DWORD ms, const char* fn)
{
    // Convert the wide process name to UTF-8 for the JSON string
    char narrow[MAX_PATH] = {};
    WideCharToMultiByte(CP_UTF8, 0, procName.c_str(), -1,
                        narrow, MAX_PATH, nullptr, nullptr);

    // Build the JSON alert line, e.g.:
    // {"pid":1234,"process":"sleeper.exe","fn":"SleepEx","ms":13000}
    std::ostringstream js;
    js << "{\"pid\":"       << pid
       << ",\"process\":\"" << narrow << "\""
       << ",\"fn\":\""      << fn     << "\""
       << ",\"ms\":"        << ms     << "}\n";
    std::string msg = js.str();

    DebugLog("SendAlert -> %s", msg.c_str());

    for (int attempt = 0; attempt < PIPE_RETRIES; ++attempt)
    {
        // Try to open the pipe for writing.
        // OPEN_EXISTING means this will fail immediately if no server instance
        // is waiting - we never block here, only in WaitNamedPipeW below.
        HANDLE hPipe = CreateFileW(PIPE_NAME, GENERIC_WRITE,
                                   0, nullptr, OPEN_EXISTING, 0, nullptr);

        if (hPipe != INVALID_HANDLE_VALUE)
        {
            // Connected - write the alert and close immediately.
            // Each alert is a self-contained message so we don't need to keep
            // the connection open.
            DWORD written = 0;
            BOOL  ok = WriteFile(hPipe, msg.c_str(), (DWORD)msg.size(),
                                 &written, nullptr);
            CloseHandle(hPipe);
            DebugLog("WriteFile %s wrote=%lu", ok ? "OK" : "FAIL",
                     (unsigned long)written);
            return;
        }

        DWORD err = GetLastError();
        DebugLog("CreateFileW attempt %d err=%lu", attempt + 1, (unsigned long)err);

        if (err == ERROR_PIPE_BUSY)
            // A server instance exists but is busy - wait up to PIPE_TIMEOUT_MS
            // for it to finish with its current client, then retry.
            WaitNamedPipeW(PIPE_NAME, PIPE_TIMEOUT_MS);
        else
            // ERROR_FILE_NOT_FOUND means monitor.exe isn't running or has shut
            // down. No point retrying - drop the alert silently.
            return;
    }

    DebugLog("All %d attempts failed, alert dropped.", PIPE_RETRIES);
}

// ── Hook stubs ────────────────────────────────────────────────────────────────
// These three functions replace the first bytes of Sleep, SleepEx, and
// NtDelayExecution in the target process via MinHook's JMP patch.
// Every call to those functions in any thread of the target process now
// lands here first.

// Replacement for kernel32!Sleep.
// Called with the same argument the target code passed to Sleep().
static VOID WINAPI HookedSleep(DWORD dwMilliseconds)
{
    DebugLog("HookedSleep %lu ms", (unsigned long)dwMilliseconds);

    // Only alert if the requested delay meets or exceeds the threshold.
    if (dwMilliseconds >= THRESHOLD_MS)
        SendAlert(GetCurrentProcessId(), GetCurrentProcessName(),
                  dwMilliseconds, "Sleep");

    // Always call the original function through the MinHook trampoline so
    // the target process actually sleeps as requested.
    g_origSleep(dwMilliseconds);
}

// Replacement for kernel32!SleepEx.
// bAlertable=TRUE means the sleep can be interrupted by APCs (async procedure
// calls), which is common in alertable wait patterns used by malware.
static DWORD WINAPI HookedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    DebugLog("HookedSleepEx %lu ms alertable=%d",
             (unsigned long)dwMilliseconds, (int)bAlertable);

    if (dwMilliseconds >= THRESHOLD_MS)
        SendAlert(GetCurrentProcessId(), GetCurrentProcessName(),
                  dwMilliseconds, "SleepEx");

    // Pass through to the real SleepEx and return its result (WAIT_IO_COMPLETION
    // or 0) back to the caller unchanged.
    return g_origSleepEx(dwMilliseconds, bAlertable);
}

// Converts a LARGE_INTEGER delay (100-nanosecond units) to milliseconds.
// NtDelayExecution uses negative values for relative delays (the common case).
// Positive values are absolute times - we ignore those as they're rare and
// harder to threshold meaningfully.
static DWORD LargeIntToMs(PLARGE_INTEGER li)
{
    if (!li || li->QuadPart >= 0) return 0; // null or absolute time - skip
    // Negate to get a positive count, then divide: 1 ms = 10,000 * 100 ns
    return (DWORD)((-li->QuadPart) / 10000);
}

// Replacement for ntdll!NtDelayExecution.
// This is the kernel boundary call that both Sleep() and SleepEx() ultimately
// call. Hooking it catches callers that bypass kernel32 entirely, such as
// .NET's Thread.Sleep, Go runtime timers, and hand-rolled syscall wrappers
// sometimes used by malware to evade userland hooks on Sleep/SleepEx.
static NTSTATUS NTAPI HookedNtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER interval)
{
    DWORD ms = LargeIntToMs(interval);
    DebugLog("HookedNtDelayExecution %lu ms alertable=%d",
             (unsigned long)ms, (int)alertable);

    if (ms >= THRESHOLD_MS)
        SendAlert(GetCurrentProcessId(), GetCurrentProcessName(),
                  ms, "NtDelayExecution");

    // Forward to the real NtDelayExecution via the trampoline.
    return g_origNtDelayExecution(alertable, interval);
}

// ── DLL entry point ───────────────────────────────────────────────────────────
// Windows calls DllMain whenever the DLL is loaded or unloaded from a process.
// DLL_PROCESS_ATTACH fires once when LoadLibraryW succeeds (called by our
// injector's remote thread). DLL_PROCESS_DETACH fires when the process exits
// or FreeLibrary is called.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        // Disable DLL_THREAD_ATTACH / DLL_THREAD_DETACH notifications.
        // We don't need per-thread callbacks and this improves performance
        // in processes with many threads.
        DisableThreadLibraryCalls(hModule);
        DebugLog("DLL_PROCESS_ATTACH");

        // Step 1: initialise MinHook's internal allocator.
        // This allocates trampolines near existing code so relative JMPs
        // can reach them within the ±2 GB x64 addressing constraint.
        if (MH_Initialize() != MH_OK)
        {
            DebugLog("MH_Initialize FAILED");
            return FALSE; // returning FALSE causes LoadLibrary to fail
        }

        // Step 2: prepare hooks for each target function.
        // MH_CreateHookApi locates the export by name in the specified DLL,
        // allocates a trampoline containing the original first bytes of the
        // function plus a JMP back to byte 6, and records HookedXxx as the
        // detour. The hook is NOT active yet after this call.
        MH_STATUS s1 = MH_CreateHookApi(L"kernel32", "Sleep",
                                         (LPVOID)HookedSleep,
                                         (LPVOID*)&g_origSleep);

        MH_STATUS s2 = MH_CreateHookApi(L"kernel32", "SleepEx",
                                         (LPVOID)HookedSleepEx,
                                         (LPVOID*)&g_origSleepEx);

        // Hook NtDelayExecution in ntdll to catch sleep calls that bypass
        // kernel32 (e.g. direct syscall stubs, .NET runtime, Go scheduler).
        MH_STATUS s3 = MH_CreateHookApi(L"ntdll", "NtDelayExecution",
                                         (LPVOID)HookedNtDelayExecution,
                                         (LPVOID*)&g_origNtDelayExecution);

        DebugLog("CreateHookApi Sleep=%d SleepEx=%d NtDelayExecution=%d (0=OK)",
                 (int)s1, (int)s2, (int)s3);

        if (s1 != MH_OK || s2 != MH_OK || s3 != MH_OK)
            return FALSE;

        // Step 3: activate all prepared hooks simultaneously.
        // MH_EnableHook(MH_ALL_HOOKS) calls VirtualProtect to make the first
        // bytes of each target function writable, overwrites them with a 5-byte
        // relative JMP to our detour, then restores page protection.
        // After this line returns, every thread in the process that calls
        // Sleep/SleepEx/NtDelayExecution will hit our hook stubs first.
        MH_STATUS se = MH_EnableHook(MH_ALL_HOOKS);
        DebugLog("EnableHook=%d (0=OK)", (int)se);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        // Remove all JMP patches and restore the original function bytes,
        // then free MinHook's internal allocations.
        // This is important so the target process doesn't crash after we
        // unload if any thread is about to call Sleep.
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        DebugLog("DLL_PROCESS_DETACH");
    }
    return TRUE;
}