/*
 * SleepMonitor.exe  —  Monitor & Injector
 * ========================================
 * 1. INJECTION  — scans running processes every SCAN_INTERVAL_MS,
 *    injects SleepMonitorHook.dll via CreateRemoteThread + LoadLibraryW.
 *
 * 2. PIPE SERVER — always keeps at least one named pipe instance in the
 *    ConnectNamedPipe wait state so hook DLLs never get ERROR_PIPE_BUSY.
 *    Each connected client is handed off to a worker thread immediately,
 *    and a fresh server instance is created before the worker starts,
 *    eliminating the race window that caused lost alerts.
 *
 * Build (x64 Native Tools Command Prompt):
 *   cl /EHsc /O2 /I"include" src\monitor.cpp /Fe"bin\SleepMonitor.exe"
 *      /link /MACHINE:X64 psapi.lib shlwapi.lib
 *
 * Run as Administrator.
 * Usage:
 *   SleepMonitor.exe [allowlist.json]
 *   SleepMonitor.exe --add    <proc.exe> [reason]
 *   SleepMonitor.exe --remove <proc.exe>
 *   SleepMonitor.exe --list
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string>
#include <set>
#include <thread>
#include <atomic>
#include <mutex>
#include <sstream>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#include "allowlist.h"

// ── Configuration ─────────────────────────────────────────────────────────────
static constexpr DWORD SCAN_INTERVAL_MS = 2000;   // check for new processes every 2 s
static const wchar_t*  PIPE_NAME        = L"\\\\.\\pipe\\SleepMonitorPipe";
static const char*     DEFAULT_ALLOWLIST= "allowlist.json";
static const wchar_t*  HOOK_DLL_NAME    = L"SleepMonitorHook.dll";

// ── Target filter ─────────────────────────────────────────────────────────────
// Only inject into processes whose basename matches this name (case-insensitive).
// Set to nullptr to inject into every non-allowlisted process.
static const char* TARGET_PROCESS = nullptr;

// ── Globals ───────────────────────────────────────────────────────────────────
static std::set<DWORD>   g_injectedPIDs;
static std::mutex        g_pidMutex;
static std::atomic<bool> g_running{true};
static wchar_t           g_dllPath[MAX_PATH] = {};

// ── Console colour ────────────────────────────────────────────────────────────
enum class Color { Default, Red, Yellow, Cyan, Green };

static void SetColor(Color c)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    switch (c)
    {
    case Color::Red:    attr = FOREGROUND_RED   | FOREGROUND_INTENSITY; break;
    case Color::Yellow: attr = FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
    case Color::Cyan:   attr = FOREGROUND_GREEN | FOREGROUND_BLUE  | FOREGROUND_INTENSITY; break;
    case Color::Green:  attr = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
    default: break;
    }
    SetConsoleTextAttribute(h, attr);
}
static void ResetColor()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
                            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// ── JSON field extractor ──────────────────────────────────────────────────────
static std::string JsonGet(const std::string& json, const std::string& key)
{
    std::string needle = "\"" + key + "\":";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (json[pos] == '"')
    {
        auto end = json.find('"', pos + 1);
        return json.substr(pos + 1, end - pos - 1);
    }
    auto end = json.find_first_of(",}\n", pos);
    return json.substr(pos, end - pos);
}

// ── Injection helpers ─────────────────────────────────────────────────────────
static void ResolveHookDllPath()
{
    GetModuleFileNameW(nullptr, g_dllPath, MAX_PATH);
    PathRemoveFileSpecW(g_dllPath);
    wcscat_s(g_dllPath, L"\\");
    wcscat_s(g_dllPath, HOOK_DLL_NAME);
}

static bool IsAlreadyInjected(HANDLE hProcess)
{
    HMODULE mods[1024] = {}; 
    DWORD needed = 0;
    // EnumProcessModules can fail if the process is exiting or is a different
    // bitness. Treat any failure as "not injected" so we attempt injection,
    // which will then also fail safely.
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed))
        return false;
    DWORD count = min(needed / sizeof(HMODULE), (DWORD)1024);
    for (DWORD i = 0; i < count; i++)
    {
        if (!mods[i]) continue;
        wchar_t name[MAX_PATH] = {};
        if (!GetModuleFileNameExW(hProcess, mods[i], name, MAX_PATH)) continue;
        if (_wcsicmp(PathFindFileNameW(name), HOOK_DLL_NAME) == 0)
            return true;
    }
    return false;
}

static bool InjectDll(DWORD pid)
{
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess)
    {
        // ERROR_INVALID_PARAMETER (87) = PID vanished between snapshot and OpenProcess.
        // ERROR_ACCESS_DENIED (5)      = protected/system process, expected and safe to skip.
        // Only print genuinely unexpected errors.
        DWORD err = GetLastError();
        if (err != ERROR_INVALID_PARAMETER && err != ERROR_ACCESS_DENIED)
            printf("[!] OpenProcess PID %lu failed: err=%lu\n",
                   (unsigned long)pid, (unsigned long)err);
        return false;
    }

    if (IsAlreadyInjected(hProcess)) { CloseHandle(hProcess); return true; }

    // Verify the DLL file actually exists at the resolved path
    if (GetFileAttributesW(g_dllPath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[!] Hook DLL not found at: %ls\n", g_dllPath);
        CloseHandle(hProcess);
        return false;
    }

    // Check bitness: a 64-bit DLL cannot load into a 32-bit process.
    // IsWow64Process returns TRUE when a 32-bit process runs on 64-bit Windows.
    BOOL targetIsWow64 = FALSE;
    IsWow64Process(hProcess, &targetIsWow64);
    BOOL selfIsWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &selfIsWow64);
    if (targetIsWow64 != selfIsWow64)
    {
        // Mismatch — skip silently (would need a separate x86 hook DLL)
        CloseHandle(hProcess);
        return false;
    }

    size_t pathBytes = (wcslen(g_dllPath) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(hProcess, nullptr, pathBytes,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
    {
        printf("[!] VirtualAllocEx PID %lu failed: err=%lu\n",
               (unsigned long)pid, (unsigned long)GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remote, g_dllPath, pathBytes, nullptr))
    {
        printf("[!] WriteProcessMemory PID %lu failed: err=%lu\n",
               (unsigned long)pid, (unsigned long)GetLastError());
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC loadLib = GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE)loadLib,
                                        remote, 0, nullptr);
    if (!hThread)
    {
        printf("[!] CreateRemoteThread PID %lu failed: err=%lu\n",
               (unsigned long)pid, (unsigned long)GetLastError());
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, 5000);

    // LoadLibraryW returns the HMODULE of the loaded DLL, or NULL on failure.
    // The remote thread exit code IS that return value.
    // If it is 0, the DLL failed to load (wrong arch, missing dependency, etc.)
    DWORD loadResult = 0;
    GetExitCodeThread(hThread, &loadResult);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (loadResult == 0)
    {
        // Only print the first failure with full detail to avoid flooding the console.
        static bool s_firstFailure = true;
        if (s_firstFailure)
        {
            s_firstFailure = false;
            printf("[!] LoadLibraryW failed in PID %lu (returned NULL)\n"
                   "    Most likely cause: VC++ runtime not present in target.\n"
                   "    Fix: rebuild hook DLL with /MT (static CRT):\n"
                   "      cl /LD /EHsc /O2 /MT /I\"include\" src\\hook_dll.cpp\n"
                   "         /Fe\"bin\\SleepMonitorHook.dll\"\n"
                   "         /link /MACHINE:X64 lib\\MinHook.x64.lib psapi.lib shlwapi.lib\n"
                   "    (further LoadLibraryW failures will be suppressed)\n",
                   (unsigned long)pid);
        }
        return false;
    }

    return true;
}

static bool IsSystemProcess(DWORD pid) { return pid == 0 || pid == 4; }

// ── Scanner thread ────────────────────────────────────────────────────────────
// ScanOnce is a plain C-style function (no C++ objects) so __try/__except works.
static DWORD ScanOnce()
{
    DWORD injected = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            DWORD pid = pe.th32ProcessID;
            if (IsSystemProcess(pid)) continue;

            {
                std::lock_guard<std::mutex> lk(g_pidMutex);
                if (g_injectedPIDs.count(pid)) continue;
            }

            char narrow[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                narrow, MAX_PATH, nullptr, nullptr);

            if (TARGET_PROCESS && _stricmp(narrow, TARGET_PROCESS) != 0)
                continue;

            if (AllowlistManager::Instance().IsAllowed(narrow)) continue;

            if (InjectDll(pid))
            {
                std::lock_guard<std::mutex> lk(g_pidMutex);
                g_injectedPIDs.insert(pid);
                SetColor(Color::Cyan);
                printf("[+] Injected  PID %-6lu  %s\n",
                       (unsigned long)pid, narrow);
                ResetColor();
                injected++;
            }

        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return injected;
}

// Thin SEH wrapper — no C++ objects here so __try is allowed.
static void ScanOnceSafe(DWORD scanCount)
{
    __try
    {
        ScanOnce();
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        SetColor(Color::Yellow);
        printf("[!] Scanner exception 0x%08lX on scan #%lu - continuing\n",
               (unsigned long)GetExceptionCode(), (unsigned long)scanCount);
        ResetColor();
    }
}

static void ScannerThread()
{
    printf("[*] Scanner thread started.\n");
    DWORD scanCount = 0;

    while (g_running)
    {
        ScanOnceSafe(++scanCount);
        Sleep(SCAN_INTERVAL_MS);
    }

    printf("[!] Scanner thread exited after %lu scans.\n", (unsigned long)scanCount);
}

// ── Pipe client worker ────────────────────────────────────────────────────────
static void HandlePipeClient(HANDLE hPipe)
{
    char buf[4096] = {};
    DWORD read = 0;

    while (ReadFile(hPipe, buf, sizeof(buf) - 1, &read, nullptr) && read > 0)
    {
        buf[read] = '\0';
        std::istringstream stream(buf);
        std::string line;

        while (std::getline(stream, line))
        {
            if (line.empty()) continue;

            std::string process = JsonGet(line, "process");
            std::string fn      = JsonGet(line, "fn");
            std::string ms      = JsonGet(line, "ms");
            std::string pid     = JsonGet(line, "pid");

            if (AllowlistManager::Instance().IsAllowed(process)) continue;

            // Human-readable duration
            DWORD msVal = ms.empty() ? 0 : (DWORD)std::stoul(ms);
            char  duration[64] = {};
            if      (msVal >= 3600000) sprintf_s(duration, "%.1f hr",  msVal / 3600000.0);
            else if (msVal >= 60000)   sprintf_s(duration, "%.1f min", msVal / 60000.0);
            else                       sprintf_s(duration, "%lu ms",   (unsigned long)msVal);

            SYSTEMTIME st = {};
            GetLocalTime(&st);

            // Entire line in bright red
            SetColor(Color::Red);
            printf("[ALERT] %02d:%02d:%02d  PID %-6s  %-25s  %s(%s)\n",
                   st.wHour, st.wMinute, st.wSecond,
                   pid.c_str(), process.c_str(), fn.c_str(), duration);
            ResetColor();
        }
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}

// ── Pipe server ───────────────────────────────────────────────────────────────
// KEY FIX: create the NEXT pipe instance BEFORE handing the current client
// to a worker thread. This ensures there is always a waiting server instance
// and hook DLLs never receive ERROR_PIPE_BUSY.
static HANDLE CreatePipeInstance()
{
    // Grant write access to Everyone so injected DLLs running as normal users
    // (or in lower-integrity processes) can connect. Without this, CreateFileW
    // inside the target process fails with ERROR_ACCESS_DENIED (err=5).
    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    // NULL DACL = allow all access from any account/integrity level
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle       = FALSE;

    return CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        0, 4096,
        100,
        &sa);   // <-- pass security attributes instead of nullptr
}

static void PipeServerThread()
{
    HANDLE hPipe = CreatePipeInstance();

    while (g_running)
    {
        if (hPipe == INVALID_HANDLE_VALUE)
        {
            Sleep(200);
            hPipe = CreatePipeInstance();
            continue;
        }

        // Block until a hook DLL connects
        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            CloseHandle(hPipe);
            hPipe = CreatePipeInstance();
            continue;
        }

        // Create the next waiting instance BEFORE spawning the worker,
        // so there is zero gap where the pipe has no server instance.
        HANDLE hNext = CreatePipeInstance();

        // Hand current connection to a detached worker thread
        HANDLE hCurrent = hPipe;
        std::thread([hCurrent]{ HandlePipeClient(hCurrent); }).detach();

        hPipe = hNext;
    }

    CloseHandle(hPipe);
}

// ── Stale PID cleanup ─────────────────────────────────────────────────────────
static void CleanupThread()
{
    while (g_running)
    {
        Sleep(15000);
        std::lock_guard<std::mutex> lk(g_pidMutex);
        for (auto it = g_injectedPIDs.begin(); it != g_injectedPIDs.end(); )
        {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, *it);
            if (!h) { it = g_injectedPIDs.erase(it); continue; }
            DWORD code = 0;
            GetExitCodeProcess(h, &code);
            CloseHandle(h);
            it = (code != STILL_ACTIVE) ? g_injectedPIDs.erase(it) : std::next(it);
        }
    }
}

// ── Ctrl+C handler ────────────────────────────────────────────────────────────
static BOOL WINAPI ConsoleHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT)
    {
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

// ── Entry point ───────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    const char* allowlistPath = DEFAULT_ALLOWLIST;

    // Sub-commands (--add, --remove, --list) removed
    // Edit allowlist.json directly to modify the allowlist

    // Monitor mode
    AllowlistManager::Instance().Load(allowlistPath);
    ResolveHookDllPath();
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    SetColor(Color::Green);
    puts("==========================================");
    puts("      Sleep Monitor -- Defense Tool       ");
    puts("==========================================");
    ResetColor();

    printf("  Threshold : %lu ms\n",
           (unsigned long)AllowlistManager::Instance().ThresholdMs());
    printf("  Allowlist : %s\n", allowlistPath);
    printf("  Hook DLL  : %ls\n", g_dllPath);
    printf("  Scan rate : %lu ms\n\n", (unsigned long)SCAN_INTERVAL_MS);

    puts("  Edit allowlist.json directly to add/remove processes.\n");

    printf("  Debug log : C:\\SleepMonitorHook.log\n");
    puts("  Press Ctrl+C to stop.\n");

    std::thread(PipeServerThread).detach();
    std::thread(CleanupThread).detach();
    ScannerThread(); // blocks until Ctrl+C

    puts("\n[*] Shutting down.");
    return 0;
}