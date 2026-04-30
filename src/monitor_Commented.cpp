/*
 * SleepMonitor.exe  —  Monitor & Injector
 * ========================================
 * Coordinates two activities running on separate threads:
 *
 * 1. INJECTION (ScannerThread)
 *    Every SCAN_INTERVAL_MS, takes a snapshot of all running processes and
 *    attempts to inject SleepMonitorHook.dll into any that are not on the
 *    allowlist and haven't already been injected. Uses the classic
 *    CreateRemoteThread + LoadLibraryW injection technique.
 *
 * 2. PIPE SERVER (PipeServerThread)
 *    Listens on a named pipe. Each injected hook DLL instance writes a JSON
 *    alert to the pipe whenever it intercepts a long sleep call. The server
 *    decodes the JSON and prints a red alert line to the console.
 *    A new pipe instance is always created BEFORE handing off a connected
 *    client to a worker thread, eliminating the race window where the pipe
 *    has no waiting server instance (which would cause ERROR_PIPE_BUSY in the
 *    hook DLL and silently drop the alert).
 *
 * Build (x64 Native Tools Command Prompt):
 *   cl /EHsc /O2 /MT /I"include" src\monitor.cpp /Fe"bin\SleepMonitor.exe"
 *      /link /MACHINE:X64 psapi.lib shlwapi.lib advapi32.lib
 *
 * Run as Administrator (required to open handles to other processes).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>   // core Win32 API
#include <tlhelp32.h>  // CreateToolhelp32Snapshot, Process32FirstW/NextW
#include <psapi.h>     // EnumProcessModules, GetModuleFileNameExW
#include <shlwapi.h>   // PathRemoveFileSpecW, PathFindFileNameW
#include <stdio.h>     // printf
#include <string>
#include <set>         // g_injectedPIDs - O(log n) lookup to skip already-injected
#include <thread>      // std::thread for pipe server and cleanup
#include <atomic>      // g_running - safe cross-thread shutdown flag
#include <mutex>       // g_pidMutex - protects g_injectedPIDs from concurrent access
#include <sstream>     // std::istringstream - parse pipe messages line by line

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// AllowlistManager - loads allowlist.json and provides IsAllowed() queries.
// Defined in include/allowlist.h (header-only).
#include "allowlist.h"

// ── Configuration ─────────────────────────────────────────────────────────────
// How often the scanner looks for new processes to inject into.
static constexpr DWORD SCAN_INTERVAL_MS = 2000;
// Named pipe path - must match PIPE_NAME in hook_dll.cpp exactly.
static const wchar_t*  PIPE_NAME        = L"\\\\.\\pipe\\SleepMonitorPipe";
// Default allowlist file path - loaded relative to the working directory.
static const char*     DEFAULT_ALLOWLIST= "allowlist.json";
// Filename of the hook DLL - resolved to a full path at startup by ResolveHookDllPath.
static const wchar_t*  HOOK_DLL_NAME    = L"SleepMonitorHook.dll";

// ── Target filter ─────────────────────────────────────────────────────────────
// When set to a process name, only that process will be injected into.
// Useful for focused testing. Set to nullptr to monitor all processes.
static const char* TARGET_PROCESS = nullptr;

// ── Global state ──────────────────────────────────────────────────────────────
// Set of PIDs that have already been successfully injected.
// Checked every scan so we don't inject the same process twice.
static std::set<DWORD>   g_injectedPIDs;
// Mutex protecting g_injectedPIDs - accessed from both scanner and cleanup threads.
static std::mutex        g_pidMutex;
// Set to false by ConsoleHandler (Ctrl+C) to signal all threads to exit.
static std::atomic<bool> g_running{true};
// Full path to SleepMonitorHook.dll, resolved once at startup.
// Written into target process memory as the argument to LoadLibraryW.
static wchar_t           g_dllPath[MAX_PATH] = {};

// ── Console colour helpers ────────────────────────────────────────────────────
// SetConsoleTextAttribute changes the colour of subsequent printf output.
// Used to make injections cyan, alerts red, and errors yellow.
enum class Color { Default, Red, Yellow, Cyan, Green };

static void SetColor(Color c)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    // Default: white (all three channels on, no intensity)
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
    // Restore plain white text
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
                            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// ── Minimal JSON field extractor ──────────────────────────────────────────────
// Extracts the value for a given key from a flat JSON object string.
// Not a general JSON parser - only handles the specific alert format:
// {"pid":1234,"process":"foo.exe","fn":"Sleep","ms":5000}
// Returns empty string if the key is not found.
static std::string JsonGet(const std::string& json, const std::string& key)
{
    std::string needle = "\"" + key + "\":";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    // Skip any whitespace between : and the value
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (json[pos] == '"')
    {
        // String value - find the closing quote
        auto end = json.find('"', pos + 1);
        return json.substr(pos + 1, end - pos - 1);
    }
    // Numeric value - read until delimiter
    auto end = json.find_first_of(",}\n", pos);
    return json.substr(pos, end - pos);
}

// ── Injection helpers ─────────────────────────────────────────────────────────

// Builds the full absolute path to SleepMonitorHook.dll by taking the directory
// of the running SleepMonitor.exe and appending the DLL filename.
// This means the hook DLL must be in the same folder as the monitor exe.
static void ResolveHookDllPath()
{
    GetModuleFileNameW(nullptr, g_dllPath, MAX_PATH); // get our own exe path
    PathRemoveFileSpecW(g_dllPath);                   // strip the filename
    wcscat_s(g_dllPath, L"\\");
    wcscat_s(g_dllPath, HOOK_DLL_NAME);               // append hook DLL name
}

// Checks whether SleepMonitorHook.dll is already loaded in the given process
// by enumerating its loaded modules and comparing filenames.
// Prevents double-injection if the scanner sees a PID it already injected
// before the PID was added to g_injectedPIDs (e.g. after a crash/restart).
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
        // Case-insensitive comparison of just the filename portion
        if (_wcsicmp(PathFindFileNameW(name), HOOK_DLL_NAME) == 0)
            return true;
    }
    return false;
}

// Injects SleepMonitorHook.dll into the process identified by pid.
// Technique: allocate memory in the target for the DLL path string, then
// spawn a remote thread whose start address is LoadLibraryW. Windows runs
// LoadLibraryW inside the target process, which loads and initialises our DLL.
// Returns true if injection succeeded (LoadLibraryW returned a non-null HMODULE).
static bool InjectDll(DWORD pid)
{
    // Open the target process with all permissions needed for injection.
    // This will fail with ERROR_ACCESS_DENIED for protected/system processes.
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess)
    {
        DWORD err = GetLastError();
        // 87 = process died between snapshot and OpenProcess - harmless race, suppress.
        // 5  = access denied on protected process - expected, suppress.
        if (err != ERROR_INVALID_PARAMETER && err != ERROR_ACCESS_DENIED)
            printf("[!] OpenProcess PID %lu failed: err=%lu\n",
                   (unsigned long)pid, (unsigned long)err);
        return false;
    }

    // Skip if the hook DLL is already loaded in this process
    if (IsAlreadyInjected(hProcess)) { CloseHandle(hProcess); return true; }

    // Make sure the DLL file exists before attempting injection.
    // If it's missing, every injection will fail with a confusing NULL result.
    if (GetFileAttributesW(g_dllPath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[!] Hook DLL not found at: %ls\n", g_dllPath);
        CloseHandle(hProcess);
        return false;
    }

    // Bitness check: a 64-bit DLL cannot be loaded into a 32-bit process.
    // IsWow64Process returns TRUE for 32-bit processes running on 64-bit Windows.
    // If the target and monitor have mismatched bitness, skip silently.
    BOOL targetIsWow64 = FALSE;
    IsWow64Process(hProcess, &targetIsWow64);
    BOOL selfIsWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &selfIsWow64);
    if (targetIsWow64 != selfIsWow64)
    {
        CloseHandle(hProcess);
        return false;
    }

    // Allocate memory in the target process to hold the DLL path string.
    // LoadLibraryW needs to read this path from within the target's address space.
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

    // Copy the DLL path string into the target process's memory.
    if (!WriteProcessMemory(hProcess, remote, g_dllPath, pathBytes, nullptr))
    {
        printf("[!] WriteProcessMemory PID %lu failed: err=%lu\n",
               (unsigned long)pid, (unsigned long)GetLastError());
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of LoadLibraryW in our own kernel32.dll.
    // Because kernel32.dll is always loaded at the same base address in every
    // process on the same Windows session, this address is valid in the target too.
    FARPROC loadLib = GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW");

    // Create a thread in the target process that runs LoadLibraryW(g_dllPath).
    // This causes Windows to load our hook DLL into the target, triggering DllMain.
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

    // Wait up to 5 seconds for LoadLibraryW to complete inside the target.
    WaitForSingleObject(hThread, 5000);

    // The thread exit code is the return value of LoadLibraryW.
    // LoadLibraryW returns the HMODULE on success, or NULL on failure.
    // If NULL, the DLL failed to load (wrong arch, missing dependency, etc.)
    DWORD loadResult = 0;
    GetExitCodeThread(hThread, &loadResult);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (loadResult == 0)
    {
        // Only print the full diagnostic once to avoid flooding the console.
        static bool s_firstFailure = true;
        if (s_firstFailure)
        {
            s_firstFailure = false;
            printf("[!] LoadLibraryW failed in PID %lu (returned NULL)\n"
                   "    Most likely cause: missing dependency (MinHook DLL or CRT).\n"
                   "    Fix: rebuild hook DLL with /MT and link MinHook_static.lib.\n"
                   "    (further LoadLibraryW failures will be suppressed)\n",
                   (unsigned long)pid);
        }
        return false;
    }

    return true;
}

// Returns true for PIDs that must never be injected regardless of allowlist.
// PID 0 = System Idle, PID 4 = System kernel process.
static bool IsSystemProcess(DWORD pid) { return pid == 0 || pid == 4; }

// ── Scanner ───────────────────────────────────────────────────────────────────

// Performs one full scan: snapshots all running processes and attempts to
// inject into any that pass the allowlist and target filter checks.
// Returns the number of new processes successfully injected this scan.
static int ScanOnce()
{
    int injected = 0;

    // CreateToolhelp32Snapshot captures a point-in-time list of all processes.
    // TH32CS_SNAPPROCESS = include process entries in the snapshot.
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe); // must be set before first call

    if (!Process32FirstW(snap, &pe))
    {
        CloseHandle(snap);
        return 0;
    }

    do
    {
        DWORD pid = pe.th32ProcessID;

        // Never touch the system idle or kernel processes
        if (IsSystemProcess(pid)) continue;

        // Skip if already injected - check under lock to avoid races with
        // the cleanup thread which may be removing dead PIDs concurrently.
        {
            std::lock_guard<std::mutex> lk(g_pidMutex);
            if (g_injectedPIDs.count(pid)) continue;
        }

        // Convert the wide process name to narrow for allowlist comparison
        char narrow[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                            narrow, MAX_PATH, nullptr, nullptr);

        // If TARGET_PROCESS is set, only inject into that specific process name.
        // Useful for focused testing without injecting into everything.
        if (TARGET_PROCESS && _stricmp(narrow, TARGET_PROCESS) != 0)
            continue;

        // Skip processes explicitly listed in allowlist.json.
        // These are known-safe processes that produce noisy false positives.
        if (AllowlistManager::Instance().IsAllowed(narrow)) continue;

        // Attempt injection - this is the main work of the scanner
        if (InjectDll(pid))
        {
            std::lock_guard<std::mutex> lk(g_pidMutex);
            g_injectedPIDs.insert(pid);
            SetColor(Color::Cyan);
            printf("[+] Injected  PID %-6lu  %s\n", (unsigned long)pid, narrow);
            ResetColor();
            injected++;
        }

    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return injected;
}

// SEH wrapper around ScanOnce so that an access violation or other structured
// exception in the scanner doesn't kill the thread. The scanner keeps running
// and prints a warning instead of silently dying.
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

// Main scanner loop - runs on the main thread until g_running is set to false.
static void ScannerThread()
{
    printf("[*] Scanner thread started.\n");
    DWORD scanCount = 0;

    while (g_running)
    {
        ScanOnceSafe(++scanCount);        // scan all processes
        Sleep(SCAN_INTERVAL_MS);          // wait before next scan
    }

    printf("[!] Scanner thread exited after %lu scans.\n", (unsigned long)scanCount);
}

// ── Pipe client worker ────────────────────────────────────────────────────────
// Reads JSON alert lines from a connected hook DLL and prints red alert
// messages to the console. Runs on a detached thread per connection.
static void HandlePipeClient(HANDLE hPipe)
{
    char buf[4096] = {};
    DWORD read = 0;

    // ReadFile blocks until data arrives or the client disconnects.
    // The hook DLL sends one JSON line per alert and then closes the connection,
    // so typically we get one read then ReadFile returns false.
    while (ReadFile(hPipe, buf, sizeof(buf) - 1, &read, nullptr) && read > 0)
    {
        buf[read] = '\0';
        // Split the buffer into lines in case multiple alerts arrived together
        std::istringstream stream(buf);
        std::string line;

        while (std::getline(stream, line))
        {
            if (line.empty()) continue;

            // Parse the four fields from the JSON alert
            std::string process = JsonGet(line, "process");
            std::string fn      = JsonGet(line, "fn");
            std::string ms      = JsonGet(line, "ms");
            std::string pid     = JsonGet(line, "pid");

            // Double-check the allowlist in case the process was added after
            // injection (the hook DLL can't update its check mid-run).
            if (AllowlistManager::Instance().IsAllowed(process)) continue;

            // Convert raw milliseconds to a human-readable duration string.
            // Makes it immediately obvious whether a sleep is seconds, minutes, or hours.
            DWORD msVal = ms.empty() ? 0 : (DWORD)std::stoul(ms);
            char  duration[64] = {};
            if      (msVal >= 3600000) sprintf_s(duration, "%.1f hr",  msVal / 3600000.0);
            else if (msVal >= 60000)   sprintf_s(duration, "%.1f min", msVal / 60000.0);
            else                       sprintf_s(duration, "%lu ms",   (unsigned long)msVal);

            SYSTEMTIME st = {};
            GetLocalTime(&st);

            // Print the full alert line in bright red so it stands out
            SetColor(Color::Red);
            printf("[ALERT] %02d:%02d:%02d  PID %-6s  %-25s  %s(%s)\n",
                   st.wHour, st.wMinute, st.wSecond,
                   pid.c_str(), process.c_str(), fn.c_str(), duration);
            ResetColor();
        }
    }

    // Clean up the pipe handle when the client disconnects
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}

// ── Pipe server ───────────────────────────────────────────────────────────────

// Creates one named pipe server instance with a permissive security descriptor
// so that hook DLLs running inside lower-privilege or lower-integrity processes
// can connect to it. Without the NULL DACL, CreateFileW in the hook DLL would
// fail with ERROR_ACCESS_DENIED (err=5) when the target runs as a normal user
// while the monitor runs as Administrator.
static HANDLE CreatePipeInstance()
{
    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    // NULL DACL = grant full access to everyone, regardless of user or integrity level
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle       = FALSE;

    return CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_INBOUND,                           // monitor only reads
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,                      // one instance per injected process
        0, 4096,                                       // out/in buffer sizes
        100,                                           // default timeout ms
        &sa);
}

// Pipe server loop - always keeps one pipe instance blocked in ConnectNamedPipe
// so hook DLLs always have somewhere to connect to.
//
// Key design: the next pipe instance is created BEFORE handing the current
// client to a worker thread. This eliminates the race window where no server
// instance is waiting, which would cause ERROR_PIPE_BUSY in hook DLLs and
// silently drop alerts.
static void PipeServerThread()
{
    HANDLE hPipe = CreatePipeInstance();

    while (g_running)
    {
        if (hPipe == INVALID_HANDLE_VALUE)
        {
            // Pipe creation failed - wait briefly and retry
            Sleep(200);
            hPipe = CreatePipeInstance();
            continue;
        }

        // Block here until a hook DLL connects to the pipe
        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            // Connection failed - recreate and try again
            CloseHandle(hPipe);
            hPipe = CreatePipeInstance();
            continue;
        }

        // A hook DLL has connected. Create the NEXT waiting instance first
        // so there is zero gap where the pipe has no available server slot.
        HANDLE hNext = CreatePipeInstance();

        // Hand this connection to a detached worker thread.
        // The worker reads alerts and prints them, then closes the handle.
        HANDLE hCurrent = hPipe;
        std::thread([hCurrent]{ HandlePipeClient(hCurrent); }).detach();

        // Move to the next pipe instance and loop back to ConnectNamedPipe
        hPipe = hNext;
    }

    CloseHandle(hPipe);
}

// ── Stale PID cleanup ─────────────────────────────────────────────────────────
// Runs every 15 seconds and removes dead PIDs from g_injectedPIDs.
// Without this, a process that exits and whose PID gets reused by a new
// process would never get injected because the PID is still in the set.
static void CleanupThread()
{
    while (g_running)
    {
        Sleep(15000);
        std::lock_guard<std::mutex> lk(g_pidMutex);
        for (auto it = g_injectedPIDs.begin(); it != g_injectedPIDs.end(); )
        {
            // Try to open the process - if it's gone, OpenProcess returns NULL
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, *it);
            if (!h) { it = g_injectedPIDs.erase(it); continue; }
            DWORD code = 0;
            GetExitCodeProcess(h, &code);
            CloseHandle(h);
            // STILL_ACTIVE = process is running; anything else = it has exited
            it = (code != STILL_ACTIVE) ? g_injectedPIDs.erase(it) : std::next(it);
        }
    }
}

// ── Ctrl+C handler ────────────────────────────────────────────────────────────
// Registered with SetConsoleCtrlHandler. Sets g_running to false so all
// threads exit gracefully on the next iteration of their loops.
static BOOL WINAPI ConsoleHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT)
    {
        g_running = false;
        return TRUE; // tell Windows we handled it (don't terminate immediately)
    }
    return FALSE;
}

// ── Entry point ───────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    const char* allowlistPath = DEFAULT_ALLOWLIST;

    // Load the allowlist from allowlist.json in the current directory.
    // Edit this file directly to add or remove processes.
    AllowlistManager::Instance().Load(allowlistPath);

    // Build the full path to SleepMonitorHook.dll (same folder as this exe)
    ResolveHookDllPath();

    // Register Ctrl+C handler so we can shut down cleanly
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // Print startup banner and configuration summary
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
    puts("  Press Ctrl+C to stop.\n");

    // Start the pipe server on a background thread so it's ready before
    // the scanner begins injecting and hook DLLs start sending alerts.
    std::thread(PipeServerThread).detach();

    // Start the cleanup thread to remove stale PIDs every 15 seconds.
    std::thread(CleanupThread).detach();

    // Run the scanner on the main thread - blocks until Ctrl+C sets g_running=false.
    ScannerThread();

    puts("\n[*] Shutting down.");
    return 0;
}