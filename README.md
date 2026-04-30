# SleepMonitor — Long-Sleep Detection via DLL Injection

A system-wide sleep monitor for Windows that hooks `Sleep` and `SleepEx` via
MinHook DLL injection. Built for advanced computer-defense coursework.

---

## Architecture

```
SleepMonitor.exe (runs as Admin)
  │
  ├── Scanner thread
  │     Snapshots all PIDs every 5 s
  │     Skips: system PIDs, already-injected, allowlisted processes
  │     Calls CreateRemoteThread → LoadLibraryW("SleepMonitorHook.dll")
  │
  ├── Pipe server thread
  │     Listens on \\.\pipe\SleepMonitorPipe
  │     Decodes JSON alerts → console output
  │
  └── Cleanup thread
        Removes dead PIDs from the injected-set every 15 s


Inside each target process (after injection):
  SleepMonitorHook.dll
    DllMain → MH_Initialize → MH_CreateHookApi(kernel32, "Sleep")
                             → MH_CreateHookApi(kernel32, "SleepEx")
    HookedSleep / HookedSleepEx
      if ms >= THRESHOLD → write JSON to named pipe → call original
```

---

## Files

```
sleep_monitor/
  src/
    hook_dll.cpp        Hook DLL — MinHook-based Sleep/SleepEx intercept
    monitor.cpp         Monitor EXE — injection, pipe server, allowlist CLI
  include/
    allowlist.h         Allowlist manager (header-only, no external deps)
    MinHook.h           ← YOU MUST ADD (from MinHook release)
  lib/
    MinHook.x64.lib     ← YOU MUST ADD (MSVC) or libMinHook.x64.a (MinGW)
  config/
    allowlist.json      Default allowlist — copy next to SleepMonitor.exe
  build.bat             Build script (MSVC or MinGW, auto-detected)
  README.md             This file
  bin/                  Created by build.bat
```

---

## Setup

### 1. Get MinHook

Download the latest release from https://github.com/TsudaKageyu/minhook/releases

- Copy `include/MinHook.h`          → `sleep_monitor/include/MinHook.h`
- Copy `lib/libMinHook.x64.lib`     → `sleep_monitor/lib/MinHook.x64.lib`  (MSVC)
- Or `bin/MinHook.x64.dll` + import lib for dynamic linking

### 2. Build

Open a **Developer Command Prompt for VS 20xx** (for MSVC) or ensure MinGW is in PATH.

```bat
cd sleep_monitor
mkdir bin lib
:: place MinHook files in include\ and lib\ first
build.bat
```

### 3. Run

```bat
:: Run as Administrator
bin\SleepMonitor.exe [allowlist.json]
```

---

## Allowlist management

The allowlist is a plain JSON file loaded at startup.

```bat
:: Add an entry
SleepMonitor.exe --add   powershell.exe  "approved admin script"

:: Remove an entry
SleepMonitor.exe --remove powershell.exe

:: Print all entries
SleepMonitor.exe --list
```

The file is saved in-place; entries are case-insensitive and match on the
basename of the process image (no path, no wildcards).

### Default false-positive entries

| Process            | Why it's excluded                        |
|--------------------|------------------------------------------|
| svchost.exe        | Service host — legitimate waits          |
| SearchHost.exe     | Windows Search indexer                   |
| WmiPrvSE.exe       | WMI provider host                        |
| MsMpEng.exe        | Windows Defender engine                  |
| taskhostw.exe      | Task host                                |
| lsass.exe          | Security authority — unsafe to hook      |
| csrss.exe          | Runtime subsystem — unsafe to hook       |

---

## Threshold

Default: **5000 ms (5 seconds)**. Change `THRESHOLD_MS` in `hook_dll.cpp` and
`threshold_ms` in `allowlist.json` to adjust.

---

## Alert format (named pipe)

Each alert is a newline-terminated JSON object:

```json
{"pid":1234,"process":"malware.exe","fn":"Sleep","ms":300000}
```

You can replace the console sink in `monitor.cpp → HandlePipeClient()` with
any backend: file logging, ETW events, Syslog, Windows Event Log, etc.

---

## Extending

### Log to file

Replace or augment the `printf` in `HandlePipeClient`:

```cpp
FILE* logf = fopen("sleepmonitor.log", "a");
if (logf) { fprintf(logf, "%s\n", line.c_str()); fclose(logf); }
```

### Add duration-based severity tiers

```cpp
DWORD ms = (DWORD)std::stoul(JsonGet(line, "ms"));
if      (ms >= 3600000) SetColor(Color::Red);     // >= 1 hour
else if (ms >=  300000) SetColor(Color::Yellow);  // >= 5 min
else                    SetColor(Color::Cyan);
```

### Integrate with Windows Event Log

Use `ReportEventW` inside `HandlePipeClient` after registering an event source.

### Kernel-mode alternative

For production use replace the `CreateRemoteThread + LoadLibraryW` injection
with a minifilter or kernel driver using `PsSetCreateProcessNotifyRoutineEx`
and Kernel Patch Protection-safe hooking (SSDT shadowing or ETW-TI callbacks).
This user-mode approach is intentionally simpler for a lab/classroom context.

---

## Limitations & Notes

- **Requires Administrator** — needed for `OpenProcess` on most PIDs.
- **Protected processes** (PPL) cannot be injected; they will be skipped silently.
- **32-bit processes** require a separate x86 build of the hook DLL.
- **AntiCheat / AV** may detect `CreateRemoteThread` injection; run in a lab VM.
- This tool is for **educational and defensive use only**.
