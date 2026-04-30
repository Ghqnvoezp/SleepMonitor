#pragma once
/*
 * allowlist.h  —  Allowlist manager
 * ==================================
 * Reads allowlist.json from the same directory as the monitor executable.
 *
 * JSON format (no external library required — hand-parsed):
 * {
 *   "threshold_ms": 5000,
 *   "allowlist": [
 *     { "process": "svchost.exe",  "reason": "Windows service host" },
 *     { "process": "SearchHost.exe","reason": "Windows Search" },
 *     { "process": "WmiPrvSE.exe", "reason": "WMI provider" },
 *     { "process": "MsMpEng.exe",  "reason": "Windows Defender" }
 *   ]
 * }
 *
 * Matching is case-insensitive on the basename of the process image.
 * Wildcards are NOT supported intentionally — keep the allowlist tight.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "shlwapi.lib")

struct AllowEntry
{
    std::string process;   // lowercase basename, e.g. "svchost.exe"
    std::string reason;
};

class AllowlistManager
{
public:
    // ── Singleton ────────────────────────────────────────────────────────────
    static AllowlistManager& Instance()
    {
        static AllowlistManager inst;
        return inst;
    }

    // ── Load from JSON file ───────────────────────────────────────────────────
    bool Load(const std::string& jsonPath)
    {
        m_entries.clear();
        m_thresholdMs = 5000; // default

        std::ifstream f(jsonPath);
        if (!f.is_open()) return false;

        std::ostringstream ss;
        ss << f.rdbuf();
        std::string raw = ss.str();

        ParseJson(raw);
        m_loaded = true;
        return true;
    }

    // ── Query ─────────────────────────────────────────────────────────────────
    // Returns true when the process is on the allowlist (should be suppressed).
    bool IsAllowed(const std::string& processName) const
    {
        std::string lower = ToLower(processName);
        // Strip any path component
        auto slash = lower.rfind('\\');
        if (slash != std::string::npos) lower = lower.substr(slash + 1);
        slash = lower.rfind('/');
        if (slash != std::string::npos) lower = lower.substr(slash + 1);

        for (const auto& e : m_entries)
            if (e.process == lower) return true;

        return false;
    }

    DWORD ThresholdMs() const { return m_thresholdMs; }

    // ── Management helpers ────────────────────────────────────────────────────
    void AddEntry(const std::string& process, const std::string& reason)
    {
        AllowEntry e;
        e.process = ToLower(process);
        e.reason  = reason;
        m_entries.push_back(e);
    }

    bool RemoveEntry(const std::string& process)
    {
        std::string lower = ToLower(process);
        auto before = m_entries.size();
        m_entries.erase(
            std::remove_if(m_entries.begin(), m_entries.end(),
                [&](const AllowEntry& e){ return e.process == lower; }),
            m_entries.end());
        return m_entries.size() < before;
    }

    void PrintEntries() const
    {
        printf("[Allowlist] %zu entries (threshold: %lu ms)\n",
               m_entries.size(), (unsigned long)m_thresholdMs);
        for (const auto& e : m_entries)
            printf("  %-30s  # %s\n", e.process.c_str(), e.reason.c_str());
    }

    // ── Save back to JSON ─────────────────────────────────────────────────────
    bool Save(const std::string& jsonPath) const
    {
        std::ofstream f(jsonPath);
        if (!f.is_open()) return false;

        f << "{\n";
        f << "  \"threshold_ms\": " << m_thresholdMs << ",\n";
        f << "  \"allowlist\": [\n";
        for (size_t i = 0; i < m_entries.size(); i++)
        {
            f << "    { \"process\": \"" << m_entries[i].process
              << "\", \"reason\": \"" << m_entries[i].reason << "\" }";
            if (i + 1 < m_entries.size()) f << ",";
            f << "\n";
        }
        f << "  ]\n}\n";
        return true;
    }

private:
    AllowlistManager() = default;

    std::vector<AllowEntry> m_entries;
    DWORD m_thresholdMs = 5000;
    bool  m_loaded      = false;

    static std::string ToLower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        return s;
    }

    // ── Minimal JSON parser (no deps) ─────────────────────────────────────────
    // Only handles the specific schema above. Not general-purpose.
    void ParseJson(const std::string& json)
    {
        // Extract threshold_ms
        auto tpos = json.find("\"threshold_ms\"");
        if (tpos != std::string::npos)
        {
            auto colon = json.find(':', tpos);
            if (colon != std::string::npos)
                m_thresholdMs = (DWORD)std::stoul(json.substr(colon + 1));
        }

        // Extract allowlist array entries
        auto apos = json.find("\"allowlist\"");
        if (apos == std::string::npos) return;

        auto arrStart = json.find('[', apos);
        auto arrEnd   = json.find(']', arrStart);
        if (arrStart == std::string::npos || arrEnd == std::string::npos) return;

        std::string arr = json.substr(arrStart, arrEnd - arrStart);
        size_t pos = 0;

        while ((pos = arr.find('{', pos)) != std::string::npos)
        {
            auto objEnd = arr.find('}', pos);
            if (objEnd == std::string::npos) break;

            std::string obj = arr.substr(pos, objEnd - pos + 1);
            AllowEntry entry;
            entry.process = ToLower(ExtractString(obj, "process"));
            entry.reason  = ExtractString(obj, "reason");

            if (!entry.process.empty())
                m_entries.push_back(entry);

            pos = objEnd + 1;
        }
    }

    static std::string ExtractString(const std::string& obj, const std::string& key)
    {
        std::string needle = "\"" + key + "\"";
        auto kpos = obj.find(needle);
        if (kpos == std::string::npos) return {};

        auto colon = obj.find(':', kpos + needle.size());
        if (colon == std::string::npos) return {};

        auto q1 = obj.find('"', colon + 1);
        if (q1 == std::string::npos) return {};

        auto q2 = obj.find('"', q1 + 1);
        if (q2 == std::string::npos) return {};

        return obj.substr(q1 + 1, q2 - q1 - 1);
    }
};
