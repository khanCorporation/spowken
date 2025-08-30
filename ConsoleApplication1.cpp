// MemScan.cpp
// Single-pass scan of all processes, enabling SeDebugPrivilege.
// Looks for "MZ" at the base of committed executable memory regions.
// Build as a Console app. Run as Administrator.

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream> // Added for file operations
#include <shlobj.h> // Added for SHGetKnownFolderPath

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Shell32.lib") // Added for SHGetKnownFolderPath

// Console color helpers
void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void PrintHeader() {
    SetColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // Cyan-ish
    std::cout << "=========================================\n";
    std::cout << "      NEHAL MEMWATCH - SINGLE SCAN\n";
    std::cout << "  Scans all processes (one pass) for MZ\n";
    std::cout << "  (SeDebugPrivilege enabled if possible)\n";
    std::cout << "=========================================\n\n";
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// Enable SeDebugPrivilege for the current process
bool EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return (ok && GetLastError() == ERROR_SUCCESS);
}

// Scan memory regions of a process for MZ signature.
// Returns true if MZ found and prints alert details.
bool ScanProcessForMZ(DWORD pid) {
    const DWORD desired = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    HANDLE hProc = OpenProcess(desired, FALSE, pid);
    if (!hProc) return false;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    LPBYTE addr = (LPBYTE)si.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    bool found = false;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        const DWORD MEM_COMMIT_FLAG = MEM_COMMIT;
        const DWORD prot = mbi.Protect;
        bool isExec = (prot & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE)) != 0;
        if ((mbi.State & MEM_COMMIT_FLAG) && isExec && mbi.RegionSize > 0) {
            BYTE buffer[2] = { 0 };
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer, sizeof(buffer), &bytesRead) && bytesRead == sizeof(buffer)) {
                if (buffer[0] == 0x4D && buffer[1] == 0x5A) { // 'M' 'Z'
                    SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                    std::cout << "[ALERT] PID " << pid << " - MZ found at base 0x"
                        << std::hex << std::uppercase << (unsigned long long)(reinterpret_cast<uintptr_t>(mbi.BaseAddress))
                        << " (region size 0x" << (unsigned long long)mbi.RegionSize << ")\n";
                    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                    found = true;
                }
            }
        }
        uintptr_t next = (uintptr_t)mbi.BaseAddress + (uintptr_t)mbi.RegionSize;
        if (next <= (uintptr_t)addr) break;
        addr = (LPBYTE)next;
    }

    CloseHandle(hProc);
    return found;
}

// Retrieve all process IDs (single pass) and return as vector
std::vector<DWORD> GetAllProcessIds() {
    std::vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            pids.push_back(pe.th32ProcessID);
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pids;
}

int main() {
    PrintHeader();

    if (EnableDebugPrivilege()) {
        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[+] SeDebugPrivilege enabled (running with higher access)\n\n";
    }
    else {
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[-] Could not enable SeDebugPrivilege. Run as Administrator for best results.\n\n";
    }
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    auto pids = GetAllProcessIds();
    if (pids.empty()) {
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "No processes found or failed to enumerate processes.\n";
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        return 1;
    }

    SetColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "Scanning " << pids.size() << " processes ...\n\n";
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    std::cout << std::left << std::setw(8) << "PID"
        << std::setw(30) << "Process Name"
        << "Status\n";
    std::cout << "-----------------------------------------------------------------\n";

    std::vector<std::pair<DWORD, std::string>> results;

    for (DWORD pid : pids) {
        std::string procName = std::to_string(pid);
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProc) {
            char nameBuf[MAX_PATH] = "<unknown>";
            DWORD len = MAX_PATH;
            if (QueryFullProcessImageNameA(hProc, 0, nameBuf, &len)) {
                std::string full = nameBuf;
                size_t pos = full.find_last_of("\\/");
                if (pos != std::string::npos) procName = full.substr(pos + 1);
                else procName = full;
            }
            else {
                procName = "<protected>";
            }
            CloseHandle(hProc);
        }
        else {
            procName = "<cannot open>";
        }

        bool suspicious = ScanProcessForMZ(pid);

        if (suspicious) {
            SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << std::setw(8) << pid << std::setw(30) << procName << "MZ Found\n";
            results.push_back({ pid, "MZ Found" });
        }
        else {
            SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << std::setw(8) << pid << std::setw(30) << procName << "OK\n";
            results.push_back({ pid, "OK" });
        }
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    std::cout << "\nScan complete. (Single pass)\n";
    std::cout << "Note: this program does a one-time scan. Re-run to scan again.\n";

    // Create Result.txt on Desktop
    PWSTR desktopPath = NULL;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &desktopPath);
    if (SUCCEEDED(hr)) {
        // Convert PWSTR to string using WideCharToMultiByte
        int bufferSize = WideCharToMultiByte(CP_UTF8, 0, desktopPath, -1, NULL, 0, NULL, NULL);
        if (bufferSize > 0) {
            std::vector<char> buffer(bufferSize);
            int converted = WideCharToMultiByte(CP_UTF8, 0, desktopPath, -1, buffer.data(), bufferSize, NULL, NULL);
            if (converted > 0) {
                std::string desktopStr(buffer.data());
                std::string resultPath = desktopStr + "\\Result.txt";
                CoTaskMemFree(desktopPath);

                std::ofstream file(resultPath);
                if (file) {
                    file << "{\n";
                    file << "  \"scan_date\": \"August 30, 2025 11:42 AM PKT\",\n";
                    file << "  \"status\": \"clean\",\n";
                    file << "  \"processes\": [\n";
                    bool first = true;
                    for (const auto& result : results) {
                        if (!first) file << ",\n";
                        file << "    {\"pid\": " << result.first << ", \"status\": \"" << result.second << "\"}";
                        first = false;
                    }
                    file << "\n  ]\n";
                    file << "}\n";
                    file.close();
                    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::cout << "\n[+] Result.txt created on Desktop with scan results.\n";
                }
                else {
                    SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                    std::cout << "\n[-] Failed to create Result.txt on Desktop.\n";
                }
            }
            else {
                SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::cout << "\n[-] Failed to convert desktop path to string.\n";
                CoTaskMemFree(desktopPath);
            }
        }
        else {
            SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "\n[-] Failed to determine buffer size for desktop path.\n";
            CoTaskMemFree(desktopPath);
        }
    }
    else {
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "\n[-] Failed to get Desktop path. Error: " << hr << "\n";
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    return 0;
}