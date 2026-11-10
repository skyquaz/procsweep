// procsweep - find code-injection artifacts in running Windows processes.
//
// For every process it can open, procsweep walks the virtual address space and
// the thread list and reports:
//
//   UNBACKED_THREAD  a thread whose start address is outside every mapped
//                    image: CreateRemoteThread-style injection
//   UNBACKED_PE      a PE image (MZ/PE headers) at the base of a private or
//                    section-view allocation with executable pages:
//                    manual mapping, reflective DLL loading
//   PRIVATE_EXEC     executable private memory with no image file behind it:
//                    shellcode, injected stubs, hook trampolines (or JIT code)
//   MAPPED_EXEC      an executable view of a non-image section:
//                    section-mapping injection (NtMapViewOfSection)
//   IMAGE_NO_FILE    an image mapping whose backing file no longer exists:
//                    process ghosting / doppelganging style tricks
//
// Severity is context aware. Processes that legitimately generate code (.NET,
// Java, V8/Electron, Python ctypes, ...) get their executable heaps reported as
// LOW, and plain R-X private pages with no other indicator are LOW as well.
// A thread starting inside an allocation always raises it to HIGH. --strict
// turns all of the down-grading off.
//
// procsweep only reads. It opens targets with PROCESS_QUERY_INFORMATION |
// PROCESS_VM_READ and THREAD_QUERY_INFORMATION and never writes to, suspends
// or injects into anything.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

constexpr const wchar_t* kVersion = L"0.1.0";
constexpr uint64_t kMaxDump = 64ull << 20;          // largest allocation written by --dump
constexpr uint64_t kMaxDensityRead = 16ull << 20;   // bytes sampled when measuring how empty a region is
constexpr uint64_t kJitReservation = 64ull << 20;   // reservations this large look like JIT code ranges
constexpr double kMostlyEmpty = 0.02;               // < 2 % non-zero bytes
constexpr ULONG kThreadQuerySetWin32StartAddress = 9;

// Loaded images or mapped data files that mean the process generates machine
// code at run time, so executable heap memory is expected there.
const wchar_t* const kCodegenMarkers[] = {
    L"clrjit.dll", L"coreclr.dll", L"clr.dll", L"mscorwks.dll",             // .NET
    L"jvm.dll", L"mono-2.0-bdwgc.dll", L"mono.dll",                          // Java, Mono
    L"chrome.dll", L"msedge.dll", L"libcef.dll", L"node.exe",                // Chromium, CEF, Node
    L"icudtl.dat", L"v8_context_snapshot.bin", L"snapshot_blob.bin",        // V8 data files (Electron)
    L"vk_swiftshader.dll",                                                   // SwiftShader JIT
    L"xul.dll",                                                              // Firefox
    L"jscript9.dll", L"jscript9legacy.dll", L"chakra.dll",                   // legacy MS script engines
    L"qt5qml.dll", L"qt6qml.dll", L"lua51.dll", L"luajit.dll",               // Qt QML, LuaJIT
    L"libffi-7.dll", L"libffi-8.dll", L"libffi.dll", L"_ctypes.pyd",         // libffi closures (ctypes)
};

enum class Sev : int { Low = 1, Medium = 2, High = 3 };

Sev ToSev(int level) {
    return level >= 3 ? Sev::High : level <= 1 ? Sev::Low : Sev::Medium;
}

const wchar_t* SevName(Sev s) {
    return s == Sev::High ? L"high" : s == Sev::Medium ? L"medium" : L"low";
}

const wchar_t* SevLabel(Sev s) {
    return s == Sev::High ? L"HIGH" : s == Sev::Medium ? L"MEDIUM" : L"LOW";
}

struct Options {
    DWORD pid = 0;
    bool json = false;
    bool strict = false;
    bool help = false;
    Sev minSev = Sev::Medium;
    std::wstring dumpDir;
};

struct Region {
    uint64_t base;
    uint64_t allocBase;
    uint64_t size;
    DWORD protect;
    DWORD type;
};

struct Finding {
    DWORD pid = 0;
    std::wstring process;
    std::wstring type;
    Sev sev = Sev::Low;
    std::vector<std::wstring> attck;
    uint64_t address = 0;
    uint64_t size = 0;
    DWORD protect = 0;
    DWORD memType = 0;
    DWORD tid = 0;
    std::wstring codegen;  // marker that identified a code-generating process, if any
    std::wstring detail;
    std::wstring dump;
};

struct Stats {
    int scanned = 0;
    int inaccessible = 0;
};

// ----------------------------------------------------------------- helpers --

std::wstring Fmt(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, ap);
    va_end(ap);
    return buf;
}

std::wstring Hex(uint64_t v) { return Fmt(L"0x%016llX", v); }

std::wstring Lower(std::wstring s) {
    for (wchar_t& c : s) c = static_cast<wchar_t>(std::towlower(c));
    return s;
}

std::wstring BaseName(const std::wstring& path) {
    const size_t p = path.find_last_of(L"\\/");
    return p == std::wstring::npos ? path : path.substr(p + 1);
}

bool IsExec(DWORD protect) {
    switch (protect & 0xFF) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool IsExecWrite(DWORD protect) {
    const DWORD p = protect & 0xFF;
    return p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

const wchar_t* ProtName(DWORD protect) {
    switch (protect & 0xFF) {
    case PAGE_NOACCESS: return L"---";
    case PAGE_READONLY: return L"R--";
    case PAGE_READWRITE: return L"RW-";
    case PAGE_WRITECOPY: return L"RC-";
    case PAGE_EXECUTE: return L"--X";
    case PAGE_EXECUTE_READ: return L"R-X";
    case PAGE_EXECUTE_READWRITE: return L"RWX";
    case PAGE_EXECUTE_WRITECOPY: return L"RCX";
    default: return L"-";
    }
}

const wchar_t* MemTypeName(DWORD type) {
    switch (type) {
    case MEM_IMAGE: return L"IMAGE";
    case MEM_MAPPED: return L"MAPPED";
    case MEM_PRIVATE: return L"PRIVATE";
    default: return L"FREE";
    }
}

// Writes UTF-16 to a console, UTF-8 to a pipe or file.
class Writer {
public:
    Writer() : h_(GetStdHandle(STD_OUTPUT_HANDLE)) {
        DWORD mode = 0;
        console_ = GetConsoleMode(h_, &mode) != 0;
    }

    void operator()(const std::wstring& s) const {
        DWORD written = 0;
        if (console_) {
            WriteConsoleW(h_, s.data(), static_cast<DWORD>(s.size()), &written, nullptr);
            return;
        }
        const int len = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
        if (len <= 0) return;
        std::string utf8(static_cast<size_t>(len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), utf8.data(), len, nullptr, nullptr);
        WriteFile(h_, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
    }

private:
    HANDLE h_;
    bool console_ = false;
};

bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const bool ok = LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid) &&
                    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
                    GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD len = 0;
    const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &len) != 0;
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

// Maps NT device paths (\Device\HarddiskVolume3\...) back to drive letters.
class DriveMap {
public:
    DriveMap() {
        wchar_t drives[512] = {};
        const DWORD n = GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives) - 1), drives);
        if (n == 0 || n >= std::size(drives)) return;
        for (const wchar_t* d = drives; *d; d += std::wcslen(d) + 1) {
            const wchar_t letter[3] = {d[0], L':', 0};
            wchar_t target[MAX_PATH] = {};
            if (QueryDosDeviceW(letter, target, MAX_PATH)) entries_.emplace_back(Lower(target), letter);
        }
    }

    std::wstring ToDos(const std::wstring& device) const {
        const std::wstring low = Lower(device);
        for (const auto& [prefix, letter] : entries_) {
            if (low.size() > prefix.size() && low.compare(0, prefix.size(), prefix) == 0 && low[prefix.size()] == L'\\')
                return letter + device.substr(prefix.size());
        }
        return device;
    }

private:
    std::vector<std::pair<std::wstring, std::wstring>> entries_;
};

enum class FileState { Present, Missing, Unknown };

FileState CheckDeviceFile(const std::wstring& device) {
    const std::wstring path = L"\\\\?\\GLOBALROOT" + device;
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return FileState::Present;
    const DWORD err = GetLastError();
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND || err == ERROR_DELETE_PENDING)
        return FileState::Missing;
    return FileState::Unknown;
}

bool HasPeHeader(HANDLE process, uint64_t base) {
    unsigned char buf[0x400];
    SIZE_T got = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base), buf, sizeof(buf), &got) || got < 0x40) return false;
    if (buf[0] != 'M' || buf[1] != 'Z') return false;
    LONG lfanew = 0;
    std::memcpy(&lfanew, buf + 0x3C, sizeof(lfanew));
    if (lfanew < 0x40 || static_cast<SIZE_T>(lfanew) + 4 > got) return false;
    return std::memcmp(buf + lfanew, "PE\0\0", 4) == 0;
}

// Fraction of non-zero bytes in the executable pages of one allocation.
// Unreadable memory counts as dense so it is never down-graded.
double NonZeroRatio(HANDLE process, uint64_t allocBase, const std::vector<Region>& committed) {
    uint64_t total = 0;
    uint64_t nonZero = 0;
    std::vector<unsigned char> buf;
    for (const Region& r : committed) {
        if (r.allocBase != allocBase || !IsExec(r.protect)) continue;
        if (total >= kMaxDensityRead) break;
        const uint64_t len = std::min(r.size, kMaxDensityRead - total);
        buf.resize(static_cast<size_t>(len));
        SIZE_T got = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(r.base), buf.data(), static_cast<SIZE_T>(len), &got))
            continue;
        total += got;
        nonZero += static_cast<uint64_t>(std::count_if(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(got),
                                                       [](unsigned char b) { return b != 0; }));
    }
    return total ? static_cast<double>(nonZero) / static_cast<double>(total) : 1.0;
}

// Writes one allocation (committed regions only, gaps zero-filled) to dir.
std::wstring DumpAllocation(HANDLE process, DWORD pid, uint64_t allocBase, uint64_t allocEnd,
                            const std::vector<Region>& committed, const std::wstring& dir) {
    const uint64_t size = std::min(allocEnd - allocBase, kMaxDump);
    if (size == 0) return {};
    std::vector<unsigned char> buf(static_cast<size_t>(size), 0);
    for (const Region& r : committed) {
        if (r.allocBase != allocBase || r.base >= allocBase + size) continue;
        const uint64_t len = std::min(r.size, allocBase + size - r.base);
        SIZE_T got = 0;
        ReadProcessMemory(process, reinterpret_cast<LPCVOID>(r.base), buf.data() + (r.base - allocBase),
                          static_cast<SIZE_T>(len), &got);
    }
    const std::wstring path = dir + Fmt(L"\\pid%lu_%016llX.bin", pid, allocBase);
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    DWORD written = 0;
    const BOOL ok = WriteFile(file, buf.data(), static_cast<DWORD>(buf.size()), &written, nullptr);
    CloseHandle(file);
    return ok ? path : std::wstring();
}

using NtQueryInformationThreadFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

NtQueryInformationThreadFn ResolveNtQueryInformationThread() {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return nullptr;
    return reinterpret_cast<NtQueryInformationThreadFn>(GetProcAddress(ntdll, "NtQueryInformationThread"));
}

// ----------------------------------------------------------------- scanner --

class Scanner {
public:
    explicit Scanner(const Options& opt) : opt_(opt), ntQueryThread_(ResolveNtQueryInformationThread()) {}

    void Scan(DWORD pid, const std::wstring& exe, const std::vector<DWORD>& tids);
    std::vector<Finding>& Findings() { return findings_; }
    const Stats& GetStats() const { return stats_; }

private:
    void Report(Finding f, HANDLE process, uint64_t allocBase, uint64_t allocEnd, const std::vector<Region>& committed);

    const Options& opt_;
    NtQueryInformationThreadFn ntQueryThread_;
    DriveMap drives_;
    std::vector<Finding> findings_;
    Stats stats_;
};

void Scanner::Report(Finding f, HANDLE process, uint64_t allocBase, uint64_t allocEnd,
                     const std::vector<Region>& committed) {
    if (static_cast<int>(f.sev) < static_cast<int>(opt_.minSev)) return;
    if (!opt_.dumpDir.empty() && allocEnd > allocBase)
        f.dump = DumpAllocation(process, f.pid, allocBase, allocEnd, committed, opt_.dumpDir);
    findings_.push_back(std::move(f));
}

void Scanner::Scan(DWORD pid, const std::wstring& exe, const std::vector<DWORD>& tids) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        ++stats_.inaccessible;
        return;
    }
    ++stats_.scanned;

    // 1. Walk the address space once.
    std::vector<Region> committed;
    std::map<uint64_t, uint64_t> allocEnd;        // allocation base -> end of its last region
    std::map<uint64_t, std::wstring> imageFiles;  // image base -> NT device path ("" if unresolvable)
    std::set<std::wstring> fileNames;             // lower-case names of mapped images and data files

    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = 0;
    while (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        const uint64_t allocBase = reinterpret_cast<uint64_t>(mbi.AllocationBase);
        const uint64_t end = base + mbi.RegionSize;
        if (mbi.State != MEM_FREE) {
            uint64_t& e = allocEnd[allocBase];
            e = std::max(e, end);
        }
        if (mbi.State == MEM_COMMIT) {
            committed.push_back({base, allocBase, mbi.RegionSize, mbi.Protect, mbi.Type});
            if (base == allocBase && (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)) {
                wchar_t device[1024] = {};
                const DWORD n = GetMappedFileNameW(process, mbi.BaseAddress, device, static_cast<DWORD>(std::size(device)));
                std::wstring path = n ? std::wstring(device, n) : std::wstring();
                if (!path.empty()) fileNames.insert(Lower(BaseName(path)));
                if (mbi.Type == MEM_IMAGE) imageFiles[allocBase] = std::move(path);
            }
        }
        if (end <= addr) break;
        addr = end;
    }

    std::wstring codegen;
    for (const wchar_t* marker : kCodegenMarkers) {
        if (fileNames.count(marker)) {
            codegen = marker;
            break;
        }
    }
    const bool soften = !codegen.empty() && !opt_.strict;
    const std::wstring codegenNote = codegen.empty() ? L"" : L" [code generator: " + codegen + L"]";

    // 2. Thread start addresses outside every mapped image.
    struct ThreadStart {
        DWORD tid;
        uint64_t start;
        MEMORY_BASIC_INFORMATION mbi;
    };
    std::vector<ThreadStart> unbackedThreads;
    std::set<uint64_t> threadAllocs;  // allocations that contain an unbacked thread start
    if (ntQueryThread_) {
        for (const DWORD tid : tids) {
            HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
            if (!thread) continue;
            PVOID start = nullptr;
            const LONG status = ntQueryThread_(thread, kThreadQuerySetWin32StartAddress, &start, sizeof(start), nullptr);
            CloseHandle(thread);
            if (status < 0 || !start) continue;
            MEMORY_BASIC_INFORMATION tm{};
            if (VirtualQueryEx(process, start, &tm, sizeof(tm)) != sizeof(tm)) continue;
            if (tm.State == MEM_COMMIT && tm.Type == MEM_IMAGE) continue;
            unbackedThreads.push_back({tid, reinterpret_cast<uint64_t>(start), tm});
            if (tm.State == MEM_COMMIT) threadAllocs.insert(reinterpret_cast<uint64_t>(tm.AllocationBase));
        }
    }

    // 3. Executable memory that is not part of a mapped image, grouped by allocation.
    struct ExecAlloc {
        DWORD type = 0;
        DWORD protect = 0;
        uint64_t execBytes = 0;
        bool rwx = false;
    };
    std::map<uint64_t, ExecAlloc> execAllocs;
    for (const Region& r : committed) {
        if (r.type == MEM_IMAGE || !IsExec(r.protect)) continue;
        ExecAlloc& a = execAllocs[r.allocBase];
        if (a.execBytes == 0) {
            a.type = r.type;
            a.protect = r.protect;
        }
        a.execBytes += r.size;
        if (IsExecWrite(r.protect)) {
            a.rwx = true;
            a.protect = r.protect;
        }
    }

    for (const auto& [allocBase, a] : execAllocs) {
        const uint64_t end = allocEnd[allocBase];
        Finding f;
        f.pid = pid;
        f.process = exe;
        f.address = allocBase;
        f.size = end - allocBase;
        f.protect = a.protect;
        f.memType = a.type;
        f.codegen = codegen;
        const wchar_t* kind = a.type == MEM_MAPPED ? L"section-view" : L"private";
        const wchar_t* rwx = a.rwx ? L" (RWX)" : L"";
        const bool threadHere = threadAllocs.count(allocBase) != 0;

        if (HasPeHeader(process, allocBase)) {
            f.type = L"UNBACKED_PE";
            f.attck = {L"T1055.002", L"T1620"};
            f.sev = soften && !threadHere ? Sev::Medium : Sev::High;
            f.detail = Fmt(L"PE image in %ls memory, %llu KB executable%ls", kind, a.execBytes / 1024, rwx) +
                       (threadHere ? L" [a thread starts here]" : soften ? codegenNote : L"");
            Report(std::move(f), process, allocBase, end, committed);
            continue;
        }

        int level = 0;
        std::wstring why;
        if (threadHere) {
            level = 3;
            why = L" [a thread starts here]";
        } else if (opt_.strict) {
            level = a.rwx ? 3 : 2;
        } else if (soften) {
            level = 1;
            why = codegenNote;
        } else if (f.size >= kJitReservation) {
            level = 1;
            why = Fmt(L" [%llu MB reservation, JIT-like]", f.size >> 20);
        } else if (a.rwx || a.type == MEM_MAPPED) {
            level = a.rwx ? 3 : 2;
            const double ratio = NonZeroRatio(process, allocBase, committed);
            if (ratio < kMostlyEmpty) {
                --level;
                why = Fmt(L" [mostly empty: %.2f%% non-zero]", ratio * 100.0);
            }
        } else {
            level = 1;
            why = L" [R-X with no other indicator]";
        }
        f.type = a.type == MEM_MAPPED ? L"MAPPED_EXEC" : L"PRIVATE_EXEC";
        f.attck = {L"T1055"};
        f.sev = ToSev(level);
        f.detail = Fmt(L"%llu KB executable %ls memory with no image file behind it%ls", a.execBytes / 1024, kind, rwx) + why;
        Report(std::move(f), process, allocBase, end, committed);
    }

    // 4. Report the unbacked threads.
    for (const ThreadStart& t : unbackedThreads) {
        const uint64_t allocBase = reinterpret_cast<uint64_t>(t.mbi.AllocationBase);
        const bool mapped = t.mbi.State == MEM_COMMIT;
        Finding f;
        f.pid = pid;
        f.process = exe;
        f.type = L"UNBACKED_THREAD";
        f.attck = {L"T1055"};
        f.address = t.start;
        f.size = t.mbi.RegionSize;
        f.protect = mapped ? t.mbi.Protect : 0;
        f.memType = t.mbi.State == MEM_FREE ? 0 : t.mbi.Type;
        f.tid = t.tid;
        f.codegen = codegen;
        f.sev = mapped ? Sev::High : Sev::Medium;
        f.detail = mapped ? Fmt(L"thread %lu starts in %ls %ls memory outside every mapped image", t.tid,
                                MemTypeName(t.mbi.Type), ProtName(t.mbi.Protect))
                          : Fmt(L"thread %lu start address is no longer mapped (freed after the thread started)", t.tid);
        const auto it = allocEnd.find(allocBase);
        Report(std::move(f), process, allocBase, it != allocEnd.end() ? it->second : allocBase, committed);
    }

    // 5. Image mappings whose file is gone.
    for (const auto& [imageBase, device] : imageFiles) {
        const FileState state = device.empty() ? FileState::Missing : CheckDeviceFile(device);
        if (state != FileState::Missing) continue;
        Finding f;
        f.pid = pid;
        f.process = exe;
        f.type = L"IMAGE_NO_FILE";
        f.attck = {L"T1055.013"};
        f.sev = Sev::Medium;
        f.address = imageBase;
        f.size = allocEnd[imageBase] - imageBase;
        f.memType = MEM_IMAGE;
        f.codegen = codegen;
        f.detail = device.empty() ? std::wstring(L"image mapping has no resolvable backing file")
                                  : L"image backing file no longer exists: " + drives_.ToDos(device);
        Report(std::move(f), process, imageBase, imageBase, committed);  // images are not dumped
    }

    CloseHandle(process);
}

// ------------------------------------------------------------------ output --

std::wstring JsonStr(const std::wstring& s) {
    std::wstring o = L"\"";
    for (const wchar_t c : s) {
        switch (c) {
        case L'"': o += L"\\\""; break;
        case L'\\': o += L"\\\\"; break;
        case L'\n': o += L"\\n"; break;
        case L'\r': o += L"\\r"; break;
        case L'\t': o += L"\\t"; break;
        default:
            if (c < 0x20) o += Fmt(L"\\u%04x", static_cast<unsigned>(c));
            else o += c;
        }
    }
    return o + L"\"";
}

std::wstring JsonOrNull(const std::wstring& s) { return s.empty() ? std::wstring(L"null") : JsonStr(s); }

void PrintJson(const Writer& out, const std::vector<Finding>& findings, const Stats& st, bool elevated) {
    std::wstring s = Fmt(L"{\n  \"tool\": \"procsweep\",\n  \"version\": \"%ls\",\n  \"elevated\": %ls,\n"
                         L"  \"scanned\": %d,\n  \"inaccessible\": %d,\n  \"findings\": [",
                         kVersion, elevated ? L"true" : L"false", st.scanned, st.inaccessible);
    for (size_t i = 0; i < findings.size(); ++i) {
        const Finding& f = findings[i];
        std::wstring attck;
        for (size_t k = 0; k < f.attck.size(); ++k) attck += (k ? L", " : L"") + JsonStr(f.attck[k]);
        s += i ? L",\n    {" : L"\n    {";
        s += L"\"pid\": " + std::to_wstring(f.pid);
        s += L", \"process\": " + JsonStr(f.process);
        s += L", \"type\": " + JsonStr(f.type);
        s += L", \"severity\": " + JsonStr(SevName(f.sev));
        s += L", \"attck\": [" + attck + L"]";
        s += L", \"address\": " + JsonStr(Hex(f.address));
        s += L", \"size\": " + std::to_wstring(f.size);
        s += L", \"protection\": " + JsonStr(f.protect ? ProtName(f.protect) : L"");
        s += L", \"memory\": " + JsonStr(MemTypeName(f.memType));
        s += L", \"tid\": " + (f.tid ? std::to_wstring(f.tid) : std::wstring(L"null"));
        s += L", \"codegen_host\": " + JsonOrNull(f.codegen);
        s += L", \"detail\": " + JsonStr(f.detail);
        s += L", \"dump\": " + JsonOrNull(f.dump);
        s += L"}";
    }
    s += findings.empty() ? L"]\n}\n" : L"\n  ]\n}\n";
    out(s);
}

void PrintText(const Writer& out, const std::vector<Finding>& findings, const Stats& st, bool elevated, Sev minSev) {
    out(Fmt(L"procsweep %ls: scanned %d process%ls, %d inaccessible%ls\n\n", kVersion, st.scanned,
            st.scanned == 1 ? L"" : L"es", st.inaccessible,
            elevated ? L"" : L" (not elevated; run as administrator for full coverage)"));
    int counts[4] = {};
    for (const Finding& f : findings) {
        ++counts[static_cast<int>(f.sev)];
        std::wstring attck;
        for (size_t k = 0; k < f.attck.size(); ++k) attck += (k ? L"," : L"") + f.attck[k];
        out(Fmt(L"%-6ls  pid %-6lu %-24ls %-16ls %ls  %-7ls %-3ls  %ls\n        %ls\n", SevLabel(f.sev), f.pid,
                f.process.c_str(), f.type.c_str(), Hex(f.address).c_str(), MemTypeName(f.memType),
                f.protect ? ProtName(f.protect) : L"-", attck.c_str(), f.detail.c_str()));
        if (!f.dump.empty()) out(L"        dumped to " + f.dump + L"\n");
    }
    if (findings.empty()) {
        out(Fmt(L"No findings at or above %ls.\n", SevName(minSev)));
        return;
    }
    out(Fmt(L"\n%zu finding%ls at or above %ls: %d high, %d medium, %d low\n", findings.size(),
            findings.size() == 1 ? L"" : L"s", SevName(minSev),
            counts[static_cast<int>(Sev::High)], counts[static_cast<int>(Sev::Medium)], counts[static_cast<int>(Sev::Low)]));
}

void PrintUsage(const Writer& out) {
    out(Fmt(L"procsweep %ls - find code-injection artifacts in running processes\n\n", kVersion) +
        L"usage: procsweep [--pid N] [--min low|medium|high] [--all] [--strict] [--json] [--dump DIR]\n\n"
        L"  --pid N      scan one process instead of all of them\n"
        L"  --min LEVEL  lowest severity to report (default: medium)\n"
        L"  --all        report everything (same as --min low)\n"
        L"  --strict     no context-based down-grading (code generators, JIT-sized\n"
        L"               reservations, empty pools, plain R-X pages)\n"
        L"  --json       print a JSON report\n"
        L"  --dump DIR   save each flagged allocation to DIR for offline analysis\n\n"
        L"Run elevated to cover services and other users' processes.\n"
        L"Exit code: 0 = nothing reported, 1 = findings reported, 2 = usage error.\n");
}

bool ParseArgs(int argc, wchar_t** argv, Options& o) {
    for (int i = 1; i < argc; ++i) {
        const std::wstring a = argv[i];
        const bool hasValue = i + 1 < argc;
        if (a == L"-h" || a == L"--help" || a == L"/?") {
            o.help = true;
        } else if (a == L"--json") {
            o.json = true;
        } else if (a == L"--strict") {
            o.strict = true;
        } else if (a == L"--all") {
            o.minSev = Sev::Low;
        } else if (a == L"--pid" && hasValue) {
            o.pid = std::wcstoul(argv[++i], nullptr, 10);
            if (o.pid == 0) return false;
        } else if (a == L"--min" && hasValue) {
            const std::wstring v = Lower(argv[++i]);
            if (v == L"low") o.minSev = Sev::Low;
            else if (v == L"medium") o.minSev = Sev::Medium;
            else if (v == L"high") o.minSev = Sev::High;
            else return false;
        } else if (a == L"--dump" && hasValue) {
            o.dumpDir = argv[++i];
        } else {
            return false;
        }
    }
    return true;
}

int Run(int argc, wchar_t** argv) {
    const Writer out;
    Options opt;
    if (!ParseArgs(argc, argv, opt)) {
        PrintUsage(out);
        return 2;
    }
    if (opt.help) {
        PrintUsage(out);
        return 0;
    }
    if (!opt.dumpDir.empty() && !CreateDirectoryW(opt.dumpDir.c_str(), nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        out(L"cannot create dump directory: " + opt.dumpDir + L"\n");
        return 2;
    }

    EnableDebugPrivilege();
    const bool elevated = IsElevated();

    std::map<DWORD, std::wstring> processes;
    std::map<DWORD, std::vector<DWORD>> threads;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        out(L"CreateToolhelp32Snapshot failed\n");
        return 2;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) processes[pe.th32ProcessID] = pe.szExeFile;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) threads[te.th32OwnerProcessID].push_back(te.th32ThreadID);
    CloseHandle(snap);

    if (opt.pid && !processes.count(opt.pid)) {
        out(Fmt(L"no process with pid %lu\n", opt.pid));
        return 2;
    }

    Scanner scanner(opt);
    const DWORD self = GetCurrentProcessId();
    for (const auto& [pid, exe] : processes) {
        const bool skip = opt.pid ? pid != opt.pid : (pid == 0 || pid == 4 || pid == self);
        if (!skip) scanner.Scan(pid, exe, threads[pid]);
    }

    std::vector<Finding>& findings = scanner.Findings();
    std::sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
        if (a.sev != b.sev) return a.sev > b.sev;
        if (a.pid != b.pid) return a.pid < b.pid;
        return a.address < b.address;
    });

    if (opt.json) PrintJson(out, findings, scanner.GetStats(), elevated);
    else PrintText(out, findings, scanner.GetStats(), elevated, opt.minSev);
    return findings.empty() ? 0 : 1;
}

}  // namespace

int wmain(int argc, wchar_t** argv) { return Run(argc, argv); }
