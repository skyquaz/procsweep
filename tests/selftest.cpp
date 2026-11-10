// selftest - plants benign injection artifacts inside its own process so that
// procsweep's detections and severity rules can be checked end to end. It never
// opens, writes to or creates threads in any other process.
//
//   1. private R-X trampoline used as a thread start  -> UNBACKED_THREAD high
//                                                     -> PRIVATE_EXEC high (thread starts here)
//   2. copy of this module's PE headers, made R-X     -> UNBACKED_PE high
//   3. private RWX page full of code bytes            -> PRIVATE_EXEC high
//   4. RWX view of a pagefile-backed section          -> MAPPED_EXEC high
//   5. private R-X page, no thread, no other signal   -> PRIVATE_EXEC low
//   6. 64 KB RWX pool that is almost entirely zero    -> PRIVATE_EXEC medium
//
// usage: selftest [seconds]   (default 60; the artifacts stay alive that long)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

HANDLE g_stop = nullptr;

DWORD WINAPI Parked(LPVOID) {
    WaitForSingleObject(g_stop, INFINITE);
    return 0;
}

unsigned char* Alloc(SIZE_T size, DWORD protect) {
    return static_cast<unsigned char*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, protect));
}

}  // namespace

int main(int argc, char** argv) {
#if !defined(_M_X64)
    (void)argc;
    (void)argv;
    std::fprintf(stderr, "selftest must be built for x64\n");
    return 2;
#else
    const DWORD seconds = argc > 1 ? static_cast<DWORD>(std::strtoul(argv[1], nullptr, 10)) : 60;
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DWORD old = 0;

    // 1. mov rax, imm64 ; jmp rax  -- forwards the new thread to Parked().
    unsigned char stub[12] = {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};
    void* target = reinterpret_cast<void*>(&Parked);
    std::memcpy(stub + 2, &target, sizeof(target));
    unsigned char* trampoline = Alloc(0x1000, PAGE_READWRITE);
    HANDLE thread = nullptr;
    if (trampoline) {
        std::memcpy(trampoline, stub, sizeof(stub));
        VirtualProtect(trampoline, 0x1000, PAGE_EXECUTE_READ, &old);
        FlushInstructionCache(GetCurrentProcess(), trampoline, sizeof(stub));
        thread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(trampoline), nullptr, 0, nullptr);
    }

    // 2. This module's headers copied into a private allocation, then made executable.
    const auto* self = reinterpret_cast<const unsigned char*>(GetModuleHandleW(nullptr));
    unsigned char* peCopy = Alloc(0x2000, PAGE_READWRITE);
    if (peCopy) {
        std::memcpy(peCopy, self, 0x1000);
        VirtualProtect(peCopy, 0x2000, PAGE_EXECUTE_READ, &old);
    }

    // 3. Private RWX page filled with int3.
    unsigned char* rwx = Alloc(0x1000, PAGE_EXECUTE_READWRITE);
    if (rwx) std::memset(rwx, 0xCC, 0x1000);

    // 4. Executable view of a pagefile-backed section, filled with int3.
    HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, 0x1000, nullptr);
    void* view = section ? MapViewOfFile(section, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, 0x1000) : nullptr;
    if (view) std::memset(view, 0xCC, 0x1000);

    // 5. Plain R-X page (nop sled + ret) that nothing runs.
    unsigned char* plainRx = Alloc(0x1000, PAGE_READWRITE);
    if (plainRx) {
        std::memset(plainRx, 0x90, 0x1000);
        plainRx[0xFFF] = 0xC3;
        VirtualProtect(plainRx, 0x1000, PAGE_EXECUTE_READ, &old);
    }

    // 6. 64 KB RWX pool with only 16 bytes used.
    unsigned char* pool = Alloc(0x10000, PAGE_EXECUTE_READWRITE);
    if (pool) std::memset(pool, 0xCC, 16);

    if (!thread || !peCopy || !rwx || !view || !plainRx || !pool) {
        std::fprintf(stderr, "selftest setup failed (error %lu)\n", GetLastError());
        return 1;
    }

    std::printf("READY pid=%lu trampoline=%p pe_copy=%p rwx=%p section_view=%p plain_rx=%p empty_pool=%p\n",
                GetCurrentProcessId(), static_cast<void*>(trampoline), static_cast<void*>(peCopy),
                static_cast<void*>(rwx), view, static_cast<void*>(plainRx), static_cast<void*>(pool));
    std::fflush(stdout);

    Sleep(seconds * 1000);
    SetEvent(g_stop);
    WaitForSingleObject(thread, 5000);
    return 0;
#endif
}
