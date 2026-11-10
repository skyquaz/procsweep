# procsweep

[![ci](https://github.com/skyquaz/procsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/skyquaz/procsweep/actions/workflows/ci.yml)

Find code-injection artifacts in running Windows processes.

procsweep is a small, read-only, user-mode scanner for incident response and threat hunting. It walks the address space and thread list of every process it can open and reports executable memory that has no image file behind it, PE images living in private memory, threads that start outside any mapped image, and image mappings whose file has disappeared. Each finding carries a MITRE ATT&CK technique ID, and the scanner can write flagged memory to disk for offline analysis.

- Single static binary, no dependencies, no driver
- Read-only: never writes to, suspends or injects into the processes it scans
- Context-aware severity, so the default output stays quiet on a normal desktop
- Text output for people, JSON output for pipelines

## Download

Get `procsweep.exe` (x64, no dependencies) from the [latest release](https://github.com/skyquaz/procsweep/releases/latest), or build it yourself (see [Build](#build)). Each release lists the file's SHA-256. The binary is not code-signed, so Windows SmartScreen may warn on first run.

## What it detects

| Finding | Meaning | Typical cause | ATT&CK |
|---|---|---|---|
| `UNBACKED_THREAD` | A thread's start address lies outside every mapped image | `CreateRemoteThread` / `NtCreateThreadEx` pointed at injected code | T1055 |
| `UNBACKED_PE` | MZ/PE headers at the base of a private or section-view allocation that has executable pages | Manual mapping, reflective DLL loading | T1055.002, T1620 |
| `PRIVATE_EXEC` | Executable private memory with no image file behind it | Shellcode, injected stubs, hook trampolines, JIT code | T1055 |
| `MAPPED_EXEC` | Executable view of a non-image section | Section-mapping injection (`NtMapViewOfSection`) | T1055 |
| `IMAGE_NO_FILE` | An image mapping whose backing file no longer exists | Process ghosting / doppelgänging style tricks | T1055.013 |

## How severity is decided

Executable memory outside images is common in legitimate software (JIT compilers, hook libraries, thunks), so procsweep weighs each allocation against its context instead of flagging all of it:

| Situation | Severity |
|---|---|
| A thread starts inside the allocation | **HIGH** |
| PE headers in non-image executable memory | **HIGH** (MEDIUM inside a code-generating process) |
| RWX memory, or an executable section view | **HIGH** / **MEDIUM**, one level lower if the region is almost entirely zero (an empty pool) |
| Process generates code at run time (.NET, Java, V8/Electron, Python ctypes, LuaJIT, ...) | LOW |
| Allocation sits in a reservation of 64 MB or more (JIT code-range sized) | LOW |
| Plain R-X private page with no other indicator | LOW |
| Thread start address no longer mapped | MEDIUM |
| Image file missing on disk | MEDIUM |

Code-generating processes are recognised by the modules and data files they map (for example `clrjit.dll`, `jvm.dll`, `libffi-8.dll`, or V8's `icudtl.dat` and `v8_context_snapshot.bin`). The default view shows MEDIUM and above; `--all` shows everything, and `--strict` turns all context-based downgrading off.

On the development machine (Windows 10 22H2, not elevated, about 100 accessible processes including several Electron apps, PowerShell, .NET tools and Python), procsweep found roughly 190 executable allocations outside images. With context-aware severity the default view showed one: an RWX region containing code in a desktop app that loads no known code generator, which is the kind of thing worth a manual look.

## Usage

```
procsweep [--pid N] [--min low|medium|high] [--all] [--strict] [--json] [--dump DIR]

  --pid N      scan one process instead of all of them
  --min LEVEL  lowest severity to report (default: medium)
  --all        report everything (same as --min low)
  --strict     no context-based down-grading
  --json       print a JSON report
  --dump DIR   save each flagged allocation to DIR for offline analysis
```

Run it from an elevated prompt to cover services and other users' processes. Exit code is 0 when nothing is reported, 1 when findings are reported and 2 on a usage error, so it can gate scripts.

Example run against the bundled self-test process:

```
> procsweep --pid 2984 --all
procsweep 0.1.0: scanned 1 process, 0 inaccessible (not elevated; run as administrator for full coverage)

HIGH    pid 2984   selftest.exe             PRIVATE_EXEC     0x0000000000400000  PRIVATE R-X  T1055
        4 KB executable private memory with no image file behind it [a thread starts here]
HIGH    pid 2984   selftest.exe             UNBACKED_THREAD  0x0000000000400000  PRIVATE R-X  T1055
        thread 15848 starts in PRIVATE R-X memory outside every mapped image
HIGH    pid 2984   selftest.exe             UNBACKED_PE      0x0000000000410000  PRIVATE R-X  T1055.002,T1620
        PE image in private memory, 8 KB executable
HIGH    pid 2984   selftest.exe             PRIVATE_EXEC     0x0000000000420000  PRIVATE RWX  T1055
        4 KB executable private memory with no image file behind it (RWX)
HIGH    pid 2984   selftest.exe             MAPPED_EXEC      0x0000000000430000  MAPPED  RWX  T1055
        4 KB executable section-view memory with no image file behind it (RWX)
MEDIUM  pid 2984   selftest.exe             PRIVATE_EXEC     0x0000000000450000  PRIVATE RWX  T1055
        64 KB executable private memory with no image file behind it (RWX) [mostly empty: 0.02% non-zero]
LOW     pid 2984   selftest.exe             PRIVATE_EXEC     0x0000000000440000  PRIVATE R-X  T1055
        4 KB executable private memory with no image file behind it [R-X with no other indicator]

7 findings at or above low: 5 high, 1 medium, 1 low
```

JSON output (`--json`) contains the same fields per finding: `pid`, `process`, `type`, `severity`, `attck`, `address`, `size`, `protection`, `memory`, `tid`, `codegen_host`, `detail` and `dump`.

## Build

Requires Visual Studio 2022 or its Build Tools with the "Desktop development with C++" workload.

```
build.bat
```

This produces `build\procsweep.exe` and `build\selftest.exe` (x64, static CRT).

## Self-test

`tests\selftest.cpp` plants benign artifacts inside its own process (it never touches another process): a thread started from a private R-X trampoline, a copy of its own PE headers in executable private memory, an RWX page full of code, an executable section view, a plain R-X page and an almost empty RWX pool. `tests\run-selftest.ps1` scans it and checks that every artifact is reported with the expected type and severity.

```
powershell -ExecutionPolicy Bypass -File tests\run-selftest.ps1
...
PASS: all 7 planted artifacts detected with the expected severity
```

CI builds procsweep and runs this self-test on a fresh `windows-latest` runner for every push and pull request.

## How it works

1. Processes and threads come from one Toolhelp snapshot. Each process is opened with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` (`SeDebugPrivilege` is enabled when available).
2. `VirtualQueryEx` walks the whole address space. Committed executable regions that are not `MEM_IMAGE` are grouped by allocation base. `GetMappedFileNameW` names every image and file-backed view, which is how code-generating runtimes are recognised.
3. Each executable allocation is checked for MZ/PE headers at its base, its reservation size, its protection, and, when it is RWX or a section view, the share of non-zero bytes in its executable pages.
4. Thread start addresses come from `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` and are looked up with `VirtualQueryEx`.
5. Image files are checked on disk through `\\?\GLOBALROOT` plus the NT device path, so volumes without drive letters work too.

## Limitations

- User mode only. Protected (PPL) processes cannot be opened, and running without elevation skips other users' and elevated processes.
- Code living in image-backed memory is not inspected, so module stomping, inline hooks and classic process hollowing with a legitimately mapped image are out of scope for now.
- Hijacking an existing thread (`SetThreadContext`, APC queued to a running thread) leaves a legitimate start address, so only the injected memory itself can be found, and plain R-X pages are LOW by default. Use `--all` or `--strict` when hunting.
- Downgrading inside code-generating processes is a trade-off: code injected into a JIT host lands at LOW. `--strict` disables it.
- Manual maps that wipe their headers show up as `PRIVATE_EXEC` rather than `UNBACKED_PE`.
- x64 build only (it scans WOW64 processes too).

## Roadmap

- Compare in-memory `.text` of loaded modules against the file on disk (hooks, module stomping)
- Walk thread call stacks for return addresses in unbacked memory
- Companion Sigma rules for Sysmon events 8 (CreateRemoteThread), 10 (ProcessAccess) and 25 (ProcessTampering)

## Prior art

Ideas from these projects shaped procsweep: [pe-sieve / hollows_hunter](https://github.com/hasherezade/pe-sieve) by hasherezade, [Moneta](https://github.com/forrest-orr/moneta) by Forrest Orr, and [Get-InjectedThread](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2) by Jared Atkinson.

## License

MIT, see [LICENSE](LICENSE).
