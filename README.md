# Java4Shell Checker (CVE-2026-114938)

Read-only local checker scripts for **CVE-2026-114938 (Java4Shell)** on Windows and Linux.

Safe for production — never attaches to a JVM, writes no files, changes no settings.

## Affected Versions

| JDK Line | Status |
|----------|--------|
| 17 (from 17.0.6) | Fixed in **17.0.21.1** |
| 21 | Fixed in **21.0.13.1** |
| 25 | Fixed in **25.0.5.1** |
| 27 | Fixed in **27.0.1.1** |
| 18–20, 22–24, 26 | End of life, no fix — move to a patched LTS |
| 8 (standard), 11, ARM64, OpenJ9 | Not affected |
| Oracle 8u511b33-perf | Affected (fixed in 8u513-perf) |

## Quick CPU Check (Linux)

```bash
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$'
```

The output must include all four flags (`avx512f`, `avx512bw`, `avx512vbmi`, `bmi2`) for the CPU to take the vulnerable code path.

## Usage

### Windows (PowerShell)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Check-Java4Shell.ps1
```

Options: `-All`, `-NoExec`, `-ShowCommandLine`, `-QuickProcessScan`, `-ExtraPath <folders>`

### Linux (Bash)

```bash
sudo bash check_java4shell.sh
```

Options: `--all`, `--no-exec`, `--no-env`, `--deep-scan`, `--show-cmdline`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No exposed JVM found |
| 1 | Needs review (unknown versions, unverified mitigation, not admin, ...) |
| 2 | At least one running JVM is vulnerable and not mitigated |

## Interim Mitigation

Add `-XX:-UseBASE64Intrinsics` to the JVM's startup options and restart. Do not overwrite existing `JAVA_TOOL_OPTIONS`.
