<#
.SYNOPSIS
  CVE-2026-114938 (Java4Shell) read-only local checker for Windows, v2.

.DESCRIPTION
  Safe for production:
    - never attaches to a JVM (no jcmd/jstack/jinfo), writes no files, changes no settings
    - never touches network paths (UNC, mapped drives); WMI queries have a timeout
    - never opens OS or security-product processes (lsass, EDR agents) to read modules
    - runs at BelowNormal priority; directory scans are depth-limited and capped
    - versions come from each JDK's "release" file; java.exe is run only as a fallback,
      with a 15 s timeout, a small heap, and JAVA_TOOL_OPTIONS/_JAVA_OPTIONS removed
    - command lines are not printed unless -ShowCommandLine (they often contain passwords)
  Relaunches itself in 64-bit PowerShell when started from a 32-bit host (RMM/SCCM agents).

  Exit codes: 0 = nothing exposed found
              1 = needs review (unknown versions, unverified mitigation, not admin, ...)
              2 = at least one RUNNING JVM is vulnerable and not mitigated

  Data (Oracle CVE record + OpenJDK fixed builds, Nov 17 2026):
    fixed: 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1   (17 affected from 17.0.6)
    18-20, 22-24, 26: same code, end of life, no fix
    8 (standard), 11, ARM64, 32-bit, OpenJ9: not affected.  Oracle 8u511b33-perf: affected.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Check-Java4Shell.ps1
  (Tell your SOC first: "-ExecutionPolicy Bypass" is a common EDR detection.)
#>
[CmdletBinding()]
param(
    [switch]$All,              # keep checking even if the CPU is not exposed
    [switch]$NoExec,           # never run java.exe (release files only)
    [switch]$ShowCommandLine,  # print redacted command lines
    [switch]$QuickProcessScan, # only inspect java/javaw/Procrun/Tomcat processes (fewest process handles opened)
    [string[]]$ExtraPath = @() # extra folders to scan for Java (depth-limited)
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Off

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host "This PowerShell session runs in $($ExecutionContext.SessionState.LanguageMode) (AppLocker/WDAC)." -ForegroundColor Yellow
    Write-Host 'The checker needs FullLanguage to give correct results; nothing was checked.' -ForegroundColor Yellow
    exit 1
}
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Host "PowerShell $($PSVersionTable.PSVersion) is too old (3.0+ needed); nothing was checked." -ForegroundColor Yellow
    exit 1
}

# ---------- 0. 64-bit relaunch, priority, admin ----------
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:WINDIR 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $ps64) {
        $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        if ($All) { $a += '-All' }
        if ($NoExec) { $a += '-NoExec' }
        if ($ShowCommandLine) { $a += '-ShowCommandLine' }
        if ($QuickProcessScan) { $a += '-QuickProcessScan' }
        if ($ExtraPath.Count -gt 0) { $a += '-ExtraPath'; $a += ($ExtraPath -join ',') }
        & $ps64 @a
        exit $LASTEXITCODE
    }
    Write-Host "WARNING: running in 32-bit PowerShell and could not relaunch as 64-bit; results are incomplete." -ForegroundColor Yellow
}
try { (Get-Process -Id $PID).PriorityClass = 'BelowNormal' } catch { }

$script:ReviewNeeded = $false
$script:RunningVuln  = $false

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$Fix = @{ 17 = '17.0.21.1'; 21 = '21.0.13.1'; 25 = '25.0.5.1'; 27 = '27.0.1.1' }
$EolLines = @(18, 19, 20, 22, 23, 24, 26)

# ---------- helpers ----------
# Only local fixed-disk paths are ever touched (a dead file server would hang Test-Path for minutes).
$script:localRoots = @()
try {
    $script:localRoots = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 30 -ErrorAction Stop |
        ForEach-Object { $_.DeviceID.ToUpper() + '\' })
} catch { $script:localRoots = @(($env:SystemDrive.ToUpper()) + '\') }
function Test-LocalPath([string]$Path) {
    if (-not $Path) { return $false }
    $Path = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if ($Path -notmatch '^[A-Za-z]:\\') { return $false }          # rejects \\server\share, \\?\, relative paths
    return ($script:localRoots -contains $Path.Substring(0, 3).ToUpper())
}

function Test-VersionGE([string]$A, [string]$B) {
    $x = @($A.Split('.') | ForEach-Object { [int64]$_ })
    $y = @($B.Split('.') | ForEach-Object { [int64]$_ })
    for ($i = 0; $i -lt 6; $i++) {
        $p = 0; if ($i -lt $x.Count) { $p = $x[$i] }
        $q = 0; if ($i -lt $y.Count) { $q = $y[$i] }
        if ($p -gt $q) { return $true }
        if ($p -lt $q) { return $false }
    }
    return $true
}

function Get-VersionStatus([string]$Raw, [string]$Context) {
    $r = [pscustomobject]@{ Status = 'REVIEW'; Note = '' }
    if ($Context -match 'openj9') { $r.Status = 'NOT_AFFECTED'; $r.Note = 'OpenJ9 VM, not HotSpot'; return $r }
    if ($Context -match 'GRAALVM_VERSION="?21\.3') { $r.Note = 'GraalVM Enterprise 21.3: 21.3.20.0.3 affected, fixed in 21.3.20.1'; return $r }
    if ([string]::IsNullOrEmpty($Raw)) { $r.Note = 'version not found (no release file, and java.exe was not run)'; return $r }
    if ($Raw -match '-ea|internal') { $r.Note = 'early-access/internal build, check manually'; return $r }
    $perf = ("$Raw $Context" -match '-perf')
    if ($Raw -match '^(\d+(?:[._]\d+)*)') { $v = $Matches[1] -replace '_', '.' }
    else { $r.Note = "cannot parse version '$Raw'"; return $r }
    if ($v.StartsWith('1.')) { $v = $v.Substring(2) }          # 1.8.0_392 -> 8.0.392
    $major = [int]($v.Split('.')[0])

    if ($major -eq 8 -and $perf) { $r.Note = 'Oracle 8u Performance Pack: 8u511b33-perf affected, fixed in 8u513-perf'; return $r }
    if ($major -le 16) { $r.Status = 'NOT_AFFECTED'; $r.Note = "Java $major is outside the affected range"; return $r }
    if ($EolLines -contains $major) { $r.Status = 'VULNERABLE'; $r.Note = "Java $major is end of life and gets no fix: move to a patched LTS"; return $r }
    if (-not $Fix.ContainsKey($major)) { $r.Note = "Java $major is newer than this script's data, check vendor advisory"; return $r }
    if ($major -eq 17 -and -not (Test-VersionGE $v '17.0.6')) { $r.Status = 'NOT_AFFECTED'; $r.Note = 'before 17.0.6, vulnerable code not present'; return $r }
    if (Test-VersionGE $v $Fix[$major]) { $r.Status = 'PATCHED'; $r.Note = "at or above fixed build $($Fix[$major])" }
    else { $r.Status = 'VULNERABLE'; $r.Note = "below fixed build $($Fix[$major])" }
    return $r
}

function Get-ReleaseFile([string]$JavaHome) {
    if (-not (Test-LocalPath $JavaHome)) { return $null }
    foreach ($c in @((Join-Path $JavaHome 'release'), (Join-Path (Split-Path $JavaHome -Parent) 'release'))) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return (Get-Item -LiteralPath $c) }
    }
    return $null
}

function Invoke-JavaProbe([string]$Exe, [string]$Arguments, [int]$TimeoutMs = 15000) {
    if ($NoExec) { return $null }
    if (-not (Test-LocalPath $Exe)) { return $null }
    $p = $null
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.WorkingDirectory = $env:SystemRoot     # no hs_err file in a work dir
        foreach ($n in @('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH')) {
            if ($psi.EnvironmentVariables.ContainsKey($n)) { $psi.EnvironmentVariables.Remove($n) }
        }
        $p = [System.Diagnostics.Process]::Start($psi)
        if ($script:hasAsync) {
            $o = $p.StandardOutput.ReadToEndAsync()
            $e = $p.StandardError.ReadToEndAsync()
            if (-not $p.WaitForExit($TimeoutMs)) { try { $p.Kill() } catch { }; return $null }
            return ($o.Result + "`n" + $e.Result)
        } else {
            # .NET 4.0: output of these probes is a few KB, far below the pipe buffer, so no deadlock
            if (-not $p.WaitForExit($TimeoutMs)) { try { $p.Kill() } catch { }; return $null }
            return ($p.StandardOutput.ReadToEnd() + "`n" + $p.StandardError.ReadToEnd())
        }
    } catch { return $null }
    finally { if ($p) { try { $p.Dispose() } catch { } } }
}
$script:hasAsync = $null -ne [System.IO.StreamReader].GetMethod('ReadToEndAsync', [Type[]]@())

# returns object: Raw, Context, Source, ReleaseTime
function Get-JavaVersionInfo([string]$JavaHome, [string]$JavaExe) {
    $info = [pscustomobject]@{ Raw = ''; Context = ''; Source = ''; ReleaseTime = $null }
    $rel = Get-ReleaseFile $JavaHome
    if ($rel) {
        $kv = @{}
        foreach ($l in (Get-Content -LiteralPath $rel.FullName -TotalCount 200 -ErrorAction SilentlyContinue)) {
            if ($l -match '^([A-Z_]+)="?([^"]*)"?\s*$') { $kv[$Matches[1]] = $Matches[2] }
        }
        $raw = $kv['JAVA_RUNTIME_VERSION']; if (-not $raw) { $raw = $kv['JAVA_VERSION'] }
        if ($raw) {
            $info.Raw = ($raw -split '\+')[0]
            $info.Context = (@('IMPLEMENTOR', 'JVM_VARIANT', 'GRAALVM_VERSION', 'JAVA_VERSION') |
                ForEach-Object { if ($kv.ContainsKey($_)) { "$_=`"$($kv[$_])`"" } }) -join ' '
            $info.Source = 'release file'
            $t = $rel.LastWriteTime; if ($rel.CreationTime -gt $t) { $t = $rel.CreationTime }
            $info.ReleaseTime = $t
        }
    }
    if (-not $info.Raw -and (Test-LocalPath $JavaExe) -and (Test-Path -LiteralPath $JavaExe)) {
        $out = Invoke-JavaProbe $JavaExe '-Xmx64m -XX:+UseSerialGC -XX:TieredStopAtLevel=1 -XX:-UsePerfData -version'
        if ($out -and $out -match 'version "([^"]+)"') {
            $info.Raw = ($Matches[1] -split '\+')[0]; $info.Context = $out; $info.Source = 'java -version'
        }
    }
    return $info
}

function Get-DistroNote([string]$Context) {
    if ($Context -match 'IMPLEMENTOR="([^"]*(Red Hat|SUSE|Ubuntu|Debian)[^"]*)"') {
        return " (vendor build by $($Matches[1]): a backported fix may not change the version, check errata for JDK-8393212)"
    }
    return ''
}

function Split-CommandLine([string]$s) {
    $list = New-Object System.Collections.Generic.List[string]
    if (-not $s) { return , $list }
    foreach ($m in [regex]::Matches($s, '(?:"[^"]*"|[^\s"]+)+')) { $list.Add(($m.Value -replace '"', '')) }
    return , $list
}

# Tokens must be added in HotSpot processing order; the last value of a flag wins.
function Get-Mitigation($Tokens) {
    $b64 = ''; $b64s = ''; $avx = ''; $avxs = ''; $dis = ''; $xint = $false
    foreach ($t in $Tokens) {
        $tok = $t.Tok; $src = $t.Src
        if ($tok -ceq '-XX:-UseBASE64Intrinsics' -or $tok -ceq '-XX:UseBASE64Intrinsics=false') { $b64 = 'off'; $b64s = $src }
        elseif ($tok -ceq '-XX:+UseBASE64Intrinsics' -or $tok -ceq '-XX:UseBASE64Intrinsics=true') { $b64 = 'on'; $b64s = $src }
        elseif ($tok -cmatch '^-XX:UseAVX=(\d+)$') { $avx = $Matches[1]; $avxs = $src }
        elseif ($tok -cmatch '^-XX:DisableIntrinsic=.*_base64_decodeBlock') { $dis = $src }
        elseif ($tok -cmatch '^-XX:ControlIntrinsic=.*-_base64_decodeBlock') { $dis = $src }
        elseif ($tok -ceq '-Xint') { $xint = $true }
    }
    if ($b64 -eq 'off') { return [pscustomobject]@{ Text = "-XX:-UseBASE64Intrinsics via $b64s"; Src = $b64s } }
    if ($avx -match '^[0-2]$') { return [pscustomobject]@{ Text = "-XX:UseAVX=$avx via $avxs"; Src = $avxs } }
    if ($dis) { return [pscustomobject]@{ Text = "DisableIntrinsic _base64_decodeBlock via $dis"; Src = $dis } }
    if ($xint) { return [pscustomobject]@{ Text = '-Xint (no JIT)'; Src = 'command line' } }
    return $null
}

function Add-Tokens($List, [string]$Source, $Words) {
    foreach ($w in $Words) { if ($w) { $List.Add([pscustomobject]@{ Tok = $w; Src = $Source }) } }
}

function Add-FileTokens($List, [string]$Source, [string]$File, [bool]$FlagsFormat) {
    if (-not (Test-LocalPath $File) -or -not (Test-Path -LiteralPath $File -PathType Leaf)) {
        $List.Add([pscustomobject]@{ Tok = '#UNREADABLE'; Src = $Source }); return
    }
    foreach ($line in (Get-Content -LiteralPath $File -TotalCount 2000 -ErrorAction SilentlyContinue)) {
        $line = ($line -split '#')[0]
        foreach ($w in (Split-CommandLine $line)) {
            if ($FlagsFormat -and $w -notmatch '^-XX:' -and ($w -match '^[+-]' -or $w -match '=')) { $w = "-XX:$w" }
            $List.Add([pscustomobject]@{ Tok = $w; Src = $Source })
        }
    }
}

function Get-RegMulti([string]$Path, [string]$Name) {
    try {
        $v = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        if ($v -is [array]) { return ($v -join ' ') } else { return [string]$v }
    } catch { return '' }
}

function Protect-Text([string]$s) {
    return ($s -replace '(?i)((pass(word)?|pwd|secret|token|apikey|api[._-]key|credential)[A-Za-z0-9._-]*[=:])\S+', '$1****')
}

function Write-Status([string]$Label, [string]$Status, [string]$Color, [string]$Note) {
    Write-Host "    $Label" -NoNewline
    Write-Host $Status -ForegroundColor $Color -NoNewline
    if ($Note) { Write-Host "  - $Note" } else { Write-Host '' }
}

# ---------- header ----------
Write-Host '=== CVE-2026-114938 (Java4Shell) local check v2 (Windows) ===' -ForegroundColor Cyan
Write-Host ("Host: {0}   OS: {1}   Date: {2:yyyy-MM-dd HH:mm} UTC" -f $env:COMPUTERNAME, [Environment]::OSVersion.VersionString, (Get-Date).ToUniversalTime())
if (-not $isAdmin) {
    Write-Host 'WARNING: not running as Administrator. Other users'' processes, their command lines and' -ForegroundColor Yellow
    Write-Host '         loaded modules cannot be read, so the result is incomplete. Re-run elevated.' -ForegroundColor Yellow
    $script:ReviewNeeded = $true
}
Write-Host ''

# ---------- 1. installed runtimes (needed first: one of them answers the CPU question) ----------
$javaExes = New-Object System.Collections.Generic.List[string]
function Add-Java([string]$p) {
    if ((Test-LocalPath $p) -and (Test-Path -LiteralPath $p -PathType Leaf)) { $javaExes.Add((Resolve-Path -LiteralPath $p).ProviderPath) }
}

# PATH, local entries only (Get-Command would also probe network PATH entries)
foreach ($pd in (($env:PATH + ';' + [Environment]::GetEnvironmentVariable('PATH', 'Machine')) -split ';')) {
    $pd = [Environment]::ExpandEnvironmentVariables($pd.Trim().Trim('"'))
    if (Test-LocalPath $pd) { Add-Java (Join-Path $pd 'java.exe') }
}
foreach ($jh in @($env:JAVA_HOME, [Environment]::GetEnvironmentVariable('JAVA_HOME', 'Machine'))) {
    if ($jh) { Add-Java (Join-Path $jh 'bin\java.exe') }
}

# registry: walk vendor keys (depth-limited) for JavaHome / Path / InstallationPath values
$regRoots = @('HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node')
$vendorKeys = @('JavaSoft', 'Eclipse Adoptium', 'Eclipse Foundation', 'AdoptOpenJDK', 'Azul Systems', 'Amazon Corretto',
                'BellSoft', 'Microsoft\JDK', 'SapMachine', 'IBM\Semeru', 'Semeru', 'Oracle\GraalVM', 'Red Hat')
function Read-RegJava([string]$Key, [int]$Depth) {
    if ($Depth -lt 0) { return }
    try {
        $props = Get-ItemProperty -LiteralPath $Key -ErrorAction Stop
        foreach ($n in @('JavaHome', 'Path', 'InstallationPath')) {
            $v = $props.$n
            if ($v -is [string] -and $v) { Add-Java (Join-Path $v 'bin\java.exe') }
        }
        foreach ($sub in @(Get-ChildItem -LiteralPath $Key -ErrorAction SilentlyContinue)) { Read-RegJava $sub.PSPath ($Depth - 1) }
    } catch { }
}
foreach ($root in $regRoots) { foreach ($vk in $vendorKeys) {
    $k = Join-Path $root $vk; if (Test-Path -LiteralPath $k) { Read-RegJava $k 4 } } }

# Procrun (Tomcat etc.) JVM paths
$procrunRoots = @('HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0', 'HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0')
foreach ($pr in $procrunRoots) {
    foreach ($svcKey in @(Get-ChildItem -LiteralPath $pr -ErrorAction SilentlyContinue)) {
        $jvm = Get-RegMulti (Join-Path $svcKey.PSPath 'Parameters\Java') 'Jvm'
        if ($jvm -and $jvm -ne 'auto' -and $jvm -match 'jvm\.dll$') {
            Add-Java (Join-Path (Split-Path (Split-Path (Split-Path $jvm -Parent) -Parent) -Parent) 'bin\java.exe')
        }
    }
}

# depth-limited, capped directory walk (no junction/symlink following)
$skipNames = @('WindowsApps', 'Windows Defender', 'Windows Defender Advanced Threat Protection', 'Microsoft Office',
               'Reference Assemblies', 'Windows Kits', 'dotnet', 'WindowsPowerShell', 'Windows NT', 'Internet Explorer',
               'node_modules', '.git', '$Recycle.Bin', 'System Volume Information', 'Windows', 'Users', 'WinSxS')
$script:dirBudget = 150000
function Find-JavaUnder([string]$Root, [int]$MaxDepth, [string[]]$ExtraSkip = @()) {
    $stack = New-Object System.Collections.Stack
    try { $stack.Push(@((New-Object System.IO.DirectoryInfo $Root), 0)) } catch { return }
    while ($stack.Count -gt 0 -and $script:dirBudget -gt 0) {
        $item = $stack.Pop(); $di = $item[0]; $depth = $item[1]
        $script:dirBudget--
        if ($di.Name -eq 'bin') {
            $j = Join-Path $di.FullName 'java.exe'
            if ([System.IO.File]::Exists($j)) { Add-Java $j }
            continue
        }
        if ($depth -ge $MaxDepth) { continue }
        try { $subs = $di.GetDirectories() } catch { continue }
        foreach ($s in $subs) {
            if (($s.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            if ($skipNames -contains $s.Name -or $ExtraSkip -contains $s.Name) { continue }
            $stack.Push(@($s, ($depth + 1)))
        }
    }
}
$scanRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) | Where-Object { $_ } | Select-Object -Unique
foreach ($r in $scanRoots) { Find-JavaUnder $r 6 }
# top-level folders of the system drive (C:\Java, C:\apps, C:\tomcat, ...)
Find-JavaUnder ($env:SystemDrive + '\') 5 @('Program Files', 'Program Files (x86)')
foreach ($x in $ExtraPath) { foreach ($y in ($x -split ',')) { if (Test-LocalPath $y) { Find-JavaUnder $y 6 } elseif ($y) { Write-Host "Skipping non-local path $y" -ForegroundColor Yellow } } }
if ($script:dirBudget -le 0) { Write-Host 'NOTE: directory scan budget reached; use -ExtraPath for specific folders.' -ForegroundColor Yellow }

$javaExes = @($javaExes | Where-Object { $_ -notmatch '\\Oracle\\Java\\javapath' } | Sort-Object -Unique)

# ---------- 2. CPU ----------
$osArch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $osArch = $env:PROCESSOR_ARCHITEW6432 }   # 32-bit host on 64-bit OS
$cpuName = ''
try { $cpuName = (Get-CimInstance Win32_Processor -OperationTimeoutSec 30 -ErrorAction Stop | Select-Object -First 1).Name } catch { }
$cpuExposed = $true
if ($osArch -ne 'AMD64') {
    Write-Host "CPU: NOT AFFECTED ($osArch; the vulnerable code is x86-64 only)" -ForegroundColor Green
    $cpuExposed = $false
} else {
    # Ask a HotSpot JVM which CPU features it sees (works in VMs, no native code needed)
    $cpuAnswer = $null
    foreach ($j in @($javaExes | Select-Object -First 5)) {
        $out = Invoke-JavaProbe $j '-Xmx32m -XX:+UseSerialGC -XX:-UsePerfData -Xlog:os+cpu -version' 10000
        if ($out -and $out -match '(?m)^.*CPU:.*\b(sse2|avx)\b.*$') {
            $line = $Matches[0]
            $cpuAnswer = ($line -match '\bavx512_vbmi\b') -and ($line -match '\bavx512bw\b')
            break
        }
    }
    if ($cpuAnswer -eq $true) {
        Write-Host "CPU: AVX-512 VBMI present ($cpuName): this hardware takes the vulnerable code path" -ForegroundColor Red
    } elseif ($cpuAnswer -eq $false) {
        Write-Host "CPU: NOT AFFECTED ($cpuName): the JVM sees no avx512_vbmi/avx512bw" -ForegroundColor Green
        Write-Host '     (in a VM this depends on the hypervisor CPU model; re-check after migration or CPU model change)'
        $cpuExposed = $false
    } else {
        Write-Host "CPU: UNKNOWN ($cpuName): no JVM could report CPU features (or -NoExec), assuming exposed" -ForegroundColor Yellow
    }
}
if (-not $cpuExposed -and -not $All) {
    Write-Host ''; Write-Host 'Host is not exposed (CPU). Use -All to inventory Java anyway.' -ForegroundColor Green
    if ($script:ReviewNeeded) { exit 1 } else { exit 0 }
}
Write-Host ''

# ---------- 3. running JVMs (the part that decides exposure) ----------
Write-Host '=== Running JVMs (processes with jvm.dll loaded) ===' -ForegroundColor Cyan
$cim = @{}
try { foreach ($p in (Get-CimInstance Win32_Process -OperationTimeoutSec 60 -ErrorAction Stop)) { $cim[[int]$p.ProcessId] = $p } } catch { }
$svcByPid = @{}
try { foreach ($s in (Get-CimInstance Win32_Service -OperationTimeoutSec 60 -ErrorAction Stop)) { if ($s.ProcessId) { $svcByPid[[int]$s.ProcessId] = $s } } } catch { }
$procrunServices = @{}
foreach ($pr in $procrunRoots) { foreach ($k in @(Get-ChildItem -LiteralPath $pr -ErrorAction SilentlyContinue)) { $procrunServices[$k.PSChildName.ToLower()] = $true } }
$machineJTO = [Environment]::GetEnvironmentVariable('JAVA_TOOL_OPTIONS', 'Machine')
$machineJO  = [Environment]::GetEnvironmentVariable('_JAVA_OPTIONS', 'Machine')
$machineJDK = [Environment]::GetEnvironmentVariable('JDK_JAVA_OPTIONS', 'Machine')

# Never open OS or security processes (e.g. lsass) for module reads: EDRs treat that as credential theft.
$denyNames = @('lsass', 'LsaIso', 'csrss', 'smss', 'wininit', 'winlogon', 'services', 'svchost', 'MsMpEng', 'NisSrv',
               'MsSense', 'SenseIR', 'SenseNdr', 'SenseCncProxy', 'MpDefenderCoreService', 'SecurityHealthService',
               'CSFalconService', 'CSFalconContainer', 'SentinelAgent', 'SentinelServiceHost', 'SentinelStaticEngine',
               'cb', 'RepMgr', 'CylanceSvc', 'xagt', 'elastic-endpoint', 'TmCCSF', 'ccSvcHst', 'SophosHealth', 'SEDService')
$winDir = $env:WINDIR.TrimEnd('\') + '\'
$securityPathPattern = '(?i)\\(CrowdStrike|SentinelOne|Sentinel Agent|Windows Defender|Microsoft Defender|Windows Defender Advanced Threat Protection|Carbon ?Black|Confer|Cylance|Sophos|Trend ?Micro|Symantec|Norton|McAfee|Trellix|FireEye|Tanium|Qualys|Rapid7|Palo Alto Networks|Cortex|Traps|ESET|Kaspersky|Bitdefender|Elastic\\Endpoint|Cybereason|Malwarebytes|Fortinet|FortiClient|Check ?Point|Deep Instinct|Huntress|Arctic ?Wolf|Darktrace|Velociraptor|osquery|Sysmon|Splunk)\\'
$runningHomes = @{}
$nJvm = 0
foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
    if ($proc.Id -le 4) { continue }
    $isJavaName = $proc.ProcessName -match '^(java|javaw)$'
    if ($denyNames -contains $proc.ProcessName) { continue }
    $exePath = $null; if ($cim.ContainsKey([int]$proc.Id)) { $exePath = $cim[[int]$proc.Id].ExecutablePath }
    if (-not $isJavaName) {
        if (-not $exePath) { continue }                                        # protected or not visible
        if ($exePath.StartsWith($winDir, [StringComparison]::OrdinalIgnoreCase)) { continue }   # OS binaries never host a JVM
        if ($exePath -match $securityPathPattern) { continue }                 # security agents: never open
        if (-not (Test-LocalPath $exePath)) { continue }
        if ($QuickProcessScan) {
            $svcName = ''; if ($svcByPid.ContainsKey([int]$proc.Id)) { $svcName = $svcByPid[[int]$proc.Id].Name.ToLower() }
            if (-not ($proc.ProcessName -match '^(tomcat\d*|prunsrv|jsvc)$' -or $procrunServices.ContainsKey($svcName))) { continue }
        }
    }
    $jvmDll = $null; $isJ9 = $false
    try {
        foreach ($m in $proc.Modules) {
            if ($m.ModuleName -ieq 'jvm.dll') { $jvmDll = $m.FileName }
            if ($m.ModuleName -like 'j9vm*.dll') { $isJ9 = $true }
        }
    } catch { }
    if (-not $jvmDll) {
        if ($isJavaName) {
            $nJvm++
            Write-Host "  PID $($proc.Id)  $($proc.ProcessName).exe  $exePath"
            Write-Status 'Verdict:    ' 'REVIEW' 'Yellow' 'jvm.dll not visible: not elevated, or a 32-bit JVM (32-bit is not affected)'
            $script:ReviewNeeded = $true
        }
        continue
    }
    $nJvm++

    $binDir = Split-Path (Split-Path $jvmDll -Parent) -Parent       # ...\bin
    $javaHome = Split-Path $binDir -Parent
    if ($jvmDll -match '\\j9vm\\') { $isJ9 = $true }
    $runningHomes[$javaHome.ToLower()] = $true
    $vi = Get-JavaVersionInfo $javaHome (Join-Path $binDir 'java.exe')
    $ctx = $vi.Context; if ($isJ9) { $ctx = "$ctx openj9" }
    $vs = Get-VersionStatus $vi.Raw $ctx

    $start = $null; try { $start = $proc.StartTime } catch { }
    $stale = ($start -and $vi.ReleaseTime -and $vi.ReleaseTime -gt $start.AddMinutes(1))

    # option sources in HotSpot order: JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS, command line / procrun, _JAVA_OPTIONS
    $toks = New-Object System.Collections.Generic.List[object]
    $svc = $svcByPid[[int]$proc.Id]
    $svcEnv = @{}
    if ($svc) {
        $envMulti = $null
        try { $envMulti = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name Environment -ErrorAction Stop).Environment } catch { }
        foreach ($e in @($envMulti)) { if ($e -match '^([^=]+)=(.*)$') { $svcEnv[$Matches[1].ToUpper()] = $Matches[2] } }
    }
    $jto = $svcEnv['JAVA_TOOL_OPTIONS']; $jtoSrc = 'service env JAVA_TOOL_OPTIONS'
    if (-not $jto) { $jto = $machineJTO; $jtoSrc = 'machine env JAVA_TOOL_OPTIONS' }
    Add-Tokens $toks $jtoSrc (Split-CommandLine $jto)
    if ($proc.ProcessName -match '^(java|javaw)$') {
        $jdk = $svcEnv['JDK_JAVA_OPTIONS']; if (-not $jdk) { $jdk = $machineJDK }
        Add-Tokens $toks 'env JDK_JAVA_OPTIONS' (Split-CommandLine $jdk)
    }
    $cmd = ''
    if ($cim.ContainsKey([int]$proc.Id)) { $cmd = $cim[[int]$proc.Id].CommandLine }
    $words = Split-CommandLine $cmd
    for ($i = 1; $i -lt $words.Count; $i++) {
        $w = $words[$i]
        if ($w.StartsWith('@')) { Add-FileTokens $toks "argfile $($w.Substring(1))" $w.Substring(1) $false }
        elseif ($w -like '-XX:VMOptionsFile=*') { Add-FileTokens $toks 'VMOptionsFile' $w.Substring(18) $false }
        elseif ($w -like '-XX:Flags=*') { Add-FileTokens $toks 'Flags file' $w.Substring(10) $true }
        else { $toks.Add([pscustomobject]@{ Tok = $w; Src = 'command line' }) }
    }
    # Procrun services keep JVM options in the registry, not on the command line
    if ($svc) {
        foreach ($pr in $procrunRoots) {
            $jk = Join-Path $pr "$($svc.Name)\Parameters\Java"
            if (Test-Path -LiteralPath $jk) {
                $raw = (Get-ItemProperty -LiteralPath $jk -ErrorAction SilentlyContinue)
                foreach ($optName in @('Options', 'Options9')) {
                    foreach ($o in @($raw.$optName)) { if ($o) { $toks.Add([pscustomobject]@{ Tok = [string]$o; Src = "Procrun $optName (service config)" }) } }
                }
            }
        }
    }
    $jo = $svcEnv['_JAVA_OPTIONS']; $joSrc = 'service env _JAVA_OPTIONS'
    if (-not $jo) { $jo = $machineJO; $joSrc = 'machine env _JAVA_OPTIONS' }
    Add-Tokens $toks $joSrc (Split-CommandLine $jo)

    $mit = Get-Mitigation $toks
    $unreadable = @($toks | Where-Object { $_.Tok -eq '#UNREADABLE' }).Count -gt 0
    $mitConfirmed = $mit -and ($mit.Src -eq 'command line' -or $mit.Src -like 'argfile*' -or $mit.Src -like 'VMOptionsFile*' -or $mit.Src -like 'Flags file*')

    $note = $vs.Note
    if (-not $cpuExposed) { $verdict = 'NOT AFFECTED (CPU)'; $col = 'Green' }
    elseif ($vs.Status -eq 'NOT_AFFECTED') { $verdict = 'NOT AFFECTED'; $col = 'Green' }
    elseif ($stale) {
        $note = 'JDK files changed after this process started (in-place upgrade or pending reboot); it may still run the OLD build. Restart it.'
        if ($mit) { $verdict = 'MITIGATED (restart pending)'; $col = 'Yellow'; $script:ReviewNeeded = $true }
        else { $verdict = 'LIKELY VULNERABLE'; $col = 'Red'; $script:RunningVuln = $true }
    }
    elseif ($vs.Status -eq 'PATCHED') { $verdict = 'PATCHED'; $col = 'Green' }
    elseif ($vs.Status -eq 'VULNERABLE') {
        if ($mitConfirmed) { $verdict = 'MITIGATED'; $col = 'Yellow' }
        elseif ($mit) {
            $verdict = 'MITIGATED (unverified)'; $col = 'Yellow'; $script:ReviewNeeded = $true
            $note = "$note; flag comes from configuration, so it only applies if the process was started after it was set (services read machine env at boot)"
        } else {
            $verdict = 'VULNERABLE'; $col = 'Red'; $script:RunningVuln = $true
            if (-not $cmd) { $note = "$note; command line not readable (run elevated)" }
            if ($unreadable) { $note = "$note; an options/arg file could not be read" }
        }
        $note = $note + (Get-DistroNote $vi.Context)
    }
    else { $verdict = 'REVIEW'; $col = 'Yellow'; $script:ReviewNeeded = $true }

    $svcLabel = ''; if ($svc) { $svcLabel = "  service=$($svc.Name)" }
    $up = ''; if ($start) { $up = "  started=$($start.ToString('yyyy-MM-dd HH:mm'))" }
    Write-Host "  PID $($proc.Id)  $($proc.ProcessName).exe$svcLabel$up"
    Write-Host "    JVM:        $javaHome"
    if ($stale) { Write-Host "    Version:    unknown, may be older than what is on disk now ($($vi.Raw))" }
    else { Write-Host "    Version:    $(if ($vi.Raw) { $vi.Raw } else { 'unknown' })$(if ($vi.Source) { " (from $($vi.Source))" })" }
    Write-Host "    Mitigation: $(if ($mit) { $mit.Text } else { 'none found' })"
    Write-Status 'Verdict:    ' $verdict $col $note
    if ($ShowCommandLine -and $cmd) {
        $c = Protect-Text $cmd; if ($c.Length -gt 400) { $c = $c.Substring(0, 400) + '...' }
        Write-Host "    CMD: $c"
    }
}
if ($nJvm -eq 0) {
    if ($isAdmin) { Write-Host '  No running JVMs found.' } else { Write-Host '  None visible to this user (run elevated).' }
}
Write-Host ''

# ---------- 4. installed runtimes (informational) ----------
Write-Host '=== Installed Java runtimes ===' -ForegroundColor Cyan
if ($javaExes.Count -eq 0) { Write-Host '  No Java runtimes found.' }
foreach ($j in $javaExes) {
    $jhome = Split-Path (Split-Path $j -Parent) -Parent
    $vi = Get-JavaVersionInfo $jhome $j
    $vs = Get-VersionStatus $vi.Raw $vi.Context
    $run = ''; if ($runningHomes.ContainsKey($jhome.ToLower())) { $run = ' (in use by a running JVM above)' }
    switch ($vs.Status) {
        'VULNERABLE'   { $col = 'Red'; if (-not $run) { $script:ReviewNeeded = $true } }
        'PATCHED'      { $col = 'Green' }
        'NOT_AFFECTED' { $col = 'Green' }
        default        { $col = 'Yellow'; $script:ReviewNeeded = $true }
    }
    $extra = ''; if ($vs.Status -eq 'VULNERABLE') { $extra = Get-DistroNote $vi.Context }
    Write-Host "  $j"
    Write-Status "$(if ($vi.Raw) { $vi.Raw } else { 'unknown' })  ->  " $vs.Status $col "$($vs.Note)$extra$run"
}
Write-Host '  Note: not-running installs only matter if something starts them (scheduled tasks, services).'
Write-Host ''

# ---------- 5. summary ----------
Write-Host '=== Summary ===' -ForegroundColor Cyan
if ($script:RunningVuln) {
    Write-Host 'At least one RUNNING JVM is vulnerable and not mitigated.' -ForegroundColor Red
    Write-Host 'Fix: upgrade to a fixed build (17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 or vendor backport) and restart.'
    Write-Host 'Interim: add -XX:-UseBASE64Intrinsics to that JVM''s own startup options (service config, Procrun'
    Write-Host '         Options, or launcher script). Do not overwrite an existing JAVA_TOOL_OPTIONS (APM agents,'
    Write-Host '         truststores). Machine-level env vars reach services only after a reboot. Restart, then re-run.'
    exit 2
} elseif ($script:ReviewNeeded) {
    Write-Host 'No unmitigated vulnerable JVM is running, but some items need review (see above).' -ForegroundColor Yellow
    exit 1
} else {
    Write-Host 'No exposed JVM found.' -ForegroundColor Green
    exit 0
}
