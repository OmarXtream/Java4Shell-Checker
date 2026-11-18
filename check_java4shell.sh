#!/usr/bin/env bash
# CVE-2026-114938 (Java4Shell) read-only local checker for Linux, v2
#
# Safe for production:
#   - never attaches to a JVM and never sends signals (no jcmd/jstack/jinfo)
#   - writes no files; lowest CPU/IO priority; marks itself first in line for the OOM killer
#   - every read of /proc or JDK files runs under a timeout (hung NFS, stuck processes)
#   - local disks only: network/autofs mounts are detected from /proc/self/mounts and skipped
#   - reads versions from each JDK's "release" file; runs a java binary only as a
#     fallback, with a timeout, a small heap, and JAVA_TOOL_OPTIONS/_JAVA_OPTIONS removed
#   - does not print command lines unless asked (they often contain passwords)
#
# Usage:  sudo bash check_java4shell.sh [--all] [--no-exec] [--no-env] [--deep-scan] [--show-cmdline]
#   --all           keep checking even if the CPU lacks AVX-512 VBMI
#   --no-exec       never run any java binary (release files only)
#   --no-env        do not read /proc/PID/environ (some EDR/Falco rules alert on it);
#                   env-var mitigations are then reported as unknown
#   --deep-scan     also search /srv /app /apps /u01 /data /home for installed JDKs
#   --show-cmdline  print (redacted) command lines of running JVMs
#
# Exit codes: 0 = nothing exposed found
#             1 = needs review (unknown version, vulnerable JDK installed but not running,
#                 not run as root, ...)
#             2 = at least one RUNNING JVM is vulnerable and not mitigated
#
# Data (Oracle CVE record + OpenJDK fixed builds, Nov 17 2026):
#   fixed: 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1   (17 affected from 17.0.6)
#   18-20, 22-24, 26: same code, end of life, no fix
#   8 (standard), 11, ARM64, OpenJ9: not affected.  Oracle 8u511b33-perf: affected.
# Distro builds (RHEL, Ubuntu, Debian, SUSE) may backport the fix (JDK-8393212)
# without reaching these version numbers: confirm with the vendor errata.

if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then echo "bash 4.0 or newer is required" >&2; exit 1; fi

set -o pipefail   # deliberately no -e / -u (set -u breaks empty arrays on bash 4.2 / RHEL 7)
export LC_ALL=C

ALL=0 NOEXEC=0 SHOWCMD=0 NOENV=0 DEEP=0
for arg in "$@"; do
  case "$arg" in
    --all) ALL=1 ;;
    --no-exec) NOEXEC=1 ;;
    --show-cmdline) SHOWCMD=1 ;;
    --no-env) NOENV=1 ;;
    --deep-scan) DEEP=1 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 64 ;;
  esac
done

renice -n 19 -p $$ >/dev/null 2>&1
ionice -c3 -p $$ >/dev/null 2>&1
# if memory ever runs out, the kernel kills this script (and its java probes) before any service
echo 1000 > /proc/$$/oom_score_adj 2>/dev/null

# timeout wrappers: a read of /proc/PID/* or a file on a hung mount can block forever
if command -v timeout >/dev/null 2>&1; then
  to()     { timeout -k 1 5 "$@"; }
  to_long(){ timeout -k 5 120 "$@"; }
else
  to()     { "$@"; }
  to_long(){ "$@"; }
fi

# filesystem type of a path, from the kernel mount table (never touches the path itself)
fstype_of() {
  awk -v p="$1" '{ m=$2; gsub(/\\040/," ",m)
    if ((p==m || index(p, (m=="/"?"/":m"/"))==1) && length(m)>=best) { best=length(m); t=$3 } }
    END { print t }' /proc/self/mounts 2>/dev/null
}
is_local_fs() {
  case "$(fstype_of "$1")" in
    nfs*|cifs|smb*|fuse*|autofs|ceph*|glusterfs|9p|davfs|sshfs|lustre|gpfs|beegfs|afs|"") return 1 ;;
    *) return 0 ;;
  esac
}

if [[ -t 1 ]]; then R=$'\e[91m' Y=$'\e[93m' G=$'\e[92m' C=$'\e[96m' N=$'\e[0m'; else R='' Y='' G='' C='' N=''; fi

FIX17=17.0.21.1 FIX21=21.0.13.1 FIX25=25.0.5.1 FIX27=27.0.1.1
REVIEW_NEEDED=0 RUNNING_VULN=0 PROBE_SKIPPED_MEM=0

# ---------- helpers ----------

# vge A B : true if dotted version A >= B (numeric, up to 6 parts, base 10)
vge() {
  local IFS=. i x y
  local -a a b
  read -r -a a <<< "$1"; read -r -a b <<< "$2"
  for ((i = 0; i < 6; i++)); do
    x=$((10#${a[i]:-0})); y=$((10#${b[i]:-0}))
    ((x > y)) && return 0
    ((x < y)) && return 1
  done
  return 0
}

# classify RAWVERSION CONTEXT_TEXT  -> sets VSTAT (VULNERABLE|PATCHED|NOT_AFFECTED|REVIEW) and VNOTE
classify() {
  local raw="$1" ctx="$2" v major fix=""
  VSTAT=REVIEW VNOTE=""
  shopt -s nocasematch
  if [[ "$ctx" == *openj9* ]]; then
    shopt -u nocasematch; VSTAT=NOT_AFFECTED VNOTE="OpenJ9 VM, not HotSpot"; return
  fi
  if [[ "$ctx" == *GRAALVM_VERSION=\"21.3* ]]; then
    shopt -u nocasematch; VNOTE="GraalVM Enterprise 21.3: 21.3.20.0.3 affected, fixed in 21.3.20.1"; return
  fi
  if [[ "$raw" == *-ea* || "$raw" == *internal* ]]; then
    shopt -u nocasematch; VNOTE="early-access/internal build, check manually"; return
  fi
  local perf=0; [[ "$raw $ctx" == *-perf* ]] && perf=1
  shopt -u nocasematch

  if [[ -z "$raw" ]]; then VNOTE="version not found (no release file, and the binary was not executed)"; return; fi
  if [[ ! "$raw" =~ ^([0-9]+([._][0-9]+)*) ]]; then VNOTE="cannot parse version '$raw'"; return; fi
  v="${BASH_REMATCH[1]//_/.}"
  [[ "$v" == 1.* ]] && v="${v#1.}"           # 1.8.0_392 -> 8.0.392
  major=$((10#${v%%.*}))

  if ((major == 8 && perf)); then
    VNOTE="Oracle 8u Performance Pack: 8u511b33-perf affected, fixed in 8u513-perf"; return
  fi
  if ((major <= 16)); then VSTAT=NOT_AFFECTED VNOTE="Java $major is outside the affected range"; return; fi
  case "$major" in
    17) if ! vge "$v" 17.0.6; then VSTAT=NOT_AFFECTED VNOTE="before 17.0.6, vulnerable code not present"; return; fi
        fix=$FIX17 ;;
    21) fix=$FIX21 ;;
    25) fix=$FIX25 ;;
    27) fix=$FIX27 ;;
    18|19|20|22|23|24|26)
        VSTAT=VULNERABLE VNOTE="Java $major is end of life and gets no fix: move to a patched LTS"; return ;;
    *)  VNOTE="Java $major is newer than this script's data, check vendor advisory"; return ;;
  esac
  if vge "$v" "$fix"; then VSTAT=PATCHED VNOTE="at or above fixed build $fix"
  else VSTAT=VULNERABLE VNOTE="below fixed build $fix"; fi
}

# read KEY from a JDK release file
relval() { to head -c 65536 "$1" 2>/dev/null | sed -n "s/^$2=\"\{0,1\}\([^\"]*\)\"\{0,1\}\$/\1/p" | head -n1; }

# find release file for a java home (handles JDK 8 jre/ subdir)
find_release() {
  local h="$1"
  if to test -f "$h/release"; then echo "$h/release"
  elif to test -f "$h/../release"; then echo "$h/../release"
  fi
}

is_elf() { [[ "$(to head -c4 "$1" 2>/dev/null | od -An -c 2>/dev/null | tr -d ' ')" == '177ELF' ]]; }

# probe_exec JAVA_BIN -> prints `java -version` output, or nothing if not allowed/failed
probe_exec() {
  local bin="$1"
  ((NOEXEC)) && return 1
  command -v timeout >/dev/null 2>&1 || return 1
  is_elf "$bin" || return 1    # never run wrapper scripts named "java"
  local avail
  avail="$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)"
  if [[ -n "$avail" && "$avail" -lt 1024 ]]; then
    PROBE_SKIPPED_MEM=1; return 1   # under 1 GB free: do not start any JVM on this host
  fi
  # -XX:-UsePerfData: no /tmp/hsperfdata file; run from / so no hs_err file lands in a work dir
  ( cd / && timeout -k 2 15 env -u JAVA_TOOL_OPTIONS -u _JAVA_OPTIONS -u JDK_JAVA_OPTIONS -u CLASSPATH \
    "$bin" -Xmx64m -XX:+UseSerialGC -XX:TieredStopAtLevel=1 -XX:-UsePerfData -version 2>&1 ) | grep -v '^Picked up' | head -n 5
}

# version_of_home HOME_PATH(with root prefix) BIN_FOR_FALLBACK -> sets VRAW VCTX VSRC
version_of_home() {
  local home="$1" bin="$2" rel out
  VRAW="" VCTX="" VSRC=""
  rel="$(find_release "$home")"
  if [[ -n "$rel" ]]; then
    VRAW="$(relval "$rel" JAVA_RUNTIME_VERSION)"
    [[ -z "$VRAW" ]] && VRAW="$(relval "$rel" JAVA_VERSION)"
    VCTX="$(to head -c 65536 "$rel" 2>/dev/null | grep -E '^(IMPLEMENTOR|JVM_VARIANT|GRAALVM_VERSION|JAVA_VERSION)=' | tr '\n' ' ')"
    VSRC="release file"
  fi
  if [[ -z "$VRAW" && -n "$bin" ]]; then
    out="$(probe_exec "$bin")"
    if [[ -n "$out" ]]; then
      VRAW="$(printf '%s\n' "$out" | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -n1)"
      VCTX="$out"; VSRC="java -version"
    fi
  fi
  # use the full runtime version when the release file gives one (e.g. 21.0.13.1+4)
  VRAW="${VRAW%%+*}"
}

impl_note() {
  local i; i="$(printf '%s' "$1" | sed -n 's/.*IMPLEMENTOR="\([^"]*\)".*/\1/p')"
  case "$i" in
    *"Red Hat"*|*Ubuntu*|*Debian*|*SUSE*|*Canonical*|*Alpine*)
      echo " (distro build by $i: a backported fix may not change the version, check errata for JDK-8393212)" ;;
  esac
}

# ---------- mitigation parsing ----------
# Tokens are added in the order HotSpot processes them; the last value of a flag wins.
TOK=() SRC=()
add_tokens() {  # SOURCE then tokens
  local s="$1"; shift
  local t
  for t in "$@"; do TOK+=("$t"); SRC+=("$s"); done
}
OPTFILE_UNREAD=0
add_file_tokens() {  # SOURCE FILE ROOT CWD FLAGSFORMAT
  local s="$1" f="$2" root="$3" cwd="$4" flagsfmt="$5" line w
  [[ "$f" != /* ]] && f="$cwd/$f"
  f="$root$f"
  if ! to test -f "$f" || ! to test -r "$f"; then OPTFILE_UNREAD=1; return; fi
  local -a words
  while IFS= read -r line; do
    line="${line%%#*}"
    read -r -a words <<< "$line"     # no glob expansion
    for w in "${words[@]}"; do
      w="${w//\"/}"; w="${w//\'/}"
      if ((flagsfmt)); then
        case "$w" in -XX:*) ;; [+-]*) w="-XX:$w" ;; *=*) w="-XX:$w" ;; esac
      fi
      TOK+=("$w"); SRC+=("$s")
    done
  done < <(to head -c 65536 "$f" 2>/dev/null)
}

eval_mitigation() {  # sets MIT (empty = none) from TOK/SRC
  local i t b64="" b64s="" avx="" avxs="" dis="" diss="" xint=""
  for ((i = 0; i < ${#TOK[@]}; i++)); do
    t="${TOK[i]}"
    case "$t" in
      -XX:-UseBASE64Intrinsics|-XX:UseBASE64Intrinsics=false) b64=off b64s="${SRC[i]}" ;;
      -XX:+UseBASE64Intrinsics|-XX:UseBASE64Intrinsics=true)  b64=on  b64s="${SRC[i]}" ;;
      -XX:UseAVX=*) avx="${t#-XX:UseAVX=}" avxs="${SRC[i]}" ;;
      -XX:DisableIntrinsic=*_base64_decodeBlock*) dis=1 diss="${SRC[i]}" ;;
      -XX:ControlIntrinsic=*-_base64_decodeBlock*) dis=1 diss="${SRC[i]}" ;;
      -Xint) xint=1 ;;
    esac
  done
  MIT=""
  if [[ "$b64" == off ]]; then MIT="-XX:-UseBASE64Intrinsics via $b64s"
  elif [[ "$avx" =~ ^[0-2]$ ]]; then MIT="-XX:UseAVX=$avx via $avxs"
  elif [[ -n "$dis" ]]; then MIT="DisableIntrinsic _base64_decodeBlock via $diss"
  elif [[ -n "$xint" ]]; then MIT="-Xint (no JIT)"
  fi
}

envval() {  # PID VAR -> value from /proc/PID/environ
  ((NOENV)) && return
  to cat "/proc/$1/environ" 2>/dev/null | tr '\0' '\n' | sed -n "s/^$2=//p" | head -n1
}

redact() {
  sed -E 's/((pass(word)?|pwd|secret|token|apikey|api[._-]key|credential)[A-Za-z0-9._-]*[=:])[^ ]+/\1****/Ig'
}

# ---------- 0. privileges ----------
echo "${C}=== CVE-2026-114938 (Java4Shell) local check v2 ===${N}"
echo "Host: $(hostname 2>/dev/null)   Kernel: $(uname -r)   Date: $(date -u '+%Y-%m-%d %H:%M UTC')"
if ((EUID != 0)); then
  echo "${Y}WARNING: not running as root. JVMs of other users and their environment cannot be read,"
  echo "         so the result below is incomplete. Re-run with sudo.${N}"
  REVIEW_NEEDED=1
fi
echo

# ---------- 1. CPU ----------
arch="$(uname -m)"
CPU_EXPOSED=1
if [[ "$arch" != x86_64 && "$arch" != amd64 ]]; then
  echo "CPU: ${G}NOT AFFECTED${N} ($arch; the vulnerable code is x86-64 only)"
  CPU_EXPOSED=0
elif [[ -r /proc/cpuinfo ]]; then
  model="$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -n1)"
  if grep -E '^flags' /proc/cpuinfo | grep -qw avx512vbmi && grep -E '^flags' /proc/cpuinfo | grep -qw avx512bw; then
    echo "CPU: ${R}AVX-512 VBMI present${N} ($model): this hardware takes the vulnerable code path"
  else
    echo "CPU: ${G}NOT AFFECTED${N} ($model): no avx512vbmi/avx512bw exposed to this OS"
    echo "     (in a VM this depends on the hypervisor's CPU model; re-check after host migration or CPU model change)"
    CPU_EXPOSED=0
  fi
else
  echo "CPU: ${Y}UNKNOWN${N} (cannot read /proc/cpuinfo), assuming exposed"
fi
if ((CPU_EXPOSED == 0 && ALL == 0)); then
  echo; echo "${G}Host is not exposed (CPU). Use --all to inventory Java anyway.${N}"
  exit $((REVIEW_NEEDED ? 1 : 0))
fi
echo

# ---------- 2. running JVMs (the part that decides exposure) ----------
echo "${C}=== Running JVMs (found via libjvm.so in process memory maps) ===${N}"
MYNS="$(readlink /proc/self/ns/mnt 2>/dev/null)"
declare -A SEEN_HOME
njvm=0
for d in /proc/[0-9]*; do
  pid="${d#/proc/}"
  [[ -r "$d/maps" ]] || continue
  mline="$(to grep -m1 -E '/libjvm\.so( \(deleted\))?$' "$d/maps" 2>/dev/null)" || continue
  [[ -n "$mline" ]] || continue
  njvm=$((njvm + 1))

  libpath="$(printf '%s\n' "$mline" | sed -E 's/^([^ ]+ +){5}//')"
  deleted=0
  if [[ "$libpath" == *" (deleted)" ]]; then deleted=1; libpath="${libpath% (deleted)}"; fi
  home="${libpath%/lib/*}"
  exe="$(readlink "$d/exe" 2>/dev/null)"
  [[ "$exe" == *" (deleted)" ]] && deleted=1
  user="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')"
  etime="$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ')"
  ns="$(readlink "$d/ns/mnt" 2>/dev/null)"
  where="host"; [[ -n "$ns" && "$ns" != "$MYNS" ]] && where="container/other mount namespace"
  root="/proc/$pid/root"; [[ "$where" == host ]] && root=""
  cwd="$(readlink "$d/cwd" 2>/dev/null)"

  openj9=0; to grep -q 'libj9vm' "$d/maps" 2>/dev/null && openj9=1

  # version of the code actually mapped in this process
  bin=""; [[ "$where" == host && $deleted -eq 0 ]] && is_local_fs "$home" && to test -x "$home/bin/java" && bin="$home/bin/java"
  version_of_home "$root$home" "$bin"
  ((openj9)) && VCTX="$VCTX openj9"
  SEEN_HOME["$home"]=1

  # mitigation flags, in HotSpot processing order
  TOK=() SRC=() OPTFILE_UNREAD=0
  envok=1; [[ -r "$d/environ" ]] || envok=0; ((NOENV)) && envok=0
  read -r -a _w <<< "$(envval "$pid" JAVA_TOOL_OPTIONS)"; add_tokens JAVA_TOOL_OPTIONS "${_w[@]}"
  read -r -a _w <<< "$(envval "$pid" JDK_JAVA_OPTIONS)";  add_tokens JDK_JAVA_OPTIONS "${_w[@]}"
  first=1
  while IFS= read -r -d '' a; do
    if ((first)); then first=0; continue; fi
    case "$a" in
      @*) add_file_tokens "argfile ${a#@}" "${a#@}" "$root" "$cwd" 0 ;;
      -XX:VMOptionsFile=*) add_file_tokens "VMOptionsFile" "${a#-XX:VMOptionsFile=}" "$root" "$cwd" 0 ;;
      -XX:Flags=*) add_file_tokens "Flags file" "${a#-XX:Flags=}" "$root" "$cwd" 1 ;;
      *) TOK+=("$a"); SRC+=("command line") ;;
    esac
  done < <(to cat "$d/cmdline" 2>/dev/null)
  read -r -a _w <<< "$(envval "$pid" _JAVA_OPTIONS)"; add_tokens _JAVA_OPTIONS "${_w[@]}"
  eval_mitigation

  # verdict for this process
  if ((openj9)); then classify "$VRAW" "openj9"; else classify "$VRAW" "$VCTX"; fi
  note="$VNOTE"
  if ((CPU_EXPOSED == 0)); then verdict="NOT AFFECTED (CPU)"; col=$G
  elif [[ "$VSTAT" == NOT_AFFECTED ]]; then verdict="NOT AFFECTED"; col=$G
  elif ((deleted)); then
    if [[ -n "$MIT" ]]; then verdict="MITIGATED (restart pending)"; col=$Y; REVIEW_NEEDED=1
    else verdict="LIKELY VULNERABLE"; col=$R; RUNNING_VULN=1; fi
    note="JDK files were replaced on disk after this process started; it still runs the OLD build. Restart it."
  elif [[ "$VSTAT" == PATCHED ]]; then verdict="PATCHED"; col=$G
  elif [[ "$VSTAT" == VULNERABLE ]]; then
    if [[ -n "$MIT" ]]; then verdict="MITIGATED"; col=$Y
    else
      verdict="VULNERABLE"; col=$R; RUNNING_VULN=1
      ((envok)) || note="$note; environment not read (--no-env or not root), an env-var mitigation would be missed"
      ((OPTFILE_UNREAD)) && note="$note; an options/arg file could not be read"
    fi
    note="$note$(impl_note "$VCTX")"
  else verdict="REVIEW"; col=$Y; REVIEW_NEEDED=1
  fi

  echo "  PID $pid  user=${user:-?}  up=${etime:-?}  [$where]"
  echo "    JVM:      $home"
  if ((deleted)); then
    echo "    Version:  unknown, older than what is on disk now (${VRAW:-?})"
  else
    echo "    Version:  ${VRAW:-unknown} ${VSRC:+(from $VSRC)}"
  fi
  echo "    Mitigation: ${MIT:-none found}"
  echo "    Verdict:  ${col}${verdict}${N}${note:+  - $note}"
  if ((SHOWCMD)); then
    echo "    CMD: $(to cat "$d/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 400 | redact)"
  fi
done
if ((njvm == 0)); then
  if ((EUID != 0)); then echo "  None visible to this user (other users' processes need root)."
  else echo "  No running JVMs found."; fi
fi
echo

# ---------- 3. installed JDKs/JREs on disk (informational) ----------
echo "${C}=== Installed Java runtimes on local disks ===${N}"
cands=()
# PATH entries: only local ones
IFS=: read -r -a _pathdirs <<< "$PATH"
for pd in "${_pathdirs[@]}"; do
  [[ "$pd" == /* ]] && is_local_fs "$pd" && to test -x "$pd/java" && cands+=("$pd/java")
done
for p in /usr/lib/jvm/*/bin/java /usr/lib/jvm/*/jre/bin/java /usr/java/*/bin/java /etc/alternatives/java; do
  [[ -e "$p" ]] && cands+=("$p")
done
tops=("/opt:5" "/usr/local:5" "/usr/share:4" "/root:6")
((DEEP)) && tops+=("/srv:6" "/app:6" "/apps:6" "/u01:6" "/data:5" "/home:6")
for td in "${tops[@]}"; do
  top="${td%%:*}" depth="${td##*:}"
  if ! is_local_fs "$top"; then
    t="$(fstype_of "$top")"; [[ -n "$t" ]] && echo "  (skipping $top: $t is not a local filesystem)"
    continue
  fi
  [[ -d "$top" ]] || continue
  while IFS= read -r p; do cands+=("$p"); done < <(to_long find "$top" -xdev -maxdepth "$depth" \
      \( -name node_modules -o -name .git -o -name .cache -o -name .m2 -o -name .gradle -o -name .npm -o -name proc \) -prune \
      -o -type f -path '*/bin/java' -print 2>/dev/null)
done
((DEEP)) || echo "  (standard locations only; add --deep-scan for /srv /app /apps /u01 /data /home)"

declare -A SEENBIN
ninst=0
for p in "${cands[@]}"; do
  real="$(to readlink -f "$p" 2>/dev/null)" || continue
  is_local_fs "$real" || continue
  [[ -n "$real" && -f "$real" && -z "${SEENBIN[$real]}" ]] || continue
  SEENBIN["$real"]=1
  ninst=$((ninst + 1))
  home="$(dirname "$(dirname "$real")")"
  version_of_home "$home" "$real"
  classify "$VRAW" "$VCTX"
  run=""; [[ -n "${SEEN_HOME[$home]}" ]] && run=" (in use by a running JVM above)"
  case "$VSTAT" in
    VULNERABLE) col=$R; [[ -z "$run" ]] && REVIEW_NEEDED=1 ;;
    PATCHED|NOT_AFFECTED) col=$G ;;
    *) col=$Y; REVIEW_NEEDED=1 ;;
  esac
  printf '  %s\n    %s  ->  %s%s%s  - %s%s%s\n' "$real" "${VRAW:-unknown}" "$col" "$VSTAT" "$N" "$VNOTE" "$([[ $VSTAT == VULNERABLE ]] && impl_note "$VCTX")" "$run"
done
((ninst == 0)) && echo "  No Java runtimes found on local disks."
echo "  Note: not-running installs only matter if something starts them (cron, batch, services)."
echo

# ---------- 4. summary ----------
if ((PROBE_SKIPPED_MEM)); then
  echo "${Y}Note: less than 1 GB memory available, so no java binary was started; some versions may be unknown.${N}"
  echo
fi
echo "${C}=== Summary ===${N}"
if ((RUNNING_VULN)); then
  echo "${R}At least one RUNNING JVM is vulnerable and not mitigated.${N}"
  echo "Fix: upgrade to a fixed build (17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 or vendor backport) and restart."
  echo "Interim: add -XX:-UseBASE64Intrinsics to that JVM's own startup options (append, do not replace"
  echo "         existing JAVA_TOOL_OPTIONS) and restart it. Verify by re-running this script."
  exit 2
elif ((REVIEW_NEEDED)); then
  echo "${Y}No unmitigated vulnerable JVM is running, but some items need review (see above).${N}"
  exit 1
else
  echo "${G}No exposed JVM found.${N}"
  exit 0
fi
