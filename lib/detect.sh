#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - lib/detect.sh
# Detectors. Each prints zero or more findings on stdout, one per line:
#     SEVERITY|CATEGORY|PID|DETAIL
# SEVERITY is HARD (high-confidence, eligible for auto-response) or SOFT
# (heuristic, alert-only). PID is "-" when not process-scoped.
# Sourced after lib/common.sh and lib/forensics.sh.
#===============================================================================

CPU_STATE_FILE="$STATE_DIR/cpu_sustain.tsv"
HASH_MARKER="$STATE_DIR/.hashscan_marker"
UPX_MARKER="$STATE_DIR/.upxscan_marker"

# Directories where an executable file is inherently suspicious.
_SUSPECT_DIRS=(/tmp /var/tmp /dev/shm)

#---------------------------------------------------------------------------
# /proc/<pid>/stat fields, counted from `state` (field 3) onward.
#
# Splitting the raw line on whitespace is wrong and exploitable: comm is
# field 2, it is chosen by the process, and it may contain spaces and
# parentheses. Everything after the last ") " is safe to split.
#   field N  ->  index N-3
#---------------------------------------------------------------------------
_proc_stat_tail() {
  local line
  line="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  [ -n "$line" ] || return 1
  case "$line" in
    *") "*) printf '%s' "${line##*") "}" ;;
    *)      return 1 ;;
  esac
}

# _proc_cpu_jiffies <pid> : utime + stime (fields 14, 15).
_proc_cpu_jiffies() {
  local -a fields
  read -r -a fields <<< "$(_proc_stat_tail "$1")" || return 1
  [ -n "${fields[12]:-}" ] || return 1
  printf '%s' "$(( ${fields[11]} + ${fields[12]} ))"
}

# _proc_starttime <pid> : field 22, the boot-relative start time. Together with
# the pid it identifies a process across pid reuse.
_proc_starttime() {
  local -a fields
  read -r -a fields <<< "$(_proc_stat_tail "$1")" || return 1
  printf '%s' "${fields[19]:-0}"
}

#---------------------------------------------------------------------------
# Instantaneous CPU for a batch of PIDs (per-core %, may exceed 100).
# Usage: inst_cpu_batch pid1 pid2 ...  -> prints "pid cpu" lines
#---------------------------------------------------------------------------
inst_cpu_batch() {
  local pids=("$@")
  [ "${#pids[@]}" -eq 0 ] && return 0
  local hz; hz="$(getconf CLK_TCK 2>/dev/null || echo 100)"
  declare -A t0 j0
  local p j
  for p in "${pids[@]}"; do
    j="$(_proc_cpu_jiffies "$p" 2>/dev/null || echo "")"
    [ -n "$j" ] && { j0["$p"]="$j"; t0["$p"]="$(date +%s%N)"; }
  done
  sleep 0.5
  for p in "${pids[@]}"; do
    [ -n "${j0[$p]:-}" ] || continue
    local j1 t1 dj dt
    j1="$(_proc_cpu_jiffies "$p" 2>/dev/null || echo "")"
    [ -n "$j1" ] || continue
    t1="$(date +%s%N)"
    dj=$(( j1 - ${j0[$p]} ))
    dt=$(( t1 - ${t0[$p]} ))
    [ "$dt" -gt 0 ] || continue
    awk -v dj="$dj" -v dt="$dt" -v hz="$hz" -v p="$p" \
      'BEGIN{ printf "%s %.1f\n", p, (dj/hz)/(dt/1e9)*100 }'
  done
}

#---------------------------------------------------------------------------
# HARD: known dropper payload present and executable
#---------------------------------------------------------------------------
detect_malware_paths() {
  local path perms
  while read -r path; do
    [ -e "$path" ] || continue
    perms="$(stat -c '%a' "$path" 2>/dev/null || echo '?')"
    [ "$perms" = "0" ] && continue
    echo "HARD|malware_path|-|${path} perms=${perms}"
  done < <(read_sig malware_paths.txt)
}

#---------------------------------------------------------------------------
# Known-malware hashes. Two lists, either of which is enough to call a file
# known-bad: md5 for the indicators that were recorded that way, sha256 for
# everything since (an md5 collision is cheap to produce).
#---------------------------------------------------------------------------
_KNOWN_MD5=()
_KNOWN_SHA256=()

_load_hash_sigs() {
  mapfile -t _KNOWN_MD5    < <(read_sig malware_md5.txt    | tr 'A-F' 'a-f')
  mapfile -t _KNOWN_SHA256 < <(read_sig malware_sha256.txt | tr 'A-F' 'a-f')
}

_have_hash_sigs() {
  [ "${#_KNOWN_MD5[@]}" -gt 0 ] || [ "${#_KNOWN_SHA256[@]}" -gt 0 ]
}

# _match_known_hash <file> : prints "md5=<h>" or "sha256=<h>" for a match and
# returns 0, otherwise returns 1. Each digest is computed only if there is a
# list to compare it against.
_match_known_hash() {
  local file="$1" h m
  if [ "${#_KNOWN_MD5[@]}" -gt 0 ]; then
    h="$(md5sum "$file" 2>/dev/null | cut -d' ' -f1)"
    if [ -n "$h" ]; then
      for m in "${_KNOWN_MD5[@]}"; do
        [ "$h" = "$m" ] && { printf 'md5=%s' "$h"; return 0; }
      done
    fi
  fi
  if [ "${#_KNOWN_SHA256[@]}" -gt 0 ]; then
    h="$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)"
    if [ -n "$h" ]; then
      for m in "${_KNOWN_SHA256[@]}"; do
        [ "$h" = "$m" ] && { printf 'sha256=%s' "$h"; return 0; }
      done
    fi
  fi
  return 1
}

#---------------------------------------------------------------------------
# HARD: file on disk whose hash matches a known-malware signature.
# Narrow scope: the suspect dirs + any */.next/standalone under /root/*.
# Full hash on the first pass, then only files newer than the last marker.
#---------------------------------------------------------------------------
detect_malware_hashes() {
  _load_hash_sigs
  _have_hash_sigs || return 0

  local -a roots=("${_SUSPECT_DIRS[@]}")
  local d
  for d in /root/*/.next/standalone; do [ -d "$d" ] && roots+=("$d"); done

  local find_args=(-type f -perm -u+x -size -80M)
  [ -f "$HASH_MARKER" ] && find_args+=(-newer "$HASH_MARKER")

  local f hit
  while IFS= read -r -d '' f; do
    if hit="$(_match_known_hash "$f")"; then
      echo "HARD|malware_hash|-|${f} ${hit}"
    fi
  done < <(find "${roots[@]}" "${find_args[@]}" -print0 2>/dev/null)

  run_action touch "$HASH_MARKER"
}

#---------------------------------------------------------------------------
# HARD: a running process executing from a volatile/world-writable directory
#       whose binary matches a known-malware hash.
# SOFT: process running from such a directory (no hash match), or running from
#       an unlinked binary whose origin was NOT a standard package path
#       (a package upgrade legitimately leaves "/usr/... (deleted)" behind).
# We only hash exes in volatile dirs -- that is where a dropper actually runs
# from -- to keep each pass cheap (no md5 of every /usr/bin/* on the host).
#---------------------------------------------------------------------------
_is_volatile_path() {
  case "$1" in
    /tmp/*|/var/tmp/*|/dev/shm/*|/dev/*|/run/*|/var/run/*) return 0 ;;
    *) return 1 ;;
  esac
}
_is_standard_path() {
  case "$1" in
    /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/opt/*|/snap/*|/nix/*) return 0 ;;
    *) return 1 ;;
  esac
}
detect_proc_exe() {
  _load_hash_sigs
  local pid exe origin hit
  while read -r pid; do
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    [ -n "$exe" ] || continue
    case "$exe" in
      *" (deleted)")
        origin="${exe% (deleted)}"
        # A process whose executable was never a file: the payload was written
        # to an anonymous memory object and executed from there. Nothing to
        # find on disk, which is the point of doing it that way. This used to
        # fall through both path tests below and be dropped silently.
        case "$origin" in
          /memfd:*|memfd:*)
            [ "${DETECT_FILELESS:-1}" = "1" ] && \
              echo "SOFT|fileless|$pid|executing from anonymous memory: $origin ($(_pid_cmdline "$pid"))"
            continue ;;
        esac
        _is_standard_path "$origin" && continue        # benign: package upgrade
        _is_volatile_path "$origin" || continue        # only care about volatile origins
        echo "SOFT|deleted_exe|$pid|running from unlinked binary: $origin"
        continue ;;
    esac
    _is_volatile_path "$exe" || continue
    if _have_hash_sigs && [ -r "$exe" ]; then
      if hit="$(_match_known_hash "$exe")"; then
        echo "HARD|malware_proc|$pid|$exe $hit"
        continue
      fi
    fi
    echo "SOFT|exe_in_volatile|$pid|executable under volatile dir: $exe"
  done < <(iter_pids)
}

#---------------------------------------------------------------------------
# HARD: netcat/socat beacon to a known C2 IP or suspicious port, or an
# established outbound socket to a known C2 IP.
#---------------------------------------------------------------------------
detect_c2() {
  local -a c2_ips c2_ports
  mapfile -t c2_ips   < <(read_sig c2_ips.txt)
  mapfile -t c2_ports < <(read_sig c2_ports.txt)

  # 1) argv of nc/ncat/netcat/socat processes
  local pid args ip port
  while read -r pid args; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    echo "$args" | grep -qE '(^|/)(nc|ncat|netcat|socat)([[:space:]]|$)' || continue
    for ip in "${c2_ips[@]}"; do
      [ -n "$ip" ] || continue
      if echo "$args" | grep -qF "$ip"; then
        echo "HARD|c2_beacon|$pid|$(echo "$args" | tr -s ' ') -> C2 $ip"
      fi
    done
    for port in "${c2_ports[@]}"; do
      [ -n "$port" ] || continue
      if echo "$args" | grep -qE "[[:space:]]${port}([[:space:]]|$)"; then
        echo "HARD|c2_beacon|$pid|$(echo "$args" | tr -s ' ') -> suspicious port $port"
      fi
    done
  done < <(ps -eo pid=,args= 2>/dev/null)

  # 2) established outbound sockets to a C2 IP (catches non-nc clients)
  command -v ss >/dev/null 2>&1 || return 0
  local line spid
  for ip in "${c2_ips[@]}"; do
    [ -n "$ip" ] || continue
    while read -r line; do
      [ -n "$line" ] || continue
      spid="$(echo "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
      echo "HARD|c2_socket|${spid:--}|established connection to C2 $ip :: $(echo "$line" | tr -s ' ')"
    done < <(ss -tanp state established 2>/dev/null | grep -F "$ip" || true)
  done
}

#---------------------------------------------------------------------------
# _pid_cmdline <pid> : the process command line, NUL separators turned into
# spaces. Read from /proc directly so it works for a process ps cannot show.
#---------------------------------------------------------------------------
_pid_cmdline() {
  tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | tr -s ' ' | sed 's/[[:space:]]*$//'
}

#---------------------------------------------------------------------------
# SOFT: argv shaped like a reverse shell.
#
# Alert-only and it stays that way: `socat` in an administrator's hands and
# `socat` in an attacker's look identical from the outside, and this daemon
# does not kill on a guess. The patterns in revshell_patterns.txt are written
# narrowly for the same reason.
#---------------------------------------------------------------------------
detect_revshell() {
  [ "${DETECT_REVSHELL:-1}" = "1" ] || return 0
  local pat
  pat="$(read_sig revshell_patterns.txt | paste -sd'|' -)"
  [ -n "$pat" ] || return 0

  local pid args
  while read -r pid args; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    [ "$pid" = "$$" ] && continue          # never report the scan itself
    echo "$args" | grep -qiE "$pat" || continue
    echo "SOFT|revshell|$pid|reverse-shell shaped argv: $(echo "$args" | tr -s ' ')"
  done < <(ps -eo pid=,args= 2>/dev/null)
}

#---------------------------------------------------------------------------
# miner: argv matches a miner pattern. HARD only if also CPU-hot, else SOFT.
#---------------------------------------------------------------------------
detect_miner() {
  local pat
  pat="$(read_sig miner_patterns.txt | paste -sd'|' -)"
  [ -n "$pat" ] || return 0

  local -a hot=()
  local pid args comm
  # shortlist offenders by lifetime CPU so the instantaneous check stays cheap
  while read -r pid comm; do
    [[ "$pid" =~ ^[0-9]+$ ]] && hot+=("$pid")
  done < <(ps -eo pid=,comm=,pcpu= --sort=-pcpu 2>/dev/null | awk -v t="$CPU_THRESHOLD" '$3+0 > t/3 {print $1, $2}')

  declare -A inst=()
  if [ "${#hot[@]}" -gt 0 ]; then
    while read -r p c; do inst["$p"]="$c"; done < <(inst_cpu_batch "${hot[@]}")
  fi

  while read -r pid args; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    echo "$args" | grep -qiE "$pat" || continue
    local c="${inst[$pid]:-0}"
    if awk -v v="$c" -v t="$CPU_THRESHOLD" 'BEGIN{exit !(v+0>t)}'; then
      echo "HARD|miner|$pid|$(echo "$args" | tr -s ' ') cpu=${c}%"
    else
      echo "SOFT|miner|$pid|miner-like argv (cpu=${c}%): $(echo "$args" | tr -s ' ')"
    fi
  done < <(ps -eo pid=,args= 2>/dev/null)
}

#---------------------------------------------------------------------------
# SOFT: sustained high CPU. Requires CPU_SUSTAIN_SAMPLES consecutive hits.
#---------------------------------------------------------------------------
detect_high_cpu() {
  [ "${DETECT_HIGH_CPU:-1}" = "1" ] || return 0

  # shortlist by lifetime average, then measure instantaneous CPU
  local -a cand=()
  local pid comm
  while read -r pid comm; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    is_whitelisted "$comm" && continue
    cand+=("$pid")
  done < <(ps -eo pid=,comm=,pcpu= --sort=-pcpu 2>/dev/null | awk -v t="$CPU_THRESHOLD" '$3+0 > t/2 {print $1, $2}')

  declare -A now=()
  if [ "${#cand[@]}" -gt 0 ]; then
    while read -r p c; do now["$p"]="$c"; done < <(inst_cpu_batch "${cand[@]}")
  fi

  # Load previous sustain counts. The key is pid:starttime, not the pid alone:
  # pids are reused, and a short-lived process inheriting the count of the
  # last hog would be reported for CPU it never used. Entries whose process is
  # gone simply never get rewritten below.
  declare -A prev=() emitted=()
  if [ -f "$CPU_STATE_FILE" ]; then
    while IFS=$'\t' read -r key cnt em; do
      [ -n "$key" ] && { prev["$key"]="$cnt"; emitted["$key"]="$em"; }
    done < "$CPU_STATE_FILE"
  fi

  local persist=1
  state_writable || persist=0
  [ "$persist" = "1" ] && : > "$CPU_STATE_FILE.tmp"
  local p cpu cnt em args key st
  for p in "${!now[@]}"; do
    cpu="${now[$p]}"
    awk -v v="$cpu" -v t="$CPU_THRESHOLD" 'BEGIN{exit !(v+0>t)}' || continue
    st="$(_proc_starttime "$p" 2>/dev/null || echo 0)"
    key="$p:$st"
    cnt=$(( ${prev[$key]:-0} + 1 ))
    em="${emitted[$key]:-0}"
    if [ "$cnt" -ge "${CPU_SUSTAIN_SAMPLES:-4}" ] && [ "$em" != "1" ]; then
      args="$(ps -p "$p" -o comm=,args= 2>/dev/null | tr -s ' ')"
      echo "SOFT|high_cpu|$p|sustained ${cpu}% CPU over ${cnt} samples: ${args}"
      em=1
    fi
    [ "$persist" = "1" ] && \
      printf '%s\t%s\t%s\n' "$key" "$cnt" "$em" >> "$CPU_STATE_FILE.tmp"
  done
  [ "$persist" = "1" ] && mv "$CPU_STATE_FILE.tmp" "$CPU_STATE_FILE"
  return 0
}

#---------------------------------------------------------------------------
# SOFT: a listening TCP port that was not in the recorded baseline.
#---------------------------------------------------------------------------
detect_new_listener() {
  [ "${DETECT_NEW_LISTENER:-1}" = "1" ] || return 0
  command -v ss >/dev/null 2>&1 || return 0
  local base="$BASELINE_DIR/listeners"
  local cur; cur="$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -u | grep -E '^[0-9]+$' || true)"
  if [ ! -f "$base" ]; then
    # First run: record what is listening now rather than reporting every
    # existing port. Under a dry run, record nothing -- seeding the baseline
    # is a change, and doing it silently would bless whatever a compromised
    # host happens to have open.
    if state_writable; then
      printf '%s\n' "$cur" > "$base"
    else
      log DRY "would seed the listener baseline at $base"
    fi
    return 0
  fi
  local port
  while read -r port; do
    [ -n "$port" ] || continue
    grep -qxF "$port" "$base" || {
      local who; who="$(ss -tlnpH "sport = :$port" 2>/dev/null | grep -oE 'users:\(\(.*\)\)' | head -1)"
      echo "SOFT|new_listener|-|new LISTEN port ${port} ${who}"
    }
  done < <(printf '%s\n' "$cur")
}

#---------------------------------------------------------------------------
# SOFT: persistence surface changed (delegated to lib/baseline.sh).
#---------------------------------------------------------------------------
detect_persistence() {
  [ "${DETECT_PERSISTENCE:-1}" = "1" ] || return 0
  # Cheap-out on most passes: the systemctl/crontab capture is the slowest probe.
  local every="${PERSISTENCE_EVERY:-10}" n="${CERBERUS_PASS:-0}"
  [ "$every" -le 1 ] || [ $(( n % every )) -eq 0 ] || return 0
  baseline_diff   # prints "SOFT|persistence|-|..." lines for additions
}

#---------------------------------------------------------------------------
# SOFT: a scheduled job or a service that downloads code and runs it.
#
# Unlike the persistence diff, this looks at content rather than at what is
# new: an entry that predates the baseline is not trustworthy just because it
# was there when the baseline was taken -- the baseline may have been recorded
# on an already-compromised host. Each distinct line is reported once, tracked
# in state/seen_loaders, so a permanent entry does not alert every pass.
#---------------------------------------------------------------------------
LOADER_SEEN_FILE="$STATE_DIR/seen_loaders"

detect_loader() {
  [ "${DETECT_LOADER:-1}" = "1" ] || return 0
  # Shares the persistence cadence: this reads crontabs and unit files, which
  # is the slow kind of probe.
  local every="${PERSISTENCE_EVERY:-10}" n="${CERBERUS_PASS:-0}"
  [ "$every" -le 1 ] || [ $(( n % every )) -eq 0 ] || return 0

  local pat
  pat="$(read_sig loader_patterns.txt | paste -sd'|' -)"
  [ -n "$pat" ] || return 0

  local persist=1
  state_writable || persist=0
  [ "$persist" = "1" ] && [ ! -f "$LOADER_SEEN_FILE" ] && : > "$LOADER_SEEN_FILE"

  local where line key
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    where="${line%%$'\t'*}"
    line="${line#*$'\t'}"
    echo "$line" | grep -qiE "$pat" || continue

    key="$(printf '%s|%s' "$where" "$line" | sha256sum | cut -d' ' -f1)"
    if [ -f "$LOADER_SEEN_FILE" ] && grep -qxF "$key" "$LOADER_SEEN_FILE"; then
      continue
    fi
    [ "$persist" = "1" ] && printf '%s\n' "$key" >> "$LOADER_SEEN_FILE"

    echo "SOFT|loader|-|downloads and executes code, in ${where}: $(echo "$line" | tr -s ' ')"
  done < <(_loader_sources)
}

# _loader_sources : "location<TAB>line" for every place a scheduled command can
# hide. Kept separate so the test can supply its own.
_loader_sources() {
  local f line
  crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' \
    | while IFS= read -r line; do printf 'root crontab\t%s\n' "$line"; done

  for f in /etc/crontab /etc/cron.d/*; do
    [ -f "$f" ] || continue
    grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null \
      | while IFS= read -r line; do printf '%s\t%s\n' "$f" "$line"; done
  done

  for f in /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    [ -f "$f" ] || continue
    grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null \
      | while IFS= read -r line; do printf '%s\t%s\n' "$f" "$line"; done
  done

  for f in /etc/systemd/system/*.service /etc/systemd/system/*/*.service; do
    [ -f "$f" ] || continue
    grep -E '^[[:space:]]*(ExecStart|ExecStartPre|ExecStartPost|ExecReload)' "$f" 2>/dev/null \
      | while IFS= read -r line; do printf '%s\t%s\n' "$f" "$line"; done
  done
}

#---------------------------------------------------------------------------
# SOFT: newly-appeared UPX-packed executable in a world-writable dir.
#---------------------------------------------------------------------------
detect_upx_new() {
  [ "${DETECT_UPX_NEW:-1}" = "1" ] || return 0
  local find_args=(-type f -perm -u+x -size -80M)
  [ -f "$UPX_MARKER" ] && find_args+=(-newer "$UPX_MARKER")
  local f
  while IFS= read -r -d '' f; do
    # grep -a rather than strings(1): strings comes from binutils, which is not
    # installed on a minimal server, and this detector silently found nothing
    # there -- the worst failure mode a detector has.
    if LC_ALL=C grep -qa 'UPX!' "$f" 2>/dev/null; then
      echo "SOFT|upx_new|-|UPX-packed executable: $f ($(md5sum "$f" 2>/dev/null | cut -d' ' -f1))"
    fi
  done < <(find "${_SUSPECT_DIRS[@]}" "${find_args[@]}" -print0 2>/dev/null)
  run_action touch "$UPX_MARKER"
}

#---------------------------------------------------------------------------
# Run every detector; all findings on stdout.
#---------------------------------------------------------------------------
run_all_detectors() {
  detect_malware_paths
  detect_malware_hashes
  detect_proc_exe
  detect_c2
  detect_revshell
  detect_miner
  detect_high_cpu
  detect_new_listener
  detect_persistence
  detect_loader
  detect_upx_new
}
