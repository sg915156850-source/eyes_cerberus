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
    j="$(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null || echo "")"
    [ -n "$j" ] && { j0["$p"]="$j"; t0["$p"]="$(date +%s%N)"; }
  done
  sleep 0.5
  for p in "${pids[@]}"; do
    [ -n "${j0[$p]:-}" ] || continue
    local j1 t1 dj dt
    j1="$(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null || echo "")"
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
# HARD: file on disk whose hash matches a known-malware signature.
# Narrow scope: the suspect dirs + any */.next/standalone under /root/*.
# Full hash on the first pass, then only files newer than the last marker.
#---------------------------------------------------------------------------
detect_malware_hashes() {
  local -a md5s
  mapfile -t md5s < <(read_sig malware_md5.txt)
  [ "${#md5s[@]}" -eq 0 ] && return 0

  local -a roots=("${_SUSPECT_DIRS[@]}")
  local d
  for d in /root/*/.next/standalone; do [ -d "$d" ] && roots+=("$d"); done

  local find_args=(-type f -perm -u+x -size -80M)
  [ -f "$HASH_MARKER" ] && find_args+=(-newer "$HASH_MARKER")

  local f h
  while IFS= read -r -d '' f; do
    h="$(md5sum "$f" 2>/dev/null | cut -d' ' -f1)"
    [ -n "$h" ] || continue
    local m
    for m in "${md5s[@]}"; do
      if [ "$h" = "$m" ]; then
        echo "HARD|malware_hash|-|${f} md5=${h}"
        break
      fi
    done
  done < <(find "${roots[@]}" "${find_args[@]}" -print0 2>/dev/null)

  run touch "$HASH_MARKER"
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
  local -a md5s
  mapfile -t md5s < <(read_sig malware_md5.txt)
  local pid exe origin h m
  while read -r pid; do
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    [ -n "$exe" ] || continue
    case "$exe" in
      *" (deleted)")
        origin="${exe% (deleted)}"
        _is_standard_path "$origin" && continue        # benign: package upgrade
        _is_volatile_path "$origin" || continue        # only care about volatile origins
        echo "SOFT|deleted_exe|$pid|running from unlinked binary: $origin"
        continue ;;
    esac
    _is_volatile_path "$exe" || continue
    if [ "${#md5s[@]}" -gt 0 ] && [ -r "$exe" ]; then
      h="$(md5sum "$exe" 2>/dev/null | cut -d' ' -f1)"
      for m in "${md5s[@]}"; do
        [ "$h" = "$m" ] && { echo "HARD|malware_proc|$pid|$exe md5=$h"; continue 2; }
      done
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

  # load previous sustain counts
  declare -A prev=() emitted=()
  if [ -f "$CPU_STATE_FILE" ]; then
    while IFS=$'\t' read -r p cnt em; do
      [ -n "$p" ] && { prev["$p"]="$cnt"; emitted["$p"]="$em"; }
    done < "$CPU_STATE_FILE"
  fi

  : > "$CPU_STATE_FILE.tmp"
  local p cpu cnt em args
  for p in "${!now[@]}"; do
    cpu="${now[$p]}"
    awk -v v="$cpu" -v t="$CPU_THRESHOLD" 'BEGIN{exit !(v+0>t)}' || continue
    cnt=$(( ${prev[$p]:-0} + 1 ))
    em="${emitted[$p]:-0}"
    if [ "$cnt" -ge "${CPU_SUSTAIN_SAMPLES:-4}" ] && [ "$em" != "1" ]; then
      args="$(ps -p "$p" -o comm=,args= 2>/dev/null | tr -s ' ')"
      echo "SOFT|high_cpu|$p|sustained ${cpu}% CPU over ${cnt} samples: ${args}"
      em=1
    fi
    printf '%s\t%s\t%s\n' "$p" "$cnt" "$em" >> "$CPU_STATE_FILE.tmp"
  done
  mv "$CPU_STATE_FILE.tmp" "$CPU_STATE_FILE"
}

#---------------------------------------------------------------------------
# SOFT: a listening TCP port that was not in the recorded baseline.
#---------------------------------------------------------------------------
detect_new_listener() {
  [ "${DETECT_NEW_LISTENER:-1}" = "1" ] || return 0
  command -v ss >/dev/null 2>&1 || return 0
  local base="$BASELINE_DIR/listeners"
  local cur; cur="$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -u | grep -E '^[0-9]+$' || true)"
  [ -f "$base" ] || { printf '%s\n' "$cur" > "$base"; return 0; }
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
# SOFT: newly-appeared UPX-packed executable in a world-writable dir.
#---------------------------------------------------------------------------
detect_upx_new() {
  [ "${DETECT_UPX_NEW:-1}" = "1" ] || return 0
  local find_args=(-type f -perm -u+x -size -80M)
  [ -f "$UPX_MARKER" ] && find_args+=(-newer "$UPX_MARKER")
  local f
  while IFS= read -r -d '' f; do
    if strings "$f" 2>/dev/null | grep -qm1 'UPX!'; then
      echo "SOFT|upx_new|-|UPX-packed executable: $f ($(md5sum "$f" 2>/dev/null | cut -d' ' -f1))"
    fi
  done < <(find "${_SUSPECT_DIRS[@]}" "${find_args[@]}" -print0 2>/dev/null)
  run touch "$UPX_MARKER"
}

#---------------------------------------------------------------------------
# Run every detector; all findings on stdout.
#---------------------------------------------------------------------------
run_all_detectors() {
  detect_malware_paths
  detect_malware_hashes
  detect_proc_exe
  detect_c2
  detect_miner
  detect_high_cpu
  detect_new_listener
  detect_persistence
  detect_upx_new
}
