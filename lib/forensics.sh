#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - lib/forensics.sh
# Non-destructive evidence collection. Always runs, even in dry-run / alert-only.
# Sourced after lib/common.sh.
#===============================================================================

# snapshot_pid <pid> <tag>
# Writes a single evidence file describing the process. Returns the file path on
# stdout. Best-effort: every probe is guarded, a dead PID still yields a stub.
snapshot_pid() {
  local pid="$1" tag="${2:-detect}"
  local ts; ts="$(date +%Y%m%d_%H%M%S)"
  local out="$EVIDENCE_DIR/${ts}_pid${pid}_${tag}.txt"

  {
    echo "=== Cerberus evidence: PID=$pid TAG=$tag ==="
    echo "collected: $(date -Iseconds)"
    echo
    echo "--- ps ---"
    ps -p "$pid" -o pid,ppid,user,pcpu,pmem,etimes,nlwp,stat,cmd 2>&1 || echo "(process gone)"
    echo
    echo "--- /proc/$pid/exe ---"
    ls -l "/proc/$pid/exe" 2>&1 || echo "(unavailable)"
    echo
    echo "--- exe hash ---"
    local exe; exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
    if [ -n "$exe" ] && [ -r "$exe" ]; then
      md5sum "$exe" 2>&1 || true
      sha256sum "$exe" 2>&1 || true
    else
      echo "(exe not readable)"
    fi
    echo
    echo "--- cwd ---"
    ls -l "/proc/$pid/cwd" 2>&1 || echo "(unavailable)"
    echo
    echo "--- cmdline ---"
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null; echo
    echo
    echo "--- environ ---"
    tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | head -80 || echo "(unavailable)"
    echo
    echo "--- parent chain ---"
    if command -v pstree >/dev/null 2>&1; then
      pstree -sp "$pid" 2>&1 || true
    else
      local p="$pid"
      while [ -n "$p" ] && [ "$p" != "0" ] && [ "$p" != "1" ]; do
        ps -o pid=,comm=,cmd= -p "$p" 2>/dev/null || break
        p="$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')"
      done
    fi
    echo
    echo "--- open files / sockets (lsof) ---"
    if command -v lsof >/dev/null 2>&1; then
      lsof -p "$pid" 2>&1 | head -120 || echo "(lsof failed)"
    else
      ls -l "/proc/$pid/fd" 2>&1 | head -120 || echo "(unavailable)"
    fi
    echo
    echo "--- network (ss) ---"
    if command -v ss >/dev/null 2>&1; then
      ss -tanp 2>/dev/null | grep -E "pid=$pid\b" || echo "(no sockets)"
    fi
  } > "$out" 2>&1

  echo "$out"
}

# _printable_strings <file> : printable runs from a binary.
#
# strings(1) is binutils, which a minimal server does not have. Without a
# fallback the evidence file kept for a quarantined payload just had an empty
# section where its strings should be -- and evidence is the whole reason the
# original is preserved rather than deleted.
_printable_strings() {
  if command -v strings >/dev/null 2>&1; then
    strings "$1" 2>/dev/null
  else
    LC_ALL=C grep -a -o '[[:print:]]\{4,\}' "$1" 2>/dev/null
  fi
}

# snapshot_file <path> <tag>
# Records metadata + hashes for a suspicious file without touching it.
snapshot_file() {
  local f="$1" tag="${2:-file}"
  local ts; ts="$(date +%Y%m%d_%H%M%S)"
  local base; base="$(basename "$f")"
  local out="$EVIDENCE_DIR/${ts}_file_${base}_${tag}.txt"
  {
    echo "=== Cerberus evidence: FILE=$f TAG=$tag ==="
    echo "collected: $(date -Iseconds)"
    echo
    stat "$f" 2>&1 || echo "(stat failed)"
    echo
    md5sum "$f" 2>&1 || true
    sha256sum "$f" 2>&1 || true
    echo
    echo "--- file(1) ---"
    file "$f" 2>&1 || true
    echo
    echo "--- strings (first 60) ---"
    _printable_strings "$f" | head -60 || true
  } > "$out" 2>&1
  echo "$out"
}
