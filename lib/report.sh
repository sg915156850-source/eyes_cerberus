#!/usr/bin/env bash
#===============================================================================
# Eyes Cerberus - lib/report.sh
# A period report over events.jsonl, as JSON or as a self-contained HTML page.
#
# This is the artefact you hand to whoever asked "so what has it been doing" --
# after an incident, at the end of a monitoring month, or to yourself in three
# weeks. It reads events.jsonl and the current state of the host; it changes
# nothing.
# Sourced after lib/common.sh.
#===============================================================================

# _report_since <days> : epoch seconds, or 0 if date(1) cannot work it out.
_report_since() {
  date -d "-${1} days" +%s 2>/dev/null || echo 0
}

# _report_json <days> : the whole report as one JSON object on stdout.
# jq does the aggregation when it is available; without jq the totals are done
# in awk, because a report is not worth a new runtime dependency.
_report_json() {
  local days="${1:-7}" since
  since="$(_report_since "$days")"

  local generated host version
  generated="$(date -Iseconds)"
  host="$(hostname 2>/dev/null || echo unknown)"
  version="${VERSION:-unknown}"

  local daemon="unknown"
  if command -v systemctl >/dev/null 2>&1; then
    daemon="$(systemctl is-active eyes-cerberus.service 2>/dev/null || echo inactive)"
  fi

  local quarantined=0
  quarantined="$(find "$QUARANTINE_DIR" -maxdepth 1 -name '*.metadata' 2>/dev/null | wc -l)"

  local c2_rules=0
  if command -v iptables >/dev/null 2>&1; then
    c2_rules="$(iptables -S 2>/dev/null | grep -c 'DROP' || true)"
  fi

  if [ ! -f "$EVENTS_LOG" ]; then
    printf '{"generated":%s,"host":%s,"version":%s,"period_days":%s,"daemon":%s,"quarantined":%s,"firewall_drop_rules":%s,"total":0,"by_severity":{},"by_category":{},"events":[]}\n' \
      "$(json_escape "$generated")" "$(json_escape "$host")" "$(json_escape "$version")" \
      "$days" "$(json_escape "$daemon")" "$quarantined" "$c2_rules"
    return 0
  fi

  if command -v jq >/dev/null 2>&1; then
    # fromdateiso8601 only accepts a "Z" suffix, and the daemon writes
    # date -Iseconds, which is "+00:00" (or a real local offset). Parsing the
    # timestamp as-is silently yielded 0 for every event, so every report came
    # back empty. Normalise to Z and subtract the offset by hand.
    jq -s --argjson since "$since" \
          --arg generated "$generated" --arg host "$host" --arg version "$version" \
          --argjson days "$days" --arg daemon "$daemon" \
          --argjson quarantined "$quarantined" --argjson rules "$c2_rules" '
      def to_epoch:
        . as $t
        | ($t | capture("(?<sign>[+-])(?<oh>[0-9]{2}):(?<om>[0-9]{2})$") ) as $off
        | ( $t | sub("(?:Z|[+-][0-9]{2}:[0-9]{2})$"; "") + "Z"
              | try fromdateiso8601 catch null ) as $base
        | if $base == null then 0
          elif $off == null then $base
          else $base
               - ( (if $off.sign == "+" then 1 else -1 end)
                   * (($off.oh | tonumber) * 3600 + ($off.om | tonumber) * 60) )
          end;
      map(select((.ts | to_epoch) >= $since))
      | {
          generated: $generated, host: $host, version: $version,
          period_days: $days, daemon: $daemon,
          quarantined: $quarantined, firewall_drop_rules: $rules,
          total: length,
          by_severity: (group_by(.severity) | map({key: .[0].severity, value: length}) | from_entries),
          by_category: (group_by(.category) | map({key: .[0].category, value: length}) | from_entries),
          events: (sort_by(.ts) | reverse | .[0:200])
        }' "$EVENTS_LOG"
    return 0
  fi

  # jq-less fallback: totals over the whole log, no per-event list and no
  # period filter -- doing date arithmetic per line in awk is not worth it when
  # jq is one package away.
  local total sev_json cat_json
  total="$(wc -l < "$EVENTS_LOG" | tr -d ' ')"
  sev_json="$(_report_count_field severity)"
  cat_json="$(_report_count_field category)"
  printf '{"generated":%s,"host":%s,"version":%s,"period_days":%s,"daemon":%s,"quarantined":%s,"firewall_drop_rules":%s,"total":%s,"by_severity":%s,"by_category":%s,"events":[]}\n' \
    "$(json_escape "$generated")" "$(json_escape "$host")" "$(json_escape "$version")" \
    "$days" "$(json_escape "$daemon")" "$quarantined" "$c2_rules" \
    "$total" "$sev_json" "$cat_json"
}

# _report_count_field <field> : {"value": count, ...} over the whole log.
_report_count_field() {
  local field="$1"
  sed -n "s/.*\"$field\":\"\\([^\"]*\\)\".*/\\1/p" "$EVENTS_LOG" \
    | sort | uniq -c \
    | awk 'BEGIN{printf "{"} {printf "%s\"%s\":%s", (NR>1?",":""), $2, $1} END{printf "}\n"}'
}

# _html_escape : stdin -> stdout, safe to drop inside an HTML element.
_html_escape() {
  sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# report_html <days> : one self-contained page, no external requests. A report
# that phones out to a CDN is not something you hand to a client, and it would
# not render on the isolated host you are most likely to be reading it on.
report_html() {
  local days="${1:-7}" json
  json="$(_report_json "$days")"

  local generated host total daemon quarantined rules
  if command -v jq >/dev/null 2>&1; then
    generated="$(printf '%s' "$json" | jq -r '.generated')"
    host="$(printf '%s' "$json" | jq -r '.host')"
    total="$(printf '%s' "$json" | jq -r '.total')"
    daemon="$(printf '%s' "$json" | jq -r '.daemon')"
    quarantined="$(printf '%s' "$json" | jq -r '.quarantined')"
    rules="$(printf '%s' "$json" | jq -r '.firewall_drop_rules')"
  else
    generated="$(date -Iseconds)"; host="$(hostname 2>/dev/null || echo unknown)"
    total="?"; daemon="unknown"; quarantined="?"; rules="?"
  fi

  cat <<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Eyes Cerberus report - $(printf '%s' "$host" | _html_escape)</title>
<style>
  :root { color-scheme: light dark; --fg:#111; --bg:#fff; --mut:#666; --line:#ddd;
          --hard:#b00020; --soft:#8a6d00; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e6e6e6; --bg:#141414; --mut:#9a9a9a; --line:#333;
            --hard:#ff6b6b; --soft:#e0b64a; }
  }
  body { margin:0; padding:2rem 1.25rem; background:var(--bg); color:var(--fg);
         font:14px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  main { max-width:60rem; margin:0 auto; }
  h1 { font-size:1.35rem; margin:0 0 .25rem; }
  .sub { color:var(--mut); margin:0 0 2rem; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));
           gap:.75rem; margin-bottom:2rem; }
  .card { border:1px solid var(--line); border-radius:.5rem; padding:.75rem .9rem; }
  .card b { display:block; font-size:1.6rem; font-weight:600; }
  .card span { color:var(--mut); font-size:.8rem; text-transform:uppercase;
               letter-spacing:.04em; }
  h2 { font-size:1rem; margin:2rem 0 .6rem; }
  .scroll { overflow-x:auto; }
  table { border-collapse:collapse; width:100%; font-size:.86rem; }
  th,td { text-align:left; padding:.4rem .6rem; border-bottom:1px solid var(--line);
          vertical-align:top; }
  th { color:var(--mut); font-weight:600; white-space:nowrap; }
  td.detail { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-word; }
  .HARD { color:var(--hard); font-weight:600; }
  .SOFT { color:var(--soft); }
  footer { color:var(--mut); font-size:.8rem; margin-top:2.5rem;
           border-top:1px solid var(--line); padding-top:1rem; }
</style></head><body><main>
<h1>Eyes Cerberus &mdash; $(printf '%s' "$host" | _html_escape)</h1>
<p class="sub">Last ${days} days &middot; generated $(printf '%s' "$generated" | _html_escape)</p>

<div class="cards">
  <div class="card"><b>${total}</b><span>events</span></div>
  <div class="card"><b>$(printf '%s' "$daemon" | _html_escape)</b><span>daemon</span></div>
  <div class="card"><b>${quarantined}</b><span>quarantined</span></div>
  <div class="card"><b>${rules}</b><span>firewall drops</span></div>
</div>
HTML

  if command -v jq >/dev/null 2>&1; then
    echo '<h2>By category</h2><div class="scroll"><table><tr><th>Category</th><th>Count</th></tr>'
    printf '%s' "$json" | jq -r '.by_category | to_entries[] | "\(.key)\t\(.value)"' \
      | sort -k2 -rn \
      | while IFS=$'\t' read -r k v; do
          printf '<tr><td>%s</td><td>%s</td></tr>\n' \
            "$(printf '%s' "$k" | _html_escape)" "$v"
        done
    echo '</table></div>'

    echo '<h2>Events</h2><div class="scroll"><table><tr><th>Time</th><th>Severity</th><th>Category</th><th>PID</th><th>Detail</th></tr>'
    printf '%s' "$json" \
      | jq -r '.events[] | [.ts, .severity, .category, .pid, .detail] | @tsv' \
      | while IFS=$'\t' read -r ts sev cat pid detail; do
          printf '<tr><td>%s</td><td class="%s">%s</td><td>%s</td><td>%s</td><td class="detail">%s</td></tr>\n' \
            "$(printf '%s' "$ts" | _html_escape)" \
            "$(printf '%s' "$sev" | tr -cd 'A-Z')" \
            "$(printf '%s' "$sev" | _html_escape)" \
            "$(printf '%s' "$cat" | _html_escape)" \
            "$(printf '%s' "$pid" | _html_escape)" \
            "$(printf '%s' "$detail" | _html_escape)"
        done
    echo '</table></div>'
  else
    echo '<p>Install <code>jq</code> for the per-event table.</p>'
  fi

  cat <<HTML
<footer>
Eyes Cerberus ${VERSION:-} &middot; SOFT findings are alert-only heuristics;
HARD findings were auto-contained if AUTO_RESPONSE was on. Evidence and
quarantined copies live under <code>${STATE_DIR}</code> on this host.
</footer>
</main></body></html>
HTML
}

# report <days> <json|html>
report() {
  local days="${1:-7}" fmt="${2:-html}"
  case "$fmt" in
    json) _report_json "$days" ;;
    html) report_html "$days" ;;
    *) err "unknown report format: $fmt (want json or html)"; return 2 ;;
  esac
}
