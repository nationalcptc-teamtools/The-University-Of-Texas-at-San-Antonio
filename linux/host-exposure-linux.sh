#!/usr/bin/env bash
# Local file exposure inventory. Run only on systems and mounted storage you may inspect.
set -uo pipefail

original_args=("$@")
deadline_child=0

usage() {
  cat <<'EOF'
Usage: host-exposure-linux.sh [--root PATH ...] [--output PATH] [--max-extract-mib N]
                            [--max-runtime-seconds N]

Without --root, inspect every mount in /proc/self/mountinfo, including network,
tmpfs, and kernel pseudo filesystems. --root limits a fixture or focused run.
Candidate lines contain unmasked values and are printed and saved locally.
EOF
}

roots=()
output=''
max_extract_mib=256
max_runtime_seconds=0
while (($#)); do
  case $1 in
    --_host-exposure-deadline-child) deadline_child=1; shift ;;
    --root) (($# >= 2)) || { usage >&2; exit 2; }; roots+=("$2"); shift 2 ;;
    --output) (($# >= 2)) || { usage >&2; exit 2; }; output=$2; shift 2 ;;
    --max-extract-mib) (($# >= 2)) || { usage >&2; exit 2; }; max_extract_mib=$2; shift 2 ;;
    --max-runtime-seconds) (($# >= 2)) || { usage >&2; exit 2; }; max_runtime_seconds=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ $max_extract_mib =~ ^[1-9][0-9]*$ ]] || { printf 'Invalid extract limit\n' >&2; exit 2; }
if ((${#max_extract_mib} > 4)); then
  printf 'Extract limit must be at most 4096 MiB\n' >&2
  exit 2
fi
((10#$max_extract_mib <= 4096)) || { printf 'Extract limit must be at most 4096 MiB\n' >&2; exit 2; }
max_extract_bytes=$((max_extract_mib * 1024 * 1024))
[[ $max_runtime_seconds =~ ^(0|[1-9][0-9]*)$ ]] || { printf 'Invalid runtime limit\n' >&2; exit 2; }
if ((${#max_runtime_seconds} > 6)); then
  printf 'Runtime limit must be at most 604800 seconds\n' >&2
  exit 2
fi
((10#$max_runtime_seconds <= 604800)) || { printf 'Runtime limit must be at most 604800 seconds\n' >&2; exit 2; }

# Whole-run deadline. Default 0 means unbounded, which is the behaviour every
# existing fixture was validated against, so this changes nothing unless the
# operator asks for it. The per-mount timeout alone is not a bound: a stalled
# NFS or CIFS mount costs its full per-mount allowance, and with N mounts the
# run can take N times that with no upper limit. This closes that.
deadline_tripped=0
deadline_remaining() {
  ((max_runtime_seconds > 0)) || { printf '%d' 0; return; }
  local left=$((max_runtime_seconds - SECONDS))
  ((left < 0)) && left=0
  printf '%d' "$left"
}

timeout_bin=$(command -v timeout || command -v gtimeout || true)
[[ -n $timeout_bin ]] || { printf 'GNU timeout is required for bounded reads\n' >&2; exit 2; }
for tool in find fold awk cat head iconv file mktemp tr uname sleep; do
  command -v "$tool" >/dev/null || { printf 'Missing required tool: %s\n' "$tool" >&2; exit 2; }
done

# Enforce the requested ceiling around the complete scan. The inner deadline
# checks provide a graceful stop between mounts, but they cannot interrupt a
# blocked open, metadata lookup, extractor, or the scan_file consumer of find.
# GNU timeout supervises this process and its children. The child handles TERM
# by writing the partial summary to both stdout and its already-open report.
if ((max_runtime_seconds > 0 && deadline_child == 0)); then
  case $0 in
    /*) self=$0 ;;
    */*) self=$PWD/${0#./} ;;
    *)
      if [[ -f $PWD/$0 ]]; then self=$PWD/$0; else self=$(command -v -- "$0"); fi
      ;;
  esac
  watchdog_pid=''
  cancel_watchdog() {
    trap '' INT TERM
    if [[ -n $watchdog_pid ]]; then
      # GNU timeout owns a new process group by default. Signal the complete
      # group so a blocked reader cannot outlive cancellation of the wrapper.
      # INT tells the child this was operator cancellation, not deadline TERM.
      kill -INT -- "-$watchdog_pid" 2>/dev/null || kill -INT "$watchdog_pid" 2>/dev/null || true
      cancel_wait=0
      while kill -0 -- "-$watchdog_pid" 2>/dev/null && ((cancel_wait < 20)); do
        sleep 0.1
        cancel_wait=$((cancel_wait + 1))
      done
      if kill -0 -- "-$watchdog_pid" 2>/dev/null; then
        kill -KILL -- "-$watchdog_pid" 2>/dev/null || true
      fi
      wait "$watchdog_pid" 2>/dev/null || true
    fi
    exit 130
  }
  trap cancel_watchdog INT TERM
  "$timeout_bin" --signal=TERM --kill-after=30s \
    "${max_runtime_seconds}s" "$BASH" "$self" \
    --_host-exposure-deadline-child "${original_args[@]}" &
  watchdog_pid=$!
  wait "$watchdog_pid"
  wrapper_rc=$?
  trap - INT TERM
  case $wrapper_rc in
    124|137) exit 3 ;;
    *) exit "$wrapper_rc" ;;
  esac
fi

bounded_timeout() {
  if ((deadline_child)); then
    # Keep nested timeouts in the supervised process group so the outer
    # whole-run watchdog can terminate the active reader or extractor too.
    "$timeout_bin" --foreground "$@"
  else
    "$timeout_bin" "$@"
  fi
}

umask 077
default_output=0
if [[ -z $output ]]; then
  default_output=1
  output="${XDG_STATE_HOME:-$HOME/.local/state}/host-exposure-audit/scan-$(date -u +%Y%m%dT%H%M%SZ)-$$.txt"
fi
report_dir=$(dirname -- "$output")
mkdir -p -- "$report_dir" || exit 1
if ((default_output)); then chmod 700 "$report_dir" || exit 1; fi
[[ ! -L $output && ! -e $output ]] || { printf 'Output already exists or is a symlink\n' >&2; exit 1; }
set -o noclobber
exec 3> "$output" || exit 1
set +o noclobber
chmod 600 "$output" || exit 1
output=$(cd -- "$report_dir" && printf '%s/%s' "$PWD" "$(basename -- "$output")")
report_dir=$(dirname -- "$output")
emit() { printf '%s\n' "$*"; printf '%s\n' "$*" >&3; }
escape() { printf '%q' "$1"; }

scratch=$(mktemp "$report_dir/.host-exposure-scratch.XXXXXXXX") || exit 1
extract_tmp=$(mktemp "$report_dir/.host-exposure-extract.XXXXXXXX") || exit 1
errors=$(mktemp "$report_dir/.host-exposure-errors.XXXXXXXX") || exit 1
scan_errors=$(mktemp "$report_dir/.host-exposure-scan-errors.XXXXXXXX") || exit 1
mount_list=$(mktemp "$report_dir/.host-exposure-mounts.XXXXXXXX") || exit 1
cleanup() { rm -f -- "$scratch" "$extract_tmp" "$errors" "$scan_errors" "$mount_list"; }
trap cleanup EXIT
interrupt_handled=0
on_interrupt() {
  local received=${1:-TERM}
  ((interrupt_handled == 0)) || return
  interrupt_handled=1
  # timeout can deliver the same signal through more than one process-group
  # path. Ignore repeats before emitting totals so the report has one ending.
  trap '' INT TERM
  if [[ $received == TERM ]] && ((deadline_child && max_runtime_seconds > 0)); then
    status partial '-' 'run deadline reached; coverage is incomplete'
    emit "SUMMARY regular_files=$files content_findings=$findings interesting_names=$named extracted_files=$extracted nonregular_skipped=$nonregular errors=$errors_count partial_or_unsupported=$partial"
    emit "SUMMARY deadline_reached=1 max_runtime_seconds=$max_runtime_seconds elapsed=${SECONDS}s"
    exit 3
  fi
  emit 'STATUS interrupted'
  exit 130
}

match_re='password|passwd|passphrase|pwd|secret|token|api[_-]?key|client[_-]?secret|connection[ _-]?string|credential|username|user_name|account_name|private[ _-]?key|://[^[:space:]:/@]+:[^[:space:]@]+@'
name_re='(^|/)(\.env($|\.)|id_(rsa|dsa|ecdsa|ed25519)$|[^/]*(pass|cred|secret|token|unattend|sysprep|web\.config|\.pem$|\.pfx$|\.kdbx$|\.bak$|\.old$|history))'
files=0; findings=0; errors_count=0; partial=0; named=0; extracted=0; nonregular=0

status() {
  emit "STATUS $1 $(escape "$2") ${3:-}"
  case $1 in
    unreadable|error) errors_count=$((errors_count + 1)) ;;
    partial|unsupported|timeout) partial=$((partial + 1)) ;;
  esac
}
trap 'on_interrupt INT' INT
trap 'on_interrupt TERM' TERM

report_matches() {
  local label=$1 encoding=$2 line
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -n $line ]] || continue
    emit "CANDIDATE path=$(escape "$label") source=$encoding text=$(escape "$line")"
    findings=$((findings + 1))
  done < "$scratch"
}

# Break even newline-free inputs into bounded records. Lookahead keeps an
# indicator and its value together across a fold boundary without buffering a
# whole dynamic or binary pseudo file as one line.
bounded_matches() {
  LC_ALL=C fold -b -w 4096 | LC_ALL=C awk -v re="$match_re" -v width=4096 -v overlap=128 '
    function emit_previous(next_record, next_exists, combined, remaining, boundary,
                           offset, consumed, start, finish, has_owned,
                           max_owned_finish, earliest_unowned, near_end, desired,
                           output_start) {
      boundary = length(previous)
      combined = previous (next_exists && previous_continues ? next_record : "")
      remaining = tolower(combined)
      offset = 0
      while (match(remaining, re)) {
        start = offset + RSTART
        finish = start + RLENGTH - 1
        if (start <= boundary) {
          if (start <= previous_suppressed_prefix) {
            if (finish > boundary && finish - boundary > next_suppression) {
              next_suppression = finish - boundary
            }
          } else {
            has_owned = 1
            if (finish > max_owned_finish) max_owned_finish = finish
            if (finish > boundary - overlap) near_end = 1
            if (finish > boundary && finish - boundary > next_suppression) {
              next_suppression = finish - boundary
            }
          }
        } else if (!earliest_unowned) {
          earliest_unowned = start
        }
        consumed = RSTART + (RLENGTH > 0 ? RLENGTH : 1) - 1
        offset += consumed
        remaining = substr(remaining, consumed + 1)
      }
      if (!has_owned) return
      desired = boundary
      if (next_exists && previous_continues && near_end) {
        desired = boundary + overlap
        if (max_owned_finish + overlap > desired) desired = max_owned_finish + overlap
        if (desired > length(combined)) desired = length(combined)
        if (earliest_unowned > max_owned_finish && earliest_unowned <= desired) {
          desired = earliest_unowned - 1
        }
      }
      if (desired > boundary && desired - boundary > next_suppression) {
        next_suppression = desired - boundary
      }
      output_start = previous_suppressed_prefix + 1
      print "segment=" previous_number ":" substr(combined, output_start, desired - output_start + 1)
    }
    {
      carried_suppression = 0
      if (have_previous) {
        next_suppression = 0
        emit_previous($0, 1)
        carried_suppression = next_suppression
      }
      previous = $0
      previous_number = NR
      previous_continues = (length(previous) == width)
      previous_suppressed_prefix = carried_suppression
      have_previous = 1
    }
    END {
      if (have_previous) {
        next_suppression = 0
        emit_previous("", 0)
      }
    }'
}

# Scan one stream in bounded memory. GNU strings covers embedded ASCII; iconv
# covers UTF-16 content that plain grep cannot see. A partial read is reported.
scan_content() {
  local path=$1 label=$2 seconds=$3 rc=0 mime
  if [[ $seconds -gt 0 ]]; then
    mime=$(bounded_timeout "${seconds}s" file -b --mime-encoding "$path" 2>/dev/null) || {
      rc=$?
      status "$([[ $rc -eq 124 ]] && echo timeout || echo partial)" "$label" "file-type-exit=$rc"
      return
    }
  else
    mime=$(file -b --mime-encoding "$path" 2>/dev/null) || { status partial "$label" 'file-type-error'; return; }
  fi
  if [[ $mime != binary && $mime != utf-16* ]]; then
    : > "$scratch"
    if [[ $seconds -gt 0 ]]; then
      { bounded_timeout "${seconds}s" cat -- "$path" | bounded_matches > "$scratch"; rc=$?; } 2> "$scan_errors"
    else
      { cat -- "$path" | bounded_matches > "$scratch"; rc=$?; } 2> "$scan_errors"
    fi
    report_matches "$label" text
    [[ $rc -eq 0 ]] || { status "$([[ $rc -eq 124 ]] && echo timeout || echo partial)" "$label" "text-read-exit=$rc"; return; }
  fi

  # Strings are useful for opaque binaries, but not a substitute for decoding.
  if [[ $mime == binary ]]; then
    : > "$scratch"
    rc=0
    if command -v strings >/dev/null; then
      if [[ $seconds -gt 0 ]]; then
        { bounded_timeout "${seconds}s" strings -a -t d -n 4 -- "$path" | bounded_matches > "$scratch"; rc=$?; } 2> "$scan_errors"
      else
        { strings -a -t d -n 4 -- "$path" | bounded_matches > "$scratch"; rc=$?; } 2> "$scan_errors"
      fi
      report_matches "$label" binary-ascii
    else
      if [[ $seconds -gt 0 ]]; then
        { bounded_timeout "${seconds}s" tr -cs '[:print:]' '\n' < "$path" | bounded_matches > "$scratch"; rc=$?; } 2> "$scan_errors"
      else
        { tr -cs '[:print:]' '\n' < "$path" | bounded_matches > "$scratch"; rc=$?; } 2> "$scan_errors"
      fi
      report_matches "$label" binary-ascii-no-offset
    fi
    [[ $rc -eq 0 ]] || status partial "$label" "binary-read-exit=$rc"
  fi

  [[ $mime == binary || $mime == utf-16* ]] || return
  for encoding in UTF-16LE UTF-16BE; do
    : > "$scratch"
    rc=0
    if [[ $seconds -gt 0 ]]; then
      { bounded_timeout "${seconds}s" iconv -c -f "$encoding" -t UTF-8 "$path" | bounded_matches > "$scratch"; rc=$?; } 2> "$scan_errors"
    else
      { iconv -c -f "$encoding" -t UTF-8 "$path" | bounded_matches > "$scratch"; rc=$?; } 2> "$scan_errors"
    fi
    # Ignore the mostly-gibberish reverse decode when no keyword appeared.
    [[ -s $scratch ]] && report_matches "$label" "$encoding"
    [[ $rc -eq 0 ]] || status "$([[ $rc -eq 124 ]] && echo timeout || echo partial)" "$label" "iconv-$encoding-exit=$rc"
  done
}

extract_content() {
  local path=$1 label=$2 seconds=$3 ext rc=0 bytes
  ext=$(printf '%s' "${path##*.}" | tr '[:upper:]' '[:lower:]')
  case $ext in
    zip|7z|tar|gz|tgz|bz2|xz|docx|xlsx|pptx|odt|ods|odp)
      if ! command -v 7z >/dev/null; then status unsupported "$label" 'archive extractor 7z unavailable'; return; fi
      : > "$extract_tmp"
      bounded_timeout "${seconds}s" 7z x -so -y -- "$path" 2> "$scan_errors" | head -c "$max_extract_bytes" > "$extract_tmp"
      rc=${PIPESTATUS[0]}
      bytes=$(wc -c < "$extract_tmp" | tr -d ' ')
      extracted=$((extracted + 1))
      scan_content "$extract_tmp" "$label!expanded-stream" 0
      [[ $rc -eq 0 && $bytes -lt $max_extract_bytes ]] || status partial "$label" "archive-exit=$rc expanded-bytes=$bytes cap=$max_extract_bytes"
      ;;
    pdf)
      if ! command -v pdftotext >/dev/null; then status unsupported "$label" 'pdftotext unavailable'; return; fi
      : > "$extract_tmp"
      bounded_timeout "${seconds}s" pdftotext -layout -enc UTF-8 "$path" - 2> "$scan_errors" | head -c "$max_extract_bytes" > "$extract_tmp"
      rc=${PIPESTATUS[0]}
      bytes=$(wc -c < "$extract_tmp" | tr -d ' ')
      extracted=$((extracted + 1))
      scan_content "$extract_tmp" "$label!pdf-text" 0
      [[ $rc -eq 0 && $bytes -lt $max_extract_bytes ]] || status partial "$label" "pdf-exit=$rc expanded-bytes=$bytes cap=$max_extract_bytes"
      ;;
    doc)
      if ! command -v antiword >/dev/null; then status unsupported "$label" 'antiword unavailable'; return; fi
      : > "$extract_tmp"
      bounded_timeout "${seconds}s" antiword "$path" 2> "$scan_errors" | head -c "$max_extract_bytes" > "$extract_tmp"
      rc=${PIPESTATUS[0]}
      bytes=$(wc -c < "$extract_tmp" | tr -d ' ')
      extracted=$((extracted + 1))
      scan_content "$extract_tmp" "$label!doc-text" 0
      [[ $rc -eq 0 && $bytes -lt $max_extract_bytes ]] || status partial "$label" "doc-exit=$rc expanded-bytes=$bytes cap=$max_extract_bytes"
      ;;
    kdbx|pfx|p12|gpg|age|enc)
      status unsupported "$label" 'protected format not decrypted'
      ;;
  esac
}

scan_file() {
  local path=$1 fs=$2 seconds=60 rc bytes inspected_bytes ext pseudo=0
  [[ $path -ef $output || $path == "$scratch" || $path == "$extract_tmp" || $path == "$errors" || $path == "$scan_errors" || $path == "$mount_list" ]] && return
  if [[ ! -f $path ]]; then nonregular=$((nonregular + 1)); return; fi
  files=$((files + 1))
  if [[ $path =~ $name_re ]]; then
    emit "CANDIDATE path=$(escape "$path") source=filename text=interesting-name"
    named=$((named + 1))
  fi
  [[ -r $path ]] || { status unreadable "$path"; return; }
  case $fs in proc|sysfs|debugfs|tracefs|securityfs|cgroup*|configfs|devpts|devtmpfs|fusectl|fuse.lxcfs) seconds=10; pseudo=1 ;; esac
  if ((pseudo)); then
    : > "$extract_tmp"
    rc=0
    bounded_timeout "${seconds}s" head -c 1048577 -- "$path" > "$extract_tmp" 2> "$scan_errors" || rc=$?
    bytes=$(wc -c < "$extract_tmp" | tr -d ' ')
    inspected_bytes=$bytes
    if ((bytes > 1048576)); then
      if ! head -c 1048576 -- "$extract_tmp" > "$scratch" || ! cat -- "$scratch" > "$extract_tmp"; then
        status error "$path" "pseudo-cap-stage-error read-bytes=$bytes"
        return
      fi
      inspected_bytes=1048576
    fi
    [[ $rc -eq 0 ]] || status "$([[ $rc -eq 124 ]] && echo timeout || echo unreadable)" "$path" "pseudo-read-exit=$rc inspected-bytes=$inspected_bytes"
    ((bytes > 1048576)) && status partial "$path" "pseudo-read-cap=1048576 inspected-bytes=$inspected_bytes"
    ((inspected_bytes > 0)) && scan_content "$extract_tmp" "$path" 0
    ext=$(printf '%s' "${path##*.}" | tr '[:upper:]' '[:lower:]')
    case $ext in
      zip|7z|tar|gz|tgz|bz2|xz|docx|xlsx|pptx|odt|ods|odp|pdf|doc)
        status unsupported "$path" 'pseudo-file container expansion skipped'
        ;;
      kdbx|pfx|p12|gpg|age|enc)
        status unsupported "$path" 'protected format not decrypted'
        ;;
    esac
  else
    scan_content "$path" "$path" "$seconds"
    extract_content "$path" "$path" "$seconds"
  fi
}

emit 'Host Exposure Audit: candidate findings, not verified credentials'
emit "UTC $(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit "HOST $(uname -n) OS $(uname -srm) ID $(id)"
emit "REPORT $(escape "$output")"
if [[ -r /etc/passwd ]]; then
  while IFS=: read -r user _ uid gid _ home shell; do
    emit "LOCAL_USER name=$(escape "$user") uid=$uid gid=$gid home=$(escape "$home") shell=$(escape "$shell")"
  done < /etc/passwd
fi

if ((${#roots[@]})); then
  for root in "${roots[@]}"; do
    fstype=''
    if command -v findmnt >/dev/null; then
      fstype=$(findmnt -T "$root" -no FSTYPE 2>/dev/null || true)
    fi
    [[ -n $fstype ]] || fstype=$(stat -f -c %T -- "$root" 2>/dev/null || printf explicit)
    printf '%s\0%s\0' "$root" "$fstype" >> "$mount_list"
  done
else
  [[ -r /proc/self/mountinfo ]] || { emit 'STATUS error mount discovery unavailable; pass --root'; exit 1; }
  while IFS= read -r row; do
    left=${row%% - *}; right=${row#* - }
    read -r _ _ _ _ mount _ <<< "$left"
    read -r fstype _ <<< "$right"
    mount=$(printf '%b_' "$mount")
    mount=${mount%_}
    printf '%s\0%s\0' "$mount" "$fstype" >> "$mount_list"
  done < /proc/self/mountinfo
fi

# Separate mounted roots prevent a bind mount or nested volume from being hidden.
# NUL pairs preserve legal TAB and newline characters in mount paths.
seen_roots=('')
while IFS= read -r -d '' root && IFS= read -r -d '' fs; do
  already_seen=0
  for prior in "${seen_roots[@]}"; do
    [[ $prior == "$root" ]] && { already_seen=1; break; }
  done
  ((already_seen)) && continue
  seen_roots+=("$root")
  if ((max_runtime_seconds > 0)) && ((SECONDS >= max_runtime_seconds)); then
    status partial "$root" 'run-deadline reached; remaining mounts not inspected'
    deadline_tripped=1
    break
  fi
  [[ -d $root || -f $root ]] || { status error "$root" 'mount missing'; continue; }
  emit "MOUNT path=$(escape "$root") type=$fs"
  : > "$errors"
  limit=3600
  case $fs in proc|sysfs|debugfs|tracefs|securityfs|cgroup*|configfs|devpts|devtmpfs|fusectl|fuse.lxcfs) limit=120 ;; esac
  # Never let a single mount outlive the whole-run budget.
  remaining=$(deadline_remaining)
  if ((remaining > 0)) && ((remaining < limit)); then limit=$remaining; fi
  find_rc=0
  while IFS= read -r -d '' path; do
    if [[ $path == __FIND_STATUS__* ]]; then
      find_rc=${path#__FIND_STATUS__}
    else
      scan_file "$path" "$fs"
    fi
  done < <(bounded_timeout "${limit}s" find "$root" -xdev -type f -print0 2> "$errors"; printf '__FIND_STATUS__%d\0' "$?")
  [[ ${find_rc:-0} -eq 0 ]] || status partial "$root" "find-exit=$find_rc"
  while IFS= read -r problem; do status error "$root" "find: $(escape "$problem")"; done < "$errors"
done < "$mount_list"
emit "SUMMARY regular_files=$files content_findings=$findings interesting_names=$named extracted_files=$extracted nonregular_skipped=$nonregular errors=$errors_count partial_or_unsupported=$partial"
if ((deadline_tripped)); then
  emit "STATUS partial '-' 'run deadline reached; coverage is incomplete'"
  emit "SUMMARY deadline_reached=1 max_runtime_seconds=$max_runtime_seconds elapsed=${SECONDS}s"
  exit 3
fi
