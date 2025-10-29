#SSRF Hunter — Portable SSRF Scanner

One-line: Lightweight Bash SSRF scanner for authorized security testing (URL params, headers, POST bodies).

Warning / Legal: Use only on systems you own or have explicit permission to test. Unauthorized testing is illegal.

Install
# create script and make executable
curl -sS -O https://example.com/ssrf_scanner.sh   # or copy the provided script
chmod +x ssrf_scanner.sh
# (optional) install helpers
sudo apt update && sudo apt install -y curl jq parallel

Quick usage
# auto-detect params in URL
./ssrf_scanner.sh --url "http://vuln.local/search?url=https://ok"

# test specific param, use proxy, custom payloads
./ssrf_scanner.sh --url "http://vuln.local/" --params url --payloads payloads.txt --proxy http://127.0.0.1:8080

Key features

Injects payloads into query params, headers, POST form or JSON bodies.

Concurrency via parallel (fallback to background jobs).

Basic heuristics flag internal IPs, metadata endpoints, passwd, timeouts/errors.

CSV output for triage (ssrf_results.csv).

Output

CSV columns: timestamp,target,tested_param,payload,final_url,status,error,indicators,snippet.

Extending / OOB

Add custom payloads in payloads.txt. For reliable detection integrate an OOB collaborator (interact.sh / Burp Collaborator) — only on authorized targets.

License & Ethics

Open for defensive/security use. Report responsibly and follow target scope and disclosure rules.
