# 🔍 SSRF Scanner

A lightweight tool to detect Server-Side Request Forgery vulnerabilities automatically.

---

## 📌 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sample Output](#-sample-output)
- [Payloads Used](#-payloads-used)
- [Project Structure](#-project-structure)
- [Notes](#-notes)
- [License](#-license)

---

## 🧠 Overview

This tool scans web applications for **SSRF (Server-Side Request Forgery)** vulnerabilities by automatically injecting crafted payloads into parameters and analyzing server responses.

It tests:

- Localhost access  
- Internal networks  
- Metadata endpoints  
- Dangerous schemes such as `file://`

> ⚠️ This is designed for **educational and penetration testing purposes only**.

---

## ✨ Features

- 🚀 Fast multi-threaded scanning  
- 🎯 Auto-detection of vulnerable parameters  
- 🧪 Multiple SSRF payload categories  
- 🔁 Follows redirects when required  
- 📝 Clear console output and logging  
- ⚠️ Simple and beginner-friendly codebase  

---

## 🛠️ How It Works

1. Extracts parameters from a target URL.  
2. Replaces their values with SSRF payloads.  
3. Sends requests with each payload.  
4. Identifies SSRF indicators such as:
   - `localhost` / `127.0.0.1` responses  
   - Internal IP blocks (10.x.x.x, 172.16.x.x, etc.)  
   - Cloud metadata responses  
   - Error messages indicating SSRF processing  

---

## 📦 Installation

### Clone the repository
```bash
git clone https://github.com/username/ssrf-scanner.git
cd ssrf-scanner
Install dependencies
pip install -r requirements.txt
```

▶️ Usage
```
Basic command
python ssrf_scanner.py "https://example.com/page?id=123&image=http://site.com/a.png"
```

Advanced
```
python ssrf_scanner.py --url <target> --threads 10 --verbose
```

Arguments
```
--url / -u       Target URL
--threads / -t   Number of threads (default: 5)
--verbose / -v   Show full request/response details
```

🧾 Sample Output
[+] Testing parameter: image
[+] Payload: http://127.0.0.1:80
[!] Possible SSRF detected! Response contains 'Apache/2.4.1 (Ubuntu)'

[+] Payload: http://169.254.169.254/latest/meta-data
[!] SSRF confirmed: Metadata endpoint responded with HTTP 200

🧨 Payloads Used
🔹 Localhost access
```
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
```

🔹 Internal network probing
```
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/
```
🔹 Cloud metadata
```
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal
```

🔹 Dangerous schemes
```
file:///etc/passwd
gopher://127.0.0.1:11211/
```

📁 Project Structure
ssrf-scanner/
│── ssrf_scanner.py
│── payloads.txt
│── README.md
│── requirements.txt

📝 Notes

Run only on systems you have permission to test.

Some responses may be blocked by WAFs or rate-limiting.

Add your own payloads in payloads.txt for more power.
