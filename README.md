# JWT Analyzer + Misconfig Scanner (Burp Suite Extension)

A lightweight Burp Suite extension (Python/Jython) that:

- Detects JWTs in **requests and responses**
- Adds a **“JWT Analyzer”** tab that decodes the header & payload
- Highlights **common JWT misconfigurations**
- Registers a **passive Scanner** issue: `JWT Misconfiguration / Weak Claims`

> Built as a Jython/Python extension for Burp Suite Community or Professional.

---

## Features

### 🔍 JWT Detection

Finds JWTs in:

- `Authorization: Bearer <token>` headers
- Cookies
- Query parameters
- JSON request/response bodies
- Form / URL-encoded bodies
- Multipart form-data
- Response bodies (e.g., tokens issued by the server)

Uses a simple regex for typical JWT structure: `header.payload.signature` starting with `eyJ` (base64 for `{`).

---

### 🧩 Analysis & Misconfig Checks

For each detected token, the extension:

#### Header checks

- `alg`:
  - Flags **`alg = "none"`** as a critical misconfiguration
  - Notes when symmetric algorithms are used (e.g., `HS256`)
  - Notes when asymmetric algorithms are used (e.g., `RS256`, `ES256`)
  - Warns if the algorithm is **not in the expected list** (`EXPECTED_ALGS`)
- `typ`:
  - Warns if `typ` is missing (recommends `typ: "JWT"`)
- `kid`:
  - Warns if `kid` is missing (important for key rotation scenarios)

#### Payload checks

- `exp`:
  - Warns if **missing** (`no explicit expiration`)
  - Warns if `exp` appears **expired** (in the past)
  - Warns if `exp` appears **too far in the future** (long-lived token)
  - Warns if `exp` is **not numeric**
- `iat`:
  - Warns if missing (`issued-at` time)
- `iss`:
  - Warns if missing (`issuer`)
- `aud`:
  - Warns if missing (`audience`)
- Role / privilege hints:
  - If `role`, `roles`, `scope`, or `scopes` is present, highlights it and suggests reviewing for least privilege.

---

### 🛡️ Passive Scanner Integration

Registers a passive Scanner check named:

> **`JWT Misconfiguration / Weak Claims`**

Severity is automatically adjusted based on findings:

- **High**  
  - If `alg = "none"` is detected
- **Medium**  
  - If a long-lived token (`exp` far in the future) is detected, but nothing High
- **Information**  
  - For lighter issues (missing claims, no kid, etc.)

The issue detail includes:

- Truncated token
- Decoded header (JSON)
- Decoded payload (JSON)
- Bullet list of all detected misconfigurations

---

## Requirements

- **Burp Suite**  
  - Community or Professional edition
- **Jython standalone JAR**  
  - e.g., `jython-standalone-2.7.x.jar`

---

## Installation

### 1. Configure Jython in Burp

1. Download the **Jython standalone JAR** (2.7.x).
2. In Burp, go to:  
   `Extensions -> Options -> Python Environment`
3. Click **Select file…** and choose the `jython-standalone-2.7.x.jar` file.
4. Apply/OK.

### 2. Load the extension

1. Save `JwtAnalyzer.py` somewhere on disk.
2. In Burp, go to:  
   `Extensions -> Installed -> Add`
3. Set:
   - **Extension type**: `Python`
   - **Extension file**: select `JwtAnalyzer.py`
4. Click **Next/OK**.
5. In the **Output** tab for this extension you should see:

   ```text
   [+] JWT Analyzer + Misconfig Scanner loaded

Usage
1. JWT Analyzer Tab


Intercept or send a request that contains a JWT:


e.g., a request with
Authorization: Bearer eyJ...




Select the request in Proxy, Repeater, or Target.


In the Request editor panel, click the “JWT Analyzer” tab.


You will see:


=== JWT #1 ===, === JWT #2 ===, etc. for multiple tokens


[Decoded Header] – pretty-printed JSON (or raw text)


[Decoded Payload] – pretty-printed JSON (or raw text)


[Analysis / Potential Misconfigurations] – bullet list of findings




If no tokens are present, the tab shows:

No JWT tokens detected.

2. Passive Scanner Issue
To generate and view issues:


Right-click the request (or response) containing a JWT.


Choose “Do passive scan”.


Go to:
Target -> Site map -> Issues


Look for:

JWT Misconfiguration / Weak Claims



Open the issue to see:


Token snippet


Decoded header/payload


List of misconfig bullets


Severity (High / Medium / Information)



Configuration
At the top of JwtAnalyzer.py there are simple configuration variables:
# Expected algorithms for your environment
EXPECTED_ALGS = ["RS256", "ES256"]

# How long is "too long" for exp, in seconds (30 days here)
LONG_EXP_THRESHOLD_SECONDS = 60 * 60 * 24 * 30

You can change these to match your environment:


Example for a stricter backend:
EXPECTED_ALGS = ["RS256"]
LONG_EXP_THRESHOLD_SECONDS = 60 * 15  # 15 minutes




Example Test Requests
You can test the extension quickly using Burp Repeater against a local HTTP server (python -m http.server 5000):
GET /api/profile HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: Burp
Accept: */*
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMiLCJuYW1lIjoiRGVtbyBVc2VyIiwicm9sZSI6ImFkbWluIn0.x
Connection: close

This token should trigger:


alg='none' misconfiguration (High severity)


Missing exp, iat, iss, aud


Role claim warning



Limitations


This extension does not verify signatures or keys.


It is static analysis only on the token structure and claims.




JWT detection is based on a regex and may:


Miss non-standard encodings


Occasionally pick up JWT-like strings that are not used as auth tokens




Always validate results and combine with deeper testing and source review where possible.

Roadmap / Ideas
Possible future improvements:


GUI-based configuration (edit expected algs and max TTL from Burp UI)


Signature verification against a provided JWK set


Support for more JWT-like token formats


Export decoded tokens/misconfigs as a report



License
This project is licensed under the MIT License (or whatever you choose).

Author
Your Name Here


Security / Application Security / AppSec Engineer


Feel free to open issues or PRs for feature requests and bug reports.



You can swap in your real name, tweak the examples, and adjust the config/roadmap sections however you like.
::contentReference[oaicite:0]{index=0}
