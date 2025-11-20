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

- **`alg`**
  - Flags **`alg = "none"`** as a critical misconfiguration  
  - Notes when symmetric algorithms are used (e.g., `HS256`)  
  - Notes when asymmetric algorithms are used (e.g., `RS256`, `ES256`)  
  - Warns if the algorithm is **not in the expected list** (`EXPECTED_ALGS`)
- **`typ`**
  - Warns if `typ` is missing (recommends `typ: "JWT"`)
- **`kid`**
  - Warns if `kid` is missing (important for key-rotation scenarios)

#### Payload checks

- **`exp`**
  - Warns if **missing** (`no explicit expiration`)  
  - Warns if `exp` appears **expired** (in the past)  
  - Warns if `exp` appears **too far in the future** (long-lived token)  
  - Warns if `exp` is **not numeric**
- **`iat`**
  - Warns if missing (`issued-at` time)
- **`iss`**
  - Warns if missing (`issuer`)
- **`aud`**
  - Warns if missing (`audience`)
- **Role / privilege hints**
  - If `role`, `roles`, `scope`, or `scopes` is present, highlights it and suggests reviewing for least privilege.

---

### 🛡️ Passive Scanner Integration

Registers a passive Scanner check named:

> **`JWT Misconfiguration / Weak Claims`**

Severity is automatically adjusted based on findings:

- **High** – if `alg = "none"` is detected  
- **Medium** – if a long-lived token (`exp` far in the future) is detected (and nothing High)  
- **Information** – for lighter issues (missing claims, no `kid`, etc.)

The issue detail includes:

- Truncated token  
- Decoded header (JSON)  
- Decoded payload (JSON)  
- Bullet list of all detected misconfigurations  

---

## Requirements

- **Burp Suite** – Community or Professional  
- **Jython standalone JAR** – e.g., `jython-standalone-2.7.x.jar`

---

## Installation

### 1. Configure Jython in Burp

1. Download the **Jython standalone JAR** (2.7.x).
2. In Burp, go to:  
   `Extensions -> Options -> Python Environment`
3. Click **Select file…** and choose the `jython-standalone-2.7.x.jar` file.
4. Apply / OK.

### 2. Load the extension

1. Save `JwtAnalyzer.py` somewhere on disk.
2. In Burp, go to:  
   `Extensions -> Installed -> Add`
3. Set:
   - **Extension type**: `Python`
   - **Extension file**: select `JwtAnalyzer.py`
4. Click **Next / OK**.
5. In the **Output** tab for this extension you should see:

   ```text
   [+] JWT Analyzer + Misconfig Scanner loaded
