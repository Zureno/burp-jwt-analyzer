# JWT Analyzer + Misconfig Scanner (Enhanced++)

`JwtAnalyzerPlus.py` is a Burp Suite extension (Jython) that makes working with JSON Web Tokens (JWTs) much more pleasant during web/API testing.

It:

- Detects JWTs in requests and responses
- Decodes and analyzes them for common misconfigurations
- Tracks token reuse across the entire project
- Surfaces everything in:
  - A **per-message “JWT Analyzer” tab**
  - A **suite-level “JWT Dashboard” tab**
- Raises **Burp Scanner issues** with human-friendly explanations and fix hints
- Adds **context-menu helpers** for quickly playing with tokens

> 💡 This extension is **passive by default**. The only “active” behavior is when you explicitly trigger menu items like “Forge alg=none token and send to Repeater”.

---

## Features

### 1. Message-level “JWT Analyzer” tab

When a request/response contains a JWT-looking string (`header.payload.signature`):

- A **“JWT Analyzer”** tab appears on that message.
- If multiple tokens are present, you can select **JWT #1 / #2 / …** from a combo box.
- For the selected token, the tab shows:

Left | Middle | Right
---- | ------ | -----
Decoded header JSON | Decoded payload JSON | Findings table

The findings table includes severity, title, and a short technical explanation.

---

### 2. Misconfiguration checks

For each token, the extension runs a set of checks and produces structured findings:

**Header checks**

- Missing `alg`
- `alg = "none"` (High)
- Symmetric algorithms (`HS256`, etc.) – informational/Medium notes
- Asymmetric algorithms (`RS256`, `ES256`, etc.) – informational notes
- Missing `typ`

**Payload / claim checks**

- Missing `exp`
- Expired tokens
- “Long-lived” tokens (`exp` far in the future, configurable threshold)
- Invalid `exp` / `nbf` formats (non-integer)
- `nbf` too far in the future
- Missing `iat`, `iss`, `aud` (each toggleable)
- Sensitive claim keys (`password`, `secret`, `ssn`, `credit_card`, etc.)
- Role / privilege-bearing claims (`role`, `roles`, `scope`, `scopes`)

Each finding includes:

- **ID** (e.g. `missing_exp`, `alg_none`)
- **Severity** (`Info`, `Low`, `Medium`, `High`)
- **Technical explanation**
- **Developer-friendly explanation**
- **Fix hint**

A per-token **aggregate severity** is calculated: `High > Medium > Low > Info`.

---

### 3. Token classification

The extension heuristically classifies tokens as:

- `id_token`
- `access_token`
- `refresh_token`
- `unknown`

Based on claims like `nonce`, `amr`, `scope`, `scp`, `typ`, `token_use`, etc.

The type is displayed:

- In the JWT Analyzer tab (`JWT #1 (High, type=access_token)`)
- In the JWT Dashboard table (with colored background per type)

---

### 4. Token reuse tracking & dashboard

Tokens are fingerprinted by **header + payload** (signature ignored), using SHA-256.

For each unique fingerprint, the extension tracks:

- First seen URL
- First seen location (e.g. `request-auth-header`, `response-json-body`, `response-set-cookie-header`, etc.)
- Last seen URL
- Last seen time
- Count (how many times this token appeared)
- Algorithm from header
- Type (id/access/refresh/unknown)
- Findings & severity
- The first/last HTTP messages (for quick jump to Repeater)

All of this shows up in the **“JWT Dashboard”** suite tab as a sortable table.

#### Summary section

At the top, the dashboard shows:

- Total tokens seen (including reuse)
- Unique tokens (fingerprints)
- By severity: `High / Medium / Low / Info`
- By type: `id / access / refresh / unknown`

#### Options section

- **Long-lived token threshold (days)** – controls when a token is flagged as “long-lived”.
- **Warn missing iat / iss / aud** – toggle noisy findings on/off.

These options directly influence the analysis logic used everywhere (Analyzer tab, Scanner issues, dashboard).

#### Table interactions

- Click column headers to **sort**.
- **Double-click** a row to open the **last-seen request** for that token in Repeater.
- Colored cells:
  - Type column: different background per token type
  - Severity column: red/orange/yellow/grey based on severity

#### Export

Buttons at the bottom:

- **Refresh** – re-builds the table and summary from in-memory token records.
- **Export JSON** – dumps all token records (header, payload, findings, metadata).
- **Export CSV** – CSV summary for easy reporting.

---

### 5. Burp Scanner issues

When JWT misconfigs are detected, the extension raises Burp Scanner issues:

- Issue name: **“JWT Misconfiguration / Weak Claims”**
- Severity: **aggregate severity** per token (High/Medium/Low/Info)
- Confidence: `Firm`
- Issue detail includes:
  - Where the token was found (`request-json-body`, `response-set-cookie-header`, etc.)
  - Token type and aggregate severity
  - Truncated raw token
  - Decoded header and payload (HTML-escaped)
  - Full list of findings (technical + developer explanation + fix hints)

You get a nice, ready-to-paste issue with both offensive and defensive context.

> 🔎 Scanning is **passive only**. The extension does **not** automatically send modified requests.

---

### 6. Context-menu helpers

When you right-click on a message that contains a JWT, the extension adds menu items:

- **JWT: Copy token to clipboard**
- **JWT: Copy header JSON**
- **JWT: Copy payload JSON**
- **JWT: Send token to Decoder**
- **JWT: Send request to Repeater with Authorization header**
  - Builds a new request with `Authorization: Bearer <token>` and sends it to Repeater.
- **JWT: Forge alg=none token and send to Repeater**
  - Modifies the header to `{"alg":"none"}` and blanks the signature.
  - Sends the forged request to Repeater as `JWT-alg-none`.
- **JWT: Highlight message in history**
  - Uses Burp’s highlight feature (yellow by default).

These are all manual actions (you choose when to use them).

---

## Requirements

- **Burp Suite** (Community or Professional)
- **Jython 2.7.x** standalone JAR  
  (tested with 2.7.3 / 2.7.4 style environments; Burp uses Jython 2, not Python 3)
- Java 8+ (whatever Burp itself runs on)

---

## Installation

1. **Configure Jython in Burp**

   - Go to: `Extender` → `Options` → **Python Environment**
   - Click **Select file…** and choose your `jython-standalone-2.7.x.jar`.

2. **Add the extension**

   - Go to: `Extender` → `Extensions`
   - Click **Add**
   - Type: `Python`
   - Extension file: `JwtAnalyzerPlus.py`
   - Click **Next / OK**  
     (watch the Extender output tab for `[+] JWT Analyzer + Misconfig Scanner (Enhanced++) loaded`)

3. **Verify tabs**

   - You should see a new **“JWT Dashboard”** tab at the top of Burp.
   - When you open an HTTP message containing a JWT, a **“JWT Analyzer”** tab should appear for that message.

---

## Usage

### Quick demo

You can use any JWT-bearing traffic, or spin up a simple test server. For example:

1. Start a local server that issues JWTs (Flask, Node, whatever).
2. Configure your browser or `curl` to go through Burp.
3. Hit an endpoint that returns a JWT, e.g.:

   ```bash
   curl -x http://127.0.0.1:8080 \
        -X POST http://127.0.0.1:5000/oauth/token \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "grant_type=password&username=alice@example.com&password=SuperSecret123!&scope=orders:read payments:write openid offline_access"
4. **In Burp**

   - Look at the Proxy → HTTP history entry.
   - Select the message; you should see JWT Analyzer appear as a tab.
   - The token should also show up in the JWT Dashboard after a scan (or when you click Refresh).

5. **Tuning analysis**

   In the JWT Dashboard:
   - Adjust “Long-lived token threshold (days)” to match your environment.
   - Toggle Warn missing iat / iss / aud if noise is too high for certain APIs.
   
   These settings are applied globally to:
   - JWT Analyzer tab
   - Dashboard
   - Scanner issues
     
6. **Implementation notes / architecture**
  BurpExtender
  -  Implements IBurpExtender, IMessageEditorTabFactory, IScannerCheck, ITab, IContextMenuFactory
  Registers:
  -  Message editor tab factory (JWT Analyzer tab)
  -  Passive scanner
  -  Suite tab (JWT Dashboard)
  -  Context menu factory
  Holds global config and token records (_token_by_fingerprint)
  JwtAnalyzerTab
  -  Per-message UI: header/payload/findings.
  -  Uses regex to find all JWT-looking strings in the message.
  JwtDashboardPanel
  - Suite-level dashboard:
    - Summary labels
    - Options panel
    - Token table
    - Export buttons
  - Handles double-click to Repeater.
  TokenRecord
  - In-memory representation of a unique token fingerprint.
  CustomScanIssue
  - Burp IScanIssue implementation for JWT misconfig findings.
7. **Performance considerations**

  Only the first 500,000 bytes (MAX_SCAN_BYTES) of a request/response are scanned to avoid lag on very large bodies.
  Fingerprinting ignores signatures (header+payload only) so the same logical token with different signatures still maps to one record.
8. **Limitations / future ideas**
   Analysis is heuristic; it doesn’t verify signatures or keys.
   No automatic active scanning (beyond manual Repeater helpers).
   Could be extended with:
    - JWK / JWKS parsing and validation
    - ID-swap/BOLA helpers
    - Better mapping of tokens to users/tenants across a test

