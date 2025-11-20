# JwtAnalyzer.py
#
# Burp Suite extension: JWT Analyzer + Misconfig Scanner
#
# Features:
#  - Detects JWTs in requests/responses
#  - Adds a "JWT Analyzer" tab showing decoded header & payload
#  - Performs simple misconfig checks and raises passive Scanner issues
#
# Requires: Jython (Burp Extender -> Options -> Python Environment)

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from burp import IScannerCheck, IScanIssue

from javax.swing import JPanel, JTextArea, JScrollPane, BorderFactory
from java.awt import BorderLayout

import re
import base64
import json
import sys
import traceback
import time

# Simple regex for JWT-looking tokens: header.payload.signature
JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*')

# Expected algorithms for your environment (edit to taste)
EXPECTED_ALGS = ["RS256", "ES256"]

# How long is "too long" for exp, in seconds (30 days here)
LONG_EXP_THRESHOLD_SECONDS = 60 * 60 * 24 * 30

# Python 2 / Jython compatibility for "long"
try:
    long
except NameError:
    long = int


def b64url_decode(segment):
    """Decode a base64url-encoded segment into bytes, handling missing padding."""
    if segment is None:
        return None
    try:
        # Jython 2.x has unicode built-in; guard in case of plain str
        if isinstance(segment, unicode):
            s = segment.encode("utf-8")
        else:
            s = segment
    except NameError:
        # Fallback if unicode is not defined (other runtimes)
        s = segment

    # Add padding if required
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        return None


def decode_jwt(token):
    """Decode a JWT token into (header_dict, payload_dict, raw_header, raw_payload)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None, None, None, None

        header_raw = b64url_decode(parts[0])
        payload_raw = b64url_decode(parts[1])

        if header_raw is None or payload_raw is None:
            return None, None, None, None

        try:
            header_json = header_raw.decode("utf-8")
        except Exception:
            header_json = str(header_raw)

        try:
            payload_json = payload_raw.decode("utf-8")
        except Exception:
            payload_json = str(payload_raw)

        header = None
        payload = None
        try:
            header = json.loads(header_json)
        except Exception:
            pass

        try:
            payload = json.loads(payload_json)
        except Exception:
            pass

        return header, payload, header_json, payload_json
    except Exception:
        return None, None, None, None


def analyze_misconfig(header, payload):
    """
    Return a list of human-readable misconfiguration messages
    based on JWT header/payload.
    """
    findings = []

    # ------------------
    # Header checks
    # ------------------
    if header is None:
        findings.append("Unable to parse JWT header as JSON.")
    else:
        alg = header.get("alg")
        typ = header.get("typ")

        if alg is None:
            findings.append("Missing 'alg' in JWT header.")
        else:
            alg_lower = str(alg).lower()
            if alg_lower == "none":
                findings.append("Token uses alg='none'. This usually indicates a critical misconfiguration.")
            elif alg_lower.startswith("hs"):
                findings.append(
                    "Token uses symmetric algorithm '%s'. Ensure shared secret is strong, "
                    "not reused, and stored securely." % alg
                )
            elif alg_lower.startswith("rs") or alg_lower.startswith("es"):
                findings.append(
                    "Token uses asymmetric algorithm '%s'. Verify key management, key rotation, "
                    "and signature validation are implemented correctly." % alg
                )

            # Expected algorithm list
            if EXPECTED_ALGS and alg not in EXPECTED_ALGS and alg_lower != "none":
                findings.append(
                    "Token algorithm '%s' does not match expected algorithms: %s."
                    % (alg, ", ".join(EXPECTED_ALGS))
                )

        if typ is None:
            findings.append("Missing 'typ' in JWT header. Consider explicitly setting 'typ': 'JWT'.")

        # kid (key id) is strongly recommended if you use key rotation
        if "kid" not in header:
            findings.append(
                "JWT header has no 'kid' (key id). If you use key rotation or multiple keys, "
                "include and validate a 'kid' claim."
            )

    # ------------------
    # Payload checks
    # ------------------
    if payload is None:
        findings.append("Unable to parse JWT payload as JSON.")
        return findings

    now = int(time.time())

    # exp (expiration)
    if "exp" not in payload:
        findings.append("JWT payload has no 'exp' claim (no explicit expiration).")
    else:
        exp_val = payload.get("exp")
        try:
            exp_int = int(exp_val)
            if exp_int < now:
                findings.append("JWT 'exp' claim appears to be in the past (token may be expired).")
            elif exp_int > now + LONG_EXP_THRESHOLD_SECONDS:
                findings.append(
                    "JWT 'exp' claim is far in the future (long-lived token). "
                    "Consider shorter token lifetimes."
                )
        except Exception:
            findings.append("JWT 'exp' claim is not a numeric timestamp; check implementation.")

    if "iat" not in payload:
        findings.append("JWT payload has no 'iat' claim (issued-at time).")
    if "iss" not in payload:
        findings.append("JWT payload has no 'iss' claim (issuer).")
    if "aud" not in payload:
        findings.append("JWT payload has no 'aud' claim (audience).")

    # Simple role / privilege hint
    for role_key in ["role", "roles", "scope", "scopes"]:
        if role_key in payload:
            findings.append(
                "Token contains '%s' claim: %s. Verify role/privilege enforcement and least privilege."
                % (role_key, payload[role_key])
            )
            break

    return findings


class JwtAnalyzerTab(IMessageEditorTab):
    """
    Custom Burp message editor tab that shows decoded JWTs and analysis.
    """

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable

        self._panel = JPanel(BorderLayout())
        self._text_area = JTextArea()
        self._text_area.setEditable(False)
        self._text_area.setLineWrap(True)
        self._text_area.setWrapStyleWord(True)

        scroll = JScrollPane(self._text_area)
        scroll.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        self._panel.add(scroll, BorderLayout.CENTER)

        self._current_message = None

    def getTabCaption(self):
        return "JWT Analyzer"

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        """
        Always show the tab; setMessage() will decide what to display.
        """
        return True

    def setMessage(self, content, isRequest):
        self._current_message = content
        if content is None:
            self._text_area.setText("")
            return

        try:
            message_str = self._helpers.bytesToString(content)
        except Exception:
            message_str = str(content)

        tokens = JWT_REGEX.findall(message_str)
        if not tokens:
            self._text_area.setText("No JWT tokens detected.")
            return

        output_lines = []
        for idx, token in enumerate(tokens):
            header, payload, header_raw, payload_raw = decode_jwt(token)

            output_lines.append("=== JWT #%d ===" % (idx + 1))
            output_lines.append("Raw token (truncated): %s..." % token[:80])

            output_lines.append("\n[Decoded Header]")
            if header_raw:
                output_lines.append(header_raw)
            else:
                output_lines.append("Unable to decode header.")

            output_lines.append("\n[Decoded Payload]")
            if payload_raw:
                output_lines.append(payload_raw)
            else:
                output_lines.append("Unable to decode payload.")

            # Misconfig analysis
            findings = analyze_misconfig(header, payload)
            if findings:
                output_lines.append("\n[Analysis / Potential Misconfigurations]")
                for f in findings:
                    output_lines.append(" - " + f)

            output_lines.append("\n")

        self._text_area.setText("\n".join(output_lines))
        self._text_area.setCaretPosition(0)

    def getMessage(self):
        # Read-only tab; do not modify the message.
        return self._current_message

    def isModified(self):
        return False

    def getSelectedData(self):
        return None


class CustomScanIssue(IScanIssue):
    """
    Simple implementation of IScanIssue for JWT misconfig findings.
    """

    def __init__(self, httpService, url, requestResponse, name, detail, severity="Information", confidence="Firm"):
        self._httpService = httpService
        self._url = url
        self._requestResponse = [requestResponse]
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        # Generic issue type. You can pick a more specific type ID if you want.
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return (
            "JSON Web Tokens (JWT) are often used for authentication and authorization. "
            "Misconfigurations in JWT usage can lead to serious security vulnerabilities, "
            "including token forgery and privilege escalation."
        )

    def getRemediationBackground(self):
        return (
            "Ensure that JWTs use strong algorithms, short-lived tokens, and proper claim validation "
            "(issuer, audience, expiration). Avoid alg='none' and weak secrets. "
            "Validate tokens server-side using trusted libraries and robust key management."
        )

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpService


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IScannerCheck):
    """
    Main Burp Extender class.
    """

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("JWT Analyzer + Misconfig Scanner")

        # Register custom tab
        callbacks.registerMessageEditorTabFactory(self)

        # Register passive scanner
        callbacks.registerScannerCheck(self)

        print("[+] JWT Analyzer + Misconfig Scanner loaded")

    # IMessageEditorTabFactory (newer Burp versions)
    def createNewInstance(self, controller, editable):
        return JwtAnalyzerTab(self, controller, editable)

    # Backwards compatibility with older Burp (harmless to keep both)
    def createNewMessageEditorTab(self, controller, editable):
        return JwtAnalyzerTab(self, controller, editable)

    # IScannerCheck methods

    def doPassiveScan(self, baseRequestResponse):
        """
        Look for JWTs in the request/response and raise issues
        when we detect suspicious configurations.
        """
        try:
            analyzedReq = self._helpers.analyzeRequest(baseRequestResponse)
            url = analyzedReq.getUrl()
            req_bytes = baseRequestResponse.getRequest()
            resp_bytes = baseRequestResponse.getResponse()

            issues = []

            # Scan request
            if req_bytes is not None:
                findings = self._scan_bytes_for_jwt(req_bytes, url, baseRequestResponse, is_request=True)
                if findings:
                    issues.extend(findings)

            # Scan response
            if resp_bytes is not None:
                findings = self._scan_bytes_for_jwt(resp_bytes, url, baseRequestResponse, is_request=False)
                if findings:
                    issues.extend(findings)

            if issues:
                return issues

            return None
        except Exception:
            traceback.print_exc(file=sys.stdout)
            return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # No active scanning for now.
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """
        Avoid duplicate issues: treat same URL + issue name as duplicate.
        Return:
          -1 to report both issues
           0 to keep existing and drop new
           1 to drop existing and keep new
        """
        if (
            existingIssue.getIssueName() == newIssue.getIssueName()
            and str(existingIssue.getUrl()) == str(newIssue.getUrl())
        ):
            return 0
        return -1

    def _scan_bytes_for_jwt(self, byte_data, url, baseRequestResponse, is_request):
        """
        Extract JWTs from raw bytes and create scan issues when misconfigs are found.
        """
        try:
            text = self._helpers.bytesToString(byte_data)
        except Exception:
            text = str(byte_data)

        tokens = JWT_REGEX.findall(text)
        if not tokens:
            return None

        all_findings_html = []
        severity = "Information"

        for token in tokens:
            header, payload, header_raw, payload_raw = decode_jwt(token)
            misconfigs = analyze_misconfig(header, payload)
            if not misconfigs:
                continue

            # Elevate severity if we see something really bad or risky
            for m in misconfigs:
                if "alg='none'" in m:
                    severity = "High"
                elif "long-lived token" in m and severity != "High":
                    severity = "Medium"

            # Build HTML detail snippet
            all_findings_html.append("<b>Token (truncated):</b> %s..." % token[:80])
            all_findings_html.append("<br><b>Decoded header:</b><br><pre>%s</pre>" % (header_raw or "N/A"))
            all_findings_html.append("<br><b>Decoded payload:</b><br><pre>%s</pre>" % (payload_raw or "N/A"))
            all_findings_html.append("<br><b>Detected issues:</b><ul>")
            for m in misconfigs:
                all_findings_html.append("<li>%s</li>" % m)
            all_findings_html.append("</ul><hr>")

        if not all_findings_html:
            return None

        location = "request" if is_request else "response"
        detail = (
            "<p>The extension detected one or more JWT tokens in the %s that exhibit "
            "potential misconfigurations:</p>%s" % (location, "".join(all_findings_html))
        )

        issue = CustomScanIssue(
            baseRequestResponse.getHttpService(),
            url,
            baseRequestResponse,
            "JWT Misconfiguration / Weak Claims",
            detail,
            severity=severity,
            confidence="Firm",
        )
        return [issue]
