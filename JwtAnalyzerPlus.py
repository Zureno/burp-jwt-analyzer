# -*- coding: utf-8 -*-
# JwtAnalyzerPlus.py
#
# Burp Suite extension: JWT Analyzer + Misconfig Scanner (Enhanced++)
#
# Features:
#  - Detects JWTs in requests/responses
#  - Adds "JWT Analyzer" tab on messages with decoded header & payload and findings
#  - Performs richer misconfig checks with severity (Info/Low/Medium/High)
#  - Checks exp/nbf, long-lived tokens, missing critical claims, alg issues
#  - Classifies tokens (id_token / access_token / refresh_token / unknown) heuristically
#  - Tracks token reuse via fingerprint (header+payload)
#  - Adds a "JWT Dashboard" suite tab with:
#       * Stats: total tokens, unique tokens, by severity, by type
#       * Table of all tokens (host(s), URLs, alg, type, severity, reuse count, etc.)
#       * Filters by severity and token type
#       * Clear / reset, Export to JSON / CSV
#       * Double-click row → open last-seen request for that token in Repeater
#  - Context menu on messages:
#       * Copy token
#       * Copy header JSON / payload JSON
#       * Send token to Decoder
#       * Highlight message
#       * Forge alg=none token and send to Repeater
#  - Raises Burp Scanner issues with technical detail + dev-friendly explanation + fix hints
#  - Simple settings panel for:
#       * Long-lived token threshold (days)
#       * Toggle warnings for missing iat / iss / aud
#
# Requires:
#  - Jython standalone JAR (e.g., 2.7.3) configured in Burp:
#      Extender -> Options -> Python Environment

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from burp import IScannerCheck, IScanIssue, ITab
from burp import IContextMenuFactory
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit

from javax.swing import (
    JPanel, JTextArea, JScrollPane, BorderFactory, JLabel, JTable,
    JButton, BoxLayout, Box, JFileChooser, JOptionPane, JComboBox,
    JMenuItem, JSplitPane, JCheckBox, JTextField
)

from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.event import ChangeListener

from java.awt import BorderLayout, Color
from java.awt.event import MouseAdapter, ActionListener, ItemListener, ItemEvent
from java.io import FileWriter
from java.util import Date

import re
import base64
import json
import sys
import traceback
import time
import hashlib

try:
    basestring
except NameError:
    basestring = str

# Simple regex for JWT-looking tokens: header.payload.signature
JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*')

# Max bytes per message to scan (performance guard)
MAX_SCAN_BYTES = 500000

# ------------------------------------------------------------------------------
# Utility / decoding helpers
# ------------------------------------------------------------------------------

def b64url_decode(segment):
    """Decode a base64url-encoded segment into bytes, handling missing padding."""
    if segment is None:
        return None
    # Jython 2.x: unicode vs str
    try:
        unicode_type = unicode
    except NameError:
        unicode_type = str
    s = segment.encode('utf-8') if isinstance(segment, unicode_type) else segment
    # Add padding if required
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += '=' * padding
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        return None


def b64url_encode(data):
    """Base64url-encode without '=' padding (for forging tokens)."""
    try:
        unicode_type = unicode
    except NameError:
        unicode_type = str
    if isinstance(data, unicode_type):
        data = data.encode('utf-8')
    encoded = base64.urlsafe_b64encode(data)
    return encoded.rstrip('=')


def decode_jwt(token):
    """Decode a JWT token into (header_dict, payload_dict, header_json, payload_json)."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, None, None

        header_raw = b64url_decode(parts[0])
        payload_raw = b64url_decode(parts[1])

        if header_raw is None or payload_raw is None:
            return None, None, None, None

        try:
            header_json = header_raw.decode('utf-8')
        except:
            header_json = str(header_raw)

        try:
            payload_json = payload_raw.decode('utf-8')
        except:
            payload_json = str(payload_raw)

        header = None
        payload = None
        try:
            header = json.loads(header_json)
        except:
            pass

        try:
            payload = json.loads(payload_json)
        except:
            pass

        return header, payload, header_json, payload_json
    except Exception:
        return None, None, None, None


def fingerprint_token(header_json, payload_json):
    """
    Stable fingerprint for reuse tracking: hash of header+payload (ignore signature).
    """
    try:
        m = hashlib.sha256()
        m.update(header_json.encode('utf-8'))
        m.update('|SEP|')
        m.update(payload_json.encode('utf-8'))
        return m.hexdigest()
    except Exception:
        return None


def current_epoch():
    return int(time.time())


# ------------------------------------------------------------------------------
# Misconfig analysis and classification
# ------------------------------------------------------------------------------

try:
    basestring
except NameError:
    basestring = str

def classify_token(header, payload):
    """
    Heuristically classify token type: id_token / access_token / refresh_token / unknown.
    """
    if payload is None:
        return "unknown"

    # OIDC-ish patterns
    if payload.get('nonce') is not None or payload.get('amr') is not None:
        return "id_token"

    # Access-token-ish
    if payload.get('scope') is not None or payload.get('scp') is not None:
        return "access_token"

    # Refresh style markers (very heuristic)
    if payload.get('typ') == 'refresh' or payload.get('token_use') == 'refresh':
        return "refresh_token"

    # Some IdPs mark "token_use": "id" / "access"
    token_use = payload.get('token_use')
    if isinstance(token_use, basestring):
        val = token_use.lower()
        if val == 'id':
            return "id_token"
        if val == 'access':
            return "access_token"

    return "unknown"


def analyze_misconfig(header, payload, options=None):
    """
    Return a structured list of findings:

    Each finding:
      {
        "id": "missing_exp",
        "title": "Missing exp claim",
        "severity": "Medium",
        "technical": "...",
        "dev_explain": "...",
        "fix_hint": "..."
      }
    """

    findings = []

    # ---- runtime options (from extender) ----
    if options is None:
        options = {}

    warn_missing_iat = options.get("warn_missing_iat", True)
    warn_missing_iss = options.get("warn_missing_iss", True)
    warn_missing_aud = options.get("warn_missing_aud", True)
    long_lived_days = options.get("long_lived_threshold_days", 7)

    # normalise long_lived_days
    try:
        long_lived_days_int = int(long_lived_days)
        if long_lived_days_int <= 0:
            long_lived_seconds = None
        else:
            long_lived_seconds = long_lived_days_int * 24 * 3600
    except Exception:
        long_lived_days_int = 7
        long_lived_seconds = 7 * 24 * 3600

    # Helper to add a finding
    def add_finding(fid, title, severity, technical, dev_explain, fix_hint):
        findings.append({
            "id": fid,
            "title": title,
            "severity": severity,
            "technical": technical,
            "dev_explain": dev_explain,
            "fix_hint": fix_hint
        })

    # ---------- Header checks ----------
    if header is None:
        add_finding(
            "header_not_json",
            "Header not valid JSON",
            "Low",
            "JWT header could not be parsed as valid JSON.",
            "The JWT header should be a well-formed JSON object. If tools cannot parse it, "
            "it may indicate corruption or a custom/unsupported token format.",
            "Ensure the JWT header is encoded from a valid JSON object and base64url-encoded correctly."
        )
        # Without header, we cannot do much more
        return findings

    alg = header.get('alg')
    typ = header.get('typ')

    if alg is None:
        add_finding(
            "missing_alg",
            "Missing alg in header",
            "Medium",
            "The JWT header does not include an 'alg' field, so it is unclear how the token is expected to be verified.",
            "Without an 'alg' claim, implementations may fall back to insecure defaults or fail open.",
            "Explicitly set 'alg' in the header to the intended algorithm and ensure server-side verification enforces it."
        )
    else:
        alg_lower = str(alg).lower()
        if alg_lower == 'none':
            add_finding(
                "alg_none",
                "Token uses alg='none'",
                "High",
                "The JWT header specifies alg='none', which means no signature verification.",
                "If the backend accepts alg='none', attackers can forge arbitrary tokens without knowing any key.",
                "Ensure your JWT library is configured to reject alg='none', and only allow strong algorithms such as RS256/ES256."
            )
        elif alg_lower.startswith('hs'):
            add_finding(
                "symmetric_alg",
                "Token uses symmetric algorithm '%s'" % alg,
                "Medium",
                "The token uses a symmetric HMAC algorithm (e.g., HS256). Symmetric keys must be kept secret and can be abused if leaked.",
                "If many services share the same secret, compromise of one service can allow forging tokens for others.",
                "Use strong, random secrets for HS* algorithms, rotate them regularly, and consider moving to asymmetric algorithms where appropriate."
            )
        elif alg_lower.startswith('rs') or alg_lower.startswith('es'):
            add_finding(
                "asymmetric_alg",
                "Token uses asymmetric algorithm '%s'" % alg,
                "Info",
                "The token uses an asymmetric algorithm (e.g., RS256/ES256). This is generally good practice when implemented correctly.",
                "Public-key-based JWTs are safer for multi-service environments, but misconfigurations (like using the public key as HMAC secret) are still possible.",
                "Ensure that verification strictly enforces the expected algorithm, and that keys are managed securely (rotate keys, pin JWKS, etc.)."
            )

    if typ is None:
        add_finding(
            "missing_typ",
            "Missing typ in header",
            "Low",
            "The JWT header does not include a 'typ' field.",
            "The 'typ' header is optional but can help tooling distinguish JWTs from other tokens.",
            "Consider setting 'typ': 'JWT' in the header for clarity and interoperability."
        )

    # ---------- Payload checks ----------
    if payload is None:
        add_finding(
            "payload_not_json",
            "Payload not valid JSON",
            "Low",
            "JWT payload could not be parsed as valid JSON.",
            "Many libraries expect the payload to be JSON; non-JSON payloads can break assumptions or tooling.",
            "Ensure the JWT payload is a valid JSON object and base64url-encoded correctly."
        )
        return findings

    now = current_epoch()
    exp = payload.get('exp')
    nbf = payload.get('nbf')
    iat = payload.get('iat')
    iss = payload.get('iss')
    aud = payload.get('aud')

    # ----- exp -----
    if exp is None:
        add_finding(
            "missing_exp",
            "Missing exp claim",
            "Medium",
            "The JWT payload does not include an 'exp' (expiration) claim.",
            "If a token with no expiration ever leaks, it may remain valid indefinitely.",
            "Include an 'exp' claim and configure the backend to reject tokens after that time. Keep token lifetimes as short as practical."
        )
    else:
        try:
            exp_int = int(exp)
            if exp_int < now:
                add_finding(
                    "expired_token",
                    "Token is expired",
                    "Medium",
                    "The 'exp' claim (%d) is in the past relative to current time (%d)." % (exp_int, now),
                    "Expired tokens should not be accepted. If they are still working in practice, that is a serious configuration issue.",
                    "Ensure that your JWT verification code rejects tokens whose 'exp' is in the past."
                )
            # Long-lived token heuristic based on options
            if long_lived_seconds and exp_int - now > long_lived_seconds:
                add_finding(
                    "long_lived_token",
                    "Long-lived token (>%d days)" % long_lived_days_int,
                    "Low",
                    "The token's 'exp' is more than %d days in the future." % long_lived_days_int,
                    "Long-lived tokens increase risk: if leaked, an attacker can use them for a long time.",
                    "Consider shortening token lifetimes and using refresh tokens or re-auth flows instead of very long-lived access tokens."
                )
        except Exception:
            add_finding(
                "exp_not_int",
                "exp claim not an integer",
                "Low",
                "The 'exp' claim could not be parsed as an integer UNIX timestamp.",
                "Incorrect 'exp' format can cause inconsistent verification across libraries.",
                "Ensure 'exp' is encoded as an integer UNIX timestamp (seconds since epoch)."
            )

    # ----- nbf -----
    if nbf is not None:
        try:
            nbf_int = int(nbf)
            if nbf_int > now + 300:
                add_finding(
                    "nbf_far_future",
                    "nbf is far in the future",
                    "Low",
                    "The 'nbf' (not before) claim is significantly in the future relative to current time.",
                    "If servers do not respect 'nbf', they may accept tokens earlier than intended.",
                    "Verify that your JWT verification logic enforces 'nbf' as a lower bound and that clocks are reasonably in sync."
                )
        except Exception:
            add_finding(
                "nbf_not_int",
                "nbf claim not an integer",
                "Low",
                "The 'nbf' claim could not be parsed as an integer UNIX timestamp.",
                "Incorrect 'nbf' format can cause inconsistent behavior.",
                "Ensure 'nbf' is encoded as an integer UNIX timestamp (seconds since epoch)."
            )

    # ----- iat -----
    if iat is None and warn_missing_iat:
        add_finding(
            "missing_iat",
            "Missing iat claim",
            "Low",
            "The JWT does not include an 'iat' (issued-at) claim.",
            "Without 'iat', it is harder to reason about token age and replay.",
            "Consider including 'iat' so you can detect tokens that are unusually old or used for longer than expected."
        )

    # ----- iss / aud -----
    if iss is None and warn_missing_iss:
        add_finding(
            "missing_iss",
            "Missing iss claim",
            "Low",
            "The JWT does not include an 'iss' (issuer) claim.",
            "The 'iss' claim is commonly used to ensure tokens come from the expected identity provider.",
            "Include 'iss' and ensure the backend validates it against a known trusted issuer."
        )

    if aud is None and warn_missing_aud:
        add_finding(
            "missing_aud",
            "Missing aud claim",
            "Low",
            "The JWT does not include an 'aud' (audience) claim.",
            "The 'aud' claim helps ensure the token is only used by the intended service.",
            "Include 'aud' and validate it server-side to prevent token re-use across different services."
        )

    # ----- Sensitive claims -----
    sensitive_keys = ['password', 'passwd', 'secret', 'ssn', 'credit_card', 'card_number']
    for k in payload.keys():
        if k.lower() in sensitive_keys:
            add_finding(
                "sensitive_claim_%s" % k,
                "Sensitive data in claim '%s'" % k,
                "High",
                "The payload contains a claim '%s' that appears to hold sensitive information." % k,
                "Storing secrets or sensitive personal data inside JWTs is risky, especially if tokens are logged or exposed in URLs.",
                "Remove sensitive data from JWTs and store it in secure server-side storage instead. Use tokens as references, not containers for secrets."
            )
            break

    # ----- Role / privilege hints -----
    for role_key in ['role', 'roles', 'scope', 'scopes']:
        if role_key in payload:
            add_finding(
                "role_claim_%s" % role_key,
                "Privilege/role claim '%s' present" % role_key,
                "Info",
                "The token contains a '%s' claim: %s" % (role_key, payload[role_key]),
                "Privilege-bearing claims should be enforced carefully to prevent privilege escalation.",
                "Ensure that backend authorization checks are based on these claims and follow least-privilege principles."
            )
            break

    return findings

def aggregate_severity(findings):
    """
    Aggregate finding severities into a single severity for the token:
      High > Medium > Low > Info
    """
    highest = "Info"
    order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3}
    for f in findings:
        sev = f.get("severity", "Info")
        if order.get(sev, 0) > order.get(highest, 0):
            highest = sev
    return highest


# ------------------------------------------------------------------------------
# Data model for tracking tokens across traffic
# ------------------------------------------------------------------------------

class TokenRecord(object):
    def __init__(self, fingerprint, token, url, location, header_json, payload_json,
                 header, payload, findings, severity, token_type, baseRequestResponse, host):
        self.fingerprint = fingerprint
        self.token = token
        self.first_seen_url = url
        self.first_seen_location = location
        self.last_seen_url = url
        self.last_seen_time = Date()
        self.count = 1
        self.header_json = header_json
        self.payload_json = payload_json
        self.header = header
        self.payload = payload
        self.findings = findings
        self.severity = severity
        self.token_type = token_type

        # HTTP messages for Repeater jump
        self.first_rr = baseRequestResponse
        self.last_rr = baseRequestResponse

        # Host tracking
        self.first_seen_host = host
        self.last_seen_host = host

    def increment(self, url, baseRequestResponse=None, host=None):
        self.count += 1
        self.last_seen_url = url
        self.last_seen_time = Date()
        if baseRequestResponse is not None:
            self.last_rr = baseRequestResponse
        if host is not None:
            self.last_seen_host = host


# ------------------------------------------------------------------------------
# JWT Analyzer message tab (visual layout)
# ------------------------------------------------------------------------------

from java.awt import BorderLayout
from javax.swing.table import DefaultTableModel

class JwtAnalyzerTab(IMessageEditorTab):
    """
    Custom Burp message editor tab that shows decoded JWTs and analysis
    in a more visual way:
      - Combo box to pick JWT #1 / #2 / ...
      - Left: header JSON
      - Middle: payload JSON
      - Right: findings table
    """

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable

        # Store parsed tokens for current message
        self._tokens = []   # list of dicts
        self._current_message = None
        self._has_jwt = False

        # ---------------- UI LAYOUT ----------------
        self._panel = JPanel(BorderLayout())

        # Top: selector for which JWT in the message
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.X_AXIS))
        self._combo = JComboBox()
        top_panel.add(JLabel("Select JWT: "))
        top_panel.add(self._combo)

        # Left / middle / right areas
        self._header_area = JTextArea()
        self._header_area.setEditable(False)
        self._header_area.setLineWrap(True)
        self._header_area.setWrapStyleWord(True)

        self._payload_area = JTextArea()
        self._payload_area.setEditable(False)
        self._payload_area.setLineWrap(True)
        self._payload_area.setWrapStyleWord(True)

        # Findings table
        findings_cols = ["Severity", "Title", "Short explanation"]
        self._findings_model = DefaultTableModel(findings_cols, 0)
        self._findings_table = JTable(self._findings_model)

        # Scroll panes
        header_scroll = JScrollPane(self._header_area)
        header_scroll.setBorder(BorderFactory.createTitledBorder("Decoded Header"))

        payload_scroll = JScrollPane(self._payload_area)
        payload_scroll.setBorder(BorderFactory.createTitledBorder("Decoded Payload"))

        findings_scroll = JScrollPane(self._findings_table)
        findings_scroll.setBorder(BorderFactory.createTitledBorder("Findings"))

        # Split panes: [Header | Payload | Findings]
        split_left = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, header_scroll, payload_scroll)
        split_left.setResizeWeight(0.5)

        split_all = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, split_left, findings_scroll)
        split_all.setResizeWeight(0.66)

        self._panel.add(top_panel, BorderLayout.NORTH)
        self._panel.add(split_all, BorderLayout.CENTER)

        # Wire combo box change -> show selected token
        class _TokenSelectorListener(ActionListener):
            def __init__(self, outer):
                self._outer = outer

            def actionPerformed(self, event):
                idx = self._outer._combo.getSelectedIndex()
                self._outer._show_token(idx)

        self._combo.addActionListener(_TokenSelectorListener(self))

    # IMessageEditorTab methods -------------------------------------------------

    def getTabCaption(self):
        return "JWT Analyzer"

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        """
        Activated when a JWT-looking string is present in the message.
        """
        if content is None:
            self._has_jwt = False
            return False

        try:
            message_str = self._helpers.bytesToString(content)
        except:
            message_str = str(content)

        match = JWT_REGEX.search(message_str)
        self._has_jwt = match is not None
        return self._has_jwt

    def setMessage(self, content, isRequest):
        self._current_message = content
        self._tokens = []

        # Clear UI if nothing to show
        if content is None or not self._has_jwt:
            self._combo.removeAllItems()
            self._header_area.setText("")
            self._payload_area.setText("")
            self._findings_model.setRowCount(0)
            return

        try:
            message_str = self._helpers.bytesToString(content)
        except:
            message_str = str(content)

        tokens = JWT_REGEX.findall(message_str)
        if not tokens:
            self._combo.removeAllItems()
            self._header_area.setText("No JWT tokens detected.")
            self._payload_area.setText("")
            self._findings_model.setRowCount(0)
            return

        # Parse all tokens and populate internal list
        self._combo.removeAllItems()
        for idx, token in enumerate(tokens):
            header, payload, header_raw, payload_raw = decode_jwt(token)
            options = self._extender.getAnalysisOptions()
            findings = analyze_misconfig(header, payload, options)
            severity = aggregate_severity(findings)
            token_type = classify_token(header, payload)

            # Save structured info
            self._tokens.append({
                "token": token,
                "header_json": header_raw,
                "payload_json": payload_raw,
                "header": header,
                "payload": payload,
                "findings": findings,
                "severity": severity,
                "type": token_type,
            })

            label = "JWT #%d  (%s, type=%s)" % (idx + 1, severity, token_type)
            self._combo.addItem(label)

        # Show first token by default
        if self._tokens:
            self._combo.setSelectedIndex(0)
            self._show_token(0)

    def _show_token(self, index):
        """
        Update text areas + findings table based on selected token index.
        """
        if index < 0 or index >= len(self._tokens):
            return

        t = self._tokens[index]

        header_raw = t["header_json"] or "Unable to decode header."
        payload_raw = t["payload_json"] or "Unable to decode payload."
        findings = t["findings"]

        self._header_area.setText(header_raw)
        self._header_area.setCaretPosition(0)

        self._payload_area.setText(payload_raw)
        self._payload_area.setCaretPosition(0)

        # Fill findings table
        self._findings_model.setRowCount(0)
        if findings:
            for f in findings:
                short = f.get("technical", "")
                # keep it short-ish
                if len(short) > 140:
                    short = short[:137] + "..."
                row = [f.get("severity", "Info"), f.get("title", ""), short]
                self._findings_model.addRow(row)

    def getMessage(self):
        # Read-only tab; do not modify the message.
        return self._current_message

    def isModified(self):
        return False

    def getSelectedData(self):
        return None
    
# ------------------------------------------------------------------------------
# Burp Scanner Issue
# ------------------------------------------------------------------------------

class CustomScanIssue(IScanIssue):
    """
    Implementation of IScanIssue for JWT misconfig findings.
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
        return ("JSON Web Tokens (JWT) are often used for authentication and authorization. "
                "Misconfigurations in JWT usage can lead to serious security vulnerabilities, "
                "including token forgery, replay, and privilege escalation.")

    def getRemediationBackground(self):
        return ("Ensure that JWTs use strong algorithms, short-lived tokens, and proper claim validation "
                "(issuer, audience, expiration). Avoid alg='none' and weak secrets. "
                "Validate tokens server-side using trusted libraries, enforce strict verification options, "
                "and treat JWTs as bearer tokens that must be protected in transit and storage.")

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpService

class TokenTypeRenderer(DefaultTableCellRenderer):
    """
    Color the 'Type' column based on token_type:
      id_token      -> light blue
      access_token  -> light green
      refresh_token -> light yellow
      unknown       -> light gray
    """

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )

        text = (str(value) if value is not None else "").lower()

        if not isSelected:
            if text == "id_token":
                comp.setBackground(Color(204, 229, 255))      # light blue
            elif text == "access_token":
                comp.setBackground(Color(204, 255, 204))      # light green
            elif text == "refresh_token":
                comp.setBackground(Color(255, 242, 204))      # light yellow
            else:
                comp.setBackground(Color(230, 230, 230))      # light gray
        return comp
    
# ------------------------------------------------------------------------------
# Suite tab (Dashboard / Tokens / Export)
# ------------------------------------------------------------------------------

class JwtDashboardPanel(JPanel):
    def __init__(self, extender):
        JPanel.__init__(self, BorderLayout())
        self._extender = extender

        # ---------- TOP CONTAINER (summary + options) ----------
        top_container = JPanel()
        top_container.setLayout(BoxLayout(top_container, BoxLayout.Y_AXIS))

        # ----- Summary panel -----
        summary_panel = JPanel()
        summary_panel.setLayout(BoxLayout(summary_panel, BoxLayout.Y_AXIS))
        summary_panel.setBorder(BorderFactory.createTitledBorder("Summary"))

        self._label_total = JLabel("Total tokens seen (including reuse): 0")
        self._label_unique = JLabel("Unique tokens (fingerprints): 0")
        self._label_severity = JLabel("By severity: High=0, Medium=0, Low=0, Info=0")
        self._label_types = JLabel("By type: id=0, access=0, refresh=0, unknown=0")

        summary_panel.add(self._label_total)
        summary_panel.add(self._label_unique)
        summary_panel.add(self._label_severity)
        summary_panel.add(self._label_types)

        # ----- Options / filters panel -----

        options_panel = JPanel()
        options_panel.setLayout(BoxLayout(options_panel, BoxLayout.X_AXIS))
        options_panel.setBorder(BorderFactory.createTitledBorder("Options"))

        # Long-lived threshold (now wired)
        options_panel.add(JLabel("Long-lived token threshold (days): "))
        self._threshold_field = JTextField(str(self._extender._long_lived_days), 4)
        options_panel.add(self._threshold_field)
        options_panel.add(Box.createHorizontalStrut(20))

        # Checkboxes for noisy "missing" claims (wired)
        self._chk_missing_iat = JCheckBox("Warn missing iat", self._extender._warn_missing_iat)
        self._chk_missing_iss = JCheckBox("Warn missing iss", self._extender._warn_missing_iss)
        self._chk_missing_aud = JCheckBox("Warn missing aud", self._extender._warn_missing_aud)

        options_panel.add(self._chk_missing_iat)
        options_panel.add(Box.createHorizontalStrut(10))
        options_panel.add(self._chk_missing_iss)
        options_panel.add(Box.createHorizontalStrut(10))
        options_panel.add(self._chk_missing_aud)
        options_panel.add(Box.createHorizontalGlue())

        header_panel = JPanel(BorderLayout())
        header_panel.add(options_panel, BorderLayout.CENTER)
        header_panel.add(summary_panel, BorderLayout.EAST)
        top_container.add(header_panel)
        
        # --- wire options -> extender ---
        class ThresholdActionListener(ActionListener):
            def __init__(self, outer):
                self._outer = outer
            def actionPerformed(self, event):
                self._outer._update_threshold_from_field()

        self._threshold_field.addActionListener(ThresholdActionListener(self))

        class ToggleListener(ItemListener):
            def __init__(self, outer, which):
                self._outer = outer
                self._which = which
            def itemStateChanged(self, event):
                selected = (event.getStateChange() == ItemEvent.SELECTED)
                if self._which == "iat":
                    self._outer._extender.setWarnMissingIat(selected)
                elif self._which == "iss":
                    self._outer._extender.setWarnMissingIss(selected)
                elif self._which == "aud":
                    self._outer._extender.setWarnMissingAud(selected)


        self._chk_missing_iat.addItemListener(ToggleListener(self, "iat"))
        self._chk_missing_iss.addItemListener(ToggleListener(self, "iss"))
        self._chk_missing_aud.addItemListener(ToggleListener(self, "aud"))

        # ---------- Table ----------
        columns = [
            "Fingerprint",
            "Type",
            "Severity",
            "Count",
            "First Seen URL",
            "First Seen Location",
            "Last Seen URL",
            "Last Seen Time",
            "Alg",
        ]
        self._table_model = DefaultTableModel(columns, 0)
        self._table = JTable(self._table_model)
        self._table.setFillsViewportHeight(True)
        self._table.setAutoCreateRowSorter(True)  # click headers to sort
        self._table.setRowHeight(20)

        # ----- mouse: double-click row -> send last request to Repeater -----
        class TableMouseListener(MouseAdapter):
            def __init__(self, outer):
                self._outer = outer
            def mouseClicked(self, event):
                if event.getClickCount() == 2:
                    table = event.getSource()
                    view_row = table.getSelectedRow()
                    if view_row < 0:
                        return
                    model_row = table.convertRowIndexToModel(view_row)
                    fp = self._outer._table_model.getValueAt(model_row, 0)
                    if fp:
                        self._outer._extender.openMessageForFingerprint(fp)

        self._table.addMouseListener(TableMouseListener(self))

        # ----- visual renderers -----
        class SeverityCellRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                c = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, table, value, isSelected, hasFocus, row, column
                )
                if not isSelected:
                    if value == "High":
                        c.setBackground(Color(255, 204, 204))   # red-ish
                    elif value == "Medium":
                        c.setBackground(Color(255, 229, 204))   # orange-ish
                    elif value == "Low":
                        c.setBackground(Color(255, 255, 204))   # yellow-ish
                    else:
                        c.setBackground(Color(240, 240, 240))   # grey
                c.setToolTipText("Aggregate severity for this token")
                return c

        class FingerprintCellRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                text = value
                full = value
                if value is not None and len(value) > 12:
                    text = value[:12] + "..."
                c = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, table, text, isSelected, hasFocus, row, column
                )
                if full is not None:
                    c.setToolTipText(full)
                return c

        class TokenTypeRendererWithTooltip(TokenTypeRenderer):
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                comp = TokenTypeRenderer.getTableCellRendererComponent(
                    self, table, value, isSelected, hasFocus, row, column
                )
                text = (str(value) if value is not None else "").lower()
                if text == "id_token":
                    comp.setToolTipText("ID token (OIDC style)")
                elif text == "access_token":
                    comp.setToolTipText("Access token (API access)")
                elif text == "refresh_token":
                    comp.setToolTipText("Refresh token")
                else:
                    comp.setToolTipText("Unknown token type")
                return comp

        # apply renderers
        self._table.getColumnModel().getColumn(0).setCellRenderer(FingerprintCellRenderer())
        self._table.getColumnModel().getColumn(1).setCellRenderer(TokenTypeRendererWithTooltip())
        self._table.getColumnModel().getColumn(2).setCellRenderer(SeverityCellRenderer())

        # optional column widths
        self._table.getColumnModel().getColumn(0).setPreferredWidth(120)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(80)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(80)
        self._table.getColumnModel().getColumn(3).setPreferredWidth(60)

        scroll = JScrollPane(self._table)
        # ---------- Buttons ----------
        button_panel = JPanel()
        button_panel.setLayout(BoxLayout(button_panel, BoxLayout.X_AXIS))

        btn_refresh = JButton("Refresh", actionPerformed=self.refresh)
        btn_export_json = JButton("Export JSON", actionPerformed=self.export_json)
        btn_export_csv = JButton("Export CSV", actionPerformed=self.export_csv)

        button_panel.add(btn_refresh)
        button_panel.add(Box.createHorizontalStrut(10))
        button_panel.add(btn_export_json)
        button_panel.add(Box.createHorizontalStrut(10))
        button_panel.add(btn_export_csv)
        button_panel.add(Box.createHorizontalGlue())

        # ---------- Layout ----------
        self.add(top_container, BorderLayout.NORTH)
        self.add(scroll, BorderLayout.CENTER)
        self.add(button_panel, BorderLayout.SOUTH)

    def _update_threshold_from_field(self):
        text = self._threshold_field.getText()
        if text is None:
            return
        text = text.strip()
        if not text:
            return
        try:
            days = int(text)
            if days <= 0:
                raise ValueError()
        except Exception:
            # reset UI to current extender value on bad input
            days = getattr(self._extender, "_long_lived_days", 7)
            self._threshold_field.setText(str(days))
            return
        self._extender.setLongLivedThreshold(days)

    # ---------- refresh/export ----------
    def refresh(self, event=None):
        self._table_model.setRowCount(0)

        total_tokens = 0
        unique_tokens = len(self._extender._token_by_fingerprint)
        sev_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        type_counts = {"id_token": 0, "access_token": 0, "refresh_token": 0, "unknown": 0}

        for fp, record in self._extender._token_by_fingerprint.items():
            total_tokens += record.count
            sev = record.severity if record.severity in sev_counts else "Info"
            sev_counts[sev] += 1

            ttype = record.token_type if record.token_type in type_counts else "unknown"
            type_counts[ttype] += 1

            alg = ""
            if record.header and isinstance(record.header, dict):
                alg = str(record.header.get("alg", ""))

            row = [
                fp,
                record.token_type,
                record.severity,
                record.count,
                str(record.first_seen_url),
                record.first_seen_location,
                str(record.last_seen_url),
                str(record.last_seen_time),
                alg,
            ]
            self._table_model.addRow(row)

        self._label_total.setText(
            "Total tokens seen (including reuse): %d" % total_tokens
        )
        self._label_unique.setText(
            "Unique tokens (fingerprints): %d" % unique_tokens
        )
        self._label_severity.setText(
            "By severity: High=%d, Medium=%d, Low=%d, Info=%d"
            % (
                sev_counts["High"],
                sev_counts["Medium"],
                sev_counts["Low"],
                sev_counts["Info"],
            )
        )
        self._label_types.setText(
            "By type: id=%d, access=%d, refresh=%d, unknown=%d"
            % (
                type_counts["id_token"],
                type_counts["access_token"],
                type_counts["refresh_token"],
                type_counts["unknown"],
            )
        )

    def export_json(self, event=None):
        chooser = JFileChooser()
        chooser.setDialogTitle("Export JWT Analysis as JSON")
        result = chooser.showSaveDialog(self)
        if result == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            path = file.getAbsolutePath()
            try:
                data = []
                for fp, record in self._extender._token_by_fingerprint.items():
                    entry = {
                        "fingerprint": fp,
                        "token_type": record.token_type,
                        "severity": record.severity,
                        "count": record.count,
                        "first_seen_url": str(record.first_seen_url),
                        "first_seen_location": record.first_seen_location,
                        "last_seen_url": str(record.last_seen_url),
                        "last_seen_time": str(record.last_seen_time),
                        "header": record.header,
                        "payload": record.payload,
                        "findings": record.findings,
                    }
                    data.append(entry)
                fw = FileWriter(path)
                fw.write(json.dumps(data, indent=2))
                fw.close()
                JOptionPane.showMessageDialog(
                    self,
                    "Exported %d token records to JSON." % len(data),
                )
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                JOptionPane.showMessageDialog(
                    self,
                    "Failed to export JSON: %s" % str(e),
                    "Error",
                    JOptionPane.ERROR_MESSAGE,
                )

    def export_csv(self, event=None):
        chooser = JFileChooser()
        chooser.setDialogTitle("Export JWT Analysis as CSV")
        result = chooser.showSaveDialog(self)
        if result == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            path = file.getAbsolutePath()
            try:
                fw = FileWriter(path)
                fw.write(
                    "fingerprint,token_type,severity,count,first_seen_url,"
                    "first_seen_location,last_seen_url,last_seen_time,alg\n"
                )
                for fp, record in self._extender._token_by_fingerprint.items():
                    alg = ""
                    if record.header and isinstance(record.header, dict):
                        alg = str(record.header.get("alg", ""))
                    line = '"%s","%s","%s",%d,"%s","%s","%s","%s","%s"\n' % (
                        fp.replace('"', "'"),
                        record.token_type.replace('"', "'"),
                        record.severity.replace('"', "'"),
                        record.count,
                        str(record.first_seen_url).replace('"', "'"),
                        record.first_seen_location.replace('"', "'"),
                        str(record.last_seen_url).replace('"', "'"),
                        str(record.last_seen_time).replace('"', "'"),
                        alg.replace('"', "'"),
                    )
                    fw.write(line)
                fw.close()
                JOptionPane.showMessageDialog(
                    self,
                    "Exported %d token records to CSV."
                    % len(self._extender._token_by_fingerprint),
                )
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                JOptionPane.showMessageDialog(
                    self,
                    "Failed to export CSV: %s" % str(e),
                    "Error",
                    JOptionPane.ERROR_MESSAGE,
                )

# ------------------------------------------------------------------------------
# Main Burp Extender
# ------------------------------------------------------------------------------

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IScannerCheck, ITab, IContextMenuFactory):
    """
    Main Burp Extender class.
    """

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("JWT Analyzer + Misconfig Scanner (Enhanced++)")

        # Storage for token records
        self._token_by_fingerprint = {}
        self._long_lived_days = 7
        self._warn_missing_iat = True
        self._warn_missing_iss = True
        self._warn_missing_aud = True

        # Register custom tab (per-message)
        callbacks.registerMessageEditorTabFactory(self)

        # Register passive scanner
        callbacks.registerScannerCheck(self)

        # Suite-level dashboard tab
        self._dashboard_panel = JwtDashboardPanel(self)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

        print("[+] JWT Analyzer + Misconfig Scanner (Enhanced++) loaded")
        sys.stdout.flush()

    # ITab
    def getTabCaption(self):
        return "JWT Dashboard"

    def getUiComponent(self):
        return self._dashboard_panel

    # IMessageEditorTabFactory
    def createNewInstance(self, controller, editable):
        return JwtAnalyzerTab(self, controller, editable)

    # IScannerCheck method
        # ---- analysis options helpers ----
    def getAnalysisOptions(self):
        return {
            "long_lived_threshold_days": getattr(self, "_long_lived_days", 7),
            "warn_missing_iat": getattr(self, "_warn_missing_iat", True),
            "warn_missing_iss": getattr(self, "_warn_missing_iss", True),
            "warn_missing_aud": getattr(self, "_warn_missing_aud", True),
        }

    def setLongLivedThreshold(self, days):
        try:
            d = int(days)
            if d <= 0:
                return
            self._long_lived_days = d
        except Exception:
            # ignore bad input
            pass

    def setWarnMissingIat(self, flag):
        self._warn_missing_iat = bool(flag)

    def setWarnMissingIss(self, flag):
        self._warn_missing_iss = bool(flag)

    def setWarnMissingAud(self, flag):
        self._warn_missing_aud = bool(flag)

    def doPassiveScan(self, baseRequestResponse):
        """
        Look for JWTs in the request/response and raise issues
        when we detect suspicious configurations.
        Also update token records for dashboard.
        """
        try:
            analyzedReq = self._helpers.analyzeRequest(baseRequestResponse)
            url = analyzedReq.getUrl()
            req_bytes = baseRequestResponse.getRequest()
            resp_bytes = baseRequestResponse.getResponse()

            issues = []

            # Apply performance guard
            if req_bytes is not None:
                scan_req_bytes = req_bytes if len(req_bytes) <= MAX_SCAN_BYTES else req_bytes[:MAX_SCAN_BYTES]
                findings_req = self._scan_bytes_for_jwt(scan_req_bytes, url, baseRequestResponse, is_request=True)
                if findings_req:
                    issues.extend(findings_req)

            if resp_bytes is not None:
                scan_resp_bytes = resp_bytes if len(resp_bytes) <= MAX_SCAN_BYTES else resp_bytes[:MAX_SCAN_BYTES]
                findings_resp = self._scan_bytes_for_jwt(scan_resp_bytes, url, baseRequestResponse, is_request=False)
                if findings_resp:
                    issues.extend(findings_resp)

            if issues:
                # Refresh dashboard summary lazily
                self._dashboard_panel.refresh()
                return issues

            return None
        except Exception:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # No active scanning for now.
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """
        Avoid duplicate issues: treat same URL + issue name as duplicate.
        """
        if (existingIssue.getIssueName() == newIssue.getIssueName()
                and str(existingIssue.getUrl()) == str(newIssue.getUrl())):
            return 0
        return -1

    def _scan_bytes_for_jwt(self, byte_data, url, baseRequestResponse, is_request):
        """
        Extract JWTs from raw bytes and create scan issues when misconfigs are found.
        Also record tokens for dashboard.
        """
        try:
            text = self._helpers.bytesToString(byte_data)
        except:
            text = str(byte_data)

        tokens = JWT_REGEX.findall(text)
        if not tokens:
            return None

        issues = []

        msg_info = None
        headers = []
        body_text = text
        body_offset = 0

        try:
            if is_request:
                msg_info = self._helpers.analyzeRequest(byte_data)
            else:
                msg_info = self._helpers.analyzeResponse(byte_data)
        except Exception:
            msg_info = None

        if msg_info is not None:
            headers = list(msg_info.getHeaders())
            body_offset = msg_info.getBodyOffset()
            body_text = text[body_offset:]

        for token in tokens:
            header, payload, header_raw, payload_raw = decode_jwt(token)
            if not header_raw or not payload_raw:
                findings = []
            else:
                options = self.getAnalysisOptions()
                findings = analyze_misconfig(header, payload, options)

            severity = aggregate_severity(findings)
            token_type = classify_token(header, payload)
            fingerprint = fingerprint_token(header_raw or "", payload_raw or "")
            location = "request" if is_request else "response"

            # Smarter location classification
            location_detail = location
            try:
                if msg_info is not None:
                    found_in_header = False
                    for h in headers:
                        if token in h:
                            hl = h.lower()
                            if is_request and hl.startswith("authorization:"):
                                location_detail = "request-auth-header"
                            elif is_request and hl.startswith("cookie:"):
                                location_detail = "request-cookie-header"
                            elif (not is_request) and hl.startswith("set-cookie:"):
                                location_detail = "response-set-cookie-header"
                            else:
                                location_detail = "request-header" if is_request else "response-header"
                            found_in_header = True
                            break

                    if not found_in_header:
                        if is_request and token in str(url):
                            location_detail = "request-url"
                        elif token in body_text:
                            ctype = ""
                            for h in headers:
                                hl = h.lower()
                                if hl.startswith("content-type:"):
                                    ctype = hl
                                    break
                            if "application/json" in ctype:
                                location_detail = "request-json-body" if is_request else "response-json-body"
                            elif "application/x-www-form-urlencoded" in ctype:
                                location_detail = "request-form-body"
                            else:
                                location_detail = "request-body" if is_request else "response-body"
            except Exception:
                pass

            # Record in our dashboard maps
            host = None
            try:
                host = url.getHost()
            except Exception:
                host = None

            self._record_token(
                fingerprint, token, url, location_detail,
                header_raw or "", payload_raw or "",
                header, payload, findings, severity, token_type,
                baseRequestResponse, host
            )

            if findings:
                # Build HTML detail snippet
                detail_lines = []

                detail_lines.append("<p>The extension detected a JWT in the %s with the following properties and findings:</p>" %
                                    location_detail)
                detail_lines.append("<p><b>Token type (heuristic):</b> %s<br>"
                                    "<b>Aggregate severity:</b> %s</p>" % (token_type, severity))

                detail_lines.append("<p><b>Raw token (truncated):</b> %s...</p>" % token[:80])

                detail_lines.append("<h4>Decoded header</h4>")
                detail_lines.append("<pre>%s</pre>" % self._escape_html(header_raw or "N/A"))

                detail_lines.append("<h4>Decoded payload</h4>")
                detail_lines.append("<pre>%s</pre>" % self._escape_html(payload_raw or "N/A"))

                detail_lines.append("<h4>Findings</h4>")
                if findings:
                    detail_lines.append("<ul>")
                    for f in findings:
                        detail_lines.append("<li><b>[%s] %s</b><br>" % (f["severity"], f["title"]))
                        detail_lines.append("Technical: %s<br>" % self._escape_html(f["technical"]))
                        detail_lines.append("For developers: %s<br>" % self._escape_html(f["dev_explain"]))
                        detail_lines.append("Fix hint: %s</li>" % self._escape_html(f["fix_hint"]))
                    detail_lines.append("</ul>")
                else:
                    detail_lines.append("<p>No obvious misconfigurations detected based on current checks.</p>")

                detail = "\n".join(detail_lines)

                issue = CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    url,
                    baseRequestResponse,
                    "JWT Misconfiguration / Weak Claims",
                    detail,
                    severity=severity,
                    confidence="Firm"
                )
                issues.append(issue)

        return issues or None

    def _record_token(self, fingerprint, token, url, location,
                  header_json, payload_json, header, payload,
                  findings, severity, token_type, baseRequestResponse, host=None):
        """
        Store token information for reuse tracking and dashboard.
        """
        if not fingerprint:
            # Cannot track without fingerprint; just skip dashboard tracking.
            return

        if host is None:
            try:
                host = url.getHost()
            except Exception:
                host = None

        existing = self._token_by_fingerprint.get(fingerprint)
        if existing is None:
            rec = TokenRecord(
                fingerprint, token, url, location,
                header_json, payload_json, header, payload,
                findings, severity, token_type, baseRequestResponse, host
            )
            self._token_by_fingerprint[fingerprint] = rec
        else:
            existing.increment(url, baseRequestResponse, host)
            # Optionally update severity if new higher severity found
            new_sev = aggregate_severity(findings) if findings else existing.severity
            order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3}
            if order.get(new_sev, 0) > order.get(existing.severity, 0):
                existing.severity = new_sev


    def _escape_html(self, s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    def _extract_first_jwt_from_message(self, message):
        """
        Look for the first JWT in the request, then response.
        Returns the token string or None.
        """
        try:
            req = message.getRequest()
            resp = message.getResponse()

            if req:
                text = self._helpers.bytesToString(req)
                m = JWT_REGEX.search(text)
                if m:
                    return m.group(0)

            if resp:
                text = self._helpers.bytesToString(resp)
                m = JWT_REGEX.search(text)
                if m:
                    return m.group(0)

            return None
        except Exception:
            traceback.print_exc(file=sys.stdout)
            return None

    def _copy_to_clipboard(self, text):
        try:
            if text is None:
                text = ""
            selection = StringSelection(text)
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection)
        except Exception:
            traceback.print_exc(file=sys.stdout)

    def _send_to_decoder(self, token):
        try:
            self._callbacks.sendToDecoder(token)
        except Exception:
            traceback.print_exc(file=sys.stdout)

    def _highlight_message(self, message, color="yellow"):
        try:
            message.setHighlight(color)
        except Exception:
            traceback.print_exc(file=sys.stdout)

    def _forge_alg_none_token(self, token):
        """
        Change alg to 'none' and blank the signature.
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            header_raw = b64url_decode(parts[0])
            if header_raw is None:
                return None
            try:
                header = json.loads(header_raw.decode('utf-8'))
            except Exception:
                header = {}
            header["alg"] = "none"
            new_header_json = json.dumps(header, separators=(',', ':'))
            new_header_b64 = b64url_encode(new_header_json)
            return "%s.%s." % (new_header_b64, parts[1])
        except Exception:
            traceback.print_exc(file=sys.stdout)
            return None

    def _send_alg_none_to_repeater(self, message, token):
        """
        Forge alg=none token and send modified request to Repeater.
        """
        try:
            forged = self._forge_alg_none_token(token)
            if not forged:
                return

            service = message.getHttpService()
            req = message.getRequest()
            if req is None:
                return

            req_info = self._helpers.analyzeRequest(req)
            headers = list(req_info.getHeaders())
            body = req[req_info.getBodyOffset():]

            new_headers = []
            replaced = False
            for h in headers:
                hl = h.lower()
                if hl.startswith("authorization:"):
                    new_headers.append("Authorization: Bearer %s" % forged)
                    replaced = True
                else:
                    new_headers.append(h)
            if not replaced:
                new_headers.append("Authorization: Bearer %s" % forged)

            new_req = self._helpers.buildHttpMessage(new_headers, body)

            host = service.getHost()
            port = service.getPort()
            use_https = (service.getProtocol().lower() == "https")

            self._callbacks.sendToRepeater(host, port, use_https, new_req, "JWT-alg-none")
        except Exception:
            traceback.print_exc(file=sys.stdout)

    def _send_to_repeater_with_jwt(self, message, token):
        """
        Build a new request with Authorization: Bearer <token>
        and send it to Repeater.
        """
        try:
            service = message.getHttpService()
            req = message.getRequest()
            if req is None:
                return

            req_info = self._helpers.analyzeRequest(req)
            headers = list(req_info.getHeaders())
            body = req[req_info.getBodyOffset():]

            new_headers = []
            for h in headers:
                if not h.lower().startswith("authorization:"):
                    new_headers.append(h)
            new_headers.append("Authorization: Bearer %s" % token)

            new_req = self._helpers.buildHttpMessage(new_headers, body)

            host = service.getHost()
            port = service.getPort()
            use_https = (service.getProtocol().lower() == "https")

            self._callbacks.sendToRepeater(host, port, use_https, new_req, "JWT-Auth")
        except Exception:
            traceback.print_exc(file=sys.stdout)

    def openMessageForFingerprint(self, fingerprint):
        """
        Open the last-seen HTTP request for this fingerprint in Repeater.
        """
        try:
            rec = self._token_by_fingerprint.get(fingerprint)
            if not rec or not rec.last_rr:
                return

            service = rec.last_rr.getHttpService()
            req = rec.last_rr.getRequest()
            if req is None:
                return

            host = service.getHost()
            port = service.getPort()
            use_https = (service.getProtocol().lower() == "https")

            tab_name = "JWT-%s" % fingerprint[:8]
            self._callbacks.sendToRepeater(host, port, use_https, req, tab_name)
        except Exception:
            traceback.print_exc(file=sys.stdout)

    def createMenuItems(self, invocation):
        try:
            messages = invocation.getSelectedMessages()
            if not messages or len(messages) == 0:
                return None

            message = messages[0]

            # Try to find a JWT in this message
            token = self._extract_first_jwt_from_message(message)
            if not token:
                # No JWT -> don't show extra menu items
                return None

            # Decode once for header/payload copy
            header, payload, header_raw, payload_raw = decode_jwt(token)

            menu_items = []

            copy_item = JMenuItem(
                "JWT: Copy token to clipboard",
                actionPerformed=lambda e, t=token: self._copy_to_clipboard(t)
            )
            menu_items.append(copy_item)

            copy_header_item = JMenuItem(
                "JWT: Copy header JSON",
                actionPerformed=lambda e, h=header_raw: self._copy_to_clipboard(h or "")
            )
            menu_items.append(copy_header_item)

            copy_payload_item = JMenuItem(
                "JWT: Copy payload JSON",
                actionPerformed=lambda e, p=payload_raw: self._copy_to_clipboard(p or "")
            )
            menu_items.append(copy_payload_item)

            decoder_item = JMenuItem(
                "JWT: Send token to Decoder",
                actionPerformed=lambda e, t=token: self._send_to_decoder(t)
            )
            menu_items.append(decoder_item)

            send_item = JMenuItem(
                "JWT: Send request to Repeater with Authorization header",
                actionPerformed=lambda e, m=message, t=token: self._send_to_repeater_with_jwt(m, t)
            )
            menu_items.append(send_item)

            alg_none_item = JMenuItem(
                "JWT: Forge alg=none token and send to Repeater",
                actionPerformed=lambda e, m=message, t=token: self._send_alg_none_to_repeater(m, t)
            )
            menu_items.append(alg_none_item)

            highlight_item = JMenuItem(
                "JWT: Highlight message in history",
                actionPerformed=lambda e, m=message: self._highlight_message(m)
            )
            menu_items.append(highlight_item)

            return menu_items
        except Exception:
            traceback.print_exc(file=sys.stdout)
            return None
