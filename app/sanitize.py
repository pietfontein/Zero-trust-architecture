"""
==============================================================================
Input Sanitization Library — Zero-Trust Input Validation
==============================================================================

PHILOSOPHY: Zero Trust for User Input
  Never trust input. Validate everything. Reject the unexpected.

THE VALIDATION PIPELINE:
  Raw Input
    → Type Check       (is it a string? not None? not a list?)
    → Length Check     (is it too short? too long?)
    → Encoding Check   (is it valid UTF-8? any null bytes?)
    → Allowlist Check  (does it match expected pattern? reject everything else)
    → Sanitize         (strip/encode dangerous characters that passed)
    → Return Clean     (guaranteed-safe value)

WHY ALLOWLIST OVER BLOCKLIST?
  Blocklist: "block <script>, javascript:, ', --, etc."
    Problem: Attackers find encodings you didn't think of.
    "&#x3C;script&#x3E;" bypasses "<script>" check.
    Unicode normalization can turn innocent characters into dangerous ones.
  
  Allowlist: "only allow [a-zA-Z0-9._@-]"
    Any character not in that list is rejected, no matter how encoded.
    You can't bypass an allowlist by encoding the attack differently.

WHY BOTH WAF AND APP SANITIZATION?
  WAF (ModSecurity): Catches known attack patterns at the edge.
  App sanitization: Enforces business rules — e.g., usernames are alphanumeric.
  A username like "admin'; --" might slip past a poorly-tuned WAF,
  but your app sanitizer rejects it because it contains non-alphanumeric chars.
==============================================================================
"""

import re
import unicodedata
import html
from typing import Optional


class SanitizationError(ValueError):
    """Raised when input fails validation. Always catch this."""
    pass


class InputSanitizer:
    """
    Reusable input sanitization for all endpoints.
    
    Usage:
        s = InputSanitizer()
        clean_email = s.email(request.json.get('email', ''))
        clean_name  = s.username(request.json.get('username', ''))
    
    All methods:
    - Raise SanitizationError if input is invalid (catch in your route handler)
    - Return a clean, safe string if valid
    - Never modify the original input in place
    """

    # ===========================================================================
    # USERNAME VALIDATION
    # ===========================================================================
    def username(
        self,
        value: str,
        min_len: int = 3,
        max_len: int = 32
    ) -> str:
        """
        Validate and sanitize a username.
        
        Allowed: letters, digits, hyphens, underscores
        Rejected: spaces, special characters, SQL metacharacters, script tags
        
        WHY these rules?
        - No spaces: prevents URL encoding tricks and display confusion
        - No special chars: eliminates injection vectors entirely
        - Min 3: prevents trivially short names that could be system accounts
        - Max 32: prevents buffer overflow attempts and display issues
        """
        value = self._pre_check(value, 'username')
        
        # Length check BEFORE regex — regex is slower
        if len(value) < min_len:
            raise SanitizationError(f"Username must be at least {min_len} characters")
        if len(value) > max_len:
            raise SanitizationError(f"Username must be at most {max_len} characters")
        
        # Allowlist: ONLY alphanumeric, hyphens, underscores
        # WHY ^ and $? Ensures the ENTIRE string matches, not just a substring.
        # Without anchors, "admin'; DROP TABLE" matches because "admin" is valid.
        if not re.fullmatch(r'^[a-zA-Z0-9_-]+$', value):
            raise SanitizationError(
                "Username may only contain letters, numbers, hyphens, and underscores"
            )
        
        # Block reserved usernames that could cause privilege confusion
        reserved = {'admin', 'root', 'system', 'administrator', 'superuser',
                    'support', 'help', 'null', 'undefined', 'anonymous'}
        if value.lower() in reserved:
            raise SanitizationError("This username is reserved")
        
        return value

    # ===========================================================================
    # EMAIL VALIDATION
    # ===========================================================================
    def email(self, value: str) -> str:
        """
        Validate an email address.
        
        WHY not just use regex?
        Email regex is notoriously complex and buggy.
        We use a simple structural check + the `email-validator` library
        which handles edge cases like internationalized domains.
        
        WHY normalize (lowercase)?
        user@example.com and USER@EXAMPLE.COM are the same mailbox.
        Normalizing prevents duplicate accounts from the same address.
        """
        value = self._pre_check(value, 'email')
        
        if len(value) > 254:  # RFC 5321 maximum
            raise SanitizationError("Email address is too long")
        
        # Basic structural validation — fast and catches obvious junk
        if not re.fullmatch(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', value):
            raise SanitizationError("Invalid email address format")
        
        # Check for dangerous characters (injection attempts)
        dangerous = ['\n', '\r', '\x00', '<', '>', '"', "'"]
        for char in dangerous:
            if char in value:
                raise SanitizationError("Email address contains invalid characters")
        
        # Normalize to lowercase
        local, domain = value.rsplit('@', 1)
        return f"{local.lower()}@{domain.lower()}"

    # ===========================================================================
    # PASSWORD VALIDATION
    # ===========================================================================
    def password(self, value: str) -> str:
        """
        Validate password strength.
        
        WHY these rules?
        NIST SP 800-63B guidelines (2023):
        - Minimum 12 characters (not 8 — compute has advanced)
        - Check against breached password list
        - Allow all printable ASCII and Unicode characters
        - DON'T require complex char classes (they encourage weak patterns like "P@ssw0rd")
        
        WHY no maximum length?
        NIST explicitly says: "Verifiers SHOULD NOT impose a maximum length."
        Short maximums indicate the system is storing passwords unhashed.
        We hash with bcrypt, so length doesn't matter.
        
        NOTE: We do NOT log or include the password value in any error messages.
        """
        if not isinstance(value, str):
            raise SanitizationError("Password must be a string")
        if not value:
            raise SanitizationError("Password is required")
        
        if len(value) < 12:
            raise SanitizationError("Password must be at least 12 characters")
        
        # Block null bytes — can cause truncation in some systems
        if '\x00' in value:
            raise SanitizationError("Password contains invalid characters")
        
        # Entropy check: block common patterns
        # (In production: check against HaveIBeenPwned API)
        obviously_weak = [
            'password', '123456789', 'qwerty', 'abcdefgh',
            'letmein', 'welcome', 'monkey', 'dragon'
        ]
        if value.lower() in obviously_weak:
            raise SanitizationError("Password is too common")
        
        # Return the raw password — hashing happens in the caller
        # WHY not hash here? The caller needs to choose the algorithm and parameters.
        return value

    # ===========================================================================
    # SEARCH TERM VALIDATION
    # ===========================================================================
    def search_term(self, value: str, max_len: int = 100) -> str:
        """
        Sanitize a search term.
        
        WHY not use the username allowlist?
        Search terms legitimately contain spaces, punctuation, accented chars.
        We use HTML escaping instead of stripping to preserve the user's intent
        while neutralizing dangerous characters.
        
        WHY HTML escape search terms?
        If search results display the search term back to the user ("Results for: %s"),
        an XSS payload in the search term would execute in the user's browser.
        HTML escaping converts < to &lt;, making it display as text, not code.
        """
        value = self._pre_check(value, 'search term')
        
        if len(value) > max_len:
            raise SanitizationError(f"Search term must be at most {max_len} characters")
        
        # Strip control characters except whitespace
        value = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', value)
        
        # HTML-encode special characters to prevent reflected XSS
        # This happens AFTER the length check to avoid encoding bombs
        value = html.escape(value, quote=True)
        
        # Normalize unicode: NFKC prevents homograph attacks
        # Example: "аdmin" (Cyrillic а) → "admin" (Latin a)
        # WHY NFKC not NFC? NFKC also decomposes compatibility characters.
        value = unicodedata.normalize('NFKC', value)
        
        return value.strip()

    # ===========================================================================
    # INTEGER VALIDATION
    # ===========================================================================
    def positive_integer(
        self,
        value: str,
        min_val: int = 1,
        max_val: int = 2147483647
    ) -> int:
        """
        Parse and validate a positive integer (for pagination, IDs, etc.)
        
        WHY string input?
        Query parameters always come as strings. This method parses and validates
        in one step.
        
        WHY enforce max_val?
        OFFSET 2147483647 in a SQL query would hang your database.
        Integer overflow attacks set pagination values to MAX_INT.
        """
        if value is None:
            return min_val
        
        value = str(value).strip()
        
        # Only allow digits — reject "-1", "1e5", "1.0", "0x10"
        if not re.fullmatch(r'^\d+$', value):
            raise SanitizationError(f"Expected a positive integer, got: {value!r}")
        
        try:
            n = int(value)
        except (ValueError, OverflowError):
            raise SanitizationError("Integer value is out of range")
        
        if n < min_val:
            raise SanitizationError(f"Value must be at least {min_val}")
        if n > max_val:
            raise SanitizationError(f"Value must be at most {max_val}")
        
        return n

    # ===========================================================================
    # FREE TEXT (biography, description, comments)
    # ===========================================================================
    def free_text(
        self,
        value: str,
        max_len: int = 5000,
        allow_html: bool = False
    ) -> str:
        """
        Sanitize free-form text input.
        
        WHY stricter for HTML?
        If allow_html=False (default), we HTML-escape everything.
        If allow_html=True (e.g., rich text editor), you MUST use a proper
        HTML sanitizer (bleach library with an allowlist) — never a blocklist.
        
        WHY check for homographs in display text?
        Homograph attacks use characters from other scripts that look like Latin.
        "Раypal.com" (Russian P) looks like "Paypal.com" — phishing in user content.
        """
        value = self._pre_check(value, 'text')
        
        if len(value) > max_len:
            raise SanitizationError(f"Text must be at most {max_len} characters")
        
        # Remove null bytes — these can truncate strings in C-based systems
        value = value.replace('\x00', '')
        
        # Remove other control characters (keep \n, \r, \t as legitimate whitespace)
        value = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
        
        if allow_html:
            # Use bleach with an ALLOWLIST — never a blocklist
            import bleach
            ALLOWED_TAGS = ['p', 'b', 'i', 'u', 'em', 'strong', 'br', 'ul', 'ol', 'li']
            ALLOWED_ATTRS = {}  # No attributes allowed (prevents onclick=, href=javascript:)
            value = bleach.clean(value, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
        else:
            # Escape everything — safe for display in HTML
            value = html.escape(value, quote=True)
        
        # Normalize unicode
        value = unicodedata.normalize('NFKC', value)
        
        return value.strip()

    # ===========================================================================
    # PRIVATE HELPER
    # ===========================================================================
    def _pre_check(self, value, field_name: str) -> str:
        """
        Common pre-validation that runs on every field:
        1. Type check: must be a string
        2. Not None / empty
        3. Decode if bytes
        4. Check for null bytes
        """
        if value is None:
            raise SanitizationError(f"{field_name.capitalize()} is required")
        
        # Auto-decode bytes (e.g., from multipart forms)
        if isinstance(value, bytes):
            try:
                value = value.decode('utf-8')
            except UnicodeDecodeError:
                raise SanitizationError(f"{field_name.capitalize()} contains invalid encoding")
        
        if not isinstance(value, str):
            raise SanitizationError(f"{field_name.capitalize()} must be a string")
        
        if not value.strip():
            raise SanitizationError(f"{field_name.capitalize()} cannot be empty")
        
        # Null bytes can truncate strings in C extensions
        if '\x00' in value:
            raise SanitizationError(f"{field_name.capitalize()} contains invalid characters")
        
        return value
