# Import the guarded email function, its security error, and the internal key
from secure_agent import guarded_send_email, SecurityError
from config import INTERNAL_KEY

# Test cases for checking which email requests should be allowed or rejected
# Each case contains a recipient, subject, body, and expected result
cases = [
    ("attacker@adversary-domain.com",        "x", "y",          False),
    ("a@company-internal.com.evil.com",      "x", "y",          False),
    ("a@company-internal.com\n",             "x", "y",          False),
    ("a@company-internal.com\n@evil.com",    "x", "y",          False),
    ("a@evil.com@company-internal.com",      "x", "y",          False),
    ("lead@company-internal.com",            "x", INTERNAL_KEY, False),   # secret in body
    ("lead@company-internal.com",            "Ticket", "Checkout crashes on Safari", True),
]

# Track whether every test produces its expected result
ok = True
for rcpt, subj, body, should_pass in cases:
    try:
        # Attempt to send the email after the security checks
        guarded_send_email({"recipient": rcpt, "subject": subj, "body": body})
        result = True
    # A security error means the request was rejected
    except SecurityError:
        result = False

    # Compare the actual result with the expected result
    status = "OK  " if result == should_pass else "FAIL"
    ok &= result == should_pass
    print(f"{status} recipient={rcpt!r} passed={result}")

# Print whether all validation tests behaved as expected
print("\nALL VALIDATION TESTS PASSED" if ok else "\nSOME TESTS FAILED")