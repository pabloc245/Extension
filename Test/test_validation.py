#!/usr/bin/env python3
"""
Test des bibliothèques de validation
"""
from email_validator import validate_email, EmailNotValidError
import bleach
import html

print("🧪 TEST DES BIBLIOTHÈQUES DE VALIDATION\n")

# Test email-validator
print("1️⃣  email-validator\n")

test_emails = [
    "Test@EXAMPLE.com",
    "<script>alert('xss')</script>@example.com",
    "user+tag@example.com",
    "test'; DROP TABLE users;--@example.com",
    "аdmin@example.com",  # Cyrillique
    "  test@example.com  ",
    "no-at-sign.com",
    "double@@example.com"
]

for email in test_emails:
    try:
        info = validate_email(email, check_deliverability=False)
        print(f"✅ {email[:40]}")
        print(f"   → {info.normalized}\n")
    except EmailNotValidError as e:
        print(f"❌ {email[:40]}")
        print(f"   → {str(e)[:60]}\n")

# Test bleach
print("\n2️⃣  bleach\n")

xss_tests = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "'; DROP TABLE users;--",
    "normal text"
]

for xss in xss_tests:
    clean = bleach.clean(xss)
    print(f"Input:  {xss}")
    print(f"Clean:  {clean}\n")

# Test html.escape
print("3️⃣  html.escape\n")

html_tests = [
    "<script>",
    "test@example.com",
    "'; DROP--"
]

for h in html_tests:
    escaped = html.escape(h)
    print(f"Input:   {h}")
    print(f"Escaped: {escaped}\n")
