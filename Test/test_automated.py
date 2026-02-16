#!/usr/bin/env python3
"""
Tests automatisés (sans interaction utilisateur)
Pour tester avec codes réels, utiliser test_scenarios.py
"""
import requests
import time
import sys

BASE_URL = "http://localhost:8000"

class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def test(self, name, condition, msg=""):
        result = "✅" if condition else "❌"
        print(f"{result} {name}: {msg}")
        if condition:
            self.passed += 1
        else:
            self.failed += 1
        self.tests.append((name, condition))
        return condition
    
    def summary(self):
        print(f"\n{'='*60}")
        print(f"Total: {len(self.tests)} | Passed: {self.passed} | Failed: {self.failed}")
        print(f"{'='*60}")
        return self.failed == 0

def main():
    print("🧪 TESTS AUTOMATISÉS\n")
    
    try:
        requests.get(BASE_URL, timeout=2)
        print(f"✅ Serveur accessible\n")
    except:
        print(f"❌ Serveur non accessible sur {BASE_URL}")
        sys.exit(1)
    
    t = TestRunner()
    
    # Test 1: Email invalides
    print("TEST 1: Validation email")
    invalid_emails = [
        "not-an-email",
        "no-at-sign.com",
        "double@@example.com",
        "<script>@example.com"
    ]
    
    for email in invalid_emails:
        r = requests.post(f"{BASE_URL}/register", json={"email": email})
        t.test(f"Reject {email[:20]}", r.status_code == 400)
    
    # Test 2: SQL injection
    print("\nTEST 2: SQL Injection")
    sql_payloads = [
        "test'; DROP TABLE users;--",
        "admin' OR '1'='1",
        "' UNION SELECT *--"
    ]
    
    for payload in sql_payloads:
        r = requests.post(f"{BASE_URL}/register", json={"email": payload})
        t.test(f"Block SQL: {payload[:20]}", r.status_code == 400)
    
    # Test 3: Token invalide
    print("\nTEST 3: Authentification")
    r = requests.get(f"{BASE_URL}/me", headers={"Authorization": "Bearer invalid"})
    t.test("Reject invalid token", r.status_code == 401)
    
    r = requests.get(f"{BASE_URL}/me")
    t.test("Reject missing token", r.status_code == 401)
    
    # Test 4: Email valide
    print("\nTEST 4: Inscription valide")
    email = f"test_{int(time.time())}@example.com"
    r = requests.post(f"{BASE_URL}/register", json={"email": email})
    t.test("Accept valid email", r.status_code == 200)
    
    if r.status_code == 200:
        data = r.json()
        t.test("Response has message", 'message' in data)
    
    # Test 5: Code invalide
    print("\nTEST 5: Vérification")
    r = requests.post(f"{BASE_URL}/verify", json={"email": email, "code": "000000"})
    t.test("Reject wrong code", r.status_code == 400)
    
    # Test 6: Rate limiting
    print("\nTEST 6: Rate limiting")
    email_base = f"rate_{int(time.time())}"
    
    status_codes = []
    for i in range(12):
        r = requests.post(f"{BASE_URL}/register", json={"email": f"{email_base}_{i}@example.com"})
        status_codes.append(r.status_code)
    
    limited = any(code == 429 for code in status_codes[10:])
    t.test("Rate limit triggered", limited, f"Got {status_codes[-1]} on request 12")
    
    # Test 7: XSS
    print("\nTEST 7: XSS Protection")
    xss_payloads = [
        "<script>alert('xss')</script>@example.com",
        "<img src=x onerror=alert(1)>@example.com"
    ]
    
    for payload in xss_payloads:
        r = requests.post(f"{BASE_URL}/register", json={"email": payload})
        t.test(f"Block XSS: {payload[:25]}", r.status_code == 400)
    
    # Test 8: Endpoints
    print("\nTEST 8: Endpoints")
    r = requests.get(f"{BASE_URL}/")
    t.test("Root endpoint", r.status_code == 200)
    
    r = requests.get(f"{BASE_URL}/notfound")
    t.test("404 on unknown route", r.status_code == 404)
    
    # Résumé
    success = t.summary()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
