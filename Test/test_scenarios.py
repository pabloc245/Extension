#!/usr/bin/env python3
"""
Tests d'intégration complets - Scénarios utilisateur
"""
import requests
import time
import sys
from datetime import datetime

BASE_URL = "http://localhost:8000"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_test(name):
    print(f"\n{Colors.BLUE}{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}{Colors.END}\n")

def print_success(msg):
    print(f"{Colors.GREEN}✅ {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.RED}❌ {msg}{Colors.END}")

def print_info(msg):
    print(f"{Colors.YELLOW}ℹ️  {msg}{Colors.END}")

class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
    
    def assert_status(self, response, expected, msg):
        if response.status_code == expected:
            print_success(f"{msg} - Status {response.status_code}")
            self.passed += 1
            return True
        else:
            print_error(f"{msg} - Expected {expected}, got {response.status_code}")
            print(f"   Response: {response.text}")
            self.failed += 1
            return False
    
    def assert_contains(self, data, key, msg):
        if key in data:
            print_success(f"{msg} - Contains '{key}'")
            self.passed += 1
            return True
        else:
            print_error(f"{msg} - Missing '{key}'")
            self.failed += 1
            return False
    
    def summary(self):
        print(f"\n{Colors.BLUE}{'='*60}")
        print(f"RÉSUMÉ")
        print(f"{'='*60}{Colors.END}")
        print(f"Total: {self.passed + self.failed}")
        print_success(f"Réussis: {self.passed}")
        if self.failed > 0:
            print_error(f"Échoués: {self.failed}")
        return self.failed == 0

def test_scenario_1_nouveau_client_success(t):
    """Scénario 1: Nouveau client s'inscrit avec succès"""
    print_test("Scénario 1: Nouveau client - Inscription réussie")
    
    email = f"newuser_{int(time.time())}@example.com"
    
    # Étape 1: Inscription
    print_info("Étape 1: Envoyer demande d'inscription")
    r = requests.post(f"{BASE_URL}/register", json={"email": email})
    t.assert_status(r, 200, "Registration request")
    data = r.json()
    t.assert_contains(data, 'message', "Response has message")
    
    # Étape 2: Vérification (simulation)
    print_info("Étape 2: Vérifier le code")
    code = input(f"   Entrez le code reçu pour {email}: ")
    
    r = requests.post(f"{BASE_URL}/verify", json={"email": email, "code": code})
    t.assert_status(r, 200, "Code verification")
    data = r.json()
    
    if t.assert_contains(data, 'token', "Response has token"):
        token = data['token']
        print_info(f"Token: {token[:30]}...")
        
        # Étape 3: Accès route protégée
        print_info("Étape 3: Accéder aux infos utilisateur")
        r = requests.get(f"{BASE_URL}/me", headers={"Authorization": f"Bearer {token}"})
        t.assert_status(r, 200, "Access protected route")
        data = r.json()
        t.assert_contains(data, 'email', "User info has email")
        
        if data.get('email') == email:
            print_success(f"Email correct: {email}")
            t.passed += 1
        else:
            print_error(f"Email mismatch")
            t.failed += 1

def test_scenario_2_email_deja_utilise(t):
    """Scénario 2: Email déjà enregistré"""
    print_test("Scénario 2: Email déjà utilisé")
    
    email = f"duplicate_{int(time.time())}@example.com"
    
    # Première inscription
    print_info("Inscription initiale")
    r = requests.post(f"{BASE_URL}/register", json={"email": email})
    t.assert_status(r, 200, "First registration")
    
    code = input(f"   Code pour {email}: ")
    r = requests.post(f"{BASE_URL}/verify", json={"email": email, "code": code})
    t.assert_status(r, 200, "Verification")
    
    # Tentative de réinscription
    print_info("Tentative de réutilisation du même email")
    r = requests.post(f"{BASE_URL}/register", json={"email": email})
    t.assert_status(r, 400, "Should reject duplicate email")
    
    data = r.json()
    if 'error' in data and 'déjà' in data['error'].lower():
        print_success("Error message correct")
        t.passed += 1
    else:
        print_error("Wrong error message")
        t.failed += 1

def test_scenario_3_code_invalide(t):
    """Scénario 3: Code de vérification invalide"""
    print_test("Scénario 3: Code invalide")
    
    email = f"wrongcode_{int(time.time())}@example.com"
    
    print_info("Inscription")
    r = requests.post(f"{BASE_URL}/register", json={"email": email})
    t.assert_status(r, 200, "Registration")
    
    # Code incorrect
    print_info("Tentative avec code incorrect")
    r = requests.post(f"{BASE_URL}/verify", json={"email": email, "code": "000000"})
    t.assert_status(r, 400, "Should reject wrong code")

def test_scenario_4_code_expire(t):
    """Scénario 4: Code expiré (nécessite d'attendre 10min ou modification DB)"""
    print_test("Scénario 4: Code expiré")
    
    print_info("⏭️  Test skipped (nécessite attente 10min)")
    print_info("   Pour tester: modifier DB manuellement ou attendre expiration")

def test_scenario_5_trop_tentatives(t):
    """Scénario 5: Trop de tentatives"""
    print_test("Scénario 5: Limite de tentatives")
    
    email = f"bruteforce_{int(time.time())}@example.com"
    
    print_info("Inscription")
    r = requests.post(f"{BASE_URL}/register", json={"email": email})
    t.assert_status(r, 200, "Registration")
    
    # 5 tentatives avec code incorrect
    print_info("5 tentatives avec code incorrect")
    for i in range(5):
        r = requests.post(f"{BASE_URL}/verify", json={"email": email, "code": f"{i:06d}"})
        print(f"   Tentative {i+1}/5: Status {r.status_code}")
    
    # 6ème tentative doit être bloquée
    print_info("6ème tentative (doit être bloquée)")
    r = requests.post(f"{BASE_URL}/verify", json={"email": email, "code": "999999"})
    t.assert_status(r, 400, "Should block after 5 attempts")

def test_scenario_6_token_invalide(t):
    """Scénario 6: Tentative avec token invalide"""
    print_test("Scénario 6: Token invalide")
    
    print_info("Accès avec token invalide")
    r = requests.get(f"{BASE_URL}/me", headers={"Authorization": "Bearer invalid_token_123"})
    t.assert_status(r, 401, "Should reject invalid token")
    
    print_info("Accès sans token")
    r = requests.get(f"{BASE_URL}/me")
    t.assert_status(r, 401, "Should reject missing token")

def test_scenario_7_email_invalide(t):
    """Scénario 7: Emails invalides"""
    print_test("Scénario 7: Validation email")
    
    invalid_emails = [
        "not-an-email",
        "missing-at-sign.com",
        "double@@example.com",
        "<script>alert('xss')</script>@example.com",
        "test'; DROP TABLE users;--@example.com",
    ]
    
    for email in invalid_emails:
        print_info(f"Test: {email[:40]}")
        r = requests.post(f"{BASE_URL}/register", json={"email": email})
        t.assert_status(r, 400, f"Should reject: {email[:30]}")

def test_scenario_8_rate_limiting(t):
    """Scénario 8: Rate limiting"""
    print_test("Scénario 8: Rate limiting")
    
    print_info("Envoi de 12 requêtes rapidement")
    
    for i in range(12):
        r = requests.post(f"{BASE_URL}/register", json={"email": f"rate{i}@example.com"})
        print(f"   Request {i+1}/12: Status {r.status_code}")
        
        if i >= 10 and r.status_code == 429:
            print_success("Rate limit activé après 10 requêtes")
            t.passed += 1
            break
    else:
        print_error("Rate limit pas détecté")
        t.failed += 1

def test_scenario_9_renvoi_code(t):
    """Scénario 9: Renvoi de code"""
    print_test("Scénario 9: Renvoi de code")
    
    email = f"resend_{int(time.time())}@example.com"
    
    # Première demande
    print_info("Première inscription")
    r = requests.post(f"{BASE_URL}/register", json={"email": email})
    t.assert_status(r, 200, "First registration")
    
    time.sleep(2)
    
    # Renvoi de code
    print_info("Demande de renvoi")
    r = requests.post(f"{BASE_URL}/register", json={"email": email})
    t.assert_status(r, 200, "Code resend")

def test_scenario_10_injection_sql(t):
    """Scénario 10: Tentatives d'injection SQL"""
    print_test("Scénario 10: Protection SQL injection")
    
    sql_payloads = [
        "test'; DROP TABLE users;--",
        "admin' OR '1'='1",
        "' UNION SELECT * FROM users--",
    ]
    
    for payload in sql_payloads:
        print_info(f"Test: {payload[:40]}")
        # Tentative d'inscription
        r = requests.post(f"{BASE_URL}/register", json={"email": payload})
        if r.status_code == 400:
            print_success("Payload rejeté par validation")
            t.passed += 1
        else:
            print_error("Payload pas rejeté")
            t.failed += 1

def main():
    print(f"\n{Colors.BLUE}{'='*60}")
    print("🧪 TESTS D'INTÉGRATION - Backend Auth")
    print(f"{'='*60}{Colors.END}\n")
    
    # Vérifier que le serveur est accessible
    try:
        r = requests.get(BASE_URL, timeout=2)
        print_success(f"Serveur accessible sur {BASE_URL}\n")
    except:
        print_error(f"Serveur non accessible sur {BASE_URL}")
        print_info("Lancez d'abord: python server_validated.py")
        sys.exit(1)
    
    t = TestRunner()
    
    # Exécution des scénarios
    try:
        test_scenario_1_nouveau_client_success(t)
        test_scenario_2_email_deja_utilise(t)
        test_scenario_3_code_invalide(t)
        test_scenario_4_code_expire(t)
        test_scenario_5_trop_tentatives(t)
        test_scenario_6_token_invalide(t)
        test_scenario_7_email_invalide(t)
        test_scenario_8_rate_limiting(t)
        test_scenario_9_renvoi_code(t)
        test_scenario_10_injection_sql(t)
    except KeyboardInterrupt:
        print_info("\n\nTests interrompus")
    except Exception as e:
        print_error(f"Erreur: {e}")
    
    # Résumé
    success = t.summary()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
