# Bibliothèques de validation utilisées

## 📚 Librairies choisies

### 1. email-validator (★★★★★)
**Pourquoi** : Standard de facto pour validation email en Python

**Ce qu'elle fait** :
- ✅ Validation RFC 5322 complète
- ✅ Normalisation automatique (lowercase, trim)
- ✅ Vérification longueur (local + domain)
- ✅ Protection contre homoglyphs (аdmin@example.com vs admin@example.com)
- ✅ Validation DNS du domaine (optionnel)
- ✅ Détection des erreurs de typo courantes

**Utilisée par** : Django, Flask-Security, FastAPI

```python
from email_validator import validate_email, EmailNotValidError

emailinfo = validate_email("Test@Example.COM", check_deliverability=False)
# emailinfo.normalized = "test@example.com"
```

### 2. bleach (★★★★★)
**Pourquoi** : Bibliothèque Mozilla pour sanitization HTML/XSS

**Ce qu'elle fait** :
- ✅ Supprime/échappe HTML malveillant
- ✅ Protection XSS
- ✅ Whitelist de tags autorisés
- ✅ Nettoyage CSS dangereux

**Utilisée par** : Mozilla, Reddit, GitHub

```python
import bleach

clean = bleach.clean("<script>alert('xss')</script>")
# clean = "&lt;script&gt;alert('xss')&lt;/script&gt;"
```

### 3. html.escape (stdlib)
**Pourquoi** : Standard Python pour échapper HTML

**Ce qu'elle fait** :
- ✅ Échappe < > & " '
- ✅ Fait partie de la stdlib (pas de dépendance)

```python
import html

safe = html.escape("<script>")
# safe = "&lt;script&gt;"
```

---

## 🛡️ Defense in Depth - Stratégie multicouche

### Couche 1 : Validation métier (email-validator)
```python
def sanitize_email(email_input):
    emailinfo = validate_email(email_input, check_deliverability=False)
    return emailinfo.normalized
```
**Rejette** : Formats invalides, homoglyphs, etc.

### Couche 2 : Sanitization XSS (bleach)
```python
clean_code = bleach.clean(code_input.strip())
```
**Neutralise** : Tags HTML, scripts, caractères dangereux

### Couche 3 : Escape HTML (html.escape)
```python
safe_email = html.escape(normalized_email)
```
**Protection** : Dernière ligne de défense avant affichage

### Couche 4 : Paramètres SQL
```python
c.execute('SELECT * FROM users WHERE email = ?', (email,))
```
**Garantie** : Aucune exécution de code SQL

---

## 🆚 Pourquoi PAS mes fonctions maison

| Aspect | Fait maison | Bibliothèque |
|--------|-------------|--------------|
| Tests | 0 tests | 1000+ tests |
| Edge cases | Quelques-uns | Tous connus |
| Maintenance | Moi seul | Communauté |
| Audits sécu | Aucun | Réguliers |
| RFC conformité | Approximative | Complète |
| Mises à jour | Jamais | Continues |

**Exemple concret** :
```python
# Mon code maison rate ça :
"test@[192.168.1.1]"  # IP valide selon RFC
"user+tag@example.com"  # Plus addressing valide
"用户@example.com"  # Unicode valide

# email-validator les gère correctement
```

---

## 🔍 Comparaison avec autres libs

### Alternatives considérées

**validate_email_address** ❌
- Pas maintenu depuis 2019
- Manque features modernes

**pyisemail** ❌  
- Trop strict (rejette emails valides)
- Performance faible

**email-validator** ✅
- Maintenu activement
- Balance strict/permissif
- Performance excellente
- Utilisé en prod par millions

---

## 📊 Tests de validation

```python
# Tests que email-validator passe

# ✅ Normalisation
"Test@EXAMPLE.com" → "test@example.com"

# ✅ Homoglyphs (caractères qui se ressemblent)
"аdmin@example.com" → Rejeté (а cyrillique)

# ✅ Whitespace
"  test@example.com  " → "test@example.com"

# ✅ Plus addressing
"user+tag@example.com" → Valide

# ✅ IP literal
"user@[192.168.1.1]" → Valide (selon RFC)

# ✅ Unicode (IDN)
"用户@例え.jp" → Valide + punycode

# ✅ Longueur
"a"*65 + "@example.com" → Rejeté (local trop long)

# ✅ Syntaxe
"no-at-sign.com" → Rejeté
"double@@example.com" → Rejeté
"@example.com" → Rejeté
```

---

## 🚨 Ce que ça protège

### 1. XSS (Cross-Site Scripting)
```python
# Input malveillant
email = "<script>alert('xss')</script>@example.com"

# Sans protection
# → Stocké tel quel, exécuté côté client

# Avec email-validator + bleach
# → Rejeté (format invalide)
```

### 2. Homoglyph attacks
```python
# Cyrillique qui ressemble à latin
email = "аdmin@example.com"  # а cyrillique

# Sans protection
# → Accepté, peut usurper admin@example.com

# Avec email-validator
# → Détecté et peut être rejeté ou normalisé
```

### 3. Buffer overflow
```python
# Email de 10000 caractères
email = "a" * 10000 + "@example.com"

# Sans protection
# → Peut causer overflow selon système

# Avec email-validator
# → Rejeté (dépasse limite RFC)
```

### 4. SQL Injection
```python
# Déjà protégé par paramètres, mais defense in depth
email = "test'; DROP TABLE users;--"

# email-validator le rejette aussi (format invalide)
```

---

## 🎯 Recommandation finale

**Pour validation input** :
1. **email-validator** pour emails
2. **bleach** pour HTML/text
3. **validators** pour URLs, IPs, etc.
4. **phonenumbers** pour téléphones

**Ne jamais** :
- ❌ Regex maison pour emails
- ❌ Strip/replace manuel
- ❌ Validation partielle
- ❌ Réinventer la roue

**Toujours** :
- ✅ Utiliser libs auditées
- ✅ Combiner plusieurs couches
- ✅ Paramètres SQL en dernier recours
- ✅ Logger les tentatives suspectes
