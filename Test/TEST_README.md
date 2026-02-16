# Scripts de test

## test_automated.py
Tests automatisés sans interaction utilisateur.

**Usage** :
```bash
python test_automated.py
```

**Tests** :
- ✅ Validation email (formats invalides)
- ✅ SQL injection
- ✅ XSS protection
- ✅ Tokens invalides
- ✅ Rate limiting
- ✅ Endpoints

## test_scenarios.py
Tests complets avec interaction (nécessite codes email).

**Usage** :
```bash
python test_scenarios.py
```

**Scénarios** :
1. Nouveau client - Inscription réussie
2. Email déjà utilisé
3. Code invalide
4. Code expiré
5. Limite de tentatives (5 max)
6. Token invalide
7. Validation email
8. Rate limiting
9. Renvoi de code
10. SQL injection

## Lancer les tests

```bash
# Terminal 1 : Serveur
python server_validated.py

# Terminal 2 : Tests auto
python test_automated.py

# Ou tests interactifs
python test_scenarios.py
```
