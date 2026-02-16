# Configuration SMTP

## Gmail

### 1. Activer authentification 2 facteurs
https://myaccount.google.com/security

### 2. Créer un App Password
1. Aller sur https://myaccount.google.com/apppasswords
2. Créer un mot de passe pour "Mail"
3. Copier le mot de passe généré (16 caractères)

### 3. Variables d'environnement
```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=votre.email@gmail.com
export SMTP_PASSWORD=xxxx xxxx xxxx xxxx  # App password
```

Ou dans `.env`:
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=votre.email@gmail.com
SMTP_PASSWORD=xxxxxxxxxxxxxxxx
```

---

## Autres fournisseurs

### Outlook / Hotmail
```
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USER=votre.email@outlook.com
SMTP_PASSWORD=votre_mot_de_passe
```

### Yahoo
```
SMTP_HOST=smtp.mail.yahoo.com
SMTP_PORT=587
SMTP_USER=votre.email@yahoo.com
SMTP_PASSWORD=app_password  # Nécessite App Password
```

### SendGrid (production recommandé)
```
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=votre_api_key
```

### Mailgun
```
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USER=postmaster@votre-domaine.mailgun.org
SMTP_PASSWORD=votre_password
```

### Amazon SES
```
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=votre_access_key
SMTP_PASSWORD=votre_secret_key
```

---

## Test SMTP

```bash
# Tester la connexion
python smtp_poc.py
```

---

## Limites par fournisseur

| Fournisseur | Emails/jour | Emails/minute |
|-------------|-------------|---------------|
| Gmail       | 500         | ~20           |
| Outlook     | 300         | ~10           |
| SendGrid    | Illimité*   | Variable      |
| Mailgun     | Illimité*   | Variable      |
| Amazon SES  | Illimité*   | Variable      |

*Selon forfait

---

## Production

Pour la production, utiliser un service dédié:
- **SendGrid** (gratuit jusqu'à 100 emails/jour)
- **Mailgun** (gratuit jusqu'à 5000 emails/mois)
- **Amazon SES** (très bon marché)

Avantages:
- Meilleure délivrabilité
- Pas de limite stricte
- Analytics
- Templates
- API moderne

---

## Sécurité

1. **Ne jamais** commiter les credentials
2. Utiliser variables d'environnement
3. Utiliser TLS (port 587)
4. Rotation des mots de passe
5. Monitoring des échecs d'envoi
