# Test Secret Manager - Guide complet

## 1. Installer la dépendance

```bash
pip install google-cloud-secret-manager
```

## 2. Créer un secret test

```bash
# Créer le secret
echo -n "mon-secret-test-12345" | gcloud secrets create test-secret --data-file=-

# Vérifier
gcloud secrets list
```

## 3. Donner les permissions au Service Account

```bash
PROJECT_ID="votre-project-id"
SA_EMAIL="auth-server@${PROJECT_ID}.iam.gserviceaccount.com"

# Permission pour lire les secrets
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor"
```

## 4. Test en local (développement)

```bash
# Télécharger la clé du service account
gcloud iam service-accounts keys create key.json \
    --iam-account="${SA_EMAIL}"

# Définir la variable d'environnement
export GOOGLE_APPLICATION_CREDENTIALS="key.json"

# Lancer le test
python test_secret_manager.py PROJECT_ID test-secret
```

## 5. Test sur la VM (production)

```bash
# SSH sur la VM
gcloud compute ssh VM_NAME

# Installer pip
sudo apt update
sudo apt install -y python3-pip

# Installer la dépendance
pip3 install google-cloud-secret-manager

# Lancer le test (pas besoin de clé, utilise le SA de la VM)
python3 test_secret_manager.py PROJECT_ID test-secret
```

## Outputs attendus

### ✅ Succès
```
Testing Secret Manager access...
Project: my-project
Secret: test-secret

Attempting to access: projects/my-project/secrets/test-secret/versions/latest

✅ SUCCESS - Secret Manager access working!
Secret value length: 21 characters
First 10 chars: mon-secret...
```

### ❌ Erreur de permission
```
❌ FAILED - PermissionDenied
Error: 403 Permission denied

Possible fixes:
1. Add role: roles/secretmanager.secretAccessor to service account
2. Verify VM is using correct service account
3. Check secret exists in this project
```

### ❌ Secret introuvable
```
❌ FAILED - NotFound
Error: 404 Secret not found

Secret not found. Create it with:
  echo -n 'your-secret-value' | gcloud secrets create test-secret --data-file=-
```

## Commandes utiles

```bash
# Lister tous les secrets
gcloud secrets list

# Voir les versions d'un secret
gcloud secrets versions list test-secret

# Lire un secret
gcloud secrets versions access latest --secret="test-secret"

# Supprimer un secret
gcloud secrets delete test-secret

# Voir les permissions d'un secret
gcloud secrets get-iam-policy test-secret

# Vérifier quel SA utilise la VM
gcloud compute instances describe VM_NAME --format="value(serviceAccounts[0].email)"
```

## Troubleshooting

### La VM n'utilise pas le bon SA
```bash
# Changer le SA de la VM
gcloud compute instances set-service-account VM_NAME \
    --service-account=auth-server@PROJECT_ID.iam.gserviceaccount.com \
    --scopes=cloud-platform

# Redémarrer la VM
gcloud compute instances stop VM_NAME
gcloud compute instances start VM_NAME
```

### Permission denied malgré le rôle
```bash
# Vérifier que le rôle est bien assigné
gcloud projects get-iam-policy PROJECT_ID \
    --flatten="bindings[].members" \
    --filter="bindings.members:serviceAccount:auth-server@PROJECT_ID.iam.gserviceaccount.com"

# Si absent, réassigner
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:auth-server@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```
