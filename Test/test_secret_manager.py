#!/usr/bin/env python3
"""
Test d'accès à Google Cloud Secret Manager
"""
from google.cloud import secretmanager
import sys

def test_secret_access(project_id, secret_id):
    """
    Test si le service account peut accéder aux secrets
    
    Args:
        project_id: ID du projet GCP
        secret_id: Nom du secret à tester
    """
    print(f"Testing Secret Manager access...")
    print(f"Project: {project_id}")
    print(f"Secret: {secret_id}\n")
    
    try:
        # Créer le client
        client = secretmanager.SecretManagerServiceClient()
        
        # Construire le nom du secret
        name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
        
        print(f"Attempting to access: {name}")
        
        # Récupérer le secret
        response = client.access_secret_version(request={"name": name})
        
        # Décoder
        secret_value = response.payload.data.decode("UTF-8")
        
        print("\n✅ SUCCESS - Secret Manager access working!")
        print(f"Secret value length: {len(secret_value)} characters")
        print(f"First 10 chars: {secret_value[:10]}...")
        
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED - {type(e).__name__}")
        print(f"Error: {str(e)}\n")
        
        if "PermissionDenied" in str(e):
            print("Possible fixes:")
            print("1. Add role: roles/secretmanager.secretAccessor to service account")
            print("2. Verify VM is using correct service account")
            print("3. Check secret exists in this project")
        elif "NotFound" in str(e):
            print("Secret not found. Create it with:")
            print(f"  echo -n 'your-secret-value' | gcloud secrets create {secret_id} --data-file=-")
        
        return False

def list_accessible_secrets(project_id):
    """Liste tous les secrets accessibles"""
    print("\nListing accessible secrets...")
    
    try:
        client = secretmanager.SecretManagerServiceClient()
        parent = f"projects/{project_id}"
        
        secrets = client.list_secrets(request={"parent": parent})
        
        count = 0
        for secret in secrets:
            print(f"  - {secret.name.split('/')[-1]}")
            count += 1
        
        if count == 0:
            print("  No secrets found or no permission to list")
        else:
            print(f"\nTotal: {count} secrets")
        
        return True
        
    except Exception as e:
        print(f"❌ Cannot list secrets: {e}")
        return False

if __name__ == "__main__":
    print("="*60)
    print("Google Cloud Secret Manager Access Test")
    print("="*60)
    print()
    
    # Configuration
    if len(sys.argv) < 3:
        print("Usage: python test_secret_manager.py PROJECT_ID SECRET_NAME")
        print("\nExample:")
        print("  python test_secret_manager.py my-project auth-secret-key")
        sys.exit(1)
    
    project_id = sys.argv[1]
    secret_id = sys.argv[2]
    
    # Test 1: Accès à un secret spécifique
    success = test_secret_access(project_id, secret_id)
    
    # Test 2: Liste des secrets
    print("\n" + "="*60)
    list_accessible_secrets(project_id)
    
    print("\n" + "="*60)
    if success:
        print("✅ Service Account has correct permissions")
        sys.exit(0)
    else:
        print("❌ Service Account needs configuration")
        sys.exit(1)
