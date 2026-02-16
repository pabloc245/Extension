#!/usr/bin/env python3
"""
PoC - Envoi email via SMTP
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import logging

logging.basicConfig(level=logging.INFO)
def send_email(email, code):
    """
    Envoie email via SMTP
    
    Configuration requise en variables d'environnement:
    - SMTP_HOST (ex: smtp.gmail.com)
    - SMTP_PORT (ex: 587)
    - SMTP_USER (votre email)
    - SMTP_PASSWORD (mot de passe ou app password)
    """
    smtp_host ="smtp.gmail.com"
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = "kbhnb90@gmail.com"
    smtp_password = "iciphtshlyqosopi"
    
    # Mode dev - affiche le code
    if not smtp_host or not smtp_user or not smtp_password:
        logging.warning(f"SMTP not configured - displaying code for {email}")
        print(f"\n{'='*50}")
        print(f"CODE pour {email}: {code}")
        print(f"{'='*50}\n")
        return
    
    try:
        # Création du message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Code de verification'
        msg['From'] = smtp_user
        msg['To'] = email
        
        # Version texte
        text = f"""
            Votre code de verification: {code}

            Ce code expire dans 10 minutes.

            Si vous n'avez pas demande ce code, ignorez cet email.
            """
        
        # Version HTML
        html = f"""
            <html>
            <body>
                <h2>Code de verification</h2>
                <p>Votre code de verification: <strong style="font-size: 24px; color: #2563eb;">{code}</strong></p>
                <p>Ce code expire dans 10 minutes.</p>
                <hr>
                <p style="color: #666; font-size: 12px;">Si vous n'avez pas demande ce code, ignorez cet email.</p>
            </body>
            </html>
            """
        
        # Attacher les deux versions
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        # Connexion SMTP
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()  # Chiffrement TLS
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        
        logging.info(f"Email sent to {email}")
        
    except smtplib.SMTPAuthenticationError:
        logging.error("SMTP Authentication failed - check credentials")
        raise Exception("Erreur authentification SMTP")
    except smtplib.SMTPException as e:
        logging.error(f"SMTP error: {e}")
        raise Exception("Erreur envoi email")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise Exception("Erreur envoi email")


# TEST
if __name__ == '__main__':
    print("TEST - Envoi email SMTP\n")
    
    # Configuration de test
    test_email = input("Email destinataire: ")
    test_code = "123456"
    
    print("\nConfiguration SMTP:")
    print(f"  SMTP_HOST: {os.getenv('SMTP_HOST', 'NOT SET')}")
    print(f"  SMTP_PORT: {os.getenv('SMTP_PORT', '587')}")
    print(f"  SMTP_USER: {os.getenv('SMTP_USER', 'NOT SET')}")
    print(f"  SMTP_PASSWORD: {'***' if os.getenv('SMTP_PASSWORD') else 'NOT SET'}")
    print()
    
    try:
        send_email(test_email, test_code)
        print("\nSUCCES: Email envoye")
    except Exception as e:
        print(f"\nERREUR: {e}")
