#!/usr/bin/env python3

"""
Script d'audit de sécurité - Projet AEGIS
Vérifie les mesures de durcissement appliquées sur la machine
"""

import subprocess
import re
import os
import glob
import string
import pwd
import crypt
from datetime import datetime, timedelta

# Couleurs pour l'affichage
VERT = "\033[92m"
ROUGE = "\033[91m"
RESET = "\033[0m"

resultats = []

def check(nom, condition, details=""):
    """Enregistre le résultat d'un test"""
    statut = "PASS" if condition else "FAIL"
    couleur = VERT if condition else ROUGE
    resultats.append((nom, statut))
    print(f"[{couleur}{statut}{RESET}] {nom}" + (f" - {details}" if details else ""))

def lire_fichier(chemin):
    """Lit un fichier et retourne son contenu, ou None si absent"""
    try:
        with open(chemin, "r") as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None

def lire_shadow():
    """Lit /etc/shadow et retourne un dict {username: hash}"""
    shadow_data = {}
    try:
        with open("/etc/shadow", "r") as f:
            for line in f:
                champs = line.strip().split(":")
                if len(champs) >= 2:
                    shadow_data[champs[0]] = champs[1]
    except (FileNotFoundError, PermissionError):
        pass
    return shadow_data

def commande(cmd):
    """Exécute une commande shell et retourne stdout"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return result.stdout.strip()
    except Exception:
        return ""

def service_actif(nom_service):
    """Vérifie si un service systemd est actif"""
    out = commande(f"systemctl is-active {nom_service}")
    return out == "active"

print("=" * 55)
print(" AUDIT DE SECURITE - PROJET AEGIS - SRV-PROD-02")
print("=" * 55)

# --- 1. SSH ---
print("\n--- SSH ---")
sshd_config = lire_fichier("/etc/ssh/sshd_config")
if sshd_config:
    check("Root login désactivé",
            re.search(r"^\s*PermitRootLogin\s+no", sshd_config, re.MULTILINE) is not None)
    check("Authentification par mot de passe désactivée",
            re.search(r"^\s*PasswordAuthentication\s+no", sshd_config, re.MULTILINE) is not None)
else:
    check("Fichier sshd_config trouvé", False)

# --- 2. Firewall (ufw) ---
print("\n--- Firewall ---")
ufw_status = commande("sudo ufw status")
check("UFW actif", "Status: active" in ufw_status)
check("Port SSH autorisé", "22" in ufw_status or "ssh" in ufw_status.lower())
check("Port HTTP autorisé (80)", "80" in ufw_status)
check("Port HTTPS autorisé (443)", "443" in ufw_status)

# --- 3. Fail2ban ---
print("\n--- Fail2ban ---")
check("Fail2ban installé et actif", service_actif("fail2ban"))

# --- 4. Permissions ---
print("\n--- Permissions ---")
dossier_web = "/var/www/html"
if os.path.exists(dossier_web):
    mode = oct(os.stat(dossier_web).st_mode)[-3:]
    check(f"Permissions dossier web ({dossier_web})",
            mode != "777", f"mode actuel: {mode}")
else:
    check("Dossier web trouvé", False, f"{dossier_web} introuvable")

# --- 5. MariaDB ---
print("\n--- MariaDB ---")
mariadb_conf = lire_fichier("/etc/mysql/mariadb.conf.d/50-server.cnf")
if mariadb_conf:
    check("MariaDB écoute uniquement en local",
            re.search(r"^\s*bind-address\s*=\s*127\.0\.0\.1", mariadb_conf, re.MULTILINE) is not None)
else:
    check("Fichier de config MariaDB trouvé", False)

# --- 6. Mises à jour automatiques ---
print("\n--- Mises à jour automatiques ---")
check("unattended-upgrades actif", service_actif("unattended-upgrades"))

# --- 7. HTTPS ---
print("\n--- HTTPS ---")
nginx_conf = lire_fichier("/etc/nginx/sites-enabled/default")
if nginx_conf:
    listen_443 = re.search(r"^\s*listen 443 ssl", nginx_conf, re.MULTILINE)
    ssl_cert = re.search(r"^\s*ssl_certificate\s+\S+", nginx_conf, re.MULTILINE)
    ssl_key = re.search(r"^\s*ssl_certificate_key\s+\S+", nginx_conf, re.MULTILINE)
    check("Nginx écoute en HTTPS (443 ssl)", listen_443 is not None)
    check("Certificat SSL référencé", ssl_cert is not None)
    check("Clé privée SSL référencée", ssl_key is not None)
else:
    check("Fichier config Nginx trouvé", False)

nginx_test = commande("sudo nginx -t 2>&1")
check("Configuration Nginx valide", "syntax is ok" in nginx_test and "test is successful" in nginx_test)

# --- 8. Logs ---
print("\n--- Logs ---")
check("Logrotate configuré", os.path.exists("/etc/logrotate.d"))
check("Rotation logs Nginx", os.path.exists("/etc/logrotate.d/nginx"))

# --- 9. Sauvegardes ---
print("\n--- Sauvegardes ---")
script_backup = os.path.exists("/etc/scripts/backup.sh") and os.access("/etc/scripts/backup.sh", os.X_OK)
check("Script de backup présent et exécutable", script_backup)

cron_root = commande("sudo crontab -l 2>/dev/null")
check("Tâche cron de backup planifiée", "backup.sh" in cron_root)

backups = glob.glob("/var/backups/web/backup_*.tar.gz")
check("Au moins une sauvegarde existe", len(backups) > 0, f"{len(backups)} fichier(s) trouvé(s)")

if backups:
    dernier_backup = max(backups, key=os.path.getmtime)
    age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(dernier_backup))
    check("Sauvegarde récente (< 7 jours)", age < timedelta(days=7),

            f"dernière sauvegarde il y a {age.days} jour(s)")
#verif mdp
filepath = './100k-most-used-passwords-NCSC.txt'
def common_passwords(filepath):
    common=[]
    try:
        with open(filepath, "r") as f:
            for line in f:
                common.append(line.strip().lower())
    except FileNotFoundError:
        print(f"{ROUGE}Erreur: Le fichier {filepath} n'a pas été trouvé.{RESET}")
    return common
def password_check(password, common_list):
    score= 0
    feedback = []
    if len(password) >= 8:
        score +=1
    else:
        feedback.append("Le mot de passe doit être au minimum de 8 caractères")
    if len(password) >= 12:
        score +=1
        feeback.append("mot de passe fort")
    if any(c in string.ascii_uppercase for c in password):
        score += 1
    else:
        feedback.append("Ajoutez au minimum une majuscule")
    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append("Ajoutez au minimum un caractère spécial")
    if any(c in string.digits for c in password):
        score += 1
    else:
        feedbackappend("Ajoutez au minimum un chiffre")
    if password.lower() in common_list:
        feedback = ["Ce mot de passe est dans la liste des mots de passes communs. Choisissez un autre"]
    return score, feedback
def main_password_checker():
    strength_labels = {
        0: "Très Faible",
        1: "Faible",
        2: "Modéré",
        3: "Bon",
        4: "Fort",
        5: "Très Fort"
    }

    common_list = common_passwords(filepath)
    if not common_list:
        print(f"{ROUGE}Impossible de procéder à la vérification des mots de passe sans la liste des mots de passe communs.{RESET}")
        return

    print("\n--- Audit des mots de passe des utilisateurs Linux ---")

    shadow_data = lire_shadow()

    try:
        for user_entry in pwd.getpwall():
            username = user_entry.pw_name

            try:
                hashed_password = shadow_data.get(username)

                if not hashed_password or hashed_password in ('!', '*', ''):
                    continue

                parts = hashed_password.split('$')
                salt = f"${parts[1]}${parts[2]}" if len(parts) >= 3 else hashed_password[:2]

                is_common = False
                for common_pwd_candidate in common_list:
                    hashed_common_pwd = crypt.crypt(common_pwd_candidate, salt)

                    if hashed_common_pwd == hashed_password:
                        check(f"Utilisateur '{username}' utilise un mot de passe commun", False, "Mot de passe faible détecté")
                        is_common = True
                        break

                if not is_common:
                    check(f"Utilisateur '{username}' n'utilise pas de mot de passe commun", True)

            except PermissionError:
                print(f"{ROUGE}Erreur de permission: Impossible de lire les mots de passe hachés pour l'utilisateur '{username}'. Exécutez le script avec des privilèges suffisants (sudo).{RESET}")
                break
            except Exception as e:
                print(f"{ROUGE}Erreur inattendue lors de la vérification de l'utilisateur '{username}': {e}{RESET}")
                continue

    except PermissionError:
        print(f"{ROUGE}Erreur de permission: Impossible de lister les utilisateurs du système. Exécutez le script avec des privilèges suffisants (sudo).{RESET}")
        return
    except Exception as e:
        print(f"{ROUGE}Erreur inattendue lors de la liste des utilisateurs: {e}{RESET}")
        return

    print("\n--- Vérificateur de force de mot de passe interactif ---")
    while True:
        password_to_check = input("Entrez un mot de passe à vérifier (ou 'q' pour quitter): ").strip()
        if password_to_check.lower() == 'q':
            break

        if not password_to_check:
            print("Veuillez entrer un mot de passe.")
            continue

        score, feedback = password_check(password_to_check, common_list)
        strength = strength_labels.get(score, "Inconnu")

        print(f"Force du mot de passe: {strength} (Score: {score}/5)")
        if feedback:
            print("Conseils:")
            for item in feedback:
                print(f" - {item}")
        else:
            print("Ce mot de passe semble fort et n'est pas dans la liste des mots de passe communs.")
        print("-" * 30)
main_password_checker()
    # --- Résumé ---
print("\n" + "=" * 55)
total = len(resultats)
reussis = sum(1 for _, s in resultats if s == "PASS")
print(f" RESULTAT : {reussis}/{total} vérifications passées")
print("=" * 55)

if reussis < total:
    print("\nPoints à corriger :")
    for nom, statut in resultats:
        if statut == "FAIL":
            print(f"  - {nom}")
else:
    print("\nToutes les vérifications sont passées avec succès.")
