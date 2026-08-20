# PRD — Parc ANEM

Gestion du parc informatique ANEM : inventaire des ordinateurs, imprimantes, consommables et partage entre sites.

## 1. Vue d'ensemble

- **Type** : Application web métier (intranet/cloud)
- **But** : Centraliser et suivre le parc informatique ANEM (AWEM/ALEM)
- **Public** : Admins et utilisateurs par site
- **Déploiement** : Railway (cloud, auto-deploy GitHub)

## 2. Acteurs & rôles

| Rôle | Droits |
|---|---|
| **Admin** | Accès complet : tous les sites, partage, utilisateurs, sécurité |
| **User** | Lecture/ajout limité à son site |

- Compte par défaut : `admin@anem.dz` / `admin`

## 3. Stack technique

| Composant | Choix |
|---|---|
| Backend | Python 3.11 / Flask 3.1.3 |
| Base de données | SQLite (`parc_anem.db`) |
| Templates | Jinja2 / HTML / CSS |
| Import Excel | openpyxl |
| Scan réseau | PowerShell (BAT généré), WMI, SNMP |
| Production | Gunicorn |

## 4. Modules fonctionnels

### 4.1 Ordinateurs (ex-Inventaire)
- Liste du parc par site (admin = tous)
- Scan réseau via fichier `.bat` téléchargé depuis l'app
- Le BAT : auto-détecte le sous-réseau `10.10.x.100-254` (x=0..6), ping parallèle (runspace pool 80), WMI parallèle (pool 20)
- Export CSV / Excel
- Import CSV / Excel (auto-détection PC vs imprimantes)
- Actions par poste : Ping, RDP, Envoyer message, Imprimantes, Modifier, Supprimer
- Champs : nom, n° série, marque/modèle, processeur, RAM, disque, OS, génération, session, obs, site

### 4.2 Imprimantes
- Scan réseau (SNMP ports 515/631/9100) + découverte WMI (USB + réseau)
- Détection automatique des stocks et niveaux de toner
- CRUD, lecture toner (SNMP)
- Import CSV / Excel
- Champs : nom, adresse IP, marque/modèle, référence toner, stock toner, niveau toner, source machine, site

### 4.3 Consommables
- **Besoins** : suivi des besoins par site (AWEM/ALEM)
- **Partage** : répartition entre sites avec auto-somme
- Année limite 2026-2036

### 4.4 Sécurité
- Vérification Kaspersky (installé, actif, à jour, version)
- Ports ouverts, vulnérabilité SMB (SMBv1 + MS17-010)
- Scan imprimantes et périphériques USB (WMI)

### 4.5 Utilisateurs
- Gestion des comptes (CRUD), mot de passe
- Rôles admin/user, filtrage par site

### 4.6 Statistiques
- Tableaux de bord page d'accueil (inventaire, imprimantes, stock toner faible, partage)

## 5. Parcours de scan réseau (BAT)

1. Utilisateur télécharge le `.bat` depuis Ordinateurs/Imprimantes
2. Le script détecte l'IP locale, déduit le sous-réseau10.10.x
3. Ping parallèle de 10.10.x.100-254 (155 adresses)
4. WMI parallèle sur les PC actifs (système, OS, processeur, BIOS, imprimantes)
5. Ajout des imprimantes USB locales
6. Menu de choix : envoi Railway / CSV / les deux

## 6. Import / Export

- **Import** : CSV/Excel via `/api/scan/import` (login requis)
- Le détecteur sépare automatiquement ordinateurs et imprimantes
- **Export** : CSV et Excel depuis les pages listes
- API scan : `/api/scan/machines` et `/api/scan/imprimantes` (auth Bearer token)

## 7. Contraintes techniques

- Token API : `anem-scan-2026-secret` (configurable via `API_TOKEN`)
- Scan web côté serveur ne peut pas joindre le réseau local (cloud) → utilisation du BAT obligatoire
- Script BAT : exécution PowerShell en `ExecutionPolicy Bypass`, parallélisme runspace

## 8. Déploiement

- **Railway** : connecter repo GitHub, build `pip install -r requirements.txt`, start `gunicorn app:app --bind 0.0.0.0:$PORT`
- **Render** : `render.yaml` préconfiguré
- **PythonAnywhere** : point WSGI `passenger_wsgi.py`

## 9. Hors périmètre (v1)

- Authentification forte (2FA)
- Gestion des licences logicielles
- API publique externe
- Multi-bases de données (PostgreSQL en prod)