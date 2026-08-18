# Parc ANEM

Application web de gestion du parc informatique ANEM (inventaire, imprimantes, consommables, partage).

## Fonctionnalites

- **Inventaire** : gestion des postes PC avec scan reseau automatique
- **Imprimantes** : scan reseau (SNMP) + USB/WMI, detection auto des stocks toner
- **Besoins consommables** : suivi des besoins par site (AWEM/ALEM)
- **Partage** : repartition des consommables entre sites avec auto-somme
- **Securite** : suivi des imprimantes et peripheriques USB
- **Utilisateurs** : gestion des comptes et roles (admin/user)
- **Statistiques** : tableaux de bord sur la page d'accueil

## Stack

- Python 3.11 / Flask 3.1.3
- SQLite (parc_anem.db)
- Jinja2 / HTML / CSS
- openpyxl (imports Excel)
- Gunicorn (production)

## Installation

```bash
git clone https://github.com/vosozert-crypto/parc-anem.git
cd parc-anem
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
python app.py
```

L'app tourne sur **http://localhost:5000**

## Comptes par defaut

| Email | Mot de passe | Role | Site |
|---|---|---|---|
| admin@anem.dz | admin | Admin | AWEM bouira |

## Deploiement

### Render
Le fichier `render.yaml` est preconfigure. Connectez le repo sur Render pour un deploiement auto.

### Railway
Connectez le repo GitHub sur Railway avec :
- Build : `pip install -r requirements.txt`
- Start : `gunicorn app:app --bind 0.0.0.0:$PORT`

### PythonAnywhere
Clonez le repo, installez les deps, creez une app Web WSGI pointant vers `app:app`.

## Structure

```
parc-anem/
  app/
    __init__.py          # create_app(), init_db()
    routes/              # auth, inventaire, imprimantes, besoins, partage, securite
    templates/           # pages HTML (Jinja2)
    static/              # CSS, logo
    scan.py              # scan reseau (WMI conditionnel Linux)
    snmp.py              # interrogation SNMP imprimantes
    donnees_consommables.py  # catalogue, sites, codes
  render.yaml
  requirements.txt
  passenger_wsgi.py      # point d'entree WSGI (PythonAnywhere)
```
