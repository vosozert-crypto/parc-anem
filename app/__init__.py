import os
import sqlite3

from flask import Flask, current_app, g

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "parc_anem.db"
)


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "changer-cette-cle-en-production"),
        DATABASE=DB_PATH,
    )
    if config:
        app.config.update(config)

    from app.routes.auth import auth_bp
    from app.routes.besoins import besoins_bp
    from app.routes.imprimantes import imprimantes_bp
    from app.routes.inventaire import inventaire_bp
    from app.routes.main import main_bp
    from app.routes.partage import partage_bp
    from app.routes.securite import securite_bp
    from app.routes.utilisateurs import utilisateurs_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(inventaire_bp)
    app.register_blueprint(imprimantes_bp)
    app.register_blueprint(securite_bp)
    app.register_blueprint(utilisateurs_bp)
    app.register_blueprint(besoins_bp)
    app.register_blueprint(partage_bp)

    from app.donnees_consommables import site_code

    app.jinja_env.filters["site_code"] = site_code

    with app.app_context():
        init_db()

    return app


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def _resynchroniser_catalogue(conn):
    """Aligne la table consommables sur le catalogue du fichier Excel."""
    from app.donnees_consommables import CATALOGUE, ref_toner_par_defaut

    existant = {}
    for r in conn.execute("SELECT id, site, designation FROM consommables"):
        existant.setdefault(r["site"], {}).setdefault(r["designation"], []).append(r["id"])

    for site, designations in CATALOGUE.items():
        ancien = existant.get(site, {})
        reste = {d: list(ids) for d, ids in ancien.items()}
        for designation in designations:
            if reste.get(designation):
                reste[designation].pop(0)
            else:
                cur = conn.execute(
                    "INSERT INTO consommables (site, designation, ref_toner) VALUES (?, ?, ?)",
                    (site, designation, ref_toner_par_defaut(designation)),
                )
                reste.setdefault(designation, [])
        for designation, ids in reste.items():
            for cid in ids:
                conn.execute("DELETE FROM besoins WHERE consommable_id = ?", (cid,))
                conn.execute("DELETE FROM consommables WHERE id = ?", (cid,))
        existant[site] = reste

    for site in list(existant.keys()):
        if site not in CATALOGUE:
            for designation, ids in existant[site].items():
                for cid in ids:
                    conn.execute("DELETE FROM besoins WHERE consommable_id = ?", (cid,))
                    conn.execute("DELETE FROM consommables WHERE id = ?", (cid,))
    for r in conn.execute(
        "SELECT id, designation FROM consommables WHERE ref_toner IS NULL OR ref_toner = ''"
    ):
        ref = ref_toner_par_defaut(r["designation"])
        if ref:
            conn.execute("UPDATE consommables SET ref_toner = ? WHERE id = ?", (ref, r["id"]))
    conn.commit()


def _resynchroniser_partage(conn):
    """Aligne partage_catalogue sur la liste des consommables partagés (le catalogue est extensible par l'admin)."""
    from app.donnees_consommables import CATALOGUE_PARTAGE

    existant = {
        r["designation"]: r["id"]
        for r in conn.execute("SELECT id, designation FROM partage_catalogue")
    }
    for designation in CATALOGUE_PARTAGE:
        if designation not in existant:
            conn.execute(
                "INSERT INTO partage_catalogue (designation) VALUES (?)",
                (designation,),
            )
    conn.commit()


def init_db():
    from werkzeug.security import generate_password_hash

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            mot_de_passe TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            date_ajout TEXT DEFAULT (datetime('now'))
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS machines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            numero_serie TEXT,
            marque_modele TEXT,
            processeur TEXT,
            generation TEXT,
            ram_go TEXT,
            disque TEXT,
            arch TEXT,
            user_session TEXT,
            obs TEXT,
            date_ajout TEXT DEFAULT (datetime('now'))
        )"""
    )
    colonnes = {r[1] for r in conn.execute("PRAGMA table_info(machines)").fetchall()}
    if "user_session" not in colonnes:
        conn.execute("ALTER TABLE machines ADD COLUMN user_session TEXT")
    colonnes_users = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "date_ajout" not in colonnes_users:
        conn.execute("ALTER TABLE users ADD COLUMN date_ajout TEXT")
        conn.execute("UPDATE users SET date_ajout = datetime('now')")
    if "site" not in colonnes_users:
        conn.execute("ALTER TABLE users ADD COLUMN site TEXT")
    colonnes_users_apres = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    conn.execute(
        """CREATE TABLE IF NOT EXISTS imprimantes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            adresse_ip TEXT,
            marque_modele TEXT,
            reference_toner TEXT,
            stock_toner INTEGER DEFAULT 0,
            niveau_toner INTEGER,
            source_machine TEXT,
            remarques TEXT,
            date_ajout TEXT DEFAULT (datetime('now'))
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS consommables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            designation TEXT NOT NULL,
            ref_toner TEXT
        )"""
    )
    colonnes_consommables = {r[1] for r in conn.execute("PRAGMA table_info(consommables)").fetchall()}
    if "ref_toner" not in colonnes_consommables:
        conn.execute("ALTER TABLE consommables ADD COLUMN ref_toner TEXT")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS besoins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            consommable_id INTEGER NOT NULL,
            annee INTEGER NOT NULL,
            stock TEXT DEFAULT '',
            besoin INTEGER DEFAULT 0,
            etat TEXT DEFAULT '',
            rempli_par TEXT,
            date_maj TEXT DEFAULT (datetime('now')),
            UNIQUE(consommable_id, annee)
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS partage_catalogue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            designation TEXT NOT NULL,
            masque INTEGER DEFAULT 0,
            date_ajout TEXT DEFAULT (datetime('now'))
        )"""
    )
    colonnes_partage = {r[1] for r in conn.execute("PRAGMA table_info(partage_catalogue)").fetchall()}
    if "masque" not in colonnes_partage:
        conn.execute("ALTER TABLE partage_catalogue ADD COLUMN masque INTEGER DEFAULT 0")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS partage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            annee INTEGER NOT NULL,
            designation_id INTEGER NOT NULL,
            qte_achetee INTEGER DEFAULT 0,
            partage_total INTEGER DEFAULT 0,
            repartition TEXT DEFAULT '{}',
            rempli_par TEXT,
            date_maj TEXT DEFAULT (datetime('now')),
            UNIQUE(annee, designation_id)
        )"""
    )
    conn.commit()
    from app.donnees_consommables import CATALOGUE, SITES_PAR_DEFAUT

    _resynchroniser_catalogue(conn)
    _resynchroniser_partage(conn)
    if "site" in colonnes_users_apres:
        for prefixe, site in SITES_PAR_DEFAUT.items():
            conn.execute(
                "UPDATE users SET site = ? WHERE email LIKE ? AND (site IS NULL OR site = '')",
                (site, prefixe + "%"),
            )
        conn.commit()
    cur = conn.execute("SELECT COUNT(*) AS n FROM users")
    if cur.fetchone()["n"] == 0:
        conn.execute(
            "INSERT INTO users (nom, email, mot_de_passe, role) VALUES (?, ?, ?, ?)",
            (
                "Administrateur",
                "admin@anem.dz",
                generate_password_hash("admin"),
                "admin",
            ),
        )
        conn.commit()
    conn.close()
