import os

from flask import Flask, current_app, g

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "parc_anem.db"
)


def _is_pg():
    return bool(os.environ.get("DATABASE_URL"))


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

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db is not None:
            try:
                db.close()
            except Exception:
                pass

    with app.app_context():
        init_db()

    return app


def get_db():
    if "db" not in g:
        from app.db import get_connection
        g.db = get_connection()
    return g.db


def _exec(db, sql, params=()):
    cur = db.execute(sql, params)
    if _is_pg():
        return cur.fetchall()
    else:
        import sqlite3
        return [dict(r) for r in cur.fetchall()]


def _resynchroniser_catalogue(db):
    from app.donnees_consommables import CATALOGUE, ref_toner_par_defaut

    rows = _exec(db, "SELECT id, site, designation FROM consommables")
    existant = {}
    for r in rows:
        site = r["site"]
        designation = r["designation"]
        existant.setdefault(site, {}).setdefault(designation, []).append(r["id"])

    for site, designations in CATALOGUE.items():
        ancien = existant.get(site, {})
        reste = {d: list(ids) for d, ids in ancien.items()}
        for designation in designations:
            if reste.get(designation):
                reste[designation].pop(0)
            else:
                db.execute(
                    "INSERT INTO consommables (site, designation, ref_toner) VALUES (?, ?, ?)",
                    (site, designation, ref_toner_par_defaut(designation)),
                )
                reste.setdefault(designation, [])
        for designation, ids in reste.items():
            for cid in ids:
                db.execute("DELETE FROM besoins WHERE consommable_id = ?", (cid,))
                db.execute("DELETE FROM consommables WHERE id = ?", (cid,))
        existant[site] = reste

    for site in list(existant.keys()):
        if site not in CATALOGUE:
            for designation, ids in existant[site].items():
                for cid in ids:
                    db.execute("DELETE FROM besoins WHERE consommable_id = ?", (cid,))
                    db.execute("DELETE FROM consommables WHERE id = ?", (cid,))

    rows_to_fix = _exec(
        db, "SELECT id, designation FROM consommables WHERE ref_toner IS NULL OR ref_toner = ''"
    )
    for r in rows_to_fix:
        ref = ref_toner_par_defaut(r["designation"])
        if ref:
            db.execute("UPDATE consommables SET ref_toner = ? WHERE id = ?", (ref, r["id"]))
    db.commit()


def _resynchroniser_partage(db):
    from app.donnees_consommables import CATALOGUE_PARTAGE

    rows = _exec(db, "SELECT id, designation FROM partage_catalogue")
    existant = {r["designation"]: r["id"] for r in rows}
    for designation in CATALOGUE_PARTAGE:
        if designation not in existant:
            db.execute(
                "INSERT INTO partage_catalogue (designation) VALUES (?)",
                (designation,),
            )
    db.commit()


def init_db():
    from werkzeug.security import generate_password_hash
    from app.donnees_consommables import SITES_PAR_DEFAUT

    if _is_pg():
        _init_pg()
    else:
        _init_sqlite()

    db = get_db()

    _resynchroniser_catalogue(db)
    _resynchroniser_partage(db)

    if not _is_pg():
        import sqlite3
        raw = sqlite3.connect(DB_PATH)
        raw.row_factory = sqlite3.Row
        colonnes_users = {r[1] for r in raw.execute("PRAGMA table_info(users)").fetchall()}
        if "site" in colonnes_users:
            for prefixe, site in SITES_PAR_DEFAUT.items():
                raw.execute(
                    "UPDATE users SET site = ? WHERE email LIKE ? AND (site IS NULL OR site = '')",
                    (site, prefixe + "%"),
                )
            raw.commit()
        n = raw.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        raw.close()
    else:
        rows = _exec(db, "SELECT COUNT(*) AS n FROM users")
        n = rows[0]["n"] if rows else 0

    if n == 0:
        _seed_initial(db)
    else:
        _migrer_users(db)


def _migrer_users(db):
    """Ajoute les users du seed s'ils n'existent pas encore (migration auto)."""
    from werkzeug.security import generate_password_hash

    all_users = [
        ("alem.bouira", "alem.bouira@anem.dz", "Xt3jQKEUTe", "user", "ALEM bouira"),
        ("awem.bouira", "awem.bouira@anem.dz", "FyphYUo33L", "user", "AWEM bouira"),
        ("alem.selghozlane", "alem.selghozlane@anem.dz", "SoeY9IAfmO", "user", "ALEM seg"),
        ("alem.mchedellah", "alem.mchedellah@anem.dz", "qhMNW9mJWg", "user", "ALEM m'chedellah"),
        ("alem.lakhdaria", "alem.lakhdaria@anem.dz", "PM5uHjxEUV", "user", "ALEM lakhdaria"),
        ("alem.ainbessam", "alem.ainbessam@anem.dz", "EHPa2mXBaX", "user", "ALEM ain bessam"),
        ("alem.bordjkhris", "alem.bordjkhris@anem.dz", "Br0rdj!2026", "user", "ALEM bordj khris"),
    ]
    existing = {
        r["email"]: r["site"]
        for r in db.execute("SELECT email, site FROM users").fetchall()
    }
    for nom, email, pwd, role, site in all_users:
        if email not in existing:
            db.execute(
                "INSERT INTO users (nom, email, mot_de_passe, role, site) VALUES (?, ?, ?, ?, ?)",
                (nom, email, generate_password_hash(pwd), role, site),
            )
        elif not existing[email] and site:
            db.execute("UPDATE users SET site = ? WHERE email = ? AND (site IS NULL OR site = '')", (site, email))
    db.commit()


def _seed_initial(db):
    from werkzeug.security import generate_password_hash

    db.execute(
        "INSERT INTO users (nom, email, mot_de_passe, role) VALUES (?, ?, ?, ?)",
        ("Administrateur", "admin@anem.dz", generate_password_hash("admin"), "admin"),
    )
    users = [
        ("alem.bouira", "alem.bouira@anem.dz", "Xt3jQKEUTe", "user", "ALEM bouira"),
        ("awem.bouira", "awem.bouira@anem.dz", "FyphYUo33L", "user", "AWEM bouira"),
        ("alem.selghozlane", "alem.selghozlane@anem.dz", "SoeY9IAfmO", "user", "ALEM seg"),
        ("alem.mchedellah", "alem.mchedellah@anem.dz", "qhMNW9mJWg", "user", "ALEM m'chedellah"),
        ("alem.lakhdaria", "alem.lakhdaria@anem.dz", "PM5uHjxEUV", "user", "ALEM lakhdaria"),
        ("alem.ainbessam", "alem.ainbessam@anem.dz", "EHPa2mXBaX", "user", "ALEM ain bessam"),
        ("alem.bordjkhris", "alem.bordjkhris@anem.dz", "Br0rdj!2026", "user", "ALEM bordj khris"),
    ]
    for nom, email, pwd, role, site in users:
        db.execute(
            "INSERT INTO users (nom, email, mot_de_passe, role, site) VALUES (?, ?, ?, ?, ?)",
            (nom, email, generate_password_hash(pwd), role, site),
        )
    db.commit()


def _init_pg():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        nom TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        mot_de_passe TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        site TEXT,
        date_ajout TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS machines (
        id SERIAL PRIMARY KEY,
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
        date_ajout TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS imprimantes (
        id SERIAL PRIMARY KEY,
        nom TEXT NOT NULL,
        adresse_ip TEXT,
        marque_modele TEXT,
        reference_toner TEXT,
        stock_toner INTEGER DEFAULT 0,
        niveau_toner INTEGER,
        source_machine TEXT,
        remarques TEXT,
        date_ajout TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS consommables (
        id SERIAL PRIMARY KEY,
        site TEXT NOT NULL,
        designation TEXT NOT NULL,
        ref_toner TEXT
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS besoins (
        id SERIAL PRIMARY KEY,
        consommable_id INTEGER NOT NULL,
        annee INTEGER NOT NULL,
        stock TEXT DEFAULT '',
        besoin INTEGER DEFAULT 0,
        etat TEXT DEFAULT '',
        rempli_par TEXT,
        date_maj TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(consommable_id, annee)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS partage_catalogue (
        id SERIAL PRIMARY KEY,
        designation TEXT NOT NULL,
        masque INTEGER DEFAULT 0,
        date_ajout TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS partage (
        id SERIAL PRIMARY KEY,
        annee INTEGER NOT NULL,
        designation_id INTEGER NOT NULL,
        qte_achetee INTEGER DEFAULT 0,
        partage_total INTEGER DEFAULT 0,
        repartition TEXT DEFAULT '{}',
        rempli_par TEXT,
        date_maj TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(annee, designation_id)
    )""")
    db.commit()


def _init_sqlite():
    import sqlite3

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
    conn.close()
