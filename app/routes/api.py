import csv
import io
import json
import os
import re

from flask import (
    Blueprint, Response, jsonify, redirect, request, session, url_for,
)

from app import get_db
from app.routes.auth import login_required, admin_required

api_bp = Blueprint("api", __name__, url_prefix="/api")

API_TOKEN = os.environ.get("API_TOKEN", "anem-scan-2026-secret")


def _check_token():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    if not token:
        token = request.args.get("token", "")
    if token != API_TOKEN:
        return jsonify({"erreur": "Token invalide."}), 401
    return None


@api_bp.route("/scan/machines", methods=["POST"])
def recevoir_machines():
    err = _check_token()
    if err:
        return err
    data = request.get_json(force=True, silent=True)
    if not data or "machines" not in data:
        return jsonify({"erreur": "JSON requis avec cle 'machines'."}), 400
    db = get_db()
    site = data.get("site", "")
    existants = {
        r["nom"] for r in db.execute("SELECT nom FROM machines").fetchall()
    }
    ajoutes = 0
    ignores = 0
    for m in data["machines"]:
        nom = (m.get("nom") or "").strip()
        if not nom:
            continue
        if nom in existants:
            ignores += 1
            continue
        db.execute(
            """INSERT INTO machines (nom, numero_serie, marque_modele, processeur,
               generation, ram_go, disque, arch, user_session, obs, site)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (nom, m.get("numero_serie", ""), m.get("marque_modele", ""),
             m.get("processeur", ""), m.get("generation", ""),
             m.get("ram_go", ""), m.get("disque", ""), m.get("arch", ""),
             m.get("user_session", ""), m.get("obs", ""),
             m.get("site", site)),
        )
        existants.add(nom)
        ajoutes += 1
    db.commit()
    return jsonify({"ajoutes": ajoutes, "ignores": ignores, "total": len(data["machines"])})


@api_bp.route("/scan/imprimantes", methods=["POST"])
def recevoir_imprimantes():
    err = _check_token()
    if err:
        return err
    data = request.get_json(force=True, silent=True)
    if not data or "imprimantes" not in data:
        return jsonify({"erreur": "JSON requis avec cle 'imprimantes'."}), 400
    db = get_db()
    existants_ip = {
        r["adresse_ip"]
        for r in db.execute(
            "SELECT adresse_ip FROM imprimantes WHERE adresse_ip != ''"
        ).fetchall()
    }
    existants_nom = {
        r["nom"] for r in db.execute("SELECT nom FROM imprimantes").fetchall()
    }
    ajoutes = 0
    ignores = 0
    for p in data["imprimantes"]:
        ip = (p.get("adresse_ip") or "").strip()
        nom = (p.get("nom") or "").strip()
        if not nom and not ip:
            continue
        if ip and ip in existants_ip:
            ignores += 1
            continue
        if nom and nom in existants_nom:
            ignores += 1
            continue
            db.execute(
                """INSERT INTO imprimantes (nom, adresse_ip, marque_modele,
                   reference_toner, stock_toner, source_machine, remarques, site)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (nom or "Imprimante " + ip, ip, p.get("marque_modele", ""),
                 p.get("reference_toner", ""), p.get("stock_toner", 0),
                 p.get("source_machine", ""), p.get("remarques", ""),
                 p.get("site", site)),
            )
        if ip:
            existants_ip.add(ip)
        if nom:
            existants_nom.add(nom)
        ajoutes += 1
    db.commit()
    return jsonify({"ajoutes": ajoutes, "ignores": ignores, "total": len(data["imprimantes"])})


@api_bp.route("/scan/status", methods=["GET"])
def status():
    err = _check_token()
    if err:
        return err
    db = get_db()
    machines = db.execute("SELECT COUNT(*) AS n FROM machines").fetchone()["n"]
    imprimantes = db.execute(
        "SELECT COUNT(*) AS n FROM imprimantes"
    ).fetchone()["n"]
    users = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    return jsonify({"machines": machines, "imprimantes": imprimantes, "users": users})


@api_bp.route("/scan/import", methods=["POST"])
@login_required
def import_excel():
    fichier = request.files.get("fichier")
    if not fichier:
        return jsonify({"erreur": "Aucun fichier envoye."}), 400

    filename = (fichier.filename or "").lower()
    content = fichier.read().decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(content))
    rows = list(reader)
    if len(rows) < 2:
        return jsonify({"erreur": "Fichier vide ou sans donnees."}), 400

    header = [h.strip().lower().replace(" ", "_") for h in rows[0]]

    def find_col(possibles):
        for p in possibles:
            for i, h in enumerate(header):
                if p in h:
                    return i
        return None

    col_nom = find_col(["nom", "hostname", "pc"])
    col_sn = find_col(["numero_serie", "serial", "sn"])
    col_modele = find_col(["marque_modele", "modele", "model", "marque"])
    col_proc = find_col(["processeur", "cpu", "processor"])
    col_ram = find_col(["ram", "memoire", "memory"])
    col_arch = find_col(["arch", "architecture", "os"])
    col_site = find_col(["site", "location", "localisation"])

    db = get_db()
    site_utilisateur = session.get("site", "")
    existants_machines = {
        r["nom"] for r in db.execute("SELECT nom FROM machines").fetchall()
    }
    existants_imp_ip = {
        r["adresse_ip"]
        for r in db.execute(
            "SELECT adresse_ip FROM imprimantes WHERE adresse_ip != ''"
        ).fetchall()
    }
    existants_imp_nom = {
        r["nom"] for r in db.execute("SELECT nom FROM imprimantes").fetchall()
    }

    ajoutes_machines = 0
    ajoutes_imp = 0
    ignores = 0

    for row in rows[1:]:
        if len(row) < 2:
            continue
        vals = [c.strip() if c else "" for c in row]
        nom = vals[col_nom] if col_nom is not None and col_nom < len(vals) else ""
        if not nom:
            continue

        is_imprimante = "impr" in (filename or "") or any(
            kw in " ".join(vals).lower()
            for kw in ["imprimante", "printer", "toner", "hp ", "brother", "canon", "xerox"]
        )

        if is_imprimante:
            ip = vals[1] if len(vals) > 1 else ""
            if ip in existants_imp_ip or nom in existants_imp_nom:
                ignores += 1
                continue
            mode = vals[col_modele] if col_modele is not None and col_modele < len(vals) else ""
            source = vals[col_site] if col_site is not None and col_site < len(vals) else ""
            db.execute(
                """INSERT INTO imprimantes (nom, adresse_ip, marque_modele,
                   reference_toner, stock_toner, source_machine, remarques, site)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (nom, ip, mode, "", 0, source, "import excel", site_utilisateur),
            )
            if ip:
                existants_imp_ip.add(ip)
            existants_imp_nom.add(nom)
            ajoutes_imp += 1
        else:
            if nom in existants_machines:
                ignores += 1
                continue
            sn = vals[col_sn] if col_sn is not None and col_sn < len(vals) else ""
            modele = vals[col_modele] if col_modele is not None and col_modele < len(vals) else ""
            proc = vals[col_proc] if col_proc is not None and col_proc < len(vals) else ""
            ram = vals[col_ram] if col_ram is not None and col_ram < len(vals) else ""
            arch = vals[col_arch] if col_arch is not None and col_arch < len(vals) else ""
            site = (vals[col_site] if col_site is not None and col_site < len(vals) else "") or site_utilisateur
            db.execute(
                """INSERT INTO machines (nom, numero_serie, marque_modele, processeur,
                   generation, ram_go, disque, arch, user_session, obs, site)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (nom, sn, modele, proc, "", ram, "", arch, "", "import excel", site),
            )
            existants_machines.add(nom)
            ajoutes_machines += 1

    db.commit()
    return jsonify({
        "ajoutes_machines": ajoutes_machines,
        "ajoutes_imprimantes": ajoutes_imp,
        "ignores": ignores,
    })
