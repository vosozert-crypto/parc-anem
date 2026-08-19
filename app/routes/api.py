import hashlib
import json
import os
import secrets

from flask import Blueprint, Blueprint, jsonify, request

from app import get_db
from app.routes.auth import login_required

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
        return jsonify({"erreur": "JSON requis avec clé 'machines'."}), 400
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
            continues
        if nom in existants:
            ignores += 1
            continue
        db.execute(
            """INSERT INTO machines (nom, numero_serie, marque_modele, processeur,
               generation, ram_go, disque, arch, user_session, obs)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (nom, m.get("numero_serie", ""), m.get("marque_modele", ""),
             m.get("processeur", ""), m.get("generation", ""), m.get("ram_go", ""),
             m.get("disque", ""), m.get("arch", ""), m.get("user_session", ""),
             m.get("obs", "")),
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
        return jsonify({"erreur": "JSON requis avec clé 'imprimantes'."}), 400
    db = get_db()
    existants_ip = {
        r["adresse_ip"]
        for r in db.execute("SELECT adresse_ip FROM imprimantes WHERE adresse_ip != ''").fetchall()
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
               reference_toner, stock_toner, source_machine, remarques)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (nom or "Imprimante " + ip, ip, p.get("marque_modele", ""),
             p.get("reference_toner", ""), p.get("stock_toner", 0),
             p.get("source_machine", ""), p.get("remarques", "")),
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
    imprimantes = db.execute("SELECT COUNT(*) AS n FROM imprimantes").fetchone()["n"]
    users = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    return jsonify({"machines": machines, "imprimantes": imprimantes, "users": users})
