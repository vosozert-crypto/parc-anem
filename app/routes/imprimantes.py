import datetime
import threading

from flask import Blueprint, flash, redirect, render_template, request, url_for

from app import get_db
from app.routes.auth import login_required
from app.scan import (
    construire_plage,
    detecter_cidr,
    lister_imprimantes,
    ping,
    scan_imprimantes_reseau,
)
from app.snmp import lire_toner

imprimantes_bp = Blueprint("imprimantes", __name__, url_prefix="/imprimantes")

_SCANS = {}
_SCANS_LOCK = threading.Lock()

CHAMPS = [
    ("nom", "Nom de l'imprimante"),
    ("adresse_ip", "Adresse IP"),
    ("marque_modele", "Marque / Modèle"),
    ("reference_toner", "Référence toner / cartouche"),
    ("stock_toner", "Nombre en stock"),
    ("source_machine", "Poste source"),
    ("remarques", "Remarques"),
]


def _toner_etat(niveau):
    """Badge d'état en fonction du niveau de toner (%)."""
    if niveau is None:
        return "inconnu", "—"
    if niveau < 15:
        return "epuise", "Épuisé"
    if niveau < 40:
        return "faible", "Faible"
    return "ok", "OK"


@imprimantes_bp.route("/")
@login_required
def liste():
    db = get_db()
    imprimantes = db.execute(
        "SELECT * FROM imprimantes ORDER BY nom"
    ).fetchall()
    return render_template("imprimantes/liste.html", imprimantes=imprimantes)


def _donnees_formulaire():
    donnees = {c[0]: request.form.get(c[0], "").strip() for c in CHAMPS}
    try:
        donnees["stock_toner"] = int(donnees["stock_toner"] or 0)
    except ValueError:
        donnees["stock_toner"] = 0
    return donnees


@imprimantes_bp.route("/ajouter", methods=["GET", "POST"])
@login_required
def ajouter():
    if request.method == "POST":
        donnees = _donnees_formulaire()
        if not donnees["nom"]:
            flash("Le nom de l'imprimante est obligatoire.", "danger")
            return render_template("imprimantes/formulaire.html", imp={}, titre="Ajouter une imprimante", champs=CHAMPS)
        db = get_db()
        db.execute(
            """INSERT INTO imprimantes (nom, adresse_ip, marque_modele, reference_toner,
               stock_toner, source_machine, remarques)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (donnees["nom"], donnees["adresse_ip"], donnees["marque_modele"],
             donnees["reference_toner"], donnees["stock_toner"],
             donnees["source_machine"], donnees["remarques"]),
        )
        db.commit()
        flash("Imprimante « " + donnees["nom"] + " » ajoutée.", "success")
        return redirect(url_for("imprimantes.liste"))
    return render_template("imprimantes/formulaire.html", imp={}, titre="Ajouter une imprimante", champs=CHAMPS)


def _trouver(pid):
    db = get_db()
    imp = db.execute("SELECT * FROM imprimantes WHERE id = ?", (pid,)).fetchone()
    return db, imp


@imprimantes_bp.route("/modifier/<int:pid>", methods=["GET", "POST"])
@login_required
def modifier(pid):
    db, imp = _trouver(pid)
    if imp is None:
        flash("Imprimante introuvable.", "warning")
        return redirect(url_for("imprimantes.liste"))
    if request.method == "POST":
        donnees = _donnees_formulaire()
        if not donnees["nom"]:
            flash("Le nom de l'imprimante est obligatoire.", "danger")
            return render_template("imprimantes/formulaire.html", imp=imp, titre="Modifier l'imprimante", champs=CHAMPS)
        db.execute(
            """UPDATE imprimantes SET nom = ?, adresse_ip = ?, marque_modele = ?,
               reference_toner = ?, stock_toner = ?, source_machine = ?, remarques = ?
               WHERE id = ?""",
            (donnees["nom"], donnees["adresse_ip"], donnees["marque_modele"],
             donnees["reference_toner"], donnees["stock_toner"],
             donnees["source_machine"], donnees["remarques"], pid),
        )
        db.commit()
        flash("Imprimante « " + donnees["nom"] + " » modifiée.", "success")
        return redirect(url_for("imprimantes.liste"))
    return render_template("imprimantes/formulaire.html", imp=imp, titre="Modifier l'imprimante", champs=CHAMPS)


@imprimantes_bp.route("/supprimer/<int:pid>", methods=["POST"])
@login_required
def supprimer(pid):
    db, imp = _trouver(pid)
    if imp is None:
        flash("Imprimante introuvable.", "warning")
        return redirect(url_for("imprimantes.liste"))
    db.execute("DELETE FROM imprimantes WHERE id = ?", (pid,))
    db.commit()
    flash("Imprimante « " + imp["nom"] + " » supprimée.", "info")
    return redirect(url_for("imprimantes.liste"))


@imprimantes_bp.route("/snmp/<int:pid>", methods=["POST"])
@login_required
def snmp(pid):
    db, imp = _trouver(pid)
    if imp is None:
        flash("Imprimante introuvable.", "warning")
        return redirect(url_for("imprimantes.liste"))
    hote = imp["adresse_ip"]
    if not hote:
        flash("Adresse IP absente : impossible d'interroger en SNMP.", "warning")
        return redirect(url_for("imprimantes.liste"))
    en_ligne, _ = ping(hote)
    if not en_ligne:
        flash("Imprimante injoignable (ping).", "danger")
        return redirect(url_for("imprimantes.liste"))
    info = lire_toner(hote)
    if info is None or info.get("niveau") is None:
        flash("Pas de réponse SNMP (toner non lu).", "warning")
        return redirect(url_for("imprimantes.liste"))
    db.execute(
        "UPDATE imprimantes SET niveau_toner = ? WHERE id = ?",
        (info["niveau"], pid),
    )
    db.commit()
    etat, libelle = _toner_etat(info["niveau"])
    flash(
        "Toner lu : niveau {}% ({}){}.".format(
            info["niveau"], libelle,
            " – " + info["description"] if info.get("description") else "",
        ),
        "success",
    )
    return redirect(url_for("imprimantes.liste"))


@imprimantes_bp.route("/decouvrir")
@login_required
def decouvrir():
    from concurrent.futures import ThreadPoolExecutor, as_completed

    db = get_db()
    machines = db.execute(
        "SELECT id, nom FROM machines ORDER BY nom"
    ).fetchall()
    trouves = {}
    erreurs = []
    verrou = __import__("threading").Lock()

    def _trait(m):
        en_ligne, _ = ping(m["nom"])
        if not en_ligne:
            return None
        resultat = lister_imprimantes(m["nom"])
        if resultat.get("erreur"):
            return (m["nom"], resultat["erreur"], None)
        return (None, None, resultat.get("liste", []))

    with ThreadPoolExecutor(max_workers=10) as executor:
        futurs = [executor.submit(_trait, m) for m in machines]
        for fut in as_completed(futurs):
            nom, erreur, liste = fut.result()
            with verrou:
                if erreur:
                    erreurs.append((nom, erreur))
                    continue
                for p in liste:
                    nom_p = p["nom"]
                    if nom_p in trouves:
                        continue
                    trouves[nom_p] = {
                        "nom": nom_p,
                        "partage": p["partage"],
                        "port": p["port"],
                        "source": nom,
                    }

    existants = {
        r["nom"] for r in db.execute("SELECT nom FROM imprimantes").fetchall()
    }
    return render_template(
        "imprimantes/decouvrir.html",
        trouves=trouves,
        erreurs=erreurs,
        existants=existants,
    )


@imprimantes_bp.route("/decouvrir/ajouter", methods=["POST"])
@login_required
def decouvrir_ajouter():
    nom = request.form.get("nom", "").strip()
    port = request.form.get("port", "").strip()
    source = request.form.get("source", "").strip()
    if not nom:
        flash("Imprimante invalide.", "danger")
        return redirect(url_for("imprimantes.decouvrir"))
    db = get_db()
    existant = db.execute(
        "SELECT id FROM imprimantes WHERE nom = ?", (nom,)
    ).fetchone()
    if existant:
        flash("Imprimante « " + nom + " » déjà présente.", "info")
        return redirect(url_for("imprimantes.liste"))
    adresse_ip = ""
    m = __import__("re").match(r"IP_?(\d+\.\d+\.\d+\.\d+)", port)
    if m:
        adresse_ip = m.group(1)
    db.execute(
        """INSERT INTO imprimantes (nom, adresse_ip, marque_modele,
           reference_toner, stock_toner, source_machine, remarques)
           VALUES (?, ?, ?, '', 0, ?, 'Ajoutée via découverte WMI')""",
        (nom, adresse_ip, port or "", source),
    )
    db.commit()
    flash("Imprimante « " + nom + " » ajoutée.", "success")
    return redirect(url_for("imprimantes.liste"))


@imprimantes_bp.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    from app.routes.besoins import preparer_besoins_site, _site_utilisateur

    cidr_actuel = detecter_cidr() or ""
    if request.method == "POST":
        plage = request.form.get("plage", "").strip() or cidr_actuel
        if not plage:
            flash("Indiquez la plage réseau (ex : 192.168.1.0/24).", "warning")
            return render_template("imprimantes/scan.html", cidr_actuel=cidr_actuel)
        try:
            parallelisme = int(request.form.get("parallelisme", "50"))
        except ValueError:
            parallelisme = 50
        try:
            hosts = construire_plage(plage)
        except ValueError as e:
            flash(str(e), "danger")
            return render_template("imprimantes/scan.html", cidr_actuel=cidr_actuel)
        preparer_besoins_site(datetime.date.today().year, _site_utilisateur())
        scan_id = _demarrer_scan(plage, hosts, parallelisme)
        return redirect(url_for("imprimantes.live_scan", scan_id=scan_id))
    return render_template("imprimantes/scan.html", cidr_actuel=cidr_actuel)


def _demarrer_scan(plage, hosts, parallelisme):
    import uuid

    scan_id = uuid.uuid4().hex
    etat = {
        "scan_id": scan_id,
        "plage": plage,
        "total": len(hosts),
        "checked": 0,
        "en_cours": True,
        "erreur": None,
        "resultats": [],
        "resultats_wmi": [],
        "phase": "scan réseau",
        "insere": False,
        "ajoutes": 0,
        "ignores": 0,
    }
    with _SCANS_LOCK:
        _SCANS[scan_id] = etat
        if len(_SCANS) > 30:
            for cid in [c for c, e in _SCANS.items() if not e["en_cours"]][: len(_SCANS) - 30]:
                _SCANS.pop(cid, None)

    def _avance(i, total, h, trouve):
        etat["checked"] = i

    def _lancer():
        try:
            etat["resultats"] = scan_imprimantes_reseau(hosts, parallelisme, progres=_avance)
        except Exception as e:
            etat["erreur"] = str(e)

        etat["phase"] = "WMI (USB)"
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            from app.scan import lister_imprimantes, ping

            db = get_db()
            machines = db.execute("SELECT nom FROM machines ORDER BY nom").fetchall()
            def _wmi(m):
                en_ligne, _ = ping(m["nom"])
                if not en_ligne:
                    return []
                res = lister_imprimantes(m["nom"])
                if res.get("erreur") or not res.get("liste"):
                    return []
                return [
                    {"ip": "", "description": p["nom"], "source": m["nom"], "type": "USB"}
                    for p in res["liste"]
                    if p["port"] and ("USB" in (p["port"] or "").upper() or "WSD" in (p["port"] or "").upper() or not "." in (p["port"] or ""))
                ]
            with ThreadPoolExecutor(max_workers=10) as ex:
                for fut in as_completed([ex.submit(_wmi, m) for m in machines]):
                    etat["resultats_wmi"].extend(fut.result())
        except Exception as e:
            etat["erreur"] = (etat["erreur"] or "") + (" WMI: " + str(e) if str(e) else "")
        finally:
            etat["en_cours"] = False

    threading.Thread(target=_lancer, daemon=True).start()
    return scan_id


@imprimantes_bp.route("/scan/live/<scan_id>")
@login_required
def live_scan(scan_id):
    etat = _SCANS.get(scan_id)
    if etat is None:
        return redirect(url_for("imprimantes.scan"))
    return render_template("imprimantes/scan_live.html", etat=etat)


@imprimantes_bp.route("/scan/statut/<scan_id>")
@login_required
def statut_scan(scan_id):
    from flask import jsonify

    etat = _SCANS.get(scan_id)
    if etat is None:
        return jsonify({"erreur": "Scan introuvable."}), 404
    if not etat["en_cours"] and not etat["insere"]:
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
        for r in etat["resultats"]:
            ip = (r.get("ip") or "").strip()
            if not ip or ip in existants_ip:
                etat["ignores"] += 1
                continue
            desc = (r.get("description") or "Imprimante " + ip).strip()[:60]
            db.execute(
                """INSERT INTO imprimantes (nom, adresse_ip, marque_modele,
                   reference_toner, stock_toner, source_machine, remarques)
                   VALUES (?, ?, ?, '', 0, 'scan réseau', 'Ajoutée via scan réseau')""",
                (desc, ip, desc),
            )
            existants_ip.add(ip)
            existants_nom.add(desc)
            etat["ajoutes"] += 1
        for r in etat.get("resultats_wmi", []):
            nom = (r.get("description") or "").strip()
            if not nom or nom in existants_nom:
                etat["ignores"] += 1
                continue
            source = (r.get("source") or "").strip()
            db.execute(
                """INSERT INTO imprimantes (nom, adresse_ip, marque_modele,
                   reference_toner, stock_toner, source_machine, remarques)
                   VALUES (?, '', ?, '', 0, ?, 'Ajoutée via scan USB/WMI')""",
                (nom, nom, source),
            )
            existants_nom.add(nom)
            etat["ajoutes"] += 1
        db.commit()
        etat["insere"] = True
    return jsonify(
        {
            k: etat[k]
            for k in ("total", "checked", "en_cours", "erreur", "resultats",
                       "resultats_wmi", "phase", "plage",
                       "insere", "ajoutes", "ignores")
        }
    )


@imprimantes_bp.route("/scan/ajouter", methods=["POST"])
@login_required
def scan_ajouter():
    ip = request.form.get("ip", "").strip()
    description = request.form.get("description", "").strip()
    if not ip:
        flash("Imprimante invalide.", "danger")
        return redirect(url_for("imprimantes.liste"))
    nom = (description[:60] or "Imprimante " + ip).strip()
    db = get_db()
    existant = db.execute(
        "SELECT id FROM imprimantes WHERE adresse_ip = ?", (ip,)
    ).fetchone()
    if existant:
        flash("Une imprimante existe déjà avec l'adresse " + ip + ".", "info")
        return redirect(url_for("imprimantes.liste"))
    db.execute(
        """INSERT INTO imprimantes (nom, adresse_ip, marque_modele,
           reference_toner, stock_toner, source_machine, remarques)
           VALUES (?, ?, ?, '', 0, 'scan réseau', 'Ajoutée via scan réseau')""",
        (nom, ip, description),
    )
    db.commit()
    flash("Imprimante « " + nom + " » ajoutée.", "success")
    return redirect(url_for("imprimantes.liste"))
