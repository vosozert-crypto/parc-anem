from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app import get_db
from app.donnees_consommables import SITES
from app.routes.auth import admin_required, login_required

utilisateurs_bp = Blueprint("utilisateurs", __name__, url_prefix="/utilisateurs")

CHAMPS = [
    ("nom", "Nom complet"),
    ("email", "Adresse email (identifiant)"),
    ("role", "Rôle"),
]


@utilisateurs_bp.route("/")
@admin_required
def liste():
    db = get_db()
    utilisateurs = db.execute(
        "SELECT id, nom, email, role, site, date_ajout FROM users ORDER BY nom"
    ).fetchall()
    return render_template(
        "utilisateurs/liste.html",
        utilisateurs=utilisateurs,
        moi=session.get("user_id"),
    )


@utilisateurs_bp.route("/ajouter", methods=["GET", "POST"])
@admin_required
def ajouter():
    if request.method == "POST":
        donnees = _donnees_formulaire()
        erreur = _valider(donnees)
        if erreur:
            flash(erreur, "danger")
            return render_template("utilisateurs/formulaire.html", user={}, titre="Ajouter un utilisateur", champs=CHAMPS, sites=SITES)
        db = get_db()
        db.execute(
            "INSERT INTO users (nom, email, mot_de_passe, role, site) VALUES (?, ?, ?, ?, ?)",
            (donnees["nom"], donnees["email"], generate_password_hash(donnees["mot_de_passe"]), donnees["role"], donnees["site"]),
        )
        db.commit()
        flash("Utilisateur « " + donnees["nom"] + " » ajouté.", "success")
        return redirect(url_for("utilisateurs.liste"))
    return render_template("utilisateurs/formulaire.html", user={}, titre="Ajouter un utilisateur", champs=CHAMPS, sites=SITES)


@utilisateurs_bp.route("/modifier/<int:uid>", methods=["GET", "POST"])
@admin_required
def modifier(uid):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if user is None:
        flash("Utilisateur introuvable.", "warning")
        return redirect(url_for("utilisateurs.liste"))
    if request.method == "POST":
        donnees = _donnees_formulaire()
        erreur = _valider(donnees, uid=uid)
        if erreur:
            flash(erreur, "danger")
            return render_template("utilisateurs/formulaire.html", user=user, titre="Modifier l'utilisateur", champs=CHAMPS, sites=SITES)
        db.execute(
            "UPDATE users SET nom = ?, email = ?, role = ?, site = ? WHERE id = ?",
            (donnees["nom"], donnees["email"], donnees["role"], donnees["site"], uid),
        )
        if donnees["mot_de_passe"]:
            db.execute(
                "UPDATE users SET mot_de_passe = ? WHERE id = ?",
                (generate_password_hash(donnees["mot_de_passe"]), uid),
            )
        db.commit()
        flash("Utilisateur « " + donnees["nom"] + " » modifié.", "success")
        return redirect(url_for("utilisateurs.liste"))
    return render_template("utilisateurs/formulaire.html", user=user, titre="Modifier l'utilisateur", champs=CHAMPS, sites=SITES)


@utilisateurs_bp.route("/supprimer/<int:uid>", methods=["POST"])
@admin_required
def supprimer(uid):
    if uid == session.get("user_id"):
        flash("Impossible de supprimer votre propre compte.", "danger")
        return redirect(url_for("utilisateurs.liste"))
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if user is None:
        flash("Utilisateur introuvable.", "warning")
        return redirect(url_for("utilisateurs.liste"))
    if user["role"] == "admin":
        admins = db.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").fetchone()["n"]
        if admins <= 1:
            flash("Impossible de supprimer le dernier administrateur.", "danger")
            return redirect(url_for("utilisateurs.liste"))
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.commit()
    flash("Utilisateur « " + user["nom"] + " » supprimé.", "info")
    return redirect(url_for("utilisateurs.liste"))


def _donnees_formulaire():
    return {
        "nom": request.form.get("nom", "").strip(),
        "email": request.form.get("email", "").strip().lower(),
        "role": request.form.get("role", "user").strip(),
        "site": request.form.get("site", "").strip(),
        "mot_de_passe": request.form.get("mot_de_passe", ""),
    }


def _valider(donnees, uid=None):
    if not donnees["nom"]:
        return "Le nom est obligatoire."
    if not donnees["email"]:
        return "L'adresse email est obligatoire."
    if donnees["role"] not in ("admin", "user"):
        return "Rôle invalide."
    db = get_db()
    existant = db.execute(
        "SELECT id FROM users WHERE email = ? AND id != ?",
        (donnees["email"], uid or -1),
    ).fetchone()
    if existant:
        return "Cette adresse email est déjà utilisée."
    if not uid and not donnees["mot_de_passe"]:
        return "Le mot de passe est obligatoire à la création."
    return None


@utilisateurs_bp.route("/mot-de-passe", methods=["GET", "POST"])
@login_required
def mot_de_passe():
    if request.method == "POST":
        actuel = request.form.get("actuel", "")
        nouveau = request.form.get("nouveau", "")
        confirmation = request.form.get("confirmation", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if user is None:
            flash("Utilisateur introuvable.", "danger")
            return redirect(url_for("auth.logout"))
        if not check_password_hash(user["mot_de_passe"], actuel):
            flash("Mot de passe actuel incorrect.", "danger")
            return render_template("utilisateurs/mot_de_passe.html")
        if len(nouveau) < 6:
            flash("Le nouveau mot de passe doit contenir au moins 6 caractères.", "danger")
            return render_template("utilisateurs/mot_de_passe.html")
        if nouveau != confirmation:
            flash("La confirmation ne correspond pas.", "danger")
            return render_template("utilisateurs/mot_de_passe.html")
        db.execute(
            "UPDATE users SET mot_de_passe = ? WHERE id = ?",
            (generate_password_hash(nouveau), session["user_id"]),
        )
        db.commit()
        flash("Mot de passe modifié avec succès.", "success")
        return redirect(url_for("main.index"))
    return render_template("utilisateurs/mot_de_passe.html")
