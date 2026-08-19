from functools import wraps

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from app import get_db

auth_bp = Blueprint("auth", __name__)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Veuillez vous connecter pour accéder à cette page.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Veuillez vous connecter pour accéder à cette page.", "warning")
            return redirect(url_for("auth.login"))
        if session.get("role") != "admin":
            flash("Accès réservé à l'administrateur.", "danger")
            return redirect(url_for("main.index"))
        return view(*args, **kwargs)

    return wrapped


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        mot_de_passe = request.form.get("mot_de_passe", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        if user and check_password_hash(user["mot_de_passe"], mot_de_passe):
            session.clear()
            session["user_id"] = user["id"]
            session["nom"] = user["nom"]
            session["role"] = user["role"]
            session["site"] = (user["site"] or "").strip()
            flash("Bienvenue, " + user["nom"] + " !", "success")
            return redirect(url_for("main.index"))
        flash("Adresse email ou mot de passe incorrect.", "danger")
    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for("auth.login"))
