from datetime import date

from flask import Blueprint, render_template, session

from app import get_db
from app.routes.auth import login_required, admin_required
from app.routes.besoins import _lignes_regroupees
from app.routes.partage import _lignes_partage, _sites_partage

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
@login_required
def index():
    db = get_db()
    annee = date.today().year

    groupes, sites_groupes = _lignes_regroupees(annee)
    totaux_groupes = [
        sum(g["par_site"].get(s, 0) for g in groupes) for s in sites_groupes
    ]

    inventaire_par_type = db.execute(
        """
        SELECT marque_modele AS type, COUNT(*) AS total,
               GROUP_CONCAT(nom, ', ') AS details
        FROM machines
        GROUP BY marque_modele
        ORDER BY total DESC, marque_modele
        """
    ).fetchall()

    imprimantes_par_type = db.execute(
        """
        SELECT marque_modele AS type,
               COALESCE(NULLIF(reference_toner, ''), 'Non renseigné') AS ref,
               COUNT(*) AS total,
               GROUP_CONCAT(nom, ', ') AS details
        FROM imprimantes
        GROUP BY marque_modele, reference_toner
        ORDER BY total DESC, marque_modele, ref
        """
    ).fetchall()

    stock_faible = db.execute(
        """
        SELECT nom, marque_modele, reference_toner, stock_toner
        FROM imprimantes
        WHERE stock_toner IS NOT NULL AND stock_toner <= 2
        ORDER BY stock_toner
        """
    ).fetchall()

    is_admin = session.get("role") == "admin"

    stats = {
        "inventaire": {
            "total": sum(r["total"] for r in inventaire_par_type),
            "par_type": inventaire_par_type,
        },
        "imprimantes": {
            "total": sum(r["total"] for r in imprimantes_par_type),
            "par_type": imprimantes_par_type,
            "stock_faible": stock_faible,
        },
        "besoins": {
            "annee": annee,
            "groupes": groupes,
            "sites_groupes": sites_groupes,
            "totaux_groupes": totaux_groupes,
            "total": sum(g["total"] for g in groupes),
        },
    }

    if is_admin:
        items_partage = _lignes_partage(annee)
        sites_partage = _sites_partage()
        totaux_sites = [
            sum(i["par_site"][j] for i in items_partage)
            for j in range(len(sites_partage))
        ]
        stats["partage"] = {
            "nb_items": len(items_partage),
            "nb_saisis": sum(
                1 for i in items_partage
                if i["qte_achetee"] or i["partage_total"] or i["total_sites"]
            ),
            "total_qte": sum(i["qte_achetee"] for i in items_partage),
            "total_partage": sum(i["partage_total"] for i in items_partage),
            "sites": sites_partage,
            "totaux_sites": totaux_sites,
            "total_sites": sum(totaux_sites),
            "lignes": items_partage,
        }

    return render_template(
        "index.html", nom=session.get("nom", ""), stats=stats, is_admin=is_admin,
    )
