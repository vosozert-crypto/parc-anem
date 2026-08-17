import datetime
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager

try:
    import pythoncom
    import wmi

    _WMI_DISPONIBLE = True
except ImportError:
    _WMI_DISPONIBLE = False

NOMS_VIRTUELS = (
    "vmware", "virtualbox", "hyper-v", "docker", "vethernet",
    "wsl", "loopback", "pseudo", "tunnel", "vpn",
)


@contextmanager
def _com():
    if not _WMI_DISPONIBLE:
        yield
        return
    pythoncom.CoInitialize()
    try:
        yield
    finally:
        import gc

        gc.collect()
        pythoncom.CoUninitialize()


def detecter_cidr():
    if not _WMI_DISPONIBLE:
        return None
    with _com():
        for iface in wmi.WMI().Win32_NetworkAdapterConfiguration(
            IPEnabled=True
        ):
            desc = (iface.Description or "").lower()
            if any(v in desc for v in NOMS_VIRTUELS):
                continue
            ip = iface.IPAddress[0] if iface.IPAddress else ""
            mask = iface.IPSubnet[0] if iface.IPSubnet else ""
            if not ip or not mask:
                continue
            try:
                net = ipaddress.IPv4Network(ip + "/" + mask, strict=False)
                if not net.is_private:
                    continue
                return str(net)
            except (ValueError, TypeError):
                continue
        return None


def construire_plage(cidr, max_hosts=4096):
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as e:
        raise ValueError("Plage invalide : " + str(e)) from e
    hosts = [str(h) for h in net.hosts()]
    if not hosts:
        raise ValueError("Plage invalide : aucune adresse utilisable.")
    if len(hosts) > max_hosts:
        raise ValueError(
            "Plage trop large ({} adresses, /{}). Précise une plage plus petite.".format(
                len(hosts), net.prefixlen
            )
        )
    return hosts


def _is_online(host, timeout_ms=800):
    import subprocess

    try:
        code = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).returncode
        return code == 0
    except Exception:
        return False


def ping(host, timeout_ms=1000):
    import subprocess

    try:
        out = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), host],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if out.returncode != 0:
            return False, None
        m = re.search(r"temps[=<]\s*(\d+)", out.stdout, re.IGNORECASE)
        return True, int(m.group(1)) if m else None
    except Exception:
        return False, None


def lister_imprimantes(host):
    if not _WMI_DISPONIBLE:
        return {"erreur": "WMI non disponible sur ce serveur (Linux)."}
    resultat = {"erreur": "Impossible de se connecter à {} via WMI (droits/pare-feu/WinRM).".format(host)}
    with _com():
        try:
            c = wmi.WMI(computer=host)
        except Exception:
            return resultat
        try:
            liste = []
            for p in c.Win32_Printer():
                liste.append(
                    {
                        "nom": p.Name or "",
                        "partage": p.ShareName or "",
                        "port": p.PortName or "",
                        "par_defaut": bool(getattr(p, "Default", False)),
                        "hors_ligne": bool(getattr(p, "WorkOffline", False)),
                    }
                )
            resultat = {"liste": liste}
        except Exception as e:
            resultat = {"erreur": str(e)}
        finally:
            c = None
    return resultat


def _conn(host):
    return wmi.WMI(computer=host)


def _wmi_value(c, klass, prop):
    try:
        for obj in getattr(c, klass)():
            val = getattr(obj, prop, None)
            if val:
                s = str(val).strip()
                if s:
                    return s
    except Exception:
        pass
    return ""


def _ram_go(c):
    val = _wmi_value(c, "Win32_ComputerSystem", "TotalPhysicalMemory")
    try:
        return round(int(val) / (1024 ** 3))
    except (ValueError, TypeError):
        return 0


def _generation(cpu):
    if not cpu:
        return "N/A"
    m = re.search(r"i[3579]-?(\d{4,5})", cpu, re.IGNORECASE)
    if m:
        num = m.group(1)
        return "{}e Gen".format(num[:2] if len(num) >= 5 else num[:1])
    m = re.search(r"Ryzen\s+[3579]\s+(\d)\d{3}", cpu, re.IGNORECASE)
    if m:
        return "Ryzen Série {}000".format(m.group(1))
    return "N/A"


def _disque(c):
    try:
        parts = []
        for d in c.Win32_DiskDrive():
            try:
                size = int(d.Size or 0) / (1024 ** 3)
            except (ValueError, TypeError):
                continue
            mt = ((d.MediaType or "") + " " + (d.Model or "")).upper()
            typ = "SSD" if "SSD" in mt else "HDD"
            parts.append("{} Go ({})".format(round(size), typ))
        return " + ".join(parts)
    except Exception:
        return ""


def _user_session(c):
    val = _wmi_value(c, "Win32_ComputerSystem", "UserName")
    if val:
        return val
    try:
        utilisateurs = []
        for o in c.Win32_LoggedOnUser():
            ref = str(getattr(o, "Antecedent", "") or "")
            m = re.search(r"Name=\"([^\"]*)\"", ref)
            if m and m.group(1) not in utilisateurs:
                utilisateurs.append(m.group(1))
        return ", ".join(utilisateurs)
    except Exception:
        return ""


def scan_host(host):
    if not _is_online(host):
        return None
    resultat = None
    with _com():
        try:
            c = _conn(host)
        except Exception:
            return None

        try:
            nom = _wmi_value(c, "Win32_ComputerSystem", "Name") or host
            serie = _wmi_value(c, "Win32_BIOS", "SerialNumber")
            fabricant = _wmi_value(c, "Win32_ComputerSystem", "Manufacturer")
            modele = _wmi_value(c, "Win32_ComputerSystem", "Model")
            cpu = _wmi_value(c, "Win32_Processor", "Name")
            ram = _ram_go(c)
            arch = _wmi_value(c, "Win32_OperatingSystem", "OSArchitecture")
            session = _user_session(c)

            if not serie and not cpu:
                resultat = {
                    "nom": host,
                    "numero_serie": "",
                    "marque_modele": "",
                    "processeur": "",
                    "generation": "",
                    "ram_go": "",
                    "disque": "",
                    "arch": "",
                    "user_session": "",
                    "obs": "En ligne mais injoignable via WMI (droits/pare-feu/WinRM)",
                }
            else:
                resultat = {
                    "nom": nom,
                    "numero_serie": serie,
                    "marque_modele": (fabricant + " " + modele).strip(),
                    "processeur": cpu,
                    "generation": _generation(cpu),
                    "ram_go": "{} Go".format(ram) if ram > 0 else "",
                    "disque": _disque(c),
                    "arch": arch,
                    "user_session": session,
                    "obs": "",
                }
        finally:
            c = None
    return resultat


def scan_reseau(hosts, max_parallelism, progres=None):
    resultats = []
    trouves = 0
    avec = ThreadPoolExecutor(max_workers=max_parallelism)

    def _trait(h):
        return h, scan_host(h)

    futurs = [avec.submit(_trait, h) for h in hosts]
    for i, fut in enumerate(as_completed(futurs), start=1):
        h, data = fut.result()
        ok = data is not None
        if ok:
            trouves += 1
            resultats.append(data)
        if progres:
            progres(i, len(hosts), trouves, h, ok)
    avec.shutdown()
    return resultats


HKLM = 2147483650
_BASES_KASPERSKY = ("SOFTWARE\\WOW6432Node\\KasperskyLab", "SOFTWARE\\KasperskyLab")


def infos_kaspersky(host):
    """Version et dernière date de mise à jour de Kaspersky via le registre."""
    with _com():
        try:
            c = wmi.WMI(computer=host)
        except Exception:
            return {"version": "", "maj": ""}
        try:
            return _infos_kaspersky(c)
        finally:
            c = None


def _infos_kaspersky(c):
    def _appelle(methode, *args):
        try:
            res = getattr(c.StdRegProv, methode)(*args)
            if isinstance(res, tuple) and res and res[0] == 0:
                return res[1]
        except Exception:
            pass
        return None

    def _sous_cles(chemin):
        res = _appelle("EnumKey", HKLM, chemin)
        return list(res or [])

    def _lire(chemin, valeur):
        try:
            res = _appelle("GetStringValue", HKLM, chemin, valeur)
            return str(res).strip() if res else ""
        except Exception:
            return ""

    def _maj(base, produit):
        chemin_data = base + "\\protected\\" + produit + "\\Data"
        try:
            ts = _appelle("GetDWORDValue", HKLM, chemin_data, "LastSuccessfulUpdate")
            if ts:
                return datetime.datetime.fromtimestamp(int(ts)).strftime("%d/%m/%Y %H:%M")
        except Exception:
            pass
        chemin_bases = base + "\\Components"
        try:
            for comp in _sous_cles(chemin_bases):
                for ver in _sous_cles(chemin_bases + "\\" + comp):
                    av = chemin_bases + "\\" + comp + "\\" + ver + "\\Statistics\\AVState"
                    d = _lire(av, "Protection_BasesDate")
                    if d:
                        return d
        except Exception:
            pass
        return ""

    for base in _BASES_KASPERSKY:
        for produit in _sous_cles(base + "\\protected"):
            chemin_env = base + "\\protected\\" + produit + "\\environment"
            version = _lire(chemin_env, "ProductDisplayVersion")
            if not version:
                version = _lire(chemin_env, "ProductVersion")
            if not version:
                continue
            return {"version": version, "maj": _maj(base, produit)}
    return {"version": "", "maj": ""}


def etat_securite(host):
    """État antivirus (Kaspersky...) du poste via le Security Center Windows."""
    if not _is_online(host):
        return {"erreur": "Hors ligne", "produits": [], "kaspersky": None}
    resultat = {"erreur": None, "produits": [], "kaspersky": None}
    with _com():
        try:
            c = wmi.WMI(computer=host, namespace="root\\SecurityCenter2")
        except Exception:
            resultat["erreur"] = "Injoignable via WMI"
            return resultat
        try:
            vus = set()
            for p in c.AntiVirusProduct():
                nom = str(getattr(p, "displayName", "") or "")
                if not nom or nom in vus:
                    continue
                vus.add(nom)
                etat = int(getattr(p, "productState", 0) or 0)
                produit = {
                    "nom": nom,
                    "actif": (etat & 0xF000) == 0x1000,
                    "a_jour": (etat & 0x00F0) != 0x0010,
                    "est_kaspersky": "kaspersky" in nom.lower(),
                }
                resultat["produits"].append(produit)
                if produit["est_kaspersky"]:
                    resultat["kaspersky"] = produit
        except Exception as e:
            resultat["erreur"] = str(e)
        finally:
            c = None

        if resultat["kaspersky"]:
            try:
                c_reg = wmi.WMI(computer=host)
                try:
                    resultat["kaspersky"].update(_infos_kaspersky(c_reg))
                finally:
                    c_reg = None
            except Exception:
                pass
    return resultat


PORTS_COURANTS = [
    (22, "SSH"), (80, "HTTP"), (443, "HTTPS"), (135, "RPC"),
    (139, "NetBIOS"), (445, "SMB"), (3389, "RDP"), (5985, "WinRM"),
    (5900, "VNC"),
]

KB_MS17_010 = {
    "KB4012212", "KB4012213", "KB4012214", "KB4012215",
    "KB4012216", "KB4012217", "KB4013389", "KB4018466",
}


def scanner_ports(host, timeout_ms=800):
    """Ports TCP ouverts sur le poste (connexion socket)."""
    import socket as sock

    ouverts = []
    for port, nom in PORTS_COURANTS:
        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        s.settimeout(timeout_ms / 1000.0)
        try:
            if s.connect_ex((host, port)) == 0:
                ouverts.append({"port": port, "nom": nom})
        except Exception:
            pass
        finally:
            s.close()
    return ouverts


def etat_smb(host):
    """SMBv1 actif ? Patch MS17-010 (EternalBlue) présent ?"""
    if not _is_online(host):
        return {"erreur": "Hors ligne", "smbv1": None, "patche": None, "vulnerable": None}
    resultat = {"erreur": None, "smbv1": None, "patche": None, "vulnerable": None}
    with _com():
        try:
            c = wmi.WMI(computer=host)
        except Exception:
            resultat["erreur"] = "Injoignable via WMI"
            return resultat
        try:
            smbv1 = False
            try:
                for d in c.Win32_SystemDriver(Name="mrxsmb10"):
                    demarrage = int(getattr(d, "Start", 0) or 0)
                    smbv1 = demarrage < 4
            except Exception:
                smbv1 = None
            resultat["smbv1"] = smbv1

            kbs = set()
            try:
                for q in c.Win32_QuickFixEngineering():
                    hid = str(getattr(q, "HotFixID", "") or "").upper()
                    if hid:
                        kbs.add(hid)
            except Exception:
                pass
            resultat["patche"] = bool(kbs & KB_MS17_010)
            resultat["vulnerable"] = bool(smbv1) and not resultat["patche"]
        except Exception as e:
            resultat["erreur"] = str(e)
        finally:
            c = None
    return resultat


def verifier_securite(machines, max_parallelism, progres=None):
    resultats = []
    avec = ThreadPoolExecutor(max_workers=max_parallelism)

    def _trait(m):
        r = etat_securite(m["nom"])
        r["ports"] = scanner_ports(m["nom"])
        r["smb"] = etat_smb(m["nom"])
        return m, r

    futurs = [avec.submit(_trait, m) for m in machines]
    for i, fut in enumerate(as_completed(futurs), start=1):
        m, r = fut.result()
        resultats.append({"id": m["id"], "nom": m["nom"], **r})
        if progres:
            progres(i, len(machines), m["nom"])
    avec.shutdown()
    return resultats


def obtenir_adresse_locale():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return ""


PORTS_IMPRIMANTES = (515, 631, 9100)  # LPD, IPP, JetDirect

MARQUES_IMPRIMANTES = (
    "printer", "laserjet", "laser jet", "deskjet", "officejet", "designjet",
    "xerox", "canon", "brother", "epson", "kyocera", "lexmark", "ricoh",
    "samsung", "hp ", "hewlett", "oki", "konica", "minolta", "zebra",
    "dell", "sharp", "toshiba", "fuji", "imprimante", "impresora",
)


def est_imprimante(host, timeout_ms=600):
    """Détecte si l'hôte expose un port d'impression réseau."""
    import socket as sock

    for port in PORTS_IMPRIMANTES:
        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        s.settimeout(timeout_ms / 1000.0)
        try:
            if s.connect_ex((host, port)) == 0:
                return True
        except Exception:
            pass
        finally:
            s.close()
    return False


def _description_est_imprimante(desc):
    d = desc.lower()
    return any(m in d for m in MARQUES_IMPRIMANTES)


def scan_imprimantes_reseau(hosts, max_parallelism, progres=None):
    """Recherche les imprimantes réseau dans une plage d'adresses."""
    from app.snmp import lire_sysdescr

    resultats = []
    avec = ThreadPoolExecutor(max_workers=max_parallelism)

    def _trait(h):
        if not _is_online(h):
            return h, False, ""
        if est_imprimante(h):
            desc = lire_sysdescr(h, timeout=1.5) or ""
            return h, True, desc
        desc = lire_sysdescr(h, timeout=1.5) or ""
        if desc and _description_est_imprimante(desc):
            return h, True, desc
        return h, False, ""

    futurs = [avec.submit(_trait, h) for h in hosts]
    for i, fut in enumerate(as_completed(futurs), start=1):
        h, est, desc = fut.result()
        if est:
            resultats.append({"ip": h, "description": desc})
        if progres:
            progres(i, len(hosts), h, est)
    avec.shutdown()
    return resultats


def usb_actifs(host):
    """Périphériques USB actifs d'un poste via WMI."""
    if not _is_online(host):
        return {"erreur": "Hors ligne", "usb": []}
    resultat = {"erreur": None, "usb": []}
    with _com():
        try:
            c = wmi.WMI(computer=host)
        except Exception:
            resultat["erreur"] = "Injoignable via WMI"
            return resultat
        try:
            vus = set()
            for p in c.Win32_PnPEntity():
                if not str(getattr(p, "PNPClass", "") or "").startswith("USB"):
                    continue
                nom = str(getattr(p, "Name", "") or "").strip()
                if not nom or nom in vus:
                    continue
                vus.add(nom)
                statut = str(getattr(p, "Status", "") or "")
                resultat["usb"].append(
                    {
                        "nom": nom,
                        "actif": statut.lower() == "ok",
                    }
                )
        except Exception as e:
            resultat["erreur"] = str(e)
        finally:
            c = None
    return resultat


def scanner_usb_machines(machines, max_parallelism, progres=None):
    """Liste les périphériques USB actifs sur les machines de l'inventaire."""
    resultats = []
    avec = ThreadPoolExecutor(max_workers=max_parallelism)

    def _trait(m):
        r = usb_actifs(m["nom"])
        return m, r

    futurs = [avec.submit(_trait, m) for m in machines]
    for i, fut in enumerate(as_completed(futurs), start=1):
        m, r = fut.result()
        resultats.append({"id": m["id"], "nom": m["nom"], **r})
        if progres:
            progres(i, len(machines), m["nom"])
    avec.shutdown()
    return resultats
