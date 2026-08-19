#!/usr/bin/env python3
"""
Scan Reseau ANEM - Script local distribuable aux ALEM/AWEM
==========================================================
Scanne les PC et imprimantes du reseau local et envoie les resultats
a l'application centrale sur Railway.

Utilisation:
    pip install requests
    python scanner_local.py --url https://parc-anem-production.up.railway.app --token anem-scan-2026-secret --site "ALEM bouira"

Le script detecte automatiquement:
    - Tous les PC du reseau (ping + WMI)
    - Toutes les imprimantes reseau (SNMP + WMI)
    - Les imprimantes USB connectees aux postes
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("Installez requests: pip install requests")
    sys.exit(1)

try:
    import pythoncom
    import wmi
    _WMI = True
except ImportError:
    _WMI = False


def detecter_cidr():
    if not _WMI:
        return None
    pythoncom.CoInitialize()
    try:
        for iface in wmi.WMI().Win32_NetworkAdapterConfiguration(IPEnabled=True):
            desc = (iface.Description or "").lower()
            if any(v in desc for v in ("vmware", "virtualbox", "hyper-v", "docker", "loopback")):
                continue
            ip = iface.IPAddress[0] if iface.IPAddress else ""
            mask = iface.IPSubnet[0] if iface.IPSubnet else ""
            if ip and mask:
                net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                return str(net)
    finally:
        pythoncom.CoUninitialize()
    return None


def ping(ip, timeout=1):
    try:
        r = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout * 1000), ip],
            capture_output=True, timeout=timeout + 1
        )
        return r.returncode == 0
    except Exception:
        return False


def construire_plage(cidr):
    net = ipaddress.IPv4Network(cidr, strict=False)
    return [str(h) for h in net.hosts()]


def scan_pc(host):
    if not ping(host):
        return None
    if not _WMI:
        return {"nom": host, "marque_modele": "", "processeur": "", "obs": "scan sans WMI"}
    pythoncom.CoInitialize()
    try:
        try:
            c = wmi.WMI(namespace="root\\cimv2", computer=host)
            pcs = c.Win32_ComputerSystem()
            os_info = c.Win32_OperatingSystem()
            proc = c.Win32_Processor()
            bios = c.Win32_BIOS()

            nom = pcs[0].Name if pcs else host
            marque = pcs[0].Manufacturer + " " + pcs[0].Model if pcs else ""
            processeur = proc[0].Name if proc else ""
            ram = str(round(int(pcs[0].TotalPhysicalMemory or 0) / (1024**3))) + " Go" if pcs else ""
            sn = bios[0].SerialNumber.strip() if bios and bios[0].SerialNumber else ""
            arch = os_info[0].OSArchitecture if os_info else ""

            return {
                "nom": nom,
                "numero_serie": sn,
                "marque_modele": marque,
                "processeur": processeur,
                "generation": "",
                "ram_go": ram,
                "disque": "",
                "arch": arch,
                "user_session": "",
                "obs": "",
            }
        except Exception:
            return {"nom": host, "marque_modele": "", "obs": "WMI inaccessible"}
    finally:
        pythoncom.CoUninitialize()


def scanner_imprimantes_reseau(host):
    if not ping(host):
        return []
    resultats = []
    if _WMI:
        pythoncom.CoInitialize()
        try:
            try:
                c = wmi.WMI(namespace="root\\cimv2", computer=host)
                for p in c.Win32_Printer():
                    port = p.PortName or ""
                    if not port:
                        continue
                    resultats.append({
                        "nom": p.Name or "Imprimante",
                        "marque_modele": p.DriverName or "",
                        "adresse_ip": "",
                        "reference_toner": "",
                        "source_machine": host,
                        "remarques": "WMI: " + port,
                    })
            except Exception:
                pass
        finally:
            pythoncom.CoUninitialize()
    return resultats


def scan_complet(cidr=None, parallele=50):
    if not cidr:
        cidr = detecter_cidr()
    if not cidr:
        print("Impossible de detecter le reseau. Indiquez le CIDR manuellement.")
        print("Exemple: --cidr 192.168.1.0/24")
        sys.exit(1)

    print(f"Reseau detecte: {cidr}")
    hosts = construire_plage(cidr)
    print(f"Scanner {len(hosts)} hotes...")

    machines = []
    imprimantes = []
    done = [0]

    def avance(i, total):
        done[0] = i
        pct = int(i / total * 100)
        print(f"\r  Progression: {pct}% ({i}/{total})", end="", flush=True)

    with ThreadPoolExecutor(max_workers=parallele) as ex:
        futures_pc = {ex.submit(scan_pc, h): h for h in hosts}
        futures_imp = {ex.submit(scanner_imprimantes_reseau, h): h for h in hosts}
        total = len(futures_pc) + len(futures_imp)
        for fut in as_completed(futures_pc):
            r = fut.result()
            if r:
                machines.append(r)
        for fut in as_completed(futures_imp):
            r = fut.result()
            imprimantes.extend(r)

    print(f"\n  PC trouves: {len(machines)}")
    print(f"  Imprimantes trouvees: {len(imprimantes)}")
    return machines, imprimantes


def envoyer(url, token, site, machines, imprimantes):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    print(f"\nEnvoi des {len(machines)} PC a {url}...")
    r = requests.post(
        f"{url}/api/scan/machines",
        headers=headers,
        json={"machines": machines, "site": site},
        timeout=30,
    )
    if r.status_code != 200:
        print(f"  ERREUR: {r.status_code} - {r.text}")
    else:
        d = r.json()
        print(f"  OK: {d['ajoutes']} ajoutes, {d['ignores']} ignores")

    print(f"Envoi des {len(imprimantes)} imprimantes...")
    r = requests.post(
        f"{url}/api/scan/imprimantes",
        headers=headers,
        json={"imprimantes": imprimantes, "site": site},
        timeout=30,
    )
    if r.status_code != 200:
        print(f"  ERREUR: {r.status_code} - {r.text}")
    else:
        d = r.json()
        print(f"  OK: {d['ajoutes']} ajoutes, {d['ignores']} ignores")


def main():
    parser = argparse.ArgumentParser(description="Scan reseau ANEM - envoie les resultats a Railway")
    parser.add_argument("--url", required=True, help="URL de l'app (ex: https://parc-anem-production.up.railway.app)")
    parser.add_argument("--token", required=True, help="Token API")
    parser.add_argument("--site", required=True, help="Nom du site (ex: ALEM bouira)")
    parser.add_argument("--cidr", default=None, help="Plage reseau (ex: 192.168.1.0/24)")
    parser.add_argument("--parallele", type=int, default=50, help="Nombre de threads (defaut: 50)")
    args = parser.parse_args()

    url = args.url.rstrip("/")
    print("=" * 50)
    print("  SCAN RESEAU ANEM")
    print(f"  Site: {args.site}")
    print(f"  Serveur: {url}")
    print("=" * 50)

    machines, imprimantes = scan_complet(cidr=args.cidr, parallele=args.parallele)
    envoyer(url, args.token, args.site, machines, imprimantes)

    print("\nTermine !")


if __name__ == "__main__":
    main()
