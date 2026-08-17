"""Client SNMPv1 minimal (lecture du niveau de toner des imprimantes)."""

import socket
import struct
import time

COMMUNAUTES = ("public", "private")

OID_MARQUEUR_TYPE = "1.3.6.1.2.1.43.11.1.1.5.1."  # + index
OID_MARQUEUR_DESCRIPTION = "1.3.6.1.2.1.43.11.1.1.6.1."  # + index
OID_MARQUEUR_NIVEAU = "1.3.6.1.2.1.43.11.1.1.9.1."  # + index


def _longueur(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    raise ValueError("Longueur BER trop grande : " + str(n))


def _encode_oid(oid):
    parties = [int(p) for p in oid.split(".")]
    corps = []
    premier = parties[0] * 40 + parties[1]
    corps.append(premier)
    for p in parties[2:]:
        if p < 0x80:
            corps.append(p)
            continue
        octets = []
        while p >= 0x80:
            octets.insert(0, (p & 0x7F) | 0x80)
            p >>= 7
        octets.insert(0, p)
        corps.extend(octets)
    return bytes(corps)


def _decode_oid(octets):
    parties = []
    premier = octets[0]
    parties.append(premier // 40)
    parties.append(premier % 40)
    courant = 0
    for b in octets[1:]:
        courant = (courant << 7) | (b & 0x7F)
        if not (b & 0x80):
            parties.append(courant)
            courant = 0
    return ".".join(str(p) for p in parties)


def _tlv(tag, contenu):
    return bytes([tag]) + _longueur(len(contenu)) + contenu


def _entier(valeur):
    if valeur == 0:
        return b"\x00"
    if valeur < 0:
        valeur &= 0xFFFFFFFF
    octets = []
    while valeur:
        octets.insert(0, valeur & 0xFF)
        valeur >>= 8
    if octets[0] & 0x80:
        octets.insert(0, 0)
    return bytes(octets)


def _decoder_entier(octets):
    if not octets:
        return 0
    return int.from_bytes(octets, "big", signed=(octets[0] & 0x80 != 0))


def _requete_get(communaute, identifiant, oid):
    varbind = _tlv(0x30, _tlv(0x06, _encode_oid(oid)) + b"\x05\x00")
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(
        0xA0,
        _tlv(0x02, _entier(identifiant))
        + _tlv(0x02, _entier(0))
        + _tlv(0x02, _entier(0))
        + varbinds,
    )
    msg = _tlv(
        0x30,
        _tlv(0x02, _entier(0))
        + _tlv(0x04, communaute.encode("latin-1"))
        + pdu,
    )
    return msg


def _parcourir_tlv(data):
    """Analyse la réponse SNMP : renvoie le premier (type, valeur) trouvé."""
    pos = 0

    def _lire_longueur(i):
        b = data[i]
        i += 1
        if b < 0x80:
            return b, i
        n = b & 0x7F
        return int.from_bytes(data[i:i + n], "big"), i + n

    def _sauter(i):
        """Saut par-dessus un TLV complet, renvoie la position suivante."""
        tag = data[i]
        long, i = _lire_longueur(i + 1)
        return i + long

    def _lire_tlv(i):
        tag = data[i]
        long, i = _lire_longueur(i + 1)
        valeur = data[i:i + long]
        return tag, valeur, i + long

    if pos >= len(data) or data[pos] != 0x30:
        return None
    _, pos = _lire_longueur(pos + 1)  # entre dans la séquence externe
    if pos >= len(data) or data[pos] != 0x02:  # version
        return None
    pos = _sauter(pos)
    if pos >= len(data):
        return None
    tag = data[pos]
    pos = _sauter(pos)  # communauté
    if tag != 0x04 or pos >= len(data):
        return None
    if data[pos] != 0xA2:  # GET-RESPONSE
        return None
    _, pos = _lire_longueur(pos + 1)  # entre dans la PDU
    for _ in range(3):  # request-id, error-status, error-index
        if pos >= len(data) or data[pos] != 0x02:
            return None
        pos = _sauter(pos)
    if pos >= len(data) or data[pos] != 0x30:  # varbind list
        return None
    _, pos = _lire_longueur(pos + 1)  # entre dans la liste
    if pos >= len(data) or data[pos] != 0x30:  # varbind
        return None
    _, pos = _lire_longueur(pos + 1)  # entre dans le varbind
    tag, oid_octets, pos = _lire_tlv(pos)
    if tag != 0x06:
        return None
    if pos >= len(data):
        return None
    tag, valeur, _ = _lire_tlv(pos)
    return {"oid": _decode_oid(oid_octets), "type": tag, "valeur": valeur}


def _interroger_oid(hote, communaute, oid, timeout=2.0):
    identifiant = int(time.time() * 1000) & 0xFFFF
    paquet = _requete_get(communaute, identifiant, oid)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(paquet, (hote, 161))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    return _parcourir_tlv(data)


def _valeur_entier(rep):
    if rep is None or rep["type"] != 0x02:
        return None
    return _decoder_entier(rep["valeur"])


def _valeur_texte(rep):
    if rep is None or rep["type"] != 0x04:
        return None
    try:
        return rep["valeur"].decode("utf-8", "ignore").strip()
    except Exception:
        return None


def lire_toner(hote, timeout=1.5):
    """Lit niveau + description du toner via SNMP. Retourne dict ou None."""
    for communaute in COMMUNAUTES:
        resultat = {"description": "", "niveau": None, "couleur": "noir"}
        try:
            rep_type = _interroger_oid(hote, communaute, OID_MARQUEUR_TYPE + "1", timeout)
            rep_niveau = _interroger_oid(hote, communaute, OID_MARQUEUR_NIVEAU + "1", timeout)
            rep_desc = _interroger_oid(hote, communaute, OID_MARQUEUR_DESCRIPTION + "1", timeout)
        except socket.timeout:
            continue
        except OSError:
            continue
        except Exception:
            continue

        niveau = _valeur_entier(rep_niveau)
        description = _valeur_texte(rep_desc) or ""
        if niveau is None:
            continue
        if niveau < 0 or niveau > 100:
            continue
        resultat["niveau"] = niveau
        resultat["description"] = description
        return resultat
    return None


def lire_sysdescr(hote, timeout=1.5):
    """Lit la description du matériel (sysDescr) via SNMP."""
    for communaute in COMMUNAUTES:
        try:
            rep = _interroger_oid(hote, communaute, "1.3.6.1.2.1.1.1.0", timeout)
        except socket.timeout:
            continue
        except OSError:
            continue
        except Exception:
            continue
        texte = _valeur_texte(rep)
        if texte:
            return texte
    return ""
