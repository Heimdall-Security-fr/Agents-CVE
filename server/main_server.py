from flask import Flask, jsonify, request, redirect, render_template, send_file, Response
from flask_pymongo import PyMongo
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
import os
import uuid
import secrets
import threading
import requests
import re
import json
import logging
import xml.etree.ElementTree as ET
import io
import zipfile
import textwrap
import platform

try:
    import bcrypt as _bcrypt
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False

try:
    import jwt as _pyjwt
    _HAS_JWT = True
except ImportError:
    _HAS_JWT = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─── Parsing de version ───────────────────────────────────────────────────────
try:
    from packaging.version import Version as _PkgVersion, InvalidVersion
    _HAS_PACKAGING = True
except ImportError:
    _HAS_PACKAGING = False

def _parse_ver(s: str):
    """Parse a version string, returning a packaging.Version or None on failure."""
    if not _HAS_PACKAGING or not s:
        return None
    s = str(s).strip()
    # Remove known non-numeric suffixes: .windows.1, -win64, -alpha, etc.
    s = re.sub(r'[._-](windows|win|linux|macos|osx|alpha|beta|rc|git|build|release)\b.*',
               '', s, flags=re.IGNORECASE)
    # Strip leading operators that might sneak in
    s = re.sub(r'^[<>=!]+', '', s).strip()
    # Keep only digits and dots
    s = re.sub(r'[^0-9.]', '.', s).strip('.')
    if not s:
        return None
    try:
        return _PkgVersion(s)
    except Exception:
        return None

# ── Windows build-number lookup ───────────────────────────────────────────────
# Maps known Windows release codes/names to NT build numbers (major.minor.build).
# Used when CVE affected-version strings are Windows release strings instead of
# the patched software's own version number.
_WIN_BUILDS: dict[str, tuple[int,int,int]] = {
    # Windows 10
    "gold": (10,0,10240), "rtm": (10,0,10240), "1507": (10,0,10240),
    "1511": (10,0,10586),
    "1607": (10,0,14393), "2016": (10,0,14393),   # Server 2016
    "1703": (10,0,15063),
    "1709": (10,0,16299),
    "1803": (10,0,17134),
    "1809": (10,0,17763), "2019": (10,0,17763),   # Server 2019
    "1903": (10,0,18362),
    "1909": (10,0,18363),
    "2004": (10,0,19041),
    "20h2": (10,0,19042),
    "21h1": (10,0,19043),
    "21h2": (10,0,19044),
    "22h2": (10,0,19045),                          # last Win 10
    # Windows 11
    "22000": (10,0,22000),                         # Win 11 21H2
    "22621": (10,0,22621), "22h2_11": (10,0,22621),
    "22631": (10,0,22631),                         # Win 11 23H2
    "26100": (10,0,26100),                         # Win 11 24H2 / Server 2025
    "25h2":  (10,0,26200), "26200": (10,0,26200),  # Win 11 25H2
    "2022":  (10,0,20348),                         # Server 2022
    "2025":  (10,0,26100),                         # Server 2025
}

def _highest_win_build_in(s: str) -> tuple[int,int,int] | None:
    """
    Scan a version string for Windows release keywords and return the highest
    NT build tuple found, or None if the string doesn't look like a Windows
    release reference.
    """
    s_low = s.lower()
    # Quick gate: must contain a Windows-related token
    if not re.search(r'windows|server\s+20\d\d|server,?\s+version', s_low):
        return None
    found: list[tuple[int,int,int]] = []
    for code, build in _WIN_BUILDS.items():
        # Match as a word boundary so "2019" doesn't match "20192" etc.
        if re.search(r'\b' + re.escape(code) + r'\b', s_low):
            found.append(build)
    return max(found, default=None)

def _parse_os_build(os_build: str) -> tuple[int,int,int] | None:
    """
    Parse an OS build string like '10.0.19045 SP0' or '10.0.19045'
    into an (major, minor, build) int tuple, or None on failure.
    """
    if not os_build:
        return None
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', os_build)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None

def _cpe_normalize(name: str) -> str:
    """Normalize a software display name to a CPE-style search term.
    Used to match against the cpe_search_terms field in the CVE database.
    'Microsoft Edge 148.0' -> 'microsoft_edge'
    'Docker Desktop'       -> 'docker_desktop'
    '7-Zip 24.08 (x64)'   -> '7_zip'
    """
    s = re.sub(r'\s+\d[\d.\-_+a-zA-Z()\s]*$', '', name.strip(), flags=re.IGNORECASE)
    return re.sub(r'[^a-z0-9]+', '_', s.lower()).strip('_')


def _check_cpe_match(installed_ver: str, cpe_matches: list, product: str):
    """Vérifie l'appartenance d'une version aux ranges NVD `cpe_matches`.

    Retourne :
      - True  : au moins une entrée CPE matche le produit ET couvre la version
      - False : des entrées matchent le produit mais aucune ne couvre la version
      - None  : aucune entrée applicable → l'appelant doit faire le fallback
    """
    if not cpe_matches:
        return None
    inst = _parse_ver(installed_ver)
    if inst is None:
        return None  # version installée illisible → pas d'opinion

    product_low  = product.lower()
    product_norm = _cpe_normalize(product)
    saw_product_entry = False

    for cm in cpe_matches:
        m_product = (cm.get("product") or "").lower()
        if not m_product:
            continue
        # Le CPE product est déjà au format canonique (ex: "microsoft_edge").
        # On compare au nom brut ET au nom normalisé pour couvrir les deux.
        if m_product != product_low and m_product != product_norm:
            continue
        saw_product_entry = True

        v_start_inc = _parse_ver(cm.get("versionStartIncluding"))
        v_start_exc = _parse_ver(cm.get("versionStartExcluding"))
        v_end_inc   = _parse_ver(cm.get("versionEndIncluding"))
        v_end_exc   = _parse_ver(cm.get("versionEndExcluding"))
        has_range   = any([v_start_inc, v_start_exc, v_end_inc, v_end_exc])

        if not has_range:
            # Pas de range → on regarde la version du CPE lui-même.
            # "*" ou "-" = toutes versions affectées.
            cpe_ver_raw = cm.get("version") or ""
            if cpe_ver_raw in ("*", "-", ""):
                return True
            cpe_ver = _parse_ver(cpe_ver_raw)
            if cpe_ver is not None and inst == cpe_ver:
                return True
            continue  # version CPE spécifique qui ne correspond pas

        # Check des bornes
        if v_start_inc is not None and inst <  v_start_inc:  continue
        if v_start_exc is not None and inst <= v_start_exc:  continue
        if v_end_inc   is not None and inst >  v_end_inc:    continue
        if v_end_exc   is not None and inst >= v_end_exc:    continue
        return True  # dans le range

    if saw_product_entry:
        return False  # le produit est listé mais la version est en dehors
    return None       # aucune entrée pour ce produit → fallback

# ─── CVE document validity ────────────────────────────────────────────────────
_CVE_ID_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

def _is_valid_cve_doc(c: dict) -> bool:
    """Return True only if the document has a proper CVE-YYYY-NNNNN identifier."""
    return bool(_CVE_ID_RE.match(str(c.get("id", ""))))

def _in_version_range(inst_str: str, versions: list, os_build: str = "") -> bool:
    """
    Return True if inst_str is covered by at least one 'affected' version entry.
    Falls back to True (conservative/show) when versions can't be parsed.

    os_build: NT build string such as '10.0.19045 SP0' — used when the CVE
    version entries are Windows release strings instead of software semver.
    """
    inst = _parse_ver(inst_str)
    if inst is None:
        return True  # can't parse installed version → show CVE conservatively

    parsed_os = _parse_os_build(os_build) if os_build else None

    any_parsed = False
    for ve in versions:
        if ve.get("status", "affected") != "affected":
            continue
        raw_ver = str(ve.get("version", "")).strip()
        v_lt    = _parse_ver(ve.get("lessThan"))
        v_lte   = _parse_ver(ve.get("lessThanOrEqual"))

        # ── Windows-style version string? ──────────────────────────────
        # e.g. "Microsoft Windows 10 1703, 1709 and Windows Server, version 1709."
        # These can't be parsed as semver; use the OS build instead.
        if v_lt is None and v_lte is None:
            win_build = _highest_win_build_in(raw_ver)
            if win_build is not None:
                any_parsed = True
                if parsed_os is not None:
                    # Agent's OS is newer than or equal to the highest affected
                    # Windows build → patched through Windows Update → not affected
                    if parsed_os > win_build:
                        continue  # this entry does not affect us
                    else:
                        return True  # running an affected Windows version
                else:
                    return True  # can't compare OS build → conservative
                continue

        # ── Regular (semver-style) version entry ───────────────────────
        v_start = _parse_ver(raw_ver) if raw_ver else None

        if v_lt is None and v_lte is None:
            # No upper bound
            if v_start is None:
                # Unparseable version (commit SHA, branch name, etc.) — skip
                # this entry instead of returning True for the whole CVE.
                continue
            if raw_ver in ("0", "0.0", "0.0.0", "N/A", ""):
                # "any version" placeholder — still counts as parsed evidence
                any_parsed = True
                return True
            any_parsed = True
            # Exact-version entry
            if inst == v_start:
                return True
        else:
            # Range [v_start, lessThan) or [v_start, lessThanOrEqual].
            # If raw_ver is unparseable but we have an upper bound, treat as [0, upper).
            any_parsed = True
            below_start = bool(v_start and inst < v_start)
            above_lt    = bool(v_lt  and inst >= v_lt)
            above_lte   = bool(v_lte and inst >  v_lte)
            if not below_start and not above_lt and not above_lte:
                return True

    return not any_parsed  # nothing parseable → conservative True


def _cve_affects_version(installed_ver: str, cve_doc: dict, product: str,
                         os_build: str = "") -> bool:
    """
    True  → CVE is potentially relevant (show it).
    False → installed version is outside all affected ranges (filter out).

    os_build: NT build string such as '10.0.19045 SP0' passed through for
    Windows-style affected-version matching.

    Ordre de précédence :
      1. `cpe_matches` enrichi par NVD (ranges normalisés) — source la plus fiable
      2. `affected_components` issu de cvelistv5 (texte libre des CNA)
      3. Heuristiques sur le champ `version` racine
    """
    # 1. NVD cpe_matches — données structurées, donne un verdict définitif
    cpe_matches = cve_doc.get("cpe_matches", [])
    cpe_verdict = _check_cpe_match(installed_ver, cpe_matches, product)
    if cpe_verdict is not None:
        return cpe_verdict

    ac = cve_doc.get("affected_components", [])
    if not ac:
        # No structured version ranges — try the root-level version hint
        # (common in RSS-ingested CVEs). If installed is strictly newer than
        # the CVE's referenced version, the patch has likely been applied.
        root_ver = str(cve_doc.get("version", "")).strip()
        if root_ver and root_ver.lower() not in ("n/a", "", "none", "0"):
            inst = _parse_ver(installed_ver)
            rv   = _parse_ver(root_ver)
            if inst is not None and rv is not None:
                return inst <= rv  # newer than CVE version → likely patched
        return True  # no usable version info → conservative

    # Match only components whose product name actually corresponds to the
    # installed software. Otherwise we'd compare e.g. Node.js 22.21.1 against
    # Parse Server's "<9.5.2" range — which yields nonsense.
    product_low  = product.lower()
    product_norm = _cpe_normalize(product)
    matching_comps = []
    for comp in ac:
        comp_prod = str(comp.get("product", "")).strip()
        if not comp_prod:
            continue
        comp_low  = comp_prod.lower()
        comp_norm = _cpe_normalize(comp_prod)
        # Exact, normalized, or substring match in either direction
        if (comp_low == product_low
                or comp_norm == product_norm
                or (product_norm and product_norm in comp_norm)
                or (comp_norm and comp_norm in product_norm)):
            matching_comps.append(comp)

    if not matching_comps:
        # The CVE's affected components don't reference the installed product.
        # This CVE was likely matched via desc_terms / generic CPE term and is
        # not actually about this product → filter it out.
        return False

    all_versions = []
    for comp in matching_comps:
        all_versions.extend(comp.get("versions", []))
    if not all_versions:
        return True  # product matches but no version data → conservative
    return _in_version_range(installed_ver, all_versions, os_build)


def _clean(obj):
    """Recursively convert MongoDB datetime/ObjectId/extended-JSON to plain JSON-safe types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        # BSON extended-JSON: {"$date": "..."} → keep inner ISO string
        if "$date" in obj and len(obj) == 1:
            return obj["$date"]
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(i) for i in obj]
    # bson ObjectId / other non-serialisable BSON types → str
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return str(obj)

# --- Configuration ---
HEIMDALL_CVE_API  = os.getenv("HEIMDALL_CVE_API",  "http://cve_api:5000")
HEIMDALL_RSS_URL  = os.getenv("HEIMDALL_RSS_URL",   "http://cve_api:5000/cves/rss")
MONGO_URI         = os.getenv("MONGO_URI",          "mongodb://mongodb:27017/heimdall_agents")
SERVER_CVE_API_KEY = os.getenv("CVE_API_KEY", "")  # Clé serveur (premium) pour les corrélations internes
SERVER_PUBLIC_HOST = os.getenv("SERVER_PUBLIC_HOST", "127.0.0.1")
SERVER_PUBLIC_PORT = int(os.getenv("SERVER_PUBLIC_PORT", 4000))
AGENT_AUTH_TOKEN   = os.getenv("AGENT_AUTH_TOKEN",   "changeme-secret-token")
HEIMDALL_FRONT_URL = os.getenv("HEIMDALL_FRONT_URL", "http://localhost:3000")
AGENT_VERSION      = os.getenv("AGENT_VERSION", "1.0.0")

app = Flask(__name__)
app.config["MONGO_URI"] = MONGO_URI
mongo = PyMongo(app)
CORS(app, origins="*", supports_credentials=True)

# PyMongo est déjà thread-safe (pool de connexions interne).
# On garde le nom `db_lock` pour préserver la sémantique des `with db_lock:`,
# mais c'est désormais un no-op : plus de sérialisation globale des requêtes.
from contextlib import nullcontext
db_lock = nullcontext()

# ─── Dashboard auth (JWT) ─────────────────────────────────────────────────────
DASHBOARD_JWT_SECRET    = os.getenv("DASHBOARD_JWT_SECRET", secrets.token_hex(32))
DASHBOARD_JWT_EXPIRE_D  = int(os.getenv("DASHBOARD_JWT_EXPIRE_DAYS", 7))

ROLES = ("admin", "deployment", "inspection_logs", "codir")

# ─── Docker IP ranges (filtered from server view) ─────────────────────────────
_DOCKER_IP_RE = re.compile(
    r'^(172\.(1[6-9]|2[0-9]|3[01])\.'   # 172.16.0.0/12
    r'|127\.'                             # loopback
    r'|::1$)'                             # IPv6 loopback
)

def _is_docker_ip(ip: str) -> bool:
    return bool(_DOCKER_IP_RE.match(ip or ""))

def _subnet_24(ip: str) -> str | None:
    parts = ip.split('.')
    if len(parts) == 4:
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except ValueError:
            pass
    return None

# ─── Default compliance rules ─────────────────────────────────────────────────
DEFAULT_COMPLIANCE_RULES = [
    # ── Authentification & Mots de passe ─────────────────────────────────────────
    {"id": "password_min_length",
     "name": "Longueur minimale du mot de passe",
     "description": "Nombre minimum de caractères requis pour tous les mots de passe",
     "expected_op": ">=", "expected_value": 12, "type": "int",
     "severity": "high", "cis_ref": "CIS 1.1.1",
     "example": "12 minimum — 14 recommandé CIS Niveau 1",
     "platforms": ["windows", "linux", "darwin"], "enabled": True},
    {"id": "passwd_max_days",
     "name": "Expiration mot de passe (jours max)",
     "description": "PASS_MAX_DAYS — durée de vie maximale avant obligation de changement",
     "expected_op": "<=", "expected_value": 90, "type": "int",
     "severity": "medium", "cis_ref": "CIS 5.4.1.1",
     "example": "90 jours (CIS L1) — 365 maximum acceptable",
     "platforms": ["linux", "darwin"], "enabled": True},
    {"id": "passwd_min_days",
     "name": "Age minimum mot de passe (jours)",
     "description": "PASS_MIN_DAYS — délai minimum avant de pouvoir rechanger le mot de passe",
     "expected_op": ">=", "expected_value": 7, "type": "int",
     "severity": "low", "cis_ref": "CIS 5.4.1.2",
     "example": "7 jours (CIS)",
     "platforms": ["linux", "darwin"], "enabled": False},
    {"id": "account_lockout_threshold",
     "name": "Seuil de verrouillage de compte",
     "description": "Nombre de tentatives échouées avant verrouillage (0 = désactivé)",
     "expected_op": "<=", "expected_value": 5, "type": "int",
     "severity": "high", "cis_ref": "CIS 1.2.1",
     "example": "5 tentatives (CIS) — 3 pour plus de sécurité",
     "platforms": ["windows"], "enabled": True},
    {"id": "account_lockout_duration",
     "name": "Durée de verrouillage (minutes)",
     "description": "Durée minimale de verrouillage après dépassement du seuil d'echecs",
     "expected_op": ">=", "expected_value": 15, "type": "int",
     "severity": "medium", "cis_ref": "CIS 1.2.2",
     "example": "15 minutes (CIS)",
     "platforms": ["windows"], "enabled": False},
    # ── Réseau & Pare-feu ───────────────────────────────────────────────────
    {"id": "tls_min_version",
     "name": "Version TLS minimum",
     "description": "Version TLS la plus ancienne autorisée pour les connexions sécurisées",
     "expected_op": ">=", "expected_value": "1.2", "type": "tls_version",
     "severity": "critical", "cis_ref": "CIS 3.5.1",
     "example": "1.2 (CIS L1) — 1.3 recommandé pour toute nouvelle installation",
     "platforms": ["windows", "linux", "darwin"], "enabled": True},
    {"id": "firewall_enabled",
     "name": "Pare-feu activé",
     "description": "Le pare-feu système doit être actif (ufw / firewalld / Windows Firewall)",
     "expected_op": "==", "expected_value": True, "type": "bool",
     "severity": "critical", "cis_ref": "CIS 9.1",
     "example": "true",
     "platforms": ["windows", "linux"], "enabled": True},
    {"id": "sysctl_ip_forwarding",
     "name": "IP Forwarding désactivé",
     "description": "net.ipv4.ip_forward — les postes non-routeurs ne doivent pas router les paquets",
     "expected_op": "==", "expected_value": 0, "type": "int",
     "severity": "medium", "cis_ref": "CIS 3.1.1",
     "example": "0 (désactivé)",
     "platforms": ["linux"], "enabled": True},
    {"id": "sysctl_accept_redirects",
     "name": "ICMP Redirects désactivé",
     "description": "net.ipv4.conf.all.accept_redirects — protège contre le détournement de route",
     "expected_op": "==", "expected_value": 0, "type": "int",
     "severity": "medium", "cis_ref": "CIS 3.2.2",
     "example": "0 (désactivé)",
     "platforms": ["linux"], "enabled": True},
    {"id": "sysctl_syncookies",
     "name": "TCP SYN Cookies activé",
     "description": "net.ipv4.tcp_syncookies — protection contre les attaques SYN flood",
     "expected_op": "==", "expected_value": 1, "type": "int",
     "severity": "medium", "cis_ref": "CIS 3.3.8",
     "example": "1 (activé)",
     "platforms": ["linux"], "enabled": True},
    {"id": "sysctl_log_martians",
     "name": "Log des paquets martiens",
     "description": "net.ipv4.conf.all.log_martians — journalise les paquets à adresse source impossible",
     "expected_op": "==", "expected_value": 1, "type": "int",
     "severity": "low", "cis_ref": "CIS 3.2.4",
     "example": "1 (activé)",
     "platforms": ["linux"], "enabled": False},
    # ── Windows spécifique ───────────────────────────────────────────────────
    {"id": "smb1_disabled",
     "name": "SMBv1 désactivé",
     "description": "SMBv1 est exploité par WannaCry/EternalBlue — doit être désactivé",
     "expected_op": "==", "expected_value": True, "type": "bool",
     "severity": "critical", "cis_ref": "CIS 18.3.2",
     "example": "true",
     "platforms": ["windows"], "enabled": True},
    {"id": "rdp_nla_enabled",
     "name": "RDP avec NLA activé",
     "description": "Network Level Authentication doit être obligatoire pour les connexions RDP",
     "expected_op": "==", "expected_value": True, "type": "bool",
     "severity": "high", "cis_ref": "CIS 18.9.59.3",
     "example": "true",
     "platforms": ["windows"], "enabled": True},
    {"id": "defender_realtime",
     "name": "Windows Defender temps réel",
     "description": "La protection temps réel de Windows Defender doit être active",
     "expected_op": "==", "expected_value": True, "type": "bool",
     "severity": "critical", "cis_ref": "CIS 18.9.47.4",
     "example": "true",
     "platforms": ["windows"], "enabled": True},
    {"id": "uac_enabled",
     "name": "UAC activé",
     "description": "User Account Control — prévient les élévations de privilèges silencieuses",
     "expected_op": "==", "expected_value": True, "type": "bool",
     "severity": "high", "cis_ref": "CIS 2.3.17.6",
     "example": "true",
     "platforms": ["windows"], "enabled": True},
    {"id": "guest_account_disabled",
     "name": "Compte Invité désactivé",
     "description": "Le compte Invité intégré Windows doit être désactivé",
     "expected_op": "==", "expected_value": True, "type": "bool",
     "severity": "high", "cis_ref": "CIS 2.3.1.3",
     "example": "true",
     "platforms": ["windows"], "enabled": True},
    {"id": "auto_updates_enabled",
     "name": "Mises à jour automatiques",
     "description": "Les mises à jour automatiques du système doivent être activées",
     "expected_op": "==", "expected_value": True, "type": "bool",
     "severity": "high", "cis_ref": "CIS 18.9.108.2",
     "example": "true",
     "platforms": ["windows", "linux"], "enabled": True},
    {"id": "screen_lock_timeout",
     "name": "Délai verrouillage écran (secondes max)",
     "description": "Délai maximum en secondes avant verrouillage automatique de la session inactive",
     "expected_op": "<=", "expected_value": 600, "type": "int",
     "severity": "medium", "cis_ref": "CIS 2.3.7.3",
     "example": "600 (10 min, CIS) — 300 pour plus de sécurité",
     "platforms": ["windows"], "enabled": True},
    # ── SSH ──────────────────────────────────────────────────────
    {"id": "ssh_root_login_disabled",
     "name": "SSH root désactivé",
     "description": "PermitRootLogin doit être 'no' dans sshd_config",
     "expected_op": "==", "expected_value": True, "type": "bool",
     "severity": "critical", "cis_ref": "CIS 5.2.10",
     "example": "true",
     "platforms": ["linux", "darwin"], "enabled": True},
    {"id": "ssh_password_auth_disabled",
     "name": "SSH auth par clé uniquement",
     "description": "PasswordAuthentication doit être 'no' — clés SSH uniquement",
     "expected_op": "==", "expected_value": False, "type": "bool",
     "severity": "high", "cis_ref": "CIS 5.2.12",
     "example": "false (auth clé uniquement)",
     "platforms": ["linux", "darwin"], "enabled": False},
    # ── Système & Audit ─────────────────────────────────────────────────
    {"id": "core_dumps_disabled",
     "name": "Core dumps désactivés",
     "description": "Les core dumps peuvent exposer mots de passe et clés privées en mémoire",
     "expected_op": "==", "expected_value": True, "type": "bool",
     "severity": "medium", "cis_ref": "CIS 1.5.1",
     "example": "true",
     "platforms": ["linux"], "enabled": True},
    {"id": "audit_enabled",
     "name": "Daemon d'audit actif (auditd)",
     "description": "auditd doit être en cours d'exécution pour la traçabilité des événements",
     "expected_op": "==", "expected_value": True, "type": "bool",
     "severity": "high", "cis_ref": "CIS 4.1.1",
     "example": "true",
     "platforms": ["linux"], "enabled": True},
    {"id": "umask_value",
     "name": "Umask par défaut restrictif",
     "description": "Masque de création de fichiers — doit être 027 ou plus restrictif",
     "expected_op": "in", "expected_value": "027,077", "type": "string",
     "severity": "low", "cis_ref": "CIS 5.4.4",
     "example": "027 (CIS L1) — 077 pour plus de restriction",
     "platforms": ["linux", "darwin"], "enabled": False},
]

def _eval_rule(rule: dict, compliance: dict, os_str: str) -> dict:
    """Evaluate one compliance rule against an agent's compliance dict."""
    rule_id = rule["id"]
    os_lower = (os_str or "").lower()
    platforms = rule.get("platforms", [])
    if "windows" in os_lower:   pkey = "windows"
    elif "darwin" in os_lower:  pkey = "darwin"
    else:                        pkey = "linux"

    base = {
        "rule_id": rule_id, "name": rule.get("name"),
        "expected_value": rule["expected_value"], "expected_op": rule["expected_op"],
        "description": rule.get("description"),
    }
    if pkey not in platforms:
        return {**base, "status": "na", "actual_value": None}

    actual = compliance.get(rule_id)
    if actual is None:
        return {**base, "status": "unknown", "actual_value": None}

    op, exp, rtype = rule["expected_op"], rule["expected_value"], rule.get("type", "")
    try:
        if rtype == "tls_version":
            def _tv(v): return tuple(int(x) for x in str(v).replace(",", ".").split("."))
            passed = (_tv(actual) >= _tv(exp)) if op == ">=" else (str(actual) == str(exp))
        elif op == "in":
            acceptable = [v.strip() for v in str(exp).split(",")]
            passed = str(actual).strip() in acceptable
        elif isinstance(exp, bool):
            passed = bool(actual) == exp
        elif isinstance(exp, (int, float)):
            a = float(actual)
            passed = {">=": a >= exp, "<=": a <= exp, ">": a > exp, "<": a < exp}.get(op, a == exp)
        else:
            passed = str(actual) == str(exp)
    except Exception:
        passed = False
    return {**base, "status": "pass" if passed else "fail", "actual_value": actual}

# ─── Dashboard auth helpers ───────────────────────────────────────────────────
def _hash_pw(pw: str) -> str:
    if _HAS_BCRYPT:
        return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt()).decode()
    import hashlib
    return "sha256:" + hashlib.sha256(pw.encode()).hexdigest()

def _check_pw(pw: str, hashed: str) -> bool:
    if _HAS_BCRYPT and not hashed.startswith("sha256:"):
        return _bcrypt.checkpw(pw.encode(), hashed.encode())
    import hashlib
    return hashed == "sha256:" + hashlib.sha256(pw.encode()).hexdigest()

def _create_dashboard_token(user_doc: dict) -> str:
    payload = {
        "sub":   str(user_doc["_id"]),
        "email": user_doc["email"],
        "role":  user_doc["role"],
        "exp":   datetime.utcnow() + timedelta(days=DASHBOARD_JWT_EXPIRE_D),
    }
    if _HAS_JWT:
        return _pyjwt.encode(payload, DASHBOARD_JWT_SECRET, algorithm="HS256")
    # fallback: very basic (not production-safe)
    import base64
    return base64.b64encode(json.dumps(payload).encode()).decode()

def _decode_dashboard_token(token: str) -> dict | None:
    if _HAS_JWT:
        try:
            return _pyjwt.decode(token, DASHBOARD_JWT_SECRET, algorithms=["HS256"])
        except Exception:
            return None
    import base64
    try:
        return json.loads(base64.b64decode(token.encode()).decode())
    except Exception:
        return None

def _get_dashboard_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, "Token manquant"
    payload = _decode_dashboard_token(auth[7:])
    if not payload:
        return None, "Token invalide ou expiré"
    return {"id": payload["sub"], "email": payload["email"], "role": payload["role"]}, None

def require_dashboard_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user, err = _get_dashboard_user()
        if not user:
            return jsonify({"error": err}), 401
        request.dashboard_user = user
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user, err = _get_dashboard_user()
        if not user:
            return jsonify({"error": err}), 401
        if user["role"] != "admin":
            return jsonify({"error": "Accès réservé aux administrateurs"}), 403
        request.dashboard_user = user
        return f(*args, **kwargs)
    return decorated

def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user, err = _get_dashboard_user()
            if not user:
                return jsonify({"error": err}), 401
            if user["role"] not in allowed_roles:
                return jsonify({"error": "Accès insuffisant"}), 403
            request.dashboard_user = user
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─── Authentification agents ──────────────────────────────────────────────────
def require_agent_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("x-agent-token")
        if token != AGENT_AUTH_TOKEN:
            return {"error": "Unauthorized"}, 401
        return f(*args, **kwargs)
    return decorated

# ─── Statut en ligne des agents ───────────────────────────────────────────────
HEARTBEAT_TIMEOUT = 120  # secondes — hors ligne si aucun heartbeat depuis 2 min

def _is_online(agent) -> bool:
    """True si l'agent a contacté le serveur dans les 2 dernières minutes."""
    ref = agent.get("last_heartbeat") or agent.get("last_seen")
    if ref is None:
        return False
    now = datetime.utcnow()
    if isinstance(ref, str):
        try:
            ref = datetime.fromisoformat(ref.replace("Z", "+00:00"))
        except Exception:
            return False
    try:
        return (now - ref.replace(tzinfo=None)).total_seconds() < HEARTBEAT_TIMEOUT
    except TypeError:
        return False

# ─── Mise à jour CVE depuis le flux RSS ───────────────────────────────────────
def refresh_cve_from_rss():
    """Consomme le flux RSS de l'API CVE et met à jour la base locale."""
    try:
        logger.info("[RSS] Récupération du flux RSS…")
        r = requests.get(HEIMDALL_RSS_URL + "?limit=200", timeout=15)
        r.raise_for_status()
        root = ET.fromstring(r.text)
        channel = root.find('channel')
        count = 0
        for item in channel.findall('item'):
            cve_id  = item.findtext('guid', '')
            if not cve_id:
                continue
            entry = {
                "id":          cve_id,
                "title":       item.findtext('title', ''),
                "description": item.findtext('description', ''),
                "cvss_score":  float(item.findtext('cvss', '0') or 0),
                "product":     item.findtext('product', 'N/A'),
                "vendor":      item.findtext('vendor',  'N/A'),
                "version":     item.findtext('version', 'N/A'),
                "date_published": item.findtext('pubDate', ''),
                "fetched_at":  datetime.utcnow()
            }
            raw_aff = item.findtext('affected_components', '')
            if raw_aff:
                try: entry['affected_components'] = json.loads(raw_aff)
                except: pass
            with db_lock:
                mongo.db.cve_cache.update_one({"id": cve_id}, {"$set": entry}, upsert=True)
            count += 1
        logger.info(f"[RSS] {count} CVE intégrées dans le cache local.")
    except Exception as e:
        logger.warning(f"[RSS] Échec récupération flux RSS: {e}. Tentative via API directe…")
        try:
            r = requests.get(f"{HEIMDALL_CVE_API}/cves/recent", timeout=15)
            r.raise_for_status()
            cves = r.json() if isinstance(r.json(), list) else r.json().get("results", [])
            for cve in cves:
                cve["fetched_at"] = datetime.utcnow()
                with db_lock:
                    mongo.db.cve_cache.update_one({"id": cve.get("id")}, {"$set": cve}, upsert=True)
            logger.info(f"[API] {len(cves)} CVE intégrées via l'API directe.")
        except Exception as e2:
            logger.error(f"[API] Impossible de récupérer les CVE: {e2}")

# ─── Corrélation CVE/logiciels ────────────────────────────────────────────────
def correlate_vulnerabilities(software_list, cve_api_key: str = "", os_build: str = ""):
    """Pour chaque logiciel, cherche des CVE dans le cache local puis dans l'API distante.
    Filtre les CVE dont la version installée est en dehors des plages affectées.
    os_build: build NT de l'OS hôte (ex: '10.0.19045 SP0'), utilisé pour les CVE
    dont les versions affectées sont des releases Windows."""
    vulns = []
    api_headers = {"x-api-key": cve_api_key} if cve_api_key else {}
    for sw in software_list:
        product      = sw.get("product", "")
        version      = sw.get("version", "")
        product_raw  = sw.get("product_raw", product)  # raw registry name (before normalization)
        if not product:
            continue

        # 1. Cache local (RSS) — matching strict d'abord, desc_terms en dernier recours
        cpe_norm = _cpe_normalize(product)
        cpe_norm_raw = _cpe_normalize(product_raw) if product_raw != product else cpe_norm

        # Conditions strictes : product exact, CPE search terms, CPE NVD product
        strict_conditions = [
            {"product": {"$regex": f"^{re.escape(product)}$", "$options": "i"}},
            {"cpe_search_terms": cpe_norm},
            {"cpe_matches.product": cpe_norm},
        ]
        if cpe_norm_raw != cpe_norm:
            strict_conditions.append({"product": {"$regex": f"^{re.escape(product_raw)}$", "$options": "i"}})
            strict_conditions.append({"cpe_search_terms": cpe_norm_raw})
            strict_conditions.append({"cpe_matches.product": cpe_norm_raw})

        with db_lock:
            cves_raw = list(mongo.db.cve_cache.find(
                {"$or": strict_conditions},
                sort=[("cvss_score", -1)], limit=10
            ))
        cves_raw = [c for c in cves_raw if _is_valid_cve_doc(c)]

        # 2. Recherche directe dans la base CVE principale (matching strict)
        if not cves_raw:
            try:
                with db_lock:
                    cves_raw = list(mongo.cx["cve_database"]["cves"].find(
                        {"$or": strict_conditions},
                        sort=[("cvss_score", -1)], limit=10
                    ))
                    for c in cves_raw:
                        c.pop("_id", None)
                cves_raw = [c for c in cves_raw if _is_valid_cve_doc(c)]
            except Exception as e:
                logger.warning(f"Direct CVE DB lookup échoué pour {product}: {e}")

        # 2b. Dernier recours : desc_terms (matching par texte libre de la description).
        # Bruyant — on l'utilise uniquement si les CPE et le nom exact n'ont rien donné.
        if not cves_raw:
            try:
                desc_conditions = [{"desc_terms": cpe_norm}]
                if cpe_norm_raw != cpe_norm:
                    desc_conditions.append({"desc_terms": cpe_norm_raw})
                with db_lock:
                    cves_raw = list(mongo.cx["cve_database"]["cves"].find(
                        {"$or": desc_conditions},
                        sort=[("cvss_score", -1)], limit=10
                    ))
                    for c in cves_raw:
                        c.pop("_id", None)
                cves_raw = [c for c in cves_raw if _is_valid_cve_doc(c)]
            except Exception as e:
                logger.warning(f"desc_terms lookup échoué pour {product}: {e}")

        # 3. Fallback → API distante (HTTP)
        if not cves_raw:
            try:
                resp = requests.get(
                    f"{HEIMDALL_CVE_API}/cves/search",
                    params={"query": product, "type": "product", "limit": 10},
                    headers=api_headers,
                    timeout=10
                )
                if resp.status_code == 200:
                    raw = resp.json()
                    results = raw.get("results", []) if isinstance(raw, dict) else raw
                    # Drop CVEs where product is "n/a" — those are description-matched
                    # false positives with no real product assignment
                    cves_raw = [c for c in results
                                if _is_valid_cve_doc(c)
                                and c.get("product", "n/a").lower() not in ("n/a", "", "none")]
                elif resp.status_code == 429:
                    logger.warning(f"[CVE API] Rate limit atteint pour {product} (clé: {'oui' if cve_api_key else 'non'})")
                else:
                    logger.warning(f"[CVE API] HTTP {resp.status_code} pour {product}")
            except Exception as e:
                logger.warning(f"Fallback API échoué pour {product}: {e}")

        # 4. Filtrage strict par version — pas de fallback si tout est filtré
        if version:
            cves_filtered = [c for c in cves_raw if _cve_affects_version(version, c, product, os_build)]
        else:
            cves_filtered = cves_raw

        # Cap configurable — auparavant 5, ce qui cachait des CVE aux utilisateurs.
        # 50 est un plafond raisonnable pour éviter d'exploser la taille du doc Mongo
        # sur des logiciels avec beaucoup d'historique de CVE.
        cap = int(os.getenv("MAX_CVES_PER_SOFTWARE", "50"))
        cves = cves_filtered[:cap]

        if cves:
            vulns.append({
                "software":   f"{sw.get('vendor', product)}/{product} v{version}",
                "name":       product,
                "product":    product,
                "version":    version,
                "cves_count": len(cves),
                "critical":   sum(1 for c in cves if float(c.get("cvss_score", 0)) >= 9.0),
                "high":       sum(1 for c in cves if 7.0 <= float(c.get("cvss_score", 0)) < 9.0),
                # On stocke aussi `cpe_matches` (enrichissement NVD) en plus de
                # `affected_components` (CNA cvelistv5). Ainsi /api/agents/<host>/software
                # n'a plus besoin de faire un _lookup_cve par CVE pour filtrer par version :
                # toutes les données nécessaires sont déjà inline → fin du N+1.
                "cves": [{"cve_id": c.get("id"), "cvss_score": c.get("cvss_score", 0),
                          "description": c.get("description", c.get("title", "")),
                          "product": c.get("product"), "vendor": c.get("vendor"),
                          "version": c.get("version"),
                          "date_published": c.get("date_published", ""),
                          "affected_components": c.get("affected_components", []),
                          "cpe_matches": c.get("cpe_matches", [])} for c in cves]
            })
    return vulns

# ─── Endpoints agents ─────────────────────────────────────────────────────────
@app.route('/api/agents/report', methods=['POST'])
@require_agent_token
def agent_report():
    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname", "Unknown")
    software_list = data.get("software", [])
    open_ports    = data.get("open_ports", [])
    cve_api_key   = data.get("cve_api_key", "") or SERVER_CVE_API_KEY
    os_build      = data.get("os_build", "")
    compliance    = data.get("compliance", {})          # NEW: agent-sent compliance data
    ip_addresses  = data.get("ip_addresses", [])        # NEW: agent's own IPs
    agent_version = data.get("agent_version", "")        # NEW: version reportée
    remote_ip     = request.remote_addr or ""           # server-observed IP as fallback

    # Fusion IP : on prend ce que l'agent envoie + l'IP source vue par Flask.
    # On filtre Docker, mais on garde 127.0.0.1 en dernier recours pour ne pas
    # afficher "—" si l'agent tourne sur la même machine que le serveur.
    candidate_ips = [ip for ip in ([remote_ip] + ip_addresses) if ip]
    routable = list({ip for ip in candidate_ips
                     if ip not in ("127.0.0.1", "::1", "0.0.0.0")
                     and not _is_docker_ip(ip)})
    if routable:
        display_ips = sorted(routable)
    else:
        # Aucune IP routable trouvée — garder l'IP observée (souvent 127.0.0.1)
        # pour que l'utilisateur ait au moins quelque chose à voir.
        display_ips = sorted({ip for ip in candidate_ips if not _is_docker_ip(ip)})

    vulns = correlate_vulnerabilities(software_list, cve_api_key, os_build)
    # Vrais totaux CVE (somme à travers tous les logiciels), pas juste le nombre
    # de logiciels vulnérables.
    cves_total     = sum(v.get("cves_count", 0) for v in vulns)
    critical_total = sum(v.get("critical",   0) for v in vulns)
    high_total     = sum(v.get("high",       0) for v in vulns)

    # Calcul de priorité : port ouvert + CVE critique = CRITIQUE
    priority_alerts = []
    critical_services = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
                         5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
                         9200: "Elasticsearch", 8080: "HTTP-Alt"}
    for port in open_ports:
        service = critical_services.get(port, f"Port {port}")
        priority_alerts.append({"port": port, "service": service,
                                 "exposed": True, "note": "Vérifier l'accès Internet externe"})

    report = {
        "hostname":         hostname,
        "os":               data.get("os", "Unknown"),
        "release":          data.get("release", ""),
        "os_build":         os_build,
        "agent_version":    agent_version,
        "timestamp":        data.get("timestamp", datetime.utcnow().isoformat()),
        "received_at":      datetime.utcnow().isoformat(),
        "open_ports":       open_ports,
        "priority_alerts":  priority_alerts,
        # vulnerable_count = nombre de logiciels vulnérables (legacy, conservé)
        "vulnerable_count": len(vulns),
        # cve_count = vrai total de CVE remontées (somme à travers les logiciels)
        "cve_count":        cves_total,
        "critical_count":   critical_total,
        "high_count":       high_total,
        "vulnerabilities":  vulns,
        "software_count":   len(software_list),
        "software":         software_list,
        "ip_addresses":     display_ips,
        "compliance":       compliance,
    }

    with db_lock:
        # On garde l'historique et on met à jour le "dernier rapport" de ce serveur
        mongo.db.agent_reports.insert_one({**report})

        # Si la corrélation n'a rien retourné (ex: rate limit côté API), on conserve
        # les vulnérabilités précédemment connues plutôt que de les écraser par []
        update_fields = {**report, "last_seen": datetime.utcnow()}
        if not vulns:
            existing = mongo.db.agents.find_one({"hostname": hostname},
                                                 {"vulnerabilities": 1, "vulnerable_count": 1})
            if existing and existing.get("vulnerabilities"):
                update_fields.pop("vulnerabilities", None)
                update_fields.pop("vulnerable_count", None)
                logger.info(f"[RAPPORT] {hostname}: corrélation vide, conservation des {existing['vulnerable_count']} vulns précédentes")

        mongo.db.agents.update_one(
            {"hostname": hostname},
            {"$set": update_fields},
            upsert=True
        )

    report.pop("_id", None)
    logger.info(f"[RAPPORT] {hostname}: {len(vulns)} vulns, {len(open_ports)} ports ouverts")
    return jsonify(report), 200

@app.route('/api/agents/<hostname>/heartbeat', methods=['POST'])
@require_agent_token
def agent_heartbeat(hostname):
    """Heartbeat léger — met à jour la présence de l'agent sans analyse complète."""
    data = request.get_json(silent=True) or {}
    now  = datetime.utcnow()
    with db_lock:
        mongo.db.agents.update_one(
            {"hostname": hostname},
            {"$set": {
                "last_heartbeat": now,
                "last_seen":      now,
                "os":             data.get("os",       ""),
                "release":        data.get("release",  ""),
                "os_build":       data.get("os_build", ""),
            }},
            upsert=True
        )
    return jsonify({"status": "ok", "ts": now.isoformat()}), 200

@app.route('/api/agents', methods=['GET'])
def list_agents():
    with db_lock:
        agents = list(mongo.db.agents.find({}, {"_id": 0}))
    for a in agents:
        a["online"] = _is_online(a)
    return jsonify([_clean(a) for a in agents])

@app.route('/api/agents/<hostname>', methods=['GET'])
def get_agent(hostname):
    with db_lock:
        agent = mongo.db.agents.find_one({"hostname": hostname}, {"_id": 0})
    if not agent:
        return {"error": "Agent not found"}, 404
    agent["online"] = _is_online(agent)
    return jsonify(_clean(agent))

@app.route('/api/agents/<hostname>/history', methods=['GET'])
def agent_history(hostname):
    with db_lock:
        reports = list(mongo.db.agent_reports.find(
            {"hostname": hostname}, {"_id": 0}
        ).sort("received_at", -1).limit(20))
    return jsonify([_clean(r) for r in reports])

# ─── Suppressions CVE ─────────────────────────────────────────────────────────
@app.route('/api/agents/<hostname>/suppress', methods=['GET'])
def list_suppressions(hostname):
    with db_lock:
        docs = list(mongo.db.suppressed_cves.find(
            {"hostname": hostname}, {"_id": 0}
        ))
    return jsonify([_clean(d) for d in docs])

@app.route('/api/agents/<hostname>/suppress', methods=['POST'])
@require_agent_token
def add_suppression(hostname):
    data    = request.get_json(silent=True) or {}
    cve_id  = str(data.get("cve_id",  "")).strip()
    product = str(data.get("product", "")).strip()
    reason  = str(data.get("reason",  "")).strip()[:300]
    if not cve_id or not product:
        return {"error": "cve_id et product sont requis"}, 400
    doc = {"hostname": hostname, "cve_id": cve_id, "product": product,
           "reason": reason, "suppressed_at": datetime.utcnow()}
    with db_lock:
        mongo.db.suppressed_cves.update_one(
            {"hostname": hostname, "cve_id": cve_id, "product": product},
            {"$set": doc}, upsert=True
        )
    logger.info(f"[SUPPRESS] {hostname}: {cve_id} non affecté pour {product}")
    return jsonify({"status": "ok"}), 201

@app.route('/api/agents/<hostname>/suppress', methods=['DELETE'])
@require_agent_token
def remove_suppression(hostname):
    data    = request.get_json(silent=True) or {}
    cve_id  = str(data.get("cve_id",  "")).strip()
    product = str(data.get("product", "")).strip()
    with db_lock:
        mongo.db.suppressed_cves.delete_one(
            {"hostname": hostname, "cve_id": cve_id, "product": product}
        )
    return jsonify({"status": "ok"}), 200

# ─── Détail logiciels d'un agent ─────────────────────────────────────────────
@app.route('/api/agents/<hostname>/software', methods=['GET'])
def agent_software(hostname):
    """Retourne la liste enrichie des logiciels de l'agent avec les CVE associées."""
    with db_lock:
        agent = mongo.db.agents.find_one({"hostname": hostname}, {"_id": 0})
    if not agent:
        return {"error": "Agent not found"}, 404

    # Charger les suppressions pour ce host
    with db_lock:
        suppressed_raw = list(mongo.db.suppressed_cves.find(
            {"hostname": hostname}, {"_id": 0}
        ))
    # Set of (product_lower, cve_id) → suppressed
    suppressed_set = {(s["product"].lower(), s["cve_id"]) for s in suppressed_raw}

    software_list = agent.get("software", [])
    stored_vulns  = agent.get("vulnerabilities", [])

    # Construire un index: nom_produit_lower → entrée_vulnérabilité
    vuln_lookup = {}
    for v in stored_vulns:
        raw         = v.get("software", "")        # ex. "vendor/product v1.0"
        name_part   = raw.split("/")[-1]            # "product v1.0"
        product_key = re.sub(r'\s+v[\d\.].*$', '', name_part, flags=re.IGNORECASE).strip().lower()
        vuln_lookup[product_key] = v

    enriched = []
    for sw in software_list:
        product = sw.get("product", "")
        version = sw.get("version", "")
        if not product:
            continue
        vuln = vuln_lookup.get(product.lower())

        # Read stored CVEs, then apply version filtering at read time
        # Drop CVEs with no real product data (description-only false positives)
        cves_raw = [c for c in (vuln.get("cves", []) if vuln else [])
                    if c.get("product", "n/a").lower() not in ("n/a", "", "none")]
        os_build = agent.get("os_build", "")
        if version and cves_raw:
            # Les CVE stockées par correlate_vulnerabilities embarquent déjà
            # `cpe_matches` (NVD) et `affected_components` (CNA). Plus de
            # _lookup_cve par CVE → fin du N+1.
            filtered = []
            for c in cves_raw:
                if c.get("cpe_matches") or c.get("affected_components"):
                    if _cve_affects_version(version, c, product, os_build):
                        filtered.append(c)
                else:
                    filtered.append(c)  # aucune donnée de version → conservatif
            cves_raw = filtered

        # Filter suppressed CVEs
        cves_visible = []
        cves_suppressed = []
        for c in cves_raw:
            key = (product.lower(), c.get("id", ""))
            if key in suppressed_set:
                cves_suppressed.append({**c, "suppressed": True})
            else:
                cves_visible.append({**c, "suppressed": False})

        total_visible  = len(cves_visible)
        crit_visible   = sum(1 for c in cves_visible if float(c.get("cvss",  0)) >= 9.0)
        high_visible   = sum(1 for c in cves_visible if 7.0 <= float(c.get("cvss", 0)) < 9.0)

        enriched.append({
            "product":    product,
            "vendor":     sw.get("vendor", ""),
            "version":    sw.get("version", ""),
            "cve_count":  total_visible,
            "cve_suppressed_count": len(cves_suppressed),
            "critical":   crit_visible,
            "high":       high_visible,
            "cves":       cves_visible + cves_suppressed,
        })

    enriched.sort(key=lambda x: (-x["critical"], -x["high"], -x["cve_count"], x["product"].lower()))

    return jsonify(_clean({
        "hostname":         hostname,
        "os":               agent.get("os", ""),
        "release":          agent.get("release", ""),
        "software_count":   len(enriched),
        "vulnerable_count": sum(1 for s in enriched if s["cve_count"] > 0),
        "suppressed_total": sum(s["cve_suppressed_count"] for s in enriched),
        "front_url":        HEIMDALL_FRONT_URL,
        "software":         enriched,
    }))

# ─── Téléchargement agent pré-configuré ───────────────────────────────────────
@app.route('/api/download/agent/<target_os>', methods=['GET'])
def download_agent(target_os):
    """Génère et retourne un package agent pré-configuré pour Linux, macOS ou Windows."""
    if target_os not in ("linux", "macos", "windows"):
        return {"error": "OS cible invalide (linux | macos | windows)"}, 400

    server_host = request.args.get("server", SERVER_PUBLIC_HOST)
    server_port = request.args.get("port", str(SERVER_PUBLIC_PORT))
    auth_token  = AGENT_AUTH_TOKEN

    config_content = textwrap.dedent(f"""\
        [main_server]
        host = {server_host}
        port = {server_port}
        token = {auth_token}

        [agent]
        interval_minutes = 60
        port_scan = false
    """)

    # ── Windows : servir le .exe pré-compilé si disponible ──────────────────
    if target_os == "windows":
        static_dir = os.path.join(os.path.dirname(__file__), "static")
        exe_path   = os.path.join(static_dir, "heimdall-agent.exe")
        if os.path.exists(exe_path):
            logger.info(f"Téléchargement EXE servi pour {request.remote_addr}")
            return send_file(
                exe_path,
                mimetype="application/octet-stream",
                as_attachment=True,
                download_name="HeimdallAgent.exe"
            )

        # Fallback : source Python + config + build script dans un zip
        source_py  = os.path.join(os.path.dirname(__file__), "..", "windows_agent_tray.py")
        build_ps1  = os.path.join(os.path.dirname(__file__), "..", "build_windows.ps1")
        readme_txt = textwrap.dedent(f"""\
            Heimdall Agent Windows — Instructions
            =====================================

            L'exécutable n'est pas encore compilé sur ce serveur.
            Pour l'obtenir, compilez-le vous-même (une seule fois) :

            1. Copiez ce dossier sur une machine Windows avec Python 3.11+
            2. Lancez build_windows.ps1 (PowerShell en tant qu'administrateur)
            3. Récupérez dist/HeimdallAgent.exe et déployez-le sur vos serveurs

            Le fichier agent.conf inclus est pré-configuré pour votre serveur :
              Serveur : {server_host}:{server_port}

            Utilisation directe (sans compilation) :
              pip install requests pystray pillow
              python windows_agent_tray.py

            Pour pré-configurer lors du lancement :
              HeimdallAgent.exe --server {server_host} --port {server_port}
        """)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr("agent.conf", config_content)
            z.writestr("README.txt", readme_txt)
            if os.path.exists(source_py):
                z.write(os.path.abspath(source_py), "windows_agent_tray.py")
            if os.path.exists(build_ps1):
                z.write(os.path.abspath(build_ps1), "build_windows.ps1")
        buf.seek(0)
        return send_file(buf, mimetype="application/zip", as_attachment=True,
                         download_name="heimdall-agent-windows-source.zip")

    # ── Linux / macOS : zip avec install.sh + uninstall.sh ──────────────────
    # install.sh détecte l'OS à l'exécution (systemd pour Linux, launchd pour macOS)
    # et installe le service de manière idempotente. uninstall.sh est livré dans
    # le même bundle ET aussi disponible via `python3 mini_agent.py --uninstall`.
    server_base = f"http://{server_host}:{server_port}"

    bash_install = textwrap.dedent(f"""\
        #!/usr/bin/env bash
        # Heimdall Security Agent — Installation Linux / macOS
        set -e
        SERVER_BASE="{server_base}"
        INSTALL_DIR="/opt/heimdall-agent"

        OS_KIND="$(uname -s)"
        echo "🛡  Installation de l'agent Heimdall sur $OS_KIND…"

        # ── Vérif droits root (Linux ou macOS système) ──────────────────────
        if [ "$EUID" -ne 0 ]; then
          echo "❌  Lancez ce script avec sudo (l'agent s'installe dans $INSTALL_DIR et créé un service)."
          exit 1
        fi

        # ── Dépendances Python ──────────────────────────────────────────────
        if ! command -v python3 >/dev/null 2>&1; then
          echo "❌  python3 introuvable. Installez-le puis relancez."
          exit 1
        fi
        python3 -m pip install --upgrade --quiet requests || \\
            pip3 install --upgrade --quiet requests || \\
            echo "⚠  Impossible d'installer 'requests' automatiquement — installez-le manuellement."

        mkdir -p "$INSTALL_DIR"

        # ── Fichier de configuration ────────────────────────────────────────
        cat > "$INSTALL_DIR/agent.conf" << 'CONFIG'
{config_content}
CONFIG
        chmod 600 "$INSTALL_DIR/agent.conf"

        # ── Téléchargement du script agent ──────────────────────────────────
        echo "⬇  Téléchargement de mini_agent.py…"
        curl -fsSL "$SERVER_BASE/static/mini_agent.py" -o "$INSTALL_DIR/mini_agent.py"
        chmod 755 "$INSTALL_DIR/mini_agent.py"

        # ── uninstall.sh embarqué (réutilisable) ────────────────────────────
        cat > "$INSTALL_DIR/uninstall.sh" << 'UNINSTALL'
#!/usr/bin/env bash
# Heimdall Agent — Désinstallation
set +e
INSTALL_DIR="/opt/heimdall-agent"
OS_KIND="$(uname -s)"
echo "🗑  Désinstallation de l'agent Heimdall…"
if [ "$OS_KIND" = "Linux" ]; then
  systemctl stop heimdall-agent 2>/dev/null
  systemctl disable heimdall-agent 2>/dev/null
  rm -f /etc/systemd/system/heimdall-agent.service
  systemctl daemon-reload 2>/dev/null
elif [ "$OS_KIND" = "Darwin" ]; then
  PLIST="/Library/LaunchDaemons/com.heimdall.agent.plist"
  launchctl unload "$PLIST" 2>/dev/null
  rm -f "$PLIST"
fi
rm -rf "$INSTALL_DIR"
echo "✅  Agent Heimdall désinstallé."
UNINSTALL
        chmod 755 "$INSTALL_DIR/uninstall.sh"

        # ── Service : systemd (Linux) ou launchd (macOS) ────────────────────
        if [ "$OS_KIND" = "Linux" ]; then
          cat > /etc/systemd/system/heimdall-agent.service << 'SERVICE'
[Unit]
Description=Heimdall Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/heimdall-agent/mini_agent.py --daemon
Restart=always
RestartSec=30
# Hardening — l'agent lit des chemins système (sshd_config, sysctl…) mais
# n'a besoin d'écrire que dans /opt/heimdall-agent (auto-update).
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/opt/heimdall-agent
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=no
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
SERVICE
          systemctl daemon-reload
          systemctl enable heimdall-agent
          systemctl restart heimdall-agent
          echo "✅  Agent installé. Statut : $(systemctl is-active heimdall-agent)"
          echo "    Logs : journalctl -u heimdall-agent -f"
          echo "    Désinstaller : sudo $INSTALL_DIR/uninstall.sh"
        elif [ "$OS_KIND" = "Darwin" ]; then
          PYBIN="$(command -v python3)"
          cat > /Library/LaunchDaemons/com.heimdall.agent.plist << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.heimdall.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYBIN</string>
    <string>$INSTALL_DIR/mini_agent.py</string>
    <string>--daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>/var/log/heimdall-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/heimdall-agent.log</string>
</dict>
</plist>
PLIST
          launchctl unload /Library/LaunchDaemons/com.heimdall.agent.plist 2>/dev/null
          launchctl load   /Library/LaunchDaemons/com.heimdall.agent.plist
          echo "✅  Agent installé via launchd."
          echo "    Logs : tail -f /var/log/heimdall-agent.log"
          echo "    Désinstaller : sudo $INSTALL_DIR/uninstall.sh"
        else
          echo "❌  OS non supporté : $OS_KIND (attendu Linux ou Darwin)"
          exit 1
        fi
    """)

    bash_uninstall = textwrap.dedent("""\
        #!/usr/bin/env bash
        # Heimdall Agent — Désinstallation autonome
        set +e
        INSTALL_DIR="/opt/heimdall-agent"
        OS_KIND="$(uname -s)"
        if [ "$EUID" -ne 0 ]; then
          echo "❌  Lancez avec sudo."
          exit 1
        fi
        echo "🗑  Désinstallation de l'agent Heimdall…"
        if [ "$OS_KIND" = "Linux" ]; then
          systemctl stop heimdall-agent 2>/dev/null
          systemctl disable heimdall-agent 2>/dev/null
          rm -f /etc/systemd/system/heimdall-agent.service
          systemctl daemon-reload 2>/dev/null
        elif [ "$OS_KIND" = "Darwin" ]; then
          PLIST="/Library/LaunchDaemons/com.heimdall.agent.plist"
          launchctl unload "$PLIST" 2>/dev/null
          rm -f "$PLIST"
        fi
        rm -rf "$INSTALL_DIR"
        echo "✅  Agent Heimdall désinstallé."
    """)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr("agent.conf",   config_content)
        z.writestr("install.sh",   bash_install)
        z.writestr("uninstall.sh", bash_uninstall)
        z.writestr("README.txt",
                   "Heimdall Agent — Installation\n"
                   "================================\n\n"
                   "  sudo bash install.sh   # installe + démarre\n"
                   "  sudo bash uninstall.sh # désinstalle\n\n"
                   f"Serveur configuré : {server_host}:{server_port}\n"
                   "Détection automatique : systemd (Linux) ou launchd (macOS).\n"
                   "L'agent s'auto-met à jour quand une nouvelle version est publiée.\n")
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name=f"heimdall-agent-{target_os}.zip")

# ─── Version agent / mise à jour automatique ─────────────────────────────────
@app.route('/api/agent/version', methods=['GET'])
@require_agent_token
def agent_version_info():
    """Retourne la version courante de l'agent — utilisé pour l'auto-update."""
    return jsonify({
        "version":      AGENT_VERSION,
        "download_url": f"http://{SERVER_PUBLIC_HOST}:{SERVER_PUBLIC_PORT}/api/download/agent/windows/exe",
    })

@app.route('/api/download/agent/windows/exe', methods=['GET'])
@require_agent_token
def download_agent_exe():
    """Sert uniquement le .exe compilé (pour auto-update agent) — 404 si absent."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    exe_path   = os.path.join(static_dir, "heimdall-agent.exe")
    if not os.path.exists(exe_path):
        return {"error": "Exe non disponible sur ce serveur"}, 404
    return send_file(
        exe_path,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name="HeimdallAgent.exe"
    )

# ─── Route statique pour le mini_agent.py ─────────────────────────────────────
@app.route('/static/mini_agent.py', methods=['GET'])
def serve_mini_agent():
    agent_path = os.path.join(os.path.dirname(__file__), "mini_agent.py")
    if not os.path.exists(agent_path):
        return {"error": "mini_agent.py introuvable sur le serveur"}, 404
    return send_file(agent_path, mimetype='text/plain')

# ─── Ping / validation token ───────────────────────────────────────────────────────────────────────
@app.route('/api/ping', methods=['GET'])
@require_agent_token
def ping():
    """Valide le token et retourne les infos du serveur."""
    return jsonify({"status": "ok", "server": SERVER_PUBLIC_HOST, "port": SERVER_PUBLIC_PORT})

@app.route('/api/server-info', methods=['GET'])
def server_info():
    """Retourne les infos publiques du serveur (sans le token)."""
    return jsonify({"host": SERVER_PUBLIC_HOST, "port": SERVER_PUBLIC_PORT})

# ─── Entrée principale → admin authentifié ───────────────────────────────────────────
@app.route('/', methods=['GET'])
def root_redirect():
    return redirect('/admin/', code=302)

@app.route('/api/stats', methods=['GET'])
def stats():
    """Agrégat global du parc — fait en un seul pipeline MongoDB ($facet)
    au lieu d'un scan + itération Python sur tous les agents."""
    now    = datetime.utcnow()
    cutoff = now - timedelta(seconds=HEARTBEAT_TIMEOUT)
    last_ref = {"$ifNull": ["$last_heartbeat", "$last_seen"]}
    pipeline = [{"$facet": {
        "totals": [{"$count": "n"}],
        "online": [
            {"$match": {"$expr": {"$gt": [last_ref, cutoff]}}},
            {"$count": "n"},
        ],
        "vulnerable": [
            {"$match": {"vulnerable_count": {"$gt": 0}}},
            {"$count": "n"},
        ],
        "critical_hosts": [
            {"$match": {"vulnerabilities": {"$elemMatch": {"critical": {"$gt": 0}}}}},
            {"$count": "n"},
        ],
        "severity_sums": [
            {"$unwind": {"path": "$vulnerabilities", "preserveNullAndEmptyArrays": False}},
            {"$group": {
                "_id": None,
                "total_critical": {"$sum": {"$ifNull": ["$vulnerabilities.critical", 0]}},
                "total_high":     {"$sum": {"$ifNull": ["$vulnerabilities.high",     0]}},
            }},
        ],
        "os_dist": [
            {"$group": {
                "_id": {"$ifNull": [{"$trim": {"input": "$os"}}, "Unknown"]},
                "n": {"$sum": 1},
            }},
        ],
    }}]
    res = list(mongo.db.agents.aggregate(pipeline))
    bucket = res[0] if res else {}

    def _first_n(arr):
        return arr[0]["n"] if arr else 0

    agent_count       = _first_n(bucket.get("totals", []))
    online_count      = _first_n(bucket.get("online", []))
    vulnerable_agents = _first_n(bucket.get("vulnerable", []))
    critical_count    = _first_n(bucket.get("critical_hosts", []))
    sev               = (bucket.get("severity_sums") or [{}])[0]
    total_critical    = sev.get("total_critical", 0) or 0
    total_high        = sev.get("total_high",     0) or 0
    os_dist           = {(row["_id"] or "Unknown"): row["n"] for row in bucket.get("os_dist", [])}

    report_count = mongo.db.agent_reports.estimated_document_count()
    cve_count    = mongo.db.cve_cache.estimated_document_count()

    return jsonify({
        "agents_total":      agent_count,
        "agents_online":     online_count,
        "agents_offline":    agent_count - online_count,
        "reports_total":     report_count,
        "cves_in_cache":     cve_count,
        "critical_alerts":   critical_count,
        "vulnerable_agents": vulnerable_agents,
        "clean_agents":      agent_count - vulnerable_agents,
        "total_critical":    total_critical,
        "total_high":        total_high,
        "os_distribution":   os_dist,
    })

# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN DASHBOARD — Auth, Users, Servers, Compliance
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Public config (no auth required) ────────────────────────────────────────
def _effective_frontend_url() -> str:
    """URL du front CVE — DB (réglable au runtime) en priorité, sinon env var."""
    doc = mongo.db.settings.find_one({"_id": "frontend_url"}, {"value": 1, "_id": 0})
    val = (doc or {}).get("value") if doc else None
    return (val or HEIMDALL_FRONT_URL).rstrip("/")

@app.route('/api/config', methods=['GET'])
def public_config():
    """Retourne la configuration publique du serveur (utilisée par le dashboard)."""
    return jsonify({
        "frontend_url": _effective_frontend_url(),
    })

@app.route('/api/settings/frontend-url', methods=['GET'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def get_frontend_url():
    return jsonify({"frontend_url": _effective_frontend_url()})

@app.route('/api/settings/frontend-url', methods=['PUT'])
@require_role("admin")
def set_frontend_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("frontend_url") or "").strip()
    if not url:
        return jsonify({"error": "frontend_url requis"}), 400
    if not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"error": "URL invalide — doit commencer par http:// ou https://"}), 400
    mongo.db.settings.update_one(
        {"_id": "frontend_url"},
        {"$set": {"value": url.rstrip("/"), "updated_at": datetime.utcnow()}},
        upsert=True,
    )
    return jsonify({"frontend_url": url.rstrip("/")}), 200

# ─── Setup & Auth ─────────────────────────────────────────────────────────────
@app.route('/api/auth/setup-status', methods=['GET'])
def auth_setup_status():
    """Is this the first run (no admin user yet)?"""
    with db_lock:
        has_admin = mongo.db.dashboard_users.count_documents({"role": "admin"}) > 0
    return jsonify({"first_run": not has_admin})

@app.route('/api/auth/setup', methods=['POST'])
def auth_setup():
    """Create the initial admin account — only works when no admin exists."""
    with db_lock:
        if mongo.db.dashboard_users.count_documents({"role": "admin"}) > 0:
            return jsonify({"error": "Un administrateur existe déjà"}), 409
    data     = request.get_json(silent=True) or {}
    email    = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", "")).strip()
    if not email or not password:
        return jsonify({"error": "Email et mot de passe requis"}), 400
    if len(password) < 8:
        return jsonify({"error": "Mot de passe min. 8 caractères"}), 400
    doc = {
        "_id":          str(uuid.uuid4()),
        "email":        email,
        "password_hash": _hash_pw(password),
        "role":         "admin",
        "created_at":   datetime.utcnow().isoformat(),
    }
    with db_lock:
        mongo.db.dashboard_users.insert_one(doc)
    token = _create_dashboard_token(doc)
    return jsonify({"token": token, "email": email, "role": "admin"}), 201

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    data     = request.get_json(silent=True) or {}
    email    = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", "")).strip()
    with db_lock:
        user = mongo.db.dashboard_users.find_one({"email": email})
    if not user or not _check_pw(password, user.get("password_hash", "")):
        return jsonify({"error": "Identifiants incorrects"}), 401
    token = _create_dashboard_token(user)
    return jsonify({"token": token, "email": user["email"], "role": user["role"]}), 200

@app.route('/api/auth/me', methods=['GET'])
@require_dashboard_auth
def auth_me():
    return jsonify(request.dashboard_user), 200

# ─── User management (admin only) ────────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
@require_admin
def list_users():
    with db_lock:
        users = list(mongo.db.dashboard_users.find({}, {"password_hash": 0}))
    return jsonify([_clean(u) for u in users]), 200

@app.route('/api/users', methods=['POST'])
@require_admin
def create_user():
    data     = request.get_json(silent=True) or {}
    email    = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", "")).strip()
    role     = str(data.get("role", "inspection_logs")).strip()
    if not email or not password:
        return jsonify({"error": "Email et mot de passe requis"}), 400
    if role not in ROLES:
        return jsonify({"error": f"Rôle invalide. Valeurs: {', '.join(ROLES)}"}), 400
    if len(password) < 8:
        return jsonify({"error": "Mot de passe min. 8 caractères"}), 400
    with db_lock:
        if mongo.db.dashboard_users.count_documents({"email": email}) > 0:
            return jsonify({"error": "Cet email existe déjà"}), 409
    doc = {
        "_id":           str(uuid.uuid4()),
        "email":         email,
        "password_hash": _hash_pw(password),
        "role":          role,
        "created_at":    datetime.utcnow().isoformat(),
    }
    with db_lock:
        mongo.db.dashboard_users.insert_one(doc)
    doc.pop("password_hash", None)
    return jsonify(_clean(doc)), 201

@app.route('/api/users/<user_id>', methods=['PUT'])
@require_admin
def update_user(user_id):
    data  = request.get_json(silent=True) or {}
    patch = {}
    if "role" in data:
        if data["role"] not in ROLES:
            return jsonify({"error": "Rôle invalide"}), 400
        patch["role"] = data["role"]
    if "password" in data and data["password"]:
        if len(data["password"]) < 8:
            return jsonify({"error": "Mot de passe min. 8 caractères"}), 400
        patch["password_hash"] = _hash_pw(data["password"])
    if not patch:
        return jsonify({"error": "Rien à modifier"}), 400
    with db_lock:
        res = mongo.db.dashboard_users.update_one({"_id": user_id}, {"$set": patch})
    if res.matched_count == 0:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    return jsonify({"status": "ok"}), 200

@app.route('/api/users/<user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id):
    # Prevent deleting yourself
    cur = request.dashboard_user
    with db_lock:
        user = mongo.db.dashboard_users.find_one({"_id": user_id})
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    if user["email"] == cur["email"]:
        return jsonify({"error": "Impossible de supprimer votre propre compte"}), 400
    # Prevent deleting last admin
    if user["role"] == "admin":
        with db_lock:
            admin_count = mongo.db.dashboard_users.count_documents({"role": "admin"})
        if admin_count <= 1:
            return jsonify({"error": "Impossible de supprimer le dernier administrateur"}), 400
    with db_lock:
        mongo.db.dashboard_users.delete_one({"_id": user_id})
    return jsonify({"status": "ok"}), 200

# ─── Servers with network correlation ────────────────────────────────────────
@app.route('/api/servers', methods=['GET'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def list_servers():
    """List all agents with IPs, OS, online status and subnet grouping.
    Docker IPs (172.16-31.x.x) are already filtered when agents report in."""
    with db_lock:
        agents = list(mongo.db.agents.find({}, {"_id": 0, "software": 0}))

    servers = []
    subnet_map: dict = {}  # subnet -> [hostname, ...]

    for a in agents:
        a["online"] = _is_online(a)
        ips = a.get("ip_addresses", [])
        # Build subnet groups
        for ip in ips:
            sn = _subnet_24(ip)
            if sn:
                subnet_map.setdefault(sn, [])
                if a["hostname"] not in subnet_map[sn]:
                    subnet_map[sn].append(a["hostname"])
        servers.append(_clean(a))

    servers.sort(key=lambda s: s.get("hostname", "").lower())

    # Enrich with subnet peers
    for srv in servers:
        peers = set()
        ips = srv.get("ip_addresses", [])
        for ip in ips:
            sn = _subnet_24(ip)
            if sn:
                for peer in subnet_map.get(sn, []):
                    if peer != srv["hostname"]:
                        peers.add(peer)
        srv["subnet_peers"] = sorted(peers)
        # Primary subnet for display
        srv["subnet"] = next((_subnet_24(ip) for ip in ips if _subnet_24(ip)), None)

    return jsonify({"servers": servers, "subnet_map": subnet_map}), 200

# ─── All vulnerabilities across all agents ───────────────────────────────────
@app.route('/api/vulnerabilities', methods=['GET'])
@require_role("admin", "inspection_logs")
def all_vulnerabilities():
    with db_lock:
        agents = list(mongo.db.agents.find(
            {}, {"_id": 0, "hostname": 1, "os": 1, "vulnerabilities": 1,
                 "vulnerable_count": 1, "ip_addresses": 1}
        ))
    result = []
    for a in agents:
        if a.get("vulnerable_count", 0) > 0:
            result.append(_clean(a))
    result.sort(key=lambda x: -(x.get("vulnerable_count") or 0))
    return jsonify(result), 200

# ─── Compliance rules ─────────────────────────────────────────────────────────
@app.route('/api/compliance/rules', methods=['GET'])
@require_dashboard_auth
def get_compliance_rules():
    with db_lock:
        doc = mongo.db.compliance_config.find_one({"_id": "rules"}, {"_id": 0})
    rules = doc["rules"] if doc else DEFAULT_COMPLIANCE_RULES
    return jsonify(rules), 200

@app.route('/api/compliance/agent-rules', methods=['GET'])
@require_agent_token
def get_agent_compliance_rules():
    """Endpoint consommé par les agents au moment de la collecte de conformité.
    Retourne uniquement les règles activées qui ont un `collector` (les built-in
    sans collector sont déjà câblées en dur dans le code de l'agent).
    Filtre par plateforme si ?os=windows|linux|darwin.
    """
    os_arg = (request.args.get("os") or "").lower()
    doc = mongo.db.compliance_config.find_one({"_id": "rules"}, {"_id": 0})
    rules = doc["rules"] if doc else DEFAULT_COMPLIANCE_RULES
    out = []
    for r in rules:
        if not r.get("enabled", True):
            continue
        coll = r.get("collector")
        if not coll or not isinstance(coll, dict) or not coll.get("type"):
            continue
        if os_arg:
            plats = r.get("platforms") or []
            if os_arg not in plats:
                continue
        # On ne renvoie que ce dont l'agent a besoin pour collecter.
        out.append({
            "id":        r["id"],
            "collector": coll,
            # Type attendu : utile à l'agent pour normaliser la valeur retournée.
            "value_type": r.get("type", "string"),
        })
    return jsonify(out), 200

@app.route('/api/compliance/rules', methods=['PUT'])
@require_admin
def update_compliance_rules():
    data = request.get_json(silent=True) or {}
    rules = data.get("rules")
    if not isinstance(rules, list):
        return jsonify({"error": "rules doit être une liste"}), 400
    with db_lock:
        mongo.db.compliance_config.update_one(
            {"_id": "rules"},
            {"$set": {"rules": rules, "updated_at": datetime.utcnow().isoformat()}},
            upsert=True
        )
    # Invalider le cache des résultats : les règles ont changé.
    _COMPLIANCE_CACHE["computed_at"] = None
    return jsonify({"status": "ok"}), 200

# Cache TTL pour /api/compliance/results — évalué O(agents × règles), coûteux.
# Invalidé : (a) sur PUT /api/compliance/rules, (b) après COMPLIANCE_CACHE_TTL_S.
_COMPLIANCE_CACHE = {"computed_at": None, "data": None}
COMPLIANCE_CACHE_TTL_S = 60

@app.route('/api/compliance/results', methods=['GET'])
@require_role("admin", "inspection_logs", "codir")
def compliance_results():
    """Evaluate each agent's compliance data against current rules.
    Résultat mis en cache COMPLIANCE_CACHE_TTL_S secondes pour éviter le recalcul
    sur chaque ouverture de la page."""
    now = datetime.utcnow()
    cached_at = _COMPLIANCE_CACHE["computed_at"]
    if cached_at and (now - cached_at).total_seconds() < COMPLIANCE_CACHE_TTL_S and _COMPLIANCE_CACHE["data"] is not None:
        return jsonify(_COMPLIANCE_CACHE["data"]), 200

    rules_doc = mongo.db.compliance_config.find_one({"_id": "rules"}, {"_id": 0})
    agents    = list(mongo.db.agents.find(
        {}, {"_id": 0, "hostname": 1, "os": 1, "compliance": 1, "ip_addresses": 1}
    ))
    rules = (rules_doc["rules"] if rules_doc else DEFAULT_COMPLIANCE_RULES)
    enabled_rules = [r for r in rules if r.get("enabled", True)]

    results = []
    for a in agents:
        comp  = a.get("compliance") or {}
        os_str = a.get("os", "")
        evals = [_eval_rule(r, comp, os_str) for r in enabled_rules]
        passed  = sum(1 for e in evals if e["status"] == "pass")
        failed  = sum(1 for e in evals if e["status"] == "fail")
        unknown = sum(1 for e in evals if e["status"] == "unknown")
        total_applicable = sum(1 for e in evals if e["status"] != "na")
        score = round(passed / total_applicable * 100) if total_applicable > 0 else None
        results.append({
            "hostname":    a["hostname"],
            "os":          os_str,
            "ip_addresses": a.get("ip_addresses", []),
            "score":       score,
            "passed":      passed,
            "failed":      failed,
            "unknown":     unknown,
            "total":       total_applicable,
            "details":     evals,
        })

    results.sort(key=lambda x: (x["score"] is None, x.get("score", 0)))
    _COMPLIANCE_CACHE["data"]        = results
    _COMPLIANCE_CACHE["computed_at"] = now
    return jsonify(results), 200

# ─── Admin dashboard ────────────────────────────────────────────────────────────────────
@app.route('/admin')
@app.route('/admin/')
@app.route('/admin/<path:path>')
def serve_admin(path=None):
    return render_template('admin.html')

# ─── Seed compte admin par défaut ────────────────────────────────────────────
DEFAULT_ADMIN_EMAIL    = os.getenv("DEFAULT_ADMIN_EMAIL",    "root@heimdall.local")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "root")

def _seed_default_admin():
    """Crée le compte admin par défaut si aucun admin n'existe encore."""
    with db_lock:
        try:
            if mongo.db.dashboard_users.count_documents({"role": "admin"}) == 0:
                doc = {
                    "_id":           str(uuid.uuid4()),
                    "email":         DEFAULT_ADMIN_EMAIL,
                    "password_hash": _hash_pw(DEFAULT_ADMIN_PASSWORD),
                    "role":          "admin",
                    "created_at":    datetime.utcnow().isoformat(),
                }
                mongo.db.dashboard_users.insert_one(doc)
                app.logger.warning(
                    "=== COMPTE ADMIN PAR DÉFAUT CRÉÉ : %s / %s  — CHANGEZ CE MOT DE PASSE ! ===",
                    DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD
                )
        except Exception as exc:
            app.logger.error("Impossible de créer le compte admin par défaut : %s", exc)

if __name__ == "__main__":
    # Créer le compte admin par défaut si la base est vide
    with app.app_context():
        _seed_default_admin()

    # Charger le cache CVE au démarrage
    threading.Thread(target=refresh_cve_from_rss, daemon=True).start()

    # Rafraîchir le cache toutes les 6h
    import time
    def rss_scheduler():
        while True:
            time.sleep(6 * 3600)
            refresh_cve_from_rss()
    threading.Thread(target=rss_scheduler, daemon=True).start()

    app.run(host="0.0.0.0", port=SERVER_PUBLIC_PORT, debug=False)
