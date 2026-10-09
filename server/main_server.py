from flask import Flask, jsonify, request, redirect, render_template, send_file, Response
from flask_pymongo import PyMongo
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
import os
import hashlib
import hmac
import uuid
import secrets
import threading
import time
import requests
import re
import json
import logging
import xml.etree.ElementTree as ET
import io
import csv
import zipfile
import textwrap
import platform
import html

try:
    from reportlab.lib import colors as pdf_colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase import pdfmetrics
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    )
    _HAS_REPORTLAB = True
except ImportError:
    _HAS_REPORTLAB = False

try:
    from pypdf import PdfReader
    _HAS_PDF_READER = True
except ImportError:
    PdfReader = None
    _HAS_PDF_READER = False

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
    # Nom complet sans retrait du suffixe numérique : « Windows Server 2022 » →
    # windows_server_2022 (le CPE NVD), là où _cpe_normalize donnerait windows_server.
    product_full = re.sub(r'[^a-z0-9]+', '_', product_low).strip('_')
    saw_product_entry = False

    for cm in cpe_matches:
        m_product = (cm.get("product") or "").lower()
        if not m_product:
            continue
        # Le CPE product est déjà au format canonique (ex: "microsoft_edge").
        # On compare au nom brut ET au nom normalisé pour couvrir les deux.
        if m_product not in (product_low, product_norm, product_full):
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


def _vulnerability_totals(vulnerabilities) -> dict:
    """Rebuild denormalized counters from the stored vulnerability payload.

    Older documents can contain a populated ``vulnerabilities`` array alongside
    stale zero-valued counters. The array is the source of truth, so deriving
    the summary at read/write boundaries keeps every dashboard page consistent.
    """
    totals = {"vulnerable_count": 0, "cve_count": 0,
              "critical_count": 0, "high_count": 0}
    if not isinstance(vulnerabilities, list):
        return totals

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        cves = vuln.get("cves")
        if isinstance(cves, list):
            count = len(cves)
            critical = high = 0
            for cve in cves:
                if not isinstance(cve, dict):
                    continue
                try:
                    score = float(cve.get("cvss_score", cve.get("cvss", 0)) or 0)
                except (TypeError, ValueError):
                    score = 0
                if score >= 9.0:
                    critical += 1
                elif score >= 7.0:
                    high += 1
        else:
            # Compatibility with early documents which only stored aggregates.
            count = int(vuln.get("cves_count", 0) or 0)
            critical = int(vuln.get("critical", 0) or 0)
            high = int(vuln.get("high", 0) or 0)
        if count > 0:
            totals["vulnerable_count"] += 1
            totals["cve_count"] += count
            totals["critical_count"] += critical
            totals["high_count"] += high
    return totals

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
        # La recherche de l'API peut retomber sur desc_terms. Sans CPE ni
        # composant affecté, n'accepter que l'association explicite du produit
        # racine : autrement un paquet court (apt, bash, ssl...) récupère des
        # CVE qui ne parlent de lui que dans leur description.
        doc_product = _cpe_normalize(str(cve_doc.get("product", "")))
        if not doc_product or doc_product != _cpe_normalize(product):
            return False
        # No structured version ranges — try the root-level version hint.
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
        # Une correspondance par sous-chaîne est trop permissive pour les
        # paquets Linux ("apt" pouvait matcher "apache_tomcat", par exemple).
        # On ne conserve que l'identité explicite du produit/CPE.
        if (comp_low == product_low
                or comp_norm == product_norm):
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
# Assistant IA : la clé reste exclusivement sur le serveur. Les fournisseurs
# compatibles OpenAI, Anthropic et Ollama couvrent aussi les passerelles locales.
AI_PROVIDER        = os.getenv("AI_PROVIDER", "").strip().lower()
AI_BASE_URL        = os.getenv("AI_BASE_URL", "").strip().rstrip("/")
AI_API_KEY         = os.getenv("AI_API_KEY", "")
AI_MODEL           = os.getenv("AI_MODEL", "")
AI_TIMEOUT_SECONDS = max(10, min(int(os.getenv("AI_TIMEOUT_SECONDS", "60")), 120))
SERVER_PUBLIC_HOST = os.getenv("SERVER_PUBLIC_HOST", "127.0.0.1")
SERVER_PUBLIC_PORT = int(os.getenv("SERVER_PUBLIC_PORT", 4000))
AGENT_AUTH_TOKEN   = os.getenv("AGENT_AUTH_TOKEN", "")
HEIMDALL_FRONT_URL = os.getenv("HEIMDALL_FRONT_URL", "http://localhost:3000")

# L'API directe (Docker) expose /cves/..., alors que le site public la publie
# derrière /api/cves/.... Le premier 404 permet de détecter le bon préfixe sans
# débiter le quota (seules les routes /cves sont comptabilisées).
_cve_public_prefix = None
_cve_public_prefix_lock = threading.Lock()
_cve_budget_lock = threading.Lock()
_cve_budget_day = None
_cve_budget_used = 0
# Plafond local facultatif de requêtes CVE/jour. 0 (défaut) = désactivé : la seule
# limite est alors le quota du compte côté API (quota journalier du plan puis crédits).
CVE_DAILY_QUERY_BUDGET = max(0, int(os.getenv("CVE_DAILY_QUERY_BUDGET", "0") or 0))

def _claim_cve_query() -> bool:
    """Borne les appels facturables si CVE_DAILY_QUERY_BUDGET > 0 (désactivé par défaut)."""
    if CVE_DAILY_QUERY_BUDGET <= 0:
        return True
    global _cve_budget_day, _cve_budget_used
    today = datetime.utcnow().date()
    with _cve_budget_lock:
        if _cve_budget_day != today:
            _cve_budget_day, _cve_budget_used = today, 0
        if _cve_budget_used >= CVE_DAILY_QUERY_BUDGET:
            return False
        _cve_budget_used += 1
        return True

def _cve_api_get(path: str, **kwargs):
    return _cve_api_request("GET", path, **kwargs)

def _cve_api_request(method: str, path: str, **kwargs):
    global _cve_public_prefix
    base = HEIMDALL_CVE_API.rstrip("/")
    with _cve_public_prefix_lock:
        prefix = _cve_public_prefix
    if prefix is None:
        prefix = "" if not base.endswith("/api") else ""
    response = requests.request(method, f"{base}{prefix}{path}", **kwargs)
    # Fallback pour l'URL publique historique https://cve.heimdall-security.com.
    if response.status_code == 404 and not base.endswith("/api"):
        alternate = requests.request(method, f"{base}/api{path}", **kwargs)
        if alternate.status_code != 404:
            with _cve_public_prefix_lock:
                _cve_public_prefix = "/api"
            return alternate
    elif response.status_code != 404:
        with _cve_public_prefix_lock:
            _cve_public_prefix = ""
    return response
def _read_agent_version() -> str:
    """Version des agents publiée par ce serveur : variable d'environnement si définie,
    sinon le fichier .agent_version écrit au build de l'image, sinon la valeur par défaut."""
    env = os.getenv("AGENT_VERSION", "").strip()
    if env:
        return env
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent_version"),
                  encoding="utf-8") as f:
            v = f.read().strip()
            if v:
                return v
    except OSError:
        pass
    return "1.0.1"

AGENT_VERSION      = _read_agent_version()

app = Flask(__name__)
app.config["MONGO_URI"] = MONGO_URI
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024  # PDF joints : 3 MiB maximum
mongo = PyMongo(app)
_dashboard_origins = [origin.strip() for origin in os.getenv("DASHBOARD_ALLOWED_ORIGINS", "").split(",") if origin.strip()]
CORS(app, origins=_dashboard_origins, supports_credentials=False)

# PyMongo est déjà thread-safe (pool de connexions interne).
# On garde le nom `db_lock` pour préserver la sémantique des `with db_lock:`,
# mais c'est désormais un no-op : plus de sérialisation globale des requêtes.
from contextlib import nullcontext
db_lock = nullcontext()

# Une relance manuelle peut consommer une requête CVE par logiciel. Elle est
# exécutée hors requête HTTP et une seule analyse de parc peut tourner à la fois.
_cve_rescan_lock = threading.Lock()
_cve_rescan_status = {"running": False, "started_at": None, "finished_at": None,
                      "total_hosts": 0, "processed_hosts": 0, "completed_hosts": 0,
                      "deferred_hosts": 0, "estimated_requests": 0,
                      "target_hostname": None, "current_host": None, "error": None,
                              "last_reason": None}

# ─── Dashboard auth (JWT) ─────────────────────────────────────────────────────
DASHBOARD_JWT_SECRET    = os.getenv("DASHBOARD_JWT_SECRET", "")
DASHBOARD_JWT_EXPIRE_D  = int(os.getenv("DASHBOARD_JWT_EXPIRE_DAYS", 7))

if not AGENT_AUTH_TOKEN or len(AGENT_AUTH_TOKEN) < 32:
    raise RuntimeError("AGENT_AUTH_TOKEN must be configured and at least 32 characters long")
if not DASHBOARD_JWT_SECRET or len(DASHBOARD_JWT_SECRET) < 32:
    raise RuntimeError("DASHBOARD_JWT_SECRET must be configured and at least 32 characters long")

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
    {"id": "pending_updates",
     "name": "Logiciels à jour",
     "description": "Nombre de logiciels/paquets dont une version plus récente est disponible (winget, apt, dnf, brew…) — voir la page « Mises à jour »",
     "expected_op": "<=", "expected_value": 0, "type": "int",
     "severity": "medium", "cis_ref": "",
     "example": "0 = tout est à jour — mettez 5 ou 10 pour tolérer un léger retard",
     "platforms": ["windows", "linux", "darwin"], "enabled": False},
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
        if not token or not hmac.compare_digest(token, AGENT_AUTH_TOKEN):
            return {"error": "Unauthorized"}, 401
        return f(*args, **kwargs)
    return decorated

DEPLOY_ROLES = ("admin", "deployment")

def require_admin_or_agent_token(f):
    """Session admin/deployment (dashboard) OU token agent (curl / PowerShell d'installation)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("x-agent-token")
        if token and hmac.compare_digest(token, AGENT_AUTH_TOKEN):
            return f(*args, **kwargs)
        user, err = _get_dashboard_user()
        if not user:
            return jsonify({"error": err or "Unauthorized"}), 401
        if user["role"] not in DEPLOY_ROLES:
            return jsonify({"error": "Accès réservé aux rôles admin et deployment"}), 403
        request.dashboard_user = user
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
        r = requests.get(HEIMDALL_RSS_URL + "?limit=200", headers={"x-api-key": SERVER_CVE_API_KEY}, timeout=15)
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
            r = _cve_api_get("/cves/recent", headers={"x-api-key": SERVER_CVE_API_KEY}, timeout=15)
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
def _endpoint_checkin(hostname: str, cve_api_key: str):
    """Enregistre le poste auprès du compte (limite de postes du plan, sans crédit).
    Identifiant = HMAC du hostname avec la clé : l'API ne reçoit jamais le nom.
    Returns (allowed, message)."""
    endpoint_id = hmac.new(cve_api_key.encode(), hostname.strip().lower().encode(),
                           hashlib.sha256).hexdigest()[:32]
    try:
        r = _cve_api_request("POST", "/account/endpoints/checkin", timeout=10,
                             headers={"x-api-key": cve_api_key, "x-heimdall-endpoint": endpoint_id})
    except Exception as e:
        return True, f"enregistrement du poste impossible ({e}) — corrélation maintenue"
    if r.status_code == 403:
        try:
            return False, (r.json() or {}).get("error", "refusé")
        except ValueError:
            return False, "refusé"
    return True, "ok"

def _defer(status, reason: str):
    """Mémorise la première raison pour laquelle l'analyse d'un hôte reste « en attente »."""
    if status is not None and not status.get("reason"):
        status["reason"] = reason[:300]

def _epss_pct(value):
    """EPSS (0-1) → pourcentage lisible, ou "" si inconnu."""
    try:
        return round(float(value) * 100, 2) if value is not None else ""
    except (TypeError, ValueError):
        return ""

# Recherche produit + version côté API (/cves/search?version=…). Désactivée une heure si
# l'API répond sans `version_filtered` (ancienne version de l'API).
_VERSION_PARAM_RE = re.compile(r'^[\w.\-+:~ ]{1,100}$')
_api_version_search_off_until = 0.0

def _api_version_search_enabled() -> bool:
    return time.time() >= _api_version_search_off_until

def _disable_api_version_search():
    global _api_version_search_off_until
    _api_version_search_off_until = time.time() + 3600
    logger.warning("[CVE API] L'API ne gère pas encore la recherche par version — "
                   "recherche par produit seul pendant 1 h (mettez à jour cve_api).")

def correlate_vulnerabilities(software_list, cve_api_key: str = "", os_build: str = "",
                              return_status: bool = False, hostname: str = "",
                              status: dict | None = None):
    """Pour chaque logiciel, interroge l'API CVE publique (toujours — jamais de lecture
    directe en base). C'est ce qui fait consommer 1 requête du quota du compte
    propriétaire de `cve_api_key` (CVE_API_KEY, la clé nominative du client sur ce
    serveur agent) par logiciel installé : sans appel HTTP réel vers l'API, le plan
    payant du client (quota journalier lié au nombre de serveurs) n'est jamais décompté.
    Filtre les CVE dont la version installée est en dehors des plages affectées.
    os_build: build NT de l'OS hôte (ex: '10.0.19045 SP0'), utilisé pour les CVE
    dont les versions affectées sont des releases Windows.
    status: dict facultatif, reçoit {"reason": ...} si l'analyse reste incomplète."""
    if not cve_api_key:
        _defer(status, "CVE_API_KEY non configurée sur le serveur agent")
        logger.warning("[CVE API] Aucune clé configurée (CVE_API_KEY) — corrélation désactivée, "
                       "aucune requête ne sera comptée sur un plan client.")
        return ([], False) if return_status else []
    vulns = []
    complete = True
    if hostname:
        allowed, msg = _endpoint_checkin(hostname, cve_api_key)
        if not allowed:
            logger.error(f"[CVE API] {hostname} non analysé : {msg}")
            _defer(status, f"Refusé par l'API CVE : {msg}")
            return ([], False) if return_status else []
    api_headers = {"x-api-key": cve_api_key}
    cache_cutoff = datetime.utcnow() - timedelta(hours=24)
    for sw in software_list:
        product = sw.get("product", "")
        version = sw.get("version", "")
        if not product:
            continue

        # Produit + version : l'API renvoie en UNE requête toutes les CVE qui touchent
        # cette version précise (jusqu'à 500), triées par gravité. Sans version (ou avec
        # une API ancienne), on retombe sur les 100 CVE les plus récentes du produit,
        # filtrées ici. 1 requête = 1 crédit, quel que soit `limit`.
        with_version = _api_version_search_enabled() and bool(_VERSION_PARAM_RE.match(version or ""))
        fetch_limit = 500 if with_version else min(int(os.getenv("MAX_CVES_PER_SOFTWARE", "50")), 100)
        params = {"query": product, "type": "product", "limit": fetch_limit}
        if with_version:
            params["version"] = version
            if sw.get("kind") == "os" and _parse_os_build(os_build):
                params["os_build"] = "%d.%d.%d" % _parse_os_build(os_build)
        cves_raw = []
        # La version fait partie de la clé : deux versions d'un même produit n'ont pas les mêmes CVE
        cache_key = product.strip().lower() + (f"|{version.strip().lower()}" if with_version else "")
        cached = mongo.db.cve_search_cache.find_one(
            {"product": cache_key, "fetched_at": {"$gte": cache_cutoff}}, {"cves": 1})
        if cached is not None:
            cves_raw = cached.get("cves") or []
        else:
            if not _claim_cve_query():
                complete = False
                _defer(status, f"Plafond local CVE_DAILY_QUERY_BUDGET atteint ({CVE_DAILY_QUERY_BUDGET} requêtes/jour)")
                logger.info("[CVE API] Budget journalier local atteint (%s requêtes) — produit reporté: %s",
                            CVE_DAILY_QUERY_BUDGET, product)
                continue
            try:
                resp = _cve_api_get("/cves/search", params=params, headers=api_headers, timeout=20)
                # 400 « Invalid query value » = nom de produit refusé (géré plus bas) ; tout autre
                # 400 sur une recherche avec version = paramètres version/limit non reconnus.
                version_refused = resp.status_code == 400 and "Invalid query value" not in resp.text
                if with_version and (version_refused or (
                        resp.status_code == 200 and not (resp.json() or {}).get("version_filtered"))):
                    # API (ou proxy du site) pas encore mise à jour : version refusée (400) ou
                    # ignorée. On repasse en recherche par produit seul pour l'heure qui vient.
                    _disable_api_version_search()
                    params = {"query": product, "type": "product",
                              "limit": min(int(os.getenv("MAX_CVES_PER_SOFTWARE", "50")), 100)}
                    cache_key = product.strip().lower()
                    resp = _cve_api_get("/cves/search", params=params, headers=api_headers, timeout=20)
                if resp.status_code == 200:
                    raw = resp.json()
                    results = raw.get("results", []) if isinstance(raw, dict) else raw
                    cves_raw = [c for c in results
                                if _is_valid_cve_doc(c)
                                and c.get("product", "n/a").lower() not in ("n/a", "", "none")]
                    # Même produit sur plusieurs hôtes : une seule requête CVE/jour.
                    mongo.db.cve_search_cache.update_one(
                        {"product": cache_key}, {"$set": {"cves": cves_raw,
                         "fetched_at": datetime.utcnow()}}, upsert=True)
                elif resp.status_code == 400:
                    # Nom refusé par l'API (caractères non admis) : réessayer ne changera
                    # rien. On ne bloque pas tout l'hôte en « en attente » pour un seul
                    # produit, et on met le refus en cache 24 h pour ne pas repayer une
                    # requête à chaque analyse.
                    logger.info(f"[CVE API] Nom de produit refusé par l'API, ignoré : {product}")
                    mongo.db.cve_search_cache.update_one(
                        {"product": cache_key}, {"$set": {"cves": [], "fetched_at": datetime.utcnow(),
                                                          "rejected": True}}, upsert=True)
                elif resp.status_code == 429:
                    complete = False
                    _defer(status, "Quota épuisé : quota journalier du plan et crédits à 0")
                    logger.warning(f"[CVE API] Quota épuisé pour {product} — analyse mise en attente.")
                elif resp.status_code == 401:
                    complete = False
                    _defer(status, "Clé API CVE invalide ou expirée (CVE_API_KEY)")
                    logger.error(f"[CVE API] Clé API invalide/expirée pour {product} — vérifiez CVE_API_KEY.")
                else:
                    complete = False
                    _defer(status, f"API CVE : HTTP {resp.status_code} (ex. produit « {product} »)")
                    logger.warning(f"[CVE API] HTTP {resp.status_code} pour {product}")
            except Exception as e:
                complete = False
                _defer(status, f"API CVE injoignable : {str(e)[:150]}")
                logger.warning(f"Appel API CVE échoué pour {product}: {e}")

        # Filtrage strict par version — pas de fallback si tout est filtré
        if version:
            cves_filtered = [c for c in cves_raw if _cve_affects_version(version, c, product, os_build)]
        else:
            cves_filtered = cves_raw

        # Cap configurable — auparavant 5, ce qui cachait des CVE aux utilisateurs.
        # 50 est un plafond raisonnable pour éviter d'exploser la taille du doc Mongo
        # sur des logiciels avec beaucoup d'historique de CVE.
        cap = int(os.getenv("MAX_CVES_PER_SOFTWARE", "50"))
        # Les plus graves d'abord (CVSS puis EPSS) avant d'appliquer le plafond de stockage
        cves_filtered.sort(key=lambda c: (-float(c.get("cvss_score") or 0), -float(c.get("epss_score") or 0)))
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
                "epss_max":   max((float(c.get("epss_score") or 0) for c in cves), default=0),
                "cves": [{"cve_id": c.get("id"), "cvss_score": c.get("cvss_score", 0),
                          # EPSS : probabilité d'exploitation sous 30 jours (0-1) et percentile
                          "epss_score": c.get("epss_score"), "epss_percentile": c.get("epss_percentile"),
                          "description": c.get("description", c.get("title", "")),
                          "product": c.get("product"), "vendor": c.get("vendor"),
                          "version": c.get("version"),
                          "date_published": c.get("date_published", ""),
                          "affected_components": c.get("affected_components", []),
                          "cpe_matches": c.get("cpe_matches", [])} for c in cves]
            })
    return (vulns, complete) if return_status else vulns

# ─── Logs locaux des agents (debug centralisé) ────────────────────────────────
_LOG_TAIL_MAX_LINES = 200
_LOG_TAIL_MAX_CHARS = 50_000  # borne dure — entrée non fiable, un agent ne doit pas pouvoir gonfler Mongo

def _sanitize_log_tail(raw):
    """Valide/borne les lignes de log envoyées par l'agent (entrée non fiable :
    liste de chaînes, comptage et taille totale plafonnés)."""
    if not isinstance(raw, list):
        return None
    lines, total = [], 0
    for line in raw[-_LOG_TAIL_MAX_LINES:]:
        s = str(line)[:1000]
        total += len(s)
        if total > _LOG_TAIL_MAX_CHARS:
            break
        lines.append(s)
    return lines

# ─── Logiciels à mettre à jour (rapporté par les agents) ─────────────────────
def _sanitize_update_check(raw):
    """Valide/borne le bloc `update_check` envoyé par l'agent (entrée non fiable)."""
    if not isinstance(raw, dict):
        return None
    def _s(v, n=200):
        return None if v is None else str(v)[:n]
    items = []
    for it in (raw.get("items") or [])[:500]:
        if isinstance(it, dict) and it.get("name"):
            items.append({"name": _s(it.get("name")), "id": _s(it.get("id")),
                          "installed": _s(it.get("installed")),
                          "available": _s(it.get("available"))})
    ok = bool(raw.get("ok"))
    count = len(items) if ok else None
    if ok and isinstance(raw.get("count"), int) and raw["count"] >= len(items):
        count = raw["count"]           # l'agent peut avoir tronqué la liste
    age = raw.get("cache_age_hours")
    return {
        "manager":         _s(raw.get("manager"), 32),
        "ok":              ok,
        "error":           _s(raw.get("error")),
        "count":           count,
        "checked_at":      _s(raw.get("checked_at"), 40),
        "cache_age_hours": age if isinstance(age, (int, float)) else None,
        "items":           items,
    }

# ─── Endpoints agents ─────────────────────────────────────────────────────────
@app.route('/api/agents/report', methods=['POST'])
@require_agent_token
def agent_report():
    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname", "Unknown")
    software_list = data.get("software", [])
    open_ports    = data.get("open_ports", [])
    # La clé API CVE est une donnée SERVEUR (CVE_API_KEY) : on ignore volontairement
    # toute clé envoyée par un agent (ancien agent, machine compromise ou mal configurée).
    cve_api_key   = SERVER_CVE_API_KEY
    os_build      = data.get("os_build", "")
    compliance    = data.get("compliance", {})          # NEW: agent-sent compliance data
    ip_addresses  = data.get("ip_addresses", [])        # NEW: agent's own IPs
    logged_users  = [u for u in (data.get("logged_users") or [])[:100]
                     if isinstance(u, dict) and str(u.get("username", "")).strip()]
    agent_version = data.get("agent_version", "")        # NEW: version reportée
    update_check  = _sanitize_update_check(data.get("update_check"))
    log_tail      = _sanitize_log_tail(data.get("log_tail"))
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

    scan_status = {}
    vulns, cve_complete = correlate_vulnerabilities(software_list, cve_api_key, os_build,
                                                     return_status=True, hostname=hostname,
                                                     status=scan_status)
    # Chaque rapport est déjà une sauvegarde complète dans agent_reports. On
    # calcule aussi l'écart avec le dernier inventaire pour signaler tout ajout.
    existing_agent = mongo.db.agents.find_one({"hostname": hostname}, {"software": 1}) or {}
    def _software_keys(items):
        return {f"{s.get('vendor', '')}|{s.get('product', '')}|{s.get('version', '')}"
                for s in items if s.get("product")}
    previous_keys = _software_keys(existing_agent.get("software") or [])
    current_keys = _software_keys(software_list)
    inventory_changes = {
        "added": sorted(current_keys - previous_keys)[:200],
        "removed": sorted(previous_keys - current_keys)[:200],
    }
    # Vrais totaux CVE (somme à travers tous les logiciels), pas juste le nombre
    # de logiciels vulnérables.
    vuln_totals = _vulnerability_totals(vulns)
    cves_total     = vuln_totals["cve_count"]
    critical_total = vuln_totals["critical_count"]
    high_total     = vuln_totals["high_count"]

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
        "logged_users":     logged_users,
        "compliance":       compliance,
        "inventory_changes": inventory_changes,
        "cve_scan_status":  "complete" if cve_complete else "deferred",
        "cve_scan_deferred": not cve_complete,
        "cve_scan_reason":  None if cve_complete else scan_status.get("reason"),
    }
    if cve_complete:
        report["cve_last_checked_at"] = datetime.utcnow()
    # Absent (ancien agent) → on ne l'écrit pas, pour ne pas effacer le dernier résultat connu.
    if update_check is not None:
        report["update_check"] = update_check

    with db_lock:
        # On garde l'historique et on met à jour le "dernier rapport" de ce serveur
        mongo.db.agent_reports.insert_one({**report})

        # Si la corrélation n'a rien retourné (ex: rate limit côté API), on conserve
        # les vulnérabilités précédemment connues plutôt que de les écraser par []
        update_fields = {**report, "last_seen": datetime.utcnow()}
        # log_tail n'entre PAS dans `report`/agent_reports (historique) : à ~8 ko par
        # rapport, ça gonflerait Mongo inutilement pour une donnée qui n'a d'intérêt
        # que « fraîche ». Seul le dernier snapshot (mongo.db.agents) le garde.
        if log_tail is not None:
            update_fields["log_tail"] = log_tail
            update_fields["log_tail_received_at"] = datetime.utcnow()
        retained_vuln_count = None
        if not cve_complete:
            existing = mongo.db.agents.find_one({"hostname": hostname},
                                                 {"vulnerabilities": 1, "vulnerable_count": 1,
                                                  "cve_count": 1, "critical_count": 1, "high_count": 1})
            if existing and existing.get("vulnerabilities"):
                # Preserve the full previously-known CVE state when the new
                # correlation is incomplete (quota exhaustion/API failure).
                for key in ("vulnerabilities", "vulnerable_count", "cve_count", "critical_count", "high_count"):
                    update_fields.pop(key, None)
                retained_vuln_count = existing.get("cve_count", existing.get("vulnerable_count", 0))
                logger.info("[RAPPORT] %s: correlation incomplete; retaining %s previous CVEs", hostname, retained_vuln_count)

        update_ops = {"$set": update_fields}
        if cve_complete:
            update_ops["$unset"] = {"cve_scan_error": ""}
        mongo.db.agents.update_one({"hostname": hostname}, update_ops, upsert=True)

    report.pop("_id", None)
    shown_count = retained_vuln_count if retained_vuln_count is not None else cves_total
    suffix = " (previous result retained)" if retained_vuln_count is not None else ""
    logger.info(f"[RAPPORT] {hostname}: {shown_count} CVEs displayed, {len(open_ports)} open ports{suffix}")
    return jsonify(report), 200

@app.route('/api/agents/<hostname>/heartbeat', methods=['POST'])
@require_agent_token
def agent_heartbeat(hostname):
    """Heartbeat léger — met à jour la présence de l'agent sans analyse complète."""
    data = request.get_json(silent=True) or {}
    now  = datetime.utcnow()
    with db_lock:
        # La demande de revérification (dashboard) est lue et consommée en une opération.
        before = mongo.db.agents.find_one_and_update(
            {"hostname": hostname},
            {"$set": {
                "last_heartbeat": now,
                "last_seen":      now,
                "os":             data.get("os",       ""),
                "release":        data.get("release",  ""),
                "os_build":       data.get("os_build", ""),
            }, "$unset": {"refresh_updates_requested": ""}},
            projection={"refresh_updates_requested": 1},
            upsert=True
        )
    return jsonify({"status": "ok", "ts": now.isoformat(),
                    "refresh_updates": bool((before or {}).get("refresh_updates_requested"))}), 200

@app.route('/api/agents/<hostname>/refresh-updates', methods=['POST'])
@require_role("admin")
def request_updates_refresh(hostname):
    """Demande à un agent Windows de relancer sa vérification winget : transmise au
    prochain heartbeat (≤ 60 s), suivie d'un rapport immédiat."""
    with db_lock:
        res = mongo.db.agents.update_one(
            {"hostname": hostname},
            {"$set": {"refresh_updates_requested": True,
                      "refresh_updates_requested_at": datetime.utcnow()}})
    if not res.matched_count:
        return {"error": "Agent not found"}, 404
    return jsonify({"status": "ok"}), 200

def _manual_cve_rescan(hostname: str | None = None):
    """Relance la corrélation depuis les inventaires stockés, pour un hôte ou le parc."""
    global _cve_rescan_status
    try:
        query = {"hostname": hostname} if hostname else {}
        agents = list(mongo.db.agents.find(
            query, {"hostname": 1, "software": 1, "os_build": 1, "cve_last_checked_at": 1}))
        agents.sort(key=lambda a: (a.get("cve_last_checked_at") is not None,
                                   a.get("cve_last_checked_at") or datetime.min))
        for agent in agents:
            with _cve_rescan_lock:
                _cve_rescan_status["current_host"] = agent.get("hostname", "")
            scan_status = {}
            vulns, complete = correlate_vulnerabilities(agent.get("software") or [], SERVER_CVE_API_KEY,
                                                        agent.get("os_build", ""), return_status=True,
                                                        hostname=agent.get("hostname", ""),
                                                        status=scan_status)
            update = {
                "vulnerabilities": vulns,
                **_vulnerability_totals(vulns),
                "cve_last_manual_scan": datetime.utcnow(),
                "cve_last_checked_at": datetime.utcnow(),
                "cve_scan_status": "complete",
                "cve_scan_deferred": False,
                "cve_scan_reason": None,
            }
            # Si le budget s'est arrêté au milieu de l'hôte, conserver le
            # dernier résultat plutôt que de le remplacer par un faux « sain ».
            if not complete:
                update = {"cve_last_manual_scan": datetime.utcnow(),
                          "cve_scan_status": "deferred",
                          "cve_scan_deferred": True,
                          "cve_scan_reason": scan_status.get("reason")}
            mongo.db.agents.update_one({"hostname": agent.get("hostname", "Unknown")}, {"$set": update})
            with _cve_rescan_lock:
                _cve_rescan_status["processed_hosts"] += 1
                _cve_rescan_status["completed_hosts" if complete else "deferred_hosts"] += 1
                if not complete:
                    _cve_rescan_status["last_reason"] = (f"{agent.get('hostname', '')} : "
                                                         f"{scan_status.get('reason') or 'raison inconnue'}")
    except Exception as exc:
        logger.exception("[CVE RESCAN] Échec de l'analyse manuelle")
        with _cve_rescan_lock:
            _cve_rescan_status["error"] = str(exc)[:300]
    finally:
        with _cve_rescan_lock:
            _cve_rescan_status["running"] = False
            _cve_rescan_status["finished_at"] = datetime.utcnow()
            _cve_rescan_status["current_host"] = None

@app.route('/api/cve-quota', methods=['GET'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def cve_quota():
    """Proxy du solde : la clé CVE ne quitte jamais le serveur agent."""
    if not SERVER_CVE_API_KEY:
        return jsonify({"configured": False})
    try:
        response = _cve_api_get("/account/quota",
                                headers={"x-api-key": SERVER_CVE_API_KEY}, timeout=10)
        if response.status_code != 200:
            logger.warning("[CVE API] Vérification de configuration: HTTP %s", response.status_code)
            detail = {401: "clé API CVE invalide", 403: "clé refusée (IP verrouillée ou compte suspendu)",
                      404: "route introuvable (URL HEIMDALL_CVE_API ?)"}.get(response.status_code, "API en erreur")
            return jsonify({"configured": True, "available": False,
                            "message": f"HTTP {response.status_code} : {detail}"})
        data = response.json()
        return jsonify({"configured": True, "available": True,
                        "daily_limit": data.get("daily_limit"),
                        "plan": data.get("plan"), "plan_label": data.get("plan_label"),
                        "requests_used": data.get("requests_used", 0),
                        "daily_remaining": data.get("daily_remaining"),
                        "credits": data.get("credits", 0),
                        "max_endpoints": data.get("max_endpoints"),
                        "endpoints_active": data.get("endpoints_active"),
                        "reset_date": data.get("reset_date"),
                        "usage_history": data.get("usage_history", [])})
    except requests.RequestException as exc:
        logger.warning("[CVE API] Solde indisponible: %s", exc)
        return jsonify({"configured": True, "available": False,
                        "message": "Impossible de joindre l’API CVE."})

@app.route('/api/cve-rescan', methods=['GET', 'POST'])
@require_role("admin")
def cve_rescan():
    global _cve_rescan_status
    if request.method == 'GET':
        with _cve_rescan_lock:
            return jsonify(_clean(dict(_cve_rescan_status)))
    if not SERVER_CVE_API_KEY:
        return {"error": "CVE_API_KEY non configurée : analyse manuelle impossible."}, 400
    with _cve_rescan_lock:
        if _cve_rescan_status["running"]:
            return jsonify(_clean(dict(_cve_rescan_status))), 409
        agents = list(mongo.db.agents.find({}, {"software.product": 1,
                                                "cve_last_checked_at": 1}))
        # File prioritaire : jamais vérifié d'abord, puis contrôle le plus ancien.
        agents.sort(key=lambda a: (a.get("cve_last_checked_at") is not None,
                                   a.get("cve_last_checked_at") or datetime.min))
        estimate = sum(len([sw for sw in (a.get("software") or []) if sw.get("product")])
                       for a in agents)
        _cve_rescan_status = {"running": True, "started_at": datetime.utcnow(), "finished_at": None,
                              "total_hosts": len(agents), "processed_hosts": 0,
                              "completed_hosts": 0, "deferred_hosts": 0,
                              "estimated_requests": estimate, "target_hostname": None,
                              "current_host": None, "error": None, "last_reason": None}
        threading.Thread(target=_manual_cve_rescan, name="ManualCveRescan", daemon=True).start()
        return jsonify(_clean(dict(_cve_rescan_status))), 202


@app.route('/api/agents/<hostname>/cve-rescan', methods=['POST'])
@require_role("admin")
def agent_cve_rescan(hostname):
    """Lance une corrélation CVE asynchrone pour un seul inventaire."""
    global _cve_rescan_status
    if not SERVER_CVE_API_KEY:
        return {"error": "CVE_API_KEY non configurée : analyse manuelle impossible."}, 400
    with _cve_rescan_lock:
        if _cve_rescan_status.get("running"):
            current = _cve_rescan_status.get("current_host") or _cve_rescan_status.get("target_hostname")
            return jsonify({**_clean(dict(_cve_rescan_status)),
                            "error": f"Une analyse CVE est déjà en cours{f' sur {current}' if current else ''}."}), 409
        agent = mongo.db.agents.find_one(
            {"hostname": hostname}, {"hostname": 1, "software.product": 1})
        if not agent:
            return {"error": "Agent introuvable"}, 404
        estimate = len([sw for sw in (agent.get("software") or []) if sw.get("product")])
        _cve_rescan_status = {
            "running": True, "started_at": datetime.utcnow(), "finished_at": None,
            "total_hosts": 1, "processed_hosts": 0, "completed_hosts": 0,
            "deferred_hosts": 0, "estimated_requests": estimate,
            "target_hostname": hostname, "current_host": hostname, "error": None,
            "last_reason": None,
        }
        threading.Thread(target=_manual_cve_rescan, args=(hostname,),
                         name=f"CveRescan-{hostname}"[:60], daemon=True).start()
        return jsonify(_clean(dict(_cve_rescan_status))), 202

def _daily_cve_scheduler():
    """Lance la file une fois par jour, après le renouvellement des quotas."""
    while True:
        now = datetime.utcnow()
        next_run = (now.replace(hour=0, minute=10, second=0, microsecond=0) + timedelta(days=1))
        time.sleep(max(60, (next_run - now).total_seconds()))
        if not SERVER_CVE_API_KEY or not _cve_rescan_lock.acquire(blocking=False):
            continue
        try:
            if _cve_rescan_status.get("running"):
                continue
            agents = list(mongo.db.agents.find({}, {"software.product": 1,
                                                    "cve_last_checked_at": 1}))
            agents.sort(key=lambda a: (a.get("cve_last_checked_at") is not None,
                                       a.get("cve_last_checked_at") or datetime.min))
            _cve_rescan_status.update({"running": True, "started_at": datetime.utcnow(),
                                       "finished_at": None, "total_hosts": len(agents),
                                       "processed_hosts": 0, "completed_hosts": 0,
                                       "deferred_hosts": 0,
                                       "estimated_requests": sum(len(a.get("software") or []) for a in agents),
                                       "target_hostname": None, "current_host": None,
                                       "error": None, "last_reason": None})
            threading.Thread(target=_manual_cve_rescan, name="DailyCveRescan", daemon=True).start()
        finally:
            _cve_rescan_lock.release()

@app.route('/api/agents', methods=['GET'])
def list_agents():
    # log_tail exclu : peut contenir des chemins/IP internes, servi séparément
    # (endpoint authentifié dédié) — cette route n'est pas protégée par un rôle.
    with db_lock:
        agents = list(mongo.db.agents.find({}, {"_id": 0, "log_tail": 0}))
    for a in agents:
        totals = _vulnerability_totals(a.get("vulnerabilities"))
        a.update(totals)
        if a.get("cve_scan_status") not in ("complete", "deferred"):
            a["cve_scan_status"] = ("deferred" if a.get("cve_scan_deferred")
                                    else "complete" if totals["cve_count"] else "unknown")
        a["online"] = _is_online(a)
        a["agent_up_to_date"] = _agent_is_up_to_date(a.get("agent_version", ""))
    return jsonify([_clean(a) for a in agents])

@app.route('/api/agents/<hostname>', methods=['GET'])
def get_agent(hostname):
    with db_lock:
        agent = mongo.db.agents.find_one({"hostname": hostname}, {"_id": 0, "log_tail": 0})
    if not agent:
        return {"error": "Agent not found"}, 404
    totals = _vulnerability_totals(agent.get("vulnerabilities"))
    agent.update(totals)
    if agent.get("cve_scan_status") not in ("complete", "deferred"):
        agent["cve_scan_status"] = ("deferred" if agent.get("cve_scan_deferred")
                                    else "complete" if totals["cve_count"] else "unknown")
    agent["online"] = _is_online(agent)
    return jsonify(_clean(agent))

@app.route('/api/agents/<hostname>/logs', methods=['GET'])
@require_role("admin", "inspection_logs", "codir")
def agent_logs(hostname):
    """Derniers logs locaux de l'agent (débogage) — endpoint authentifié séparé :
    peut contenir des chemins de fichiers, IP, messages d'erreur internes."""
    with db_lock:
        agent = mongo.db.agents.find_one(
            {"hostname": hostname}, {"_id": 0, "log_tail": 1, "log_tail_received_at": 1})
    if not agent:
        return {"error": "Agent not found"}, 404
    return jsonify(_clean({
        "hostname": hostname,
        "log_tail": agent.get("log_tail") or [],
        "received_at": agent.get("log_tail_received_at"),
    }))

@app.route('/api/agents/<hostname>/history', methods=['GET'])
def agent_history(hostname):
    with db_lock:
        reports = list(mongo.db.agent_reports.find(
            {"hostname": hostname}, {"_id": 0}
        ).sort("received_at", -1).limit(20))
    return jsonify([_clean(r) for r in reports])

@app.route('/api/agents/<hostname>/inventory', methods=['GET'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def agent_inventory(hostname):
    """Fiche complète : inventaire courant et sauvegardes/écarts récents."""
    agent = mongo.db.agents.find_one({"hostname": hostname}, {"_id": 0, "log_tail": 0})
    if not agent:
        return {"error": "Agent not found"}, 404
    history = list(mongo.db.agent_reports.find(
        {"hostname": hostname}, {"_id": 0, "received_at": 1, "software_count": 1,
                               "inventory_changes": 1, "cve_count": 1})
        .sort("received_at", -1).limit(30))
    return jsonify(_clean({"agent": agent, "history": history}))

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
        product_key = v.get("product")
        if not product_key:  # anciens documents : "vendor/product v1.0"
            name_part   = v.get("software", "").split("/")[-1]
            product_key = re.sub(r'\s+v[\d\.].*$', '', name_part, flags=re.IGNORECASE)
        vuln_lookup[product_key.strip().lower()] = v

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
            key = (product.lower(), c.get("cve_id") or c.get("id", ""))
            if key in suppressed_set:
                cves_suppressed.append({**c, "suppressed": True})
            else:
                cves_visible.append({**c, "suppressed": False})

        total_visible  = len(cves_visible)
        def _score(c): return float(c.get("cvss_score", c.get("cvss")) or 0)
        crit_visible   = sum(1 for c in cves_visible if _score(c) >= 9.0)
        high_visible   = sum(1 for c in cves_visible if 7.0 <= _score(c) < 9.0)

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
@require_admin_or_agent_token
def download_agent(target_os):
    """Génère et retourne un package agent pré-configuré pour Linux, macOS ou Windows."""
    if target_os not in ("linux", "macos", "windows"):
        return {"error": "OS cible invalide (linux | macos | windows)"}, 400

    server_host = SERVER_PUBLIC_HOST
    server_port = str(SERVER_PUBLIC_PORT)
    auth_token  = AGENT_AUTH_TOKEN
    use_https   = "true" if _public_scheme() == "https" else "false"

    config_content = textwrap.dedent(f"""\
        [main_server]
        host = {server_host}
        port = {server_port}
        token = {auth_token}
        use_https = {use_https}
        verify_ssl = true

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
    # The packaged agent.conf is the source of truth for the installer.
    server_base = f"{_public_scheme()}://{server_host}:{server_port}"

    bash_install = textwrap.dedent(f"""\
        #!/usr/bin/env bash
        # Heimdall Security Agent — Installation Linux / macOS
        set -e
        SERVER_BASE="{server_base}"
        INSTALL_DIR="/opt/heimdall-agent"
        SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
        CONFIG_SOURCE="$SCRIPT_DIR/agent.conf"

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
        # Do not start an unusable service: agent.conf must come from the
        # downloaded bundle and must contain the pre-configured shared token.
        if [ ! -r "$CONFIG_SOURCE" ]; then
          echo "Configuration missing: $CONFIG_SOURCE"
          echo "Extract the complete ZIP, then run: sudo bash install.sh"
          exit 1
        fi
        token="$(awk -F= '/^[[:space:]]*token[[:space:]]*=/ {{sub(/^[^=]*=/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit}}' "$CONFIG_SOURCE")"
        if [ ${{#token}} -lt 32 ]; then
          echo "The token in agent.conf is invalid (32 characters minimum)."
          exit 1
        fi
        config_tmp="$INSTALL_DIR/.agent.conf.$$"
        install -m 600 "$CONFIG_SOURCE" "$config_tmp"
        mv -f "$config_tmp" "$INSTALL_DIR/agent.conf"
        echo "Configuration installed: $INSTALL_DIR/agent.conf"

        # ── Téléchargement du script agent ──────────────────────────────────
        echo "⬇  Téléchargement de mini_agent.py…"
        curl -fsSL "$SERVER_BASE/static/mini_agent.py" -o "$INSTALL_DIR/mini_agent.py"
        chmod 755 "$INSTALL_DIR/mini_agent.py"

        # ── Commande `heimdall` (heimdall --scan / --status / --configuration / ...) ──
        cat > /usr/local/bin/heimdall << WRAPPER
#!/usr/bin/env bash
exec python3 "$INSTALL_DIR/mini_agent.py" "\\$@"
WRAPPER
        chmod 755 /usr/local/bin/heimdall

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
rm -f /usr/local/bin/heimdall
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

def _public_scheme() -> str:
    """« https » si la requête est arrivée en HTTPS (directement ou via un reverse
    proxy qui pose X-Forwarded-Proto), sinon « http »."""
    proto = (request.headers.get("X-Forwarded-Proto") or request.scheme or "http")
    return "https" if proto.split(",")[0].strip().lower() == "https" else "http"

@app.route('/api/install/windows.ps1', methods=['GET'])
@require_admin_or_agent_token
def install_script_windows():
    """Script PowerShell d'installation pré-configuré (serveur, port, token).

    Installe l'agent pour l'utilisateur courant, SANS droits administrateur (donc
    sans invite UAC « éditeur inconnu »). Le téléchargement par PowerShell n'ajoute
    pas de « marque du web » : pas d'écran SmartScreen, contrairement à un
    téléchargement par navigateur. Le script contient le token : il n'est servi
    qu'à un appelant authentifié (session admin ou token agent).
    """
    q = lambda v: str(v).replace("'", "''")          # échappement PowerShell '…'
    scheme = _public_scheme()
    https_arg = ",'--https'" if scheme == "https" else ""
    script = textwrap.dedent(f"""\
        # Heimdall Agent — installation (utilisateur courant, sans droits administrateur)
        $ErrorActionPreference = 'Stop'
        $ProgressPreference    = 'SilentlyContinue'
        $server = '{q(SERVER_PUBLIC_HOST)}'
        $port   = '{q(SERVER_PUBLIC_PORT)}'
        $token  = '{q(AGENT_AUTH_TOKEN)}'

        $dir = Join-Path $env:LOCALAPPDATA 'HeimdallAgent'
        $exe = Join-Path $dir 'HeimdallAgent.exe'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null

        # Ferme une instance déjà en cours avant de remplacer l'exécutable
        Get-Process -Name HeimdallAgent -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Milliseconds 500

        Write-Host "Téléchargement de l'agent depuis $server`:$port ..."
        try {{
            Invoke-WebRequest -UseBasicParsing -Uri "{scheme}://${{server}}:${{port}}/api/download/agent/windows/exe" `
                -Headers @{{ 'x-agent-token' = $token }} -OutFile $exe
        }} catch {{
            Write-Host "Échec du téléchargement : $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Vérifiez que le serveur est joignable sur $server`:$port et que le token est valide." -ForegroundColor Yellow
            exit 1
        }}
        Unblock-File -Path $exe

        # Lancé en administrateur : l'agent démarre aussi avec la machine, avant toute
        # ouverture de session (tâche planifiée « au démarrage », compte SYSTEM) — utile
        # sur les serveurs où personne ne se connecte.
        $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($admin) {{
            $p = Start-Process -FilePath $exe -Wait -PassThru -ArgumentList @('--silent','--server',$server,'--port',$port,'--token',$token{https_arg},'--service-install')
            if ($p.ExitCode -eq 0) {{ Write-Host "Démarrage avec la machine activé (avant toute ouverture de session)." -ForegroundColor Green }}
            else {{ Write-Host "Démarrage avec la machine non activé : voir le journal de l'agent." -ForegroundColor Yellow }}
        }} else {{
            Write-Host "Astuce (serveurs) : relancez cette commande dans un PowerShell administrateur pour que l'agent démarre avec la machine, sans attendre une ouverture de session." -ForegroundColor Yellow
        }}

        # Enregistre le serveur, démarre l'agent et active le lancement avec Windows
        Start-Process -FilePath $exe -ArgumentList @('--silent','--autostart','--server',$server,'--port',$port,'--token',$token{https_arg})
        Write-Host "Agent Heimdall installé et démarré (icône dans la zone de notification)." -ForegroundColor Green
        """)
    return Response(script, mimetype="text/plain; charset=utf-8")


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
    return jsonify({"host": SERVER_PUBLIC_HOST, "port": SERVER_PUBLIC_PORT,
                    "agent_version": AGENT_VERSION})

@app.route('/api/deploy/token', methods=['GET'])
@require_role(*DEPLOY_ROLES)
def deploy_token():
    """Clé de déploiement (AGENT_AUTH_TOKEN) pour la page Déploiement du dashboard.
    Réservée aux rôles admin et deployment ; chaque consultation est journalisée."""
    logger.info("[DEPLOY] Clé de déploiement consultée par %s (%s)",
                request.dashboard_user["email"], request.dashboard_user["role"])
    resp = jsonify({"token": AGENT_AUTH_TOKEN})
    resp.headers["Cache-Control"] = "no-store"
    return resp

def _agent_is_up_to_date(agent_version: str):
    """True/False, ou None si la version de l'agent est inconnue/illisible (agent
    trop ancien pour la reporter, ou format inattendu) — ni « à jour » ni « en retard »,
    affiché à part dans le dashboard plutôt que compté comme obsolète."""
    v = _parse_ver(agent_version)
    server_v = _parse_ver(AGENT_VERSION)
    if v is None or server_v is None:
        return None
    return v >= server_v

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

    # Conformité de version — lecture légère (juste la version), pas de re-scan complet.
    with db_lock:
        versions = list(mongo.db.agents.find({}, {"_id": 0, "agent_version": 1}))
    up_to_date = outdated = unknown_version = 0
    for v in versions:
        state = _agent_is_up_to_date(v.get("agent_version", ""))
        if state is True:
            up_to_date += 1
        elif state is False:
            outdated += 1
        else:
            unknown_version += 1

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
        "server_agent_version": AGENT_VERSION,
        "agents_up_to_date":    up_to_date,
        "agents_outdated":      outdated,
        "agents_version_unknown": unknown_version,
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
        agents = list(mongo.db.agents.find({}, {"_id": 0, "software": 0, "log_tail": 0}))
        disabled_links = {d.get("key") for d in mongo.db.network_link_overrides.find(
            {"disabled": True}, {"_id": 0, "key": 1})}

    servers = []
    subnet_map: dict = {}  # subnet -> [hostname, ...]

    for a in agents:
        totals = _vulnerability_totals(a.get("vulnerabilities"))
        a.update(totals)
        if a.get("cve_scan_status") not in ("complete", "deferred"):
            # A legacy vulnerable document was necessarily analysed. A legacy
            # empty document has no proof of a completed scan, so do not label
            # it healthy until a current server version checks it.
            a["cve_scan_status"] = ("deferred" if a.get("cve_scan_deferred")
                                    else "complete" if totals["cve_count"] else "unknown")
        a["online"] = _is_online(a)
        a["agent_up_to_date"] = _agent_is_up_to_date(a.get("agent_version", ""))
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
                    key = "|".join(sorted((srv["hostname"], peer)))
                    if peer != srv["hostname"] and key not in disabled_links:
                        peers.add(peer)
        srv["subnet_peers"] = sorted(peers)
        # Conserver toutes les interfaces : un hôte multi-homé doit apparaître
        # dans chacun de ses réseaux, pas uniquement dans le premier trouvé.
        srv["subnets"] = sorted({_subnet_24(ip) for ip in ips if _subnet_24(ip)})
        srv["subnet"] = srv["subnets"][0] if srv["subnets"] else None

    return jsonify({"servers": servers, "subnet_map": subnet_map}), 200

@app.route('/api/network-links/<source>/<target>', methods=['DELETE'])
@require_role("admin")
def disable_network_link(source, target):
    """Masque manuellement un lien supposé issu d'un sous-réseau partagé."""
    if source == target:
        return {"error": "Lien invalide"}, 400
    key = "|".join(sorted((source, target)))
    mongo.db.network_link_overrides.update_one({"key": key}, {"$set": {
        "key": key, "disabled": True, "disabled_at": datetime.utcnow(),
        "disabled_by": request.dashboard_user.get("email", "")}}, upsert=True)
    return jsonify({"status": "ok"})

# ─── All vulnerabilities across all agents ───────────────────────────────────
@app.route('/api/vulnerabilities', methods=['GET'])
@require_role("admin", "inspection_logs")
def all_vulnerabilities():
    with db_lock:
        agents = list(mongo.db.agents.find(
            {}, {"_id": 0, "hostname": 1, "os": 1, "vulnerabilities": 1,
                 "vulnerable_count": 1, "cve_count": 1, "critical_count": 1,
                 "high_count": 1, "ip_addresses": 1, "cve_scan_status": 1,
                 "cve_scan_deferred": 1, "cve_scan_reason": 1, "cve_last_checked_at": 1}
        ))
    result = []
    for a in agents:
        totals = _vulnerability_totals(a.get("vulnerabilities"))
        a.update(totals)
        if a.get("cve_scan_status") not in ("complete", "deferred"):
            a["cve_scan_status"] = ("deferred" if a.get("cve_scan_deferred")
                                    else "complete" if totals["cve_count"] else "unknown")
        # Keep vulnerable hosts and hosts whose scan has not completed. Healthy
        # hosts with a confirmed scan remain omitted from this focused page.
        if a.get("cve_count", 0) > 0 or a["cve_scan_status"] != "complete":
            result.append(_clean(a))
    result.sort(key=lambda x: -(x.get("cve_count") or 0))
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

# ─── Exports partageables ────────────────────────────────────────────────────
def _csv_response(filename: str, headers: list, rows: list):
    """Retourne un CSV UTF-8 avec BOM, lisible directement dans Excel."""
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(headers)
    writer.writerows(rows)
    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _pdf_fonts():
    """Return Unicode-capable font names when DejaVu Sans is available."""
    regular = bold = "Helvetica"
    if not _HAS_REPORTLAB:
        return regular, "Helvetica-Bold"
    candidates = [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        (r"C:\Windows\Fonts\DejaVuSans.ttf", r"C:\Windows\Fonts\DejaVuSans-Bold.ttf"),
    ]
    for regular_path, bold_path in candidates:
        if os.path.exists(regular_path) and os.path.exists(bold_path):
            try:
                if "HeimdallSans" not in pdfmetrics.getRegisteredFontNames():
                    pdfmetrics.registerFont(TTFont("HeimdallSans", regular_path))
                    pdfmetrics.registerFont(TTFont("HeimdallSans-Bold", bold_path))
                return "HeimdallSans", "HeimdallSans-Bold"
            except Exception:
                pass
    return regular, "Helvetica-Bold"


def _pdf_response(filename: str, title: str, subtitle: str, summary: list,
                  headers: list, rows: list, widths: list, intro: str = ""):
    """Build a branded, paginated PDF report from tabular export data."""
    if not _HAS_REPORTLAB:
        return jsonify({"error": "Export PDF indisponible : installez reportlab puis reconstruisez le serveur."}), 503

    regular_font, bold_font = _pdf_fonts()
    accent = pdf_colors.HexColor("#ff7a2f")
    navy = pdf_colors.HexColor("#0b1328")
    navy_light = pdf_colors.HexColor("#17223d")
    text = pdf_colors.HexColor("#172033")
    muted = pdf_colors.HexColor("#64748b")
    border = pdf_colors.HexColor("#d9e1ec")
    pale = pdf_colors.HexColor("#f4f7fb")

    output = io.BytesIO()
    page_size = landscape(A4)
    doc = SimpleDocTemplate(
        output, pagesize=page_size, leftMargin=13 * mm, rightMargin=13 * mm,
        topMargin=24 * mm, bottomMargin=17 * mm,
        title=title, author="Heimdall Security",
        subject=subtitle,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "HeimdallTitle", parent=styles["Title"], fontName=bold_font,
        fontSize=22, leading=26, textColor=navy, alignment=TA_LEFT,
        spaceAfter=3 * mm,
    )
    subtitle_style = ParagraphStyle(
        "HeimdallSubtitle", parent=styles["Normal"], fontName=regular_font,
        fontSize=9, leading=13, textColor=muted, spaceAfter=5 * mm,
    )
    body_style = ParagraphStyle(
        "HeimdallBody", parent=styles["BodyText"], fontName=regular_font,
        fontSize=7.2, leading=9.2, textColor=text,
    )
    head_style = ParagraphStyle(
        "HeimdallHead", parent=body_style, fontName=bold_font,
        fontSize=7.2, leading=9, textColor=pdf_colors.white,
    )
    card_label_style = ParagraphStyle(
        "HeimdallCardLabel", parent=body_style, fontSize=7, textColor=muted,
    )
    card_value_style = ParagraphStyle(
        "HeimdallCardValue", parent=body_style, fontName=bold_font,
        fontSize=14, leading=17, textColor=navy,
    )

    def para(value, style=body_style):
        if isinstance(value, datetime):
            value = value.strftime("%d/%m/%Y %H:%M UTC")
        value = "—" if value is None or value == "" else str(value)
        if len(value) > 2000:
            value = value[:1999] + "…"
        return Paragraph(html.escape(value).replace("\n", "<br/>"), style)

    story = [
        Paragraph(html.escape(title), title_style),
        Paragraph(html.escape(subtitle), subtitle_style),
    ]
    if intro:
        story.extend([para(intro), Spacer(1, 4 * mm)])

    if summary:
        card_width = (page_size[0] - doc.leftMargin - doc.rightMargin) / len(summary)
        cards = [[Table([[para(label, card_label_style)], [para(value, card_value_style)]],
                        colWidths=[card_width - 3 * mm], rowHeights=[6 * mm, 10 * mm],
                        style=TableStyle([
                            ("BACKGROUND", (0, 0), (-1, -1), pale),
                            ("BOX", (0, 0), (-1, -1), 0.6, border),
                            ("LEFTPADDING", (0, 0), (-1, -1), 4 * mm),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
                            ("TOPPADDING", (0, 0), (-1, -1), 2 * mm),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 2 * mm),
                        ])) for label, value in summary]]
        summary_table = Table(cards, colWidths=[card_width] * len(summary), hAlign="LEFT")
        summary_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3 * mm),
        ]))
        story.extend([summary_table, Spacer(1, 6 * mm)])

    table_data = [[para(h, head_style) for h in headers]]
    table_data.extend([[para(cell) for cell in row] for row in rows])
    report_table = Table(table_data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), navy_light),
        ("TEXTCOLOR", (0, 0), (-1, 0), pdf_colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, border),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2 * mm),
        ("TOPPADDING", (0, 1), (-1, -1), 1.6 * mm),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 1.6 * mm),
    ]
    for idx, row in enumerate(rows, start=1):
        joined = " ".join(str(v).upper() for v in row)
        background = pdf_colors.white if idx % 2 else pale
        if "CRITIQUE" in joined or "ÉCHEC" in joined or "ECHEC" in joined:
            background = pdf_colors.HexColor("#fff0f0")
        elif "ÉLEVÉ" in joined or "EN ATTENTE" in joined or "NON ANALYSÉ" in joined:
            background = pdf_colors.HexColor("#fff7ed")
        table_commands.append(("BACKGROUND", (0, idx), (-1, idx), background))
    report_table.setStyle(TableStyle(table_commands))
    story.append(report_table if rows else para("Aucune donnée disponible pour ce rapport."))

    generated = datetime.utcnow().strftime("%d/%m/%Y à %H:%M UTC")
    def decorate_page(canvas, _doc):
        canvas.saveState()
        width, height = page_size
        canvas.setFillColor(navy)
        canvas.rect(0, height - 13 * mm, width, 13 * mm, stroke=0, fill=1)
        canvas.setFillColor(accent)
        canvas.rect(13 * mm, height - 8.5 * mm, 2.2 * mm, 4 * mm, stroke=0, fill=1)
        canvas.setFont(bold_font, 9)
        canvas.setFillColor(pdf_colors.white)
        canvas.drawString(18 * mm, height - 7.5 * mm, "HEIMDALL SECURITY")
        canvas.setFont(regular_font, 7)
        canvas.setFillColor(muted)
        canvas.drawString(13 * mm, 8 * mm, f"Généré le {generated}")
        canvas.drawRightString(width - 13 * mm, 8 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=decorate_page, onLaterPages=decorate_page)
    return Response(
        output.getvalue(), mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "Cache-Control": "no-store"},
    )


def _cvss_label(score) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "Inconnue"
    if value >= 9:
        return "Critique"
    if value >= 7:
        return "Élevée"
    if value >= 4:
        return "Moyenne"
    return "Faible"

@app.route('/api/exports/servers.csv', methods=['GET'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def export_servers_csv():
    """Inventaire synthétique du parc, destiné aux partages internes."""
    with db_lock:
        agents = list(mongo.db.agents.find({}, {
            "_id": 0, "hostname": 1, "os": 1, "release": 1, "os_build": 1,
            "ip_addresses": 1, "software_count": 1, "cve_count": 1,
            "vulnerable_count": 1, "critical_count": 1, "high_count": 1,
            "last_seen": 1, "agent_version": 1, "vulnerabilities": 1,
            "cve_scan_status": 1, "cve_scan_deferred": 1,
        }))
    rows = []
    for a in sorted(agents, key=lambda x: x.get("hostname", "").lower()):
        totals = _vulnerability_totals(a.get("vulnerabilities"))
        status = a.get("cve_scan_status")
        if status not in ("complete", "deferred"):
            status = "deferred" if a.get("cve_scan_deferred") else "complete" if totals["cve_count"] else "unknown"
        rows.append([
            a.get("hostname", ""), a.get("os", ""), a.get("release", ""),
            a.get("os_build", ""), ", ".join(a.get("ip_addresses") or []),
            "En ligne" if _is_online(a) else "Hors ligne", a.get("software_count", 0),
            totals["cve_count"], totals["critical_count"], totals["high_count"],
            {"complete": "Terminée", "deferred": "En attente", "unknown": "Non analysé"}.get(status, status),
            a.get("agent_version", ""), a.get("last_seen", ""),
        ])
    stamp = datetime.utcnow().strftime("%Y-%m-%d")
    return _csv_response(f"heimdall-inventaire-{stamp}.csv", [
        "Hôte", "OS", "Version OS", "Build", "Adresses IP", "Statut", "Logiciels",
        "CVE", "CVE critiques", "CVE élevées", "État analyse CVE", "Version agent", "Dernier relevé",
    ], rows)


@app.route('/api/exports/servers.pdf', methods=['GET'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def export_servers_pdf():
    """Rapport PDF lisible de l'inventaire et de son niveau d'exposition."""
    agents = list(mongo.db.agents.find({}, {
        "_id": 0, "hostname": 1, "os": 1, "release": 1, "ip_addresses": 1,
        "software_count": 1, "vulnerabilities": 1, "last_seen": 1,
        "cve_scan_status": 1, "cve_scan_deferred": 1,
    }))
    rows, total_cves, total_critical, vulnerable, pending, online = [], 0, 0, 0, 0, 0
    for a in sorted(agents, key=lambda x: x.get("hostname", "").lower()):
        totals = _vulnerability_totals(a.get("vulnerabilities"))
        status = a.get("cve_scan_status")
        if status not in ("complete", "deferred"):
            status = "deferred" if a.get("cve_scan_deferred") else "complete" if totals["cve_count"] else "unknown"
        scan_label = {"complete": "Terminée", "deferred": "En attente", "unknown": "Non analysé"}.get(status, status)
        is_online = _is_online(a)
        online += int(is_online)
        pending += int(status != "complete")
        vulnerable += int(totals["cve_count"] > 0)
        total_cves += totals["cve_count"]
        total_critical += totals["critical_count"]
        last_seen = a.get("last_seen")
        if isinstance(last_seen, datetime):
            last_seen = last_seen.strftime("%d/%m/%Y %H:%M")
        rows.append([
            a.get("hostname", ""), f"{a.get('os', '')} {a.get('release', '')}".strip(),
            ", ".join(a.get("ip_addresses") or []), "En ligne" if is_online else "Hors ligne",
            scan_label, a.get("software_count", 0), totals["cve_count"],
            f"{totals['critical_count']} / {totals['high_count']}", last_seen or "—",
        ])
    stamp = datetime.utcnow().strftime("%Y-%m-%d")
    return _pdf_response(
        f"heimdall-inventaire-{stamp}.pdf", "Rapport d'inventaire du parc",
        "État des agents, systèmes, inventaires logiciels et exposition CVE.",
        [("Hôtes", len(agents)), ("En ligne", online), ("Hôtes vulnérables", vulnerable),
         ("CVE / critiques", f"{total_cves} / {total_critical}"), ("Analyses en attente", pending)],
        ["Hôte", "Système", "Adresses IP", "Statut", "Analyse CVE", "Logiciels", "CVE",
         "Crit. / élevées", "Dernier relevé"],
        rows, [27*mm, 34*mm, 40*mm, 20*mm, 24*mm, 17*mm, 14*mm, 22*mm, 35*mm],
        "Ce document donne une vue synthétique du parc supervisé. Une analyse en attente ou non réalisée ne doit pas être interprétée comme une absence de vulnérabilité.",
    )

@app.route('/api/exports/vulnerabilities.csv', methods=['GET'])
@require_role("admin", "inspection_logs", "codir")
def export_vulnerabilities_csv():
    """Une ligne par CVE et par hôte, exploitable dans un outil de suivi."""
    with db_lock:
        agents = list(mongo.db.agents.find({}, {
            "_id": 0, "hostname": 1, "os": 1, "ip_addresses": 1,
            "vulnerabilities": 1,
        }))
    rows = []
    for a in agents:
        for vuln in a.get("vulnerabilities") or []:
            cves = vuln.get("cves") or []
            # Les agents plus anciens peuvent ne conserver que les compteurs.
            if not cves:
                rows.append([a.get("hostname", ""), ", ".join(a.get("ip_addresses") or []),
                             a.get("os", ""), vuln.get("product", ""), vuln.get("version", ""),
                             "", "", "", vuln.get("critical", 0), vuln.get("high", 0), ""])
            for cve in cves:
                rows.append([a.get("hostname", ""), ", ".join(a.get("ip_addresses") or []),
                             a.get("os", ""), vuln.get("product", ""), vuln.get("version", ""),
                             cve.get("id", cve.get("cve_id", "")), cve.get("cvss_score", cve.get("cvss", cve.get("score", ""))),
                             _epss_pct(cve.get("epss_score")),
                             vuln.get("critical", 0), vuln.get("high", 0), cve.get("title", cve.get("description", ""))])
    stamp = datetime.utcnow().strftime("%Y-%m-%d")
    return _csv_response(f"heimdall-vulnerabilites-{stamp}.csv", [
        "Hôte", "Adresses IP", "OS", "Logiciel", "Version", "CVE", "CVSS", "EPSS (%)",
        "Critiques sur le logiciel", "Élevées sur le logiciel", "Description",
    ], rows)


@app.route('/api/exports/vulnerabilities.pdf', methods=['GET'])
@require_role("admin", "inspection_logs", "codir")
def export_vulnerabilities_pdf():
    """Rapport PDF priorisé, une ligne par CVE détectée et hôte concerné."""
    agents = list(mongo.db.agents.find({}, {
        "_id": 0, "hostname": 1, "os": 1, "vulnerabilities": 1,
        "cve_scan_status": 1, "cve_scan_deferred": 1,
    }))
    rows, critical, high, affected_hosts, pending = [], 0, 0, set(), 0
    for a in agents:
        totals = _vulnerability_totals(a.get("vulnerabilities"))
        status = a.get("cve_scan_status")
        if status not in ("complete", "deferred"):
            status = "deferred" if a.get("cve_scan_deferred") else "complete" if totals["cve_count"] else "unknown"
        if status != "complete":
            pending += 1
            if not totals["cve_count"]:
                rows.append([a.get("hostname", ""), a.get("os", ""), "—", "—", "—", "—",
                             "Non analysé" if status == "unknown" else "En attente",
                             "Aucun résultat CVE complet n'est disponible pour cet hôte."])
        for vuln in a.get("vulnerabilities") or []:
            product = vuln.get("product") or vuln.get("name") or "—"
            version = vuln.get("version") or "—"
            for cve in vuln.get("cves") or []:
                score = cve.get("cvss_score", cve.get("cvss", cve.get("score")))
                severity = _cvss_label(score)
                critical += int(severity == "Critique")
                high += int(severity == "Élevée")
                affected_hosts.add(a.get("hostname", ""))
                rows.append([
                    a.get("hostname", ""), a.get("os", ""), f"{product} {version}".strip(),
                    cve.get("cve_id", cve.get("id", "")), score if score is not None else "—",
                    _epss_pct(cve.get("epss_score")) or "—",
                    severity, (cve.get("description") or cve.get("title") or "")[:500],
                ])
    severity_rank = {"Critique": 0, "Élevée": 1, "Moyenne": 2, "Faible": 3,
                     "En attente": 4, "Non analysé": 5, "Inconnue": 6}
    rows.sort(key=lambda row: (severity_rank.get(row[6], 9), str(row[0]).lower(), str(row[3])))
    stamp = datetime.utcnow().strftime("%Y-%m-%d")
    cve_rows = sum(1 for row in rows if str(row[3]).startswith("CVE-"))
    return _pdf_response(
        f"heimdall-vulnerabilites-{stamp}.pdf", "Rapport de vulnérabilités",
        "Vulnérabilités détectées, classées par criticité et rattachées aux hôtes concernés.",
        [("CVE détectées", cve_rows), ("Critiques", critical), ("Élevées", high),
         ("Hôtes affectés", len(affected_hosts)), ("Analyses en attente", pending)],
        ["Hôte", "OS", "Produit / version", "CVE", "CVSS", "EPSS %", "Sévérité", "Description"],
        rows, [25*mm, 22*mm, 40*mm, 25*mm, 13*mm, 14*mm, 19*mm, 83*mm],
        "Priorisez les vulnérabilités critiques et élevées, en commençant par celles dont l'EPSS (probabilité d'exploitation sous 30 jours) est élevé, puis confirmez l'exposition réelle avant remédiation. Les résultats dépendent de la fraîcheur des inventaires et des analyses CVE.",
    )

@app.route('/api/exports/compliance.csv', methods=['GET'])
@require_role("admin", "inspection_logs", "codir")
def export_compliance_csv():
    """Synthèse de conformité : une ligne par contrôle applicable et par hôte."""
    with db_lock:
        doc = mongo.db.compliance_config.find_one({"_id": "rules"}, {"_id": 0})
        agents = list(mongo.db.agents.find({}, {
            "_id": 0, "hostname": 1, "os": 1, "ip_addresses": 1, "compliance": 1,
        }))
    rules = [r for r in (doc.get("rules") if doc else DEFAULT_COMPLIANCE_RULES) if r.get("enabled", True)]
    rows = []
    for a in agents:
        for rule in rules:
            check = _eval_rule(rule, a.get("compliance") or {}, a.get("os", ""))
            if check.get("status") == "na":
                continue
            rows.append([
                a.get("hostname", ""), ", ".join(a.get("ip_addresses") or []), a.get("os", ""),
                check.get("rule_id", ""), check.get("name", ""), rule.get("severity", ""),
                check.get("status", ""), check.get("actual_value", ""), check.get("expected_value", ""),
                rule.get("cis_ref", ""),
            ])
    stamp = datetime.utcnow().strftime("%Y-%m-%d")
    return _csv_response(f"heimdall-conformite-{stamp}.csv", [
        "Hôte", "Adresses IP", "OS", "ID règle", "Règle", "Sévérité", "Résultat",
        "Valeur relevée", "Valeur attendue", "Référence CIS",
    ], rows)


@app.route('/api/exports/compliance.pdf', methods=['GET'])
@require_role("admin", "inspection_logs", "codir")
def export_compliance_pdf():
    """Rapport PDF des contrôles de conformité applicables au parc."""
    doc = mongo.db.compliance_config.find_one({"_id": "rules"}, {"_id": 0})
    agents = list(mongo.db.agents.find({}, {
        "_id": 0, "hostname": 1, "os": 1, "ip_addresses": 1, "compliance": 1,
    }))
    rules = [r for r in (doc.get("rules") if doc else DEFAULT_COMPLIANCE_RULES) if r.get("enabled", True)]
    rows, passed, failed, unknown = [], 0, 0, 0
    labels = {"pass": "Conforme", "fail": "Échec", "unknown": "Inconnu"}
    severity_labels = {"critical": "Critique", "high": "Élevée",
                       "medium": "Moyenne", "low": "Faible"}
    for a in agents:
        for rule in rules:
            check = _eval_rule(rule, a.get("compliance") or {}, a.get("os", ""))
            status = check.get("status")
            if status == "na":
                continue
            passed += int(status == "pass")
            failed += int(status == "fail")
            unknown += int(status == "unknown")
            rows.append([
                a.get("hostname", ""), a.get("os", ""), check.get("name", ""),
                severity_labels.get(str(rule.get("severity", "")).lower(), str(rule.get("severity", "")).capitalize()),
                labels.get(status, status),
                check.get("actual_value", "—"), check.get("expected_value", "—"),
                rule.get("cis_ref", "—"),
            ])
    status_rank = {"Échec": 0, "Inconnu": 1, "Conforme": 2}
    rows.sort(key=lambda row: (status_rank.get(row[4], 9), str(row[0]).lower(), str(row[2]).lower()))
    applicable = passed + failed + unknown
    score = round(passed / applicable * 100) if applicable else 0
    stamp = datetime.utcnow().strftime("%Y-%m-%d")
    return _pdf_response(
        f"heimdall-conformite-{stamp}.pdf", "Rapport de conformité",
        "Évaluation des règles de sécurité applicables aux systèmes supervisés.",
        [("Hôtes", len(agents)), ("Contrôles", applicable), ("Conformes", passed),
         ("Échecs", failed), ("Score global", f"{score} %")],
        ["Hôte", "OS", "Contrôle", "Sévérité", "Résultat", "Valeur relevée",
         "Valeur attendue", "Référence"],
        rows, [25*mm, 25*mm, 61*mm, 20*mm, 21*mm, 33*mm, 33*mm, 27*mm],
        "Le score global porte uniquement sur les contrôles applicables et collectés. Les résultats inconnus doivent être vérifiés avant toute conclusion de conformité.",
    )

# ─── Assistant IA (BYO model) ────────────────────────────────────────────────
def _ai_context() -> str:
    """Contexte volontairement synthétique : ni secrets, ni journaux, ni tokens."""
    with db_lock:
        agents = list(mongo.db.agents.find({}, {
            "_id": 0, "hostname": 1, "os": 1, "ip_addresses": 1,
            "vulnerable_count": 1, "cve_count": 1, "critical_count": 1,
            "high_count": 1, "last_seen": 1, "compliance": 1,
        }))
        rules_doc = mongo.db.compliance_config.find_one({"_id": "rules"}, {"_id": 0, "rules": 1}) or {}
    hosts = []
    for a in agents[:100]:
        # Les résultats de conformité suffisent à l'analyse. On borne chaque
        # valeur afin qu'un relevé anormalement volumineux ne gonfle pas le prompt.
        compliance = {
            str(k)[:80]: str(v)[:240]
            for k, v in list((a.get("compliance") or {}).items())[:40]
        }
        hosts.append({
            "host": a.get("hostname"), "os": a.get("os"), "ips": a.get("ip_addresses") or [],
            "cves": a.get("cve_count", a.get("vulnerable_count", 0)),
            "critical": a.get("critical_count", 0), "high": a.get("high_count", 0),
            "last_seen": str(a.get("last_seen", "")),
            "compliance": compliance,
        })
    rules = rules_doc.get("rules", DEFAULT_COMPLIANCE_RULES)
    rule_summary = [{
        "id": r.get("id"), "name": r.get("name"), "platforms": r.get("platforms", []),
        "enabled": r.get("enabled", True), "collector": (r.get("collector") or {}).get("type"),
    } for r in rules[:100]]
    return json.dumps({"generated_at": datetime.utcnow().isoformat() + "Z", "hosts": hosts,
        "application": {"existing_compliance_rules": rule_summary,
            "rule_fields": ["id", "name", "description", "severity", "expected_op", "expected_value", "type", "platforms", "cis_ref", "example", "enabled", "collector"],
            "supported_collectors": {"windows": {"registry": "path: HKLM\\Subkey\\ValueName"},
                "linux_macos": {"sysctl": "key", "file_grep": "path + pattern", "systemd_active": "service", "file_exists": "path"}},
            "rule_note": "The agent only reads settings; a rule never modifies an endpoint. Proposed rules require administrator approval."}}, ensure_ascii=False)

def _extract_ai_rule_proposal(reply: str):
    """Extract an optional rule proposal; the model can never execute it."""
    match = re.search(r"<heimdall_rule>\s*(\{.*?\})\s*</heimdall_rule>", reply, re.DOTALL | re.IGNORECASE)
    if not match:
        return reply.strip(), None
    clean_reply = (reply[:match.start()] + reply[match.end():]).strip()
    try:
        rule = json.loads(match.group(1))
    except (ValueError, TypeError):
        return clean_reply, None
    required = {"id", "name", "expected_op", "expected_value", "type", "platforms"}
    if not isinstance(rule, dict) or not required.issubset(rule) or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", str(rule.get("id", ""))):
        return clean_reply, None
    if rule.get("expected_op") not in {"==", ">=", "<=", ">", "<", "in"} or rule.get("type") not in {"int", "bool", "string", "tls_version"}:
        return clean_reply, None
    try:
        if rule["type"] == "int":
            rule["expected_value"] = int(rule["expected_value"])
        elif rule["type"] == "bool":
            rule["expected_value"] = str(rule["expected_value"]).lower() in {"true", "1", "yes"}
        else:
            rule["expected_value"] = str(rule["expected_value"])[:240]
    except (ValueError, TypeError):
        return clean_reply, None
    rule["platforms"] = [p for p in rule.get("platforms", []) if p in {"windows", "linux", "darwin"}]
    if not rule["platforms"]:
        return clean_reply, None
    rule["name"] = str(rule["name"])[:160]
    rule["description"] = str(rule.get("description", ""))[:800]
    rule["severity"] = rule.get("severity") if rule.get("severity") in {"critical", "high", "medium", "low"} else "medium"
    rule["cis_ref"] = str(rule.get("cis_ref", ""))[:80]
    rule["example"] = str(rule.get("example", ""))[:240]
    rule["enabled"] = bool(rule.get("enabled", True))
    collector = rule.get("collector")
    if collector and (not isinstance(collector, dict) or collector.get("type") not in {"registry", "sysctl", "file_grep", "systemd_active", "file_exists"}):
        rule.pop("collector", None)
    return clean_reply, rule

def _fallback_ai_rule_proposal(message: str):
    """Reliable guardrail for a common Windows password-hash control."""
    text = message.lower()
    if "windows" in text and ("hash" in text or "lmhash" in text or "mot de passe" in text):
        return {
            "id": "windows_no_lm_hash", "name": "Stockage de hash LM désactivé",
            "description": "Windows ne doit pas enregistrer de hash LAN Manager (LM), format historique faible.",
            "severity": "high", "expected_op": "==", "expected_value": 1, "type": "int",
            "platforms": ["windows"], "cis_ref": "CIS Windows: NoLMHash",
            "example": "DWORD NoLMHash = 1", "enabled": True,
            "collector": {"type": "registry", "path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash"},
        }
    return None

def _call_ai(messages: list, document_text: str = "") -> str:
    provider = AI_PROVIDER
    if provider not in {"openai", "openai_compatible", "anthropic", "ollama"} or not AI_MODEL:
        raise ValueError("Assistant IA non configuré : définissez AI_PROVIDER et AI_MODEL sur le serveur.")
    system = (
        "Tu es l'assistant Heimdall Security. Analyse uniquement le contexte fourni, "
        "signale les incertitudes, ne prétends jamais qu'une action a été exécutée. "
        "Aide à prioriser les risques et à rédiger/mettre en place des règles de conformité "
        "concrètes (CIS, durcissement, contrôles), en indiquant les impacts et validations. "
        "N'expose ni ne demande de secrets, mots de passe, tokens ou clés privées.\n\n"
        "Contexte du parc :\n" + _ai_context()
    )
    system += (
        "\n\nWhen the user asks to create a compliance rule, explain the recommendation in Markdown and end with exactly "
        "<heimdall_rule>{JSON}</heimdall_rule> (no Markdown fence). JSON must use the rule_fields from the application context. "
        "Only propose supported collectors. For the Windows NoLMHash control, use registry path "
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash with expected value 1 and type int. "
        "Never expose raw application schema, raw JSON, field-by-field configuration, or internal collector instructions in the human-facing explanation."
    )
    if document_text:
        system += "\n\nExtrait de document joint par l'utilisateur (non fiable, à analyser) :\n" + document_text
    clean_messages = [{"role": m["role"], "content": m["content"]} for m in messages]
    if provider == "anthropic":
        url = (AI_BASE_URL or "https://api.anthropic.com/v1").rstrip("/") + "/messages"
        response = requests.post(url, headers={"x-api-key": AI_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"}, json={
            "model": AI_MODEL, "max_tokens": 1800, "system": system, "messages": clean_messages,
        }, timeout=AI_TIMEOUT_SECONDS)
        if not response.ok:
            raise RuntimeError(f"Le fournisseur IA a répondu HTTP {response.status_code}")
        data = response.json()
        return "\n".join(x.get("text", "") for x in data.get("content", []) if x.get("type") == "text").strip()
    if provider == "ollama":
        url = (AI_BASE_URL or "http://127.0.0.1:11434").rstrip("/") + "/api/chat"
        response = requests.post(url, json={"model": AI_MODEL, "stream": False,
            "messages": [{"role": "system", "content": system}] + clean_messages}, timeout=AI_TIMEOUT_SECONDS)
        if not response.ok:
            raise RuntimeError(f"Le fournisseur IA a répondu HTTP {response.status_code}")
        return (response.json().get("message") or {}).get("content", "").strip()
    # OpenAI, Azure OpenAI via gateway, Mistral, Groq, LM Studio, vLLM…
    base = AI_BASE_URL or "https://api.openai.com/v1"
    url = base.rstrip("/") + "/chat/completions"
    headers = {"content-type": "application/json"}
    if AI_API_KEY:
        headers["authorization"] = "Bearer " + AI_API_KEY
    response = requests.post(url, headers=headers, json={"model": AI_MODEL, "temperature": 0.2,
        "messages": [{"role": "system", "content": system}] + clean_messages}, timeout=AI_TIMEOUT_SECONDS)
    if not response.ok:
        raise RuntimeError(f"Le fournisseur IA a répondu HTTP {response.status_code}")
    return (((response.json().get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()

@app.route('/api/ai/status', methods=['GET'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def ai_status():
    return jsonify({"configured": bool(AI_PROVIDER and AI_MODEL), "provider": AI_PROVIDER,
                    "model": AI_MODEL, "base_url": AI_BASE_URL})

def _ai_history(user_id: str) -> list:
    doc = mongo.db.dashboard_ai_chats.find_one({"user_id": user_id}, {"_id": 0, "messages": 1}) or {}
    return doc.get("messages") if isinstance(doc.get("messages"), list) else []

def _ai_exports_for(message: str) -> list:
    """Actions explicites, jamais des liens fournis par le modèle."""
    text = message.lower()
    if not any(word in text for word in ("export", "csv", "rapport", "partag", "extraire")):
        return []
    return [
        {"label": "Inventaire CSV", "path": "/api/exports/servers.csv", "filename": "heimdall-inventaire.csv"},
        {"label": "Inventaire PDF", "path": "/api/exports/servers.pdf", "filename": "heimdall-inventaire.pdf"},
        {"label": "Vulnérabilités CSV", "path": "/api/exports/vulnerabilities.csv", "filename": "heimdall-vulnerabilites.csv"},
        {"label": "Vulnérabilités PDF", "path": "/api/exports/vulnerabilities.pdf", "filename": "heimdall-vulnerabilites.pdf"},
        {"label": "Conformité CSV", "path": "/api/exports/compliance.csv", "filename": "heimdall-conformite.csv"},
        {"label": "Conformité PDF", "path": "/api/exports/compliance.pdf", "filename": "heimdall-conformite.pdf"},
    ]

@app.route('/api/ai/chat', methods=['GET'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def ai_chat_history():
    """Historique strictement isolé par identifiant utilisateur, limité à 10 messages."""
    return jsonify({"messages": _ai_history(request.dashboard_user["id"])[-10:]})

@app.route('/api/ai/compliance-proposals/apply', methods=['POST'])
@require_admin
def apply_ai_compliance_proposal():
    """Apply only a reviewed proposal; the agent itself never executes a change."""
    payload = request.get_json(silent=True) or {}
    rule = payload.get("rule")
    if not isinstance(rule, dict):
        return jsonify({"error": "Règle proposée invalide"}), 400
    _, normalized = _extract_ai_rule_proposal("<heimdall_rule>" + json.dumps(rule) + "</heimdall_rule>")
    if not normalized:
        return jsonify({"error": "Règle proposée invalide ou non compatible"}), 400
    with db_lock:
        doc = mongo.db.compliance_config.find_one({"_id": "rules"}, {"_id": 0}) or {}
        rules = doc.get("rules", DEFAULT_COMPLIANCE_RULES)
        if any(r.get("id") == normalized["id"] for r in rules):
            return jsonify({"error": "Une règle porte déjà cet identifiant"}), 409
        mongo.db.compliance_config.update_one({"_id": "rules"}, {"$set": {
            "rules": rules + [normalized], "updated_at": datetime.utcnow().isoformat()}}, upsert=True)
    _COMPLIANCE_CACHE["computed_at"] = None
    # Avoid showing the same accepted proposal again after a page reload.
    try:
        index = int(payload.get("message_index", -1))
        history = _ai_history(request.dashboard_user["id"])
        if 0 <= index < len(history) and isinstance(history[index], dict):
            history[index].pop("proposal", None)
            mongo.db.dashboard_ai_chats.update_one({"user_id": request.dashboard_user["id"]}, {"$set": {"messages": history}})
    except (TypeError, ValueError):
        pass
    return jsonify({"status": "ok", "rule": normalized}), 201

@app.route('/api/ai/compliance-proposals/dismiss', methods=['POST'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def dismiss_ai_compliance_proposal():
    try:
        index = int((request.get_json(silent=True) or {}).get("message_index", -1))
    except (TypeError, ValueError):
        return jsonify({"error": "Proposition invalide"}), 400
    history = _ai_history(request.dashboard_user["id"])
    if not (0 <= index < len(history)) or not isinstance(history[index], dict):
        return jsonify({"error": "Proposition introuvable"}), 404
    history[index].pop("proposal", None)
    mongo.db.dashboard_ai_chats.update_one({"user_id": request.dashboard_user["id"]}, {"$set": {"messages": history}})
    return jsonify({"status": "ok"})

@app.route('/api/ai/documents', methods=['POST'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def ai_document_upload():
    if not _HAS_PDF_READER:
        return jsonify({"error": "Lecture PDF indisponible : reconstruisez le serveur avec les dépendances à jour."}), 503
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Fichier PDF requis"}), 400
    if not uploaded.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Seuls les PDF sont acceptés"}), 400
    raw = uploaded.read(3 * 1024 * 1024 + 1)
    if len(raw) > 3 * 1024 * 1024 or not raw.startswith(b"%PDF"):
        return jsonify({"error": "PDF invalide ou supérieur à 3 MiB"}), 400
    try:
        reader = PdfReader(io.BytesIO(raw))
        if reader.is_encrypted:
            return jsonify({"error": "Les PDF chiffrés ne sont pas pris en charge"}), 400
        parts, char_count = [], 0
        for page in reader.pages[:25]:
            extracted = (page.extract_text() or "")[:10000]
            parts.append(extracted)
            char_count += len(extracted)
            if char_count >= 50000:
                break
        text = "\n".join(parts)[:50000].strip()
    except Exception:
        logger.info("[AI] PDF unreadable for user %s", request.dashboard_user["id"])
        return jsonify({"error": "Impossible d'extraire le texte de ce PDF"}), 400
    if not text:
        return jsonify({"error": "Ce PDF ne contient pas de texte exploitable (PDF scanné ou vide)"}), 400
    doc_id = uuid.uuid4().hex
    mongo.db.dashboard_ai_documents.insert_one({
        "_id": doc_id, "user_id": request.dashboard_user["id"],
        "filename": os.path.basename(uploaded.filename)[:180], "text": text,
        "created_at": datetime.utcnow(),
    })
    return jsonify({"id": doc_id, "filename": os.path.basename(uploaded.filename)[:180], "characters": len(text)})

@app.route('/api/ai/chat', methods=['POST'])
@require_role("admin", "deployment", "inspection_logs", "codir")
def ai_chat():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()[:8000]
    if not message:
        return jsonify({"error": "Message requis"}), 400
    user_id = request.dashboard_user["id"]
    messages = _ai_history(user_id)[-10:]
    messages.append({"role": "user", "content": message})
    document_text = ""
    document_id = str(data.get("document_id", "")).strip()
    if document_id:
        doc = mongo.db.dashboard_ai_documents.find_one({"_id": document_id, "user_id": user_id}, {"_id": 0, "text": 1, "filename": 1})
        if not doc:
            return jsonify({"error": "Document introuvable ou non autorisé"}), 404
        document_text = "Nom du PDF : " + str(doc.get("filename", "document")) + "\n" + str(doc.get("text", ""))
    try:
        reply = _call_ai(messages, document_text)
        if not reply:
            raise RuntimeError("Réponse vide du fournisseur IA")
        reply, proposal = _extract_ai_rule_proposal(reply)
        fallback_proposal = _fallback_ai_rule_proposal(message)
        if not proposal and fallback_proposal:
            # Local models often print their construction notes instead of the
            # structured marker. Keep the client-facing result concise.
            proposal = fallback_proposal
            reply = ("### Règle prête à être revue\n\n"
                     "J’ai préparé un contrôle Windows pour vérifier que le stockage des anciens hash LM est désactivé. "
                     "Vérifiez les paramètres dans la carte ci-dessous, puis acceptez ou refusez la proposition.")
        assistant_message = {"role": "assistant", "content": reply, "exports": _ai_exports_for(message)}
        if proposal:
            assistant_message["proposal"] = proposal
        saved = (messages + [assistant_message])[-10:]
        mongo.db.dashboard_ai_chats.update_one({"user_id": user_id}, {"$set": {
            "user_id": user_id, "messages": saved, "updated_at": datetime.utcnow()}}, upsert=True)
        # The extracted attachment is one-shot: it is not needed to replay the
        # short history and retaining it would needlessly grow MongoDB.
        if document_id:
            mongo.db.dashboard_ai_documents.delete_one({"_id": document_id, "user_id": user_id})
        return jsonify({"reply": reply, "messages": saved, "exports": assistant_message["exports"], "proposal": proposal})
    except (ValueError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except requests.RequestException as exc:
        # Headers are deliberately omitted: they can contain the provider key.
        logger.warning("[AI] Provider unreachable (%s): %s", type(exc).__name__, str(exc))
        target = AI_BASE_URL or ("http://127.0.0.1:11434" if AI_PROVIDER == "ollama" else "https://api.openai.com/v1")
        return jsonify({"error": f"Fournisseur IA inaccessible ({type(exc).__name__}). Vérifiez AI_BASE_URL et la connectivité du conteneur vers {target}."}), 502

# ─── Mises à jour logicielles ────────────────────────────────────────────────
STALE_CACHE_HOURS = 24 * 7   # cache apt > 7 jours : la liste peut être périmée

@app.route('/api/updates', methods=['GET'])
@require_role("admin", "inspection_logs", "codir")
def updates_overview():
    """Par serveur : logiciels dont une version plus récente est disponible."""
    agents = list(mongo.db.agents.find(
        {}, {"_id": 0, "hostname": 1, "os": 1, "release": 1, "update_check": 1}
    ))
    rows, outdated_hosts, checked, unavailable, total_pkgs = [], 0, 0, 0, 0
    for a in agents:
        uc = a.get("update_check")
        if not uc:
            status = "unknown"      # ancien agent : n'envoie pas encore ce rapport
        elif not uc.get("ok"):
            status = "unavailable"
            unavailable += 1
        else:
            checked += 1
            n = uc.get("count") or 0
            total_pkgs += n
            status = "outdated" if n > 0 else "up_to_date"
            if n > 0:
                outdated_hosts += 1
        age = (uc or {}).get("cache_age_hours")
        rows.append({
            "hostname":        a["hostname"],
            "os":              a.get("os", ""),
            "release":         a.get("release", ""),
            "status":          status,
            "manager":         (uc or {}).get("manager"),
            "count":           (uc or {}).get("count"),
            "error":           (uc or {}).get("error"),
            "checked_at":      (uc or {}).get("checked_at"),
            "cache_age_hours": age,
            "stale_cache":     bool(age is not None and age > STALE_CACHE_HOURS),
            "items":           (uc or {}).get("items", []),
        })
    order = {"outdated": 0, "unavailable": 1, "unknown": 2, "up_to_date": 3}
    rows.sort(key=lambda r: (order[r["status"]], -(r["count"] or 0), r["hostname"].lower()))
    return jsonify({
        "summary": {"agents": len(rows), "checked": checked, "outdated_hosts": outdated_hosts,
                    "up_to_date_hosts": checked - outdated_hosts, "unavailable": unavailable,
                    "total_outdated_packages": total_pkgs},
        "agents": rows,
    }), 200

# ─── Admin dashboard ────────────────────────────────────────────────────────────────────
@app.route('/admin')
@app.route('/admin/')
@app.route('/admin/<path:path>')
def serve_admin(path=None):
    return render_template('admin.html')

# ─── Seed compte admin par défaut ────────────────────────────────────────────
DEFAULT_ADMIN_EMAIL    = os.getenv("DEFAULT_ADMIN_EMAIL", "")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "")

def _seed_default_admin():
    """Crée le compte admin par défaut si aucun admin n'existe encore."""
    with db_lock:
        try:
            if mongo.db.dashboard_users.count_documents({"role": "admin"}) == 0:
                if not DEFAULT_ADMIN_EMAIL or len(DEFAULT_ADMIN_PASSWORD) < 12:
                    app.logger.error("No admin account exists: set DEFAULT_ADMIN_EMAIL and a 12+ character DEFAULT_ADMIN_PASSWORD")
                    return
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
    threading.Thread(target=_daily_cve_scheduler, daemon=True).start()

    app.run(host="0.0.0.0", port=SERVER_PUBLIC_PORT, debug=False)
