#!/usr/bin/env python3
"""
Heimdall Mini Agent — Windows Edition
Icône dans la zone de notification Windows, configuration in-app,
collecte automatique des logiciels installés, scan de ports.
"""
import sys
import os

# ─── Crash handler (avant TOUS les autres imports) ──────────────────────────────
def _excepthook(etype, evalue, etb):
    import traceback
    _log = os.path.join(os.environ.get('USERPROFILE', os.path.expanduser('~')),
                        'Desktop', 'heimdall-crash.log')
    try:
        with open(_log, 'w', encoding='utf-8') as _f:
            _f.write("Heimdall Agent \u2014 rapport d'erreur\n" + '=' * 50 + '\n\n')
            traceback.print_exception(etype, evalue, etb, file=_f)
    except Exception:
        pass
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0,
            f"Heimdall Agent a rencontr\u00e9 une erreur au d\u00e9marrage.\n\n"
            f"Un fichier de log a \u00e9t\u00e9 cr\u00e9\u00e9 sur votre Bureau :\n{_log}\n\n"
            f"Erreur : {evalue}",
            "Heimdall Agent \u2014 Erreur",
            0x10  # MB_ICONERROR
        )
    except Exception:
        pass

sys.excepthook = _excepthook
# ───────────────────────────────────────────────────────────────────────────────

import threading
import time
import configparser
import platform
import re
import socket
import subprocess
import logging
import argparse
import webbrowser

def _windows_release() -> str:
    """Return '11' on Windows 11+, fallback to platform.release() otherwise."""
    m = re.search(r'\d+\.\d+\.(\d+)', platform.version())
    if m and int(m.group(1)) >= 22000:
        return "11"
    return platform.release()
from datetime import datetime

AGENT_VERSION = "1.0.0"  # mis à jour à chaque build

# ─── Dépendances tierces ──────────────────────────────────────────────────────
def _msgbox(title, msg, icon=0x40):
    """MessageBox natif Windows via ctypes — fonctionne même sans tkinter."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, str(msg), str(title), icon)
    except Exception:
        pass

try:
    import requests
except ImportError:
    _msgbox("Heimdall — Dépendance manquante",
            "Module 'requests' introuvable.\nRelancez avec : pip install requests pystray pillow",
            0x10)
    sys.exit(1)

try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_OK = True
except ImportError:
    TRAY_OK = False

try:
    import tkinter as tk
    from tkinter import messagebox as _tk_msgbox
    TKINTER_OK = True
except Exception:
    TKINTER_OK = False
    tk = None
    _tk_msgbox = None


def _dlg_error(title, msg, parent=None):
    if TKINTER_OK and parent:
        _tk_msgbox.showerror(title, msg, parent=parent)
    else:
        _msgbox(title, msg, 0x10)


def _dlg_info(title, msg, parent=None):
    if TKINTER_OK and parent:
        _tk_msgbox.showinfo(title, msg, parent=parent)
    else:
        _msgbox(title, msg, 0x40)

# ─── Logging ──────────────────────────────────────────────────────────────────
_LOG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "HeimdallAgent")
os.makedirs(_LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(_LOG_DIR, "agent.log"), encoding="utf-8")
    ]
)
logger = logging.getLogger("HeimdallAgent")

# ─── Chemins de config ────────────────────────────────────────────────────────
_EXE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
CONFIG_PATHS = [
    os.path.join(_EXE_DIR, "agent.conf"),
    os.path.join(_LOG_DIR, "agent.conf"),
    r"C:\ProgramData\HeimdallAgent\agent.conf",
]

DEFAULT_CONFIG = {
    "main_server": {"host": "127.0.0.1", "port": "4000", "token": "changeme-secret-token"},
    "api":         {"cve_api_key": ""},
    "agent":       {"interval_minutes": "60", "port_scan": "false"},
}


# ─── État global ──────────────────────────────────────────────────────────────
class _State:
    def __init__(self):
        self.lock         = threading.Lock()
        self.scan_event   = threading.Event()
        self.running      = True
        self.connected    = False
        self.vuln_count   = 0
        self.last_status  = "Démarrage…"
        self.next_scan_in = 0
        self.tray_icon    = None
        self.tk_root      = None
        self.config       = None

state = _State()

# ─── Config ───────────────────────────────────────────────────────────────────
def _config_path_existing():
    for p in CONFIG_PATHS:
        if os.path.exists(p):
            return p
    return None

def config_exists() -> bool:
    return _config_path_existing() is not None

def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    loaded = cfg.read(CONFIG_PATHS)
    if not loaded:
        cfg.read_dict(DEFAULT_CONFIG)
    state.config = cfg
    return cfg

def save_config(host: str, port: str, token: str, interval: str, port_scan: bool, cve_api_key: str = ""):
    path = os.path.join(_LOG_DIR, "agent.conf")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    cfg = configparser.ConfigParser()
    cfg["main_server"] = {"host": host.strip(), "port": port.strip(), "token": token.strip()}
    cfg["api"]         = {"cve_api_key": cve_api_key.strip()}
    cfg["agent"]       = {"interval_minutes": interval.strip(), "port_scan": "true" if port_scan else "false"}
    with open(path, "w", encoding="utf-8") as f:
        cfg.write(f)
    state.config = cfg
    logger.info(f"Configuration sauvegardée → {path}")

# ─── Collecte Windows ─────────────────────────────────────────────────────────
def _normalize_product_name(name: str) -> str:
    """Clean up Windows registry display names to improve CVE matching.

    Examples:
      "7-Zip 24.08 (x64)"                                         -> "7-Zip"
      "Python 3.11.2 (64-bit)"                                    -> "Python"
      "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14" -> "Microsoft Visual C++"
      "Mozilla Firefox (x86 en-US)"                               -> "Mozilla Firefox"
      "Git version 2.44.0"                                        -> "Git"
      "Docker Desktop"                                            -> "Docker Desktop"   (unchanged)
    """
    # Remove trailing " - <number>..." pattern (e.g. "- 14.38.33130")
    name = re.sub(r'\s+-\s+\d[\d.]*\s*$', '', name).strip()
    # Remove trailing parenthetical groups: (x64), (64-bit), (x86 en-US), (32-bit x86), etc.
    # May need multiple passes for "Foo (bar) (baz)"
    for _ in range(3):
        new = re.sub(r'\s*\([^)]*\)\s*$', '', name).strip()
        if new == name:
            break
        name = new
    # Remove trailing version numbers and "version" keyword: " 24.08", " v3.11.2", " version 2.44.0"
    name = re.sub(r'\s+v?(?:version\s+)?\d[\d.\-_+]*\s*$', '', name, flags=re.IGNORECASE).strip()
    # Remove trailing redistribution/edition keywords after version strip
    name = re.sub(r'\s+Redistributable\s*$', '', name, flags=re.IGNORECASE).strip()
    # Remove trailing year ranges like " 2015-2022" when not the whole name
    if len(re.sub(r'\s+\d{4}[-–]\d{4}\s*$', '', name)) > 3:
        name = re.sub(r'\s+\d{4}[-–]\d{4}\s*$', '', name).strip()
    return name

def _registry_software():
    packages = []
    try:
        import winreg
        for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for sub in (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ):
                try:
                    key = winreg.OpenKey(root, sub)
                    i = 0
                    while True:
                        try:
                            sk = winreg.OpenKey(key, winreg.EnumKey(key, i))
                            try:
                                name = winreg.QueryValueEx(sk, "DisplayName")[0]
                                ver  = winreg.QueryValueEx(sk, "DisplayVersion")[0]
                                pub  = ""
                                try:
                                    pub = winreg.QueryValueEx(sk, "Publisher")[0]
                                except Exception:
                                    pass
                                if name and ver:
                                    clean = _normalize_product_name(name)
                                    packages.append({
                                        "vendor":          pub or name,
                                        "product":         clean,
                                        "product_raw":     name,   # nom complet original
                                        "version":         ver,
                                    })
                            except (FileNotFoundError, OSError):
                                pass
                            i += 1
                        except OSError:
                            break
                except Exception:
                    pass
    except ImportError:
        pass
    return packages

def _pip_packages():
    packages = []
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=columns"],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 2:
                packages.append({"vendor": "python", "product": parts[0].lower(), "version": parts[1]})
    except Exception:
        pass
    return packages

def collect_software():
    return _registry_software() + _pip_packages()

# ─── Scan de ports ────────────────────────────────────────────────────────────
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521,
                3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

def scan_ports(host="127.0.0.1") -> list:
    open_ports = []
    for port in COMMON_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports

# ─── Collecte des adresses IP locales ────────────────────────────────────────
def _get_local_ips() -> list:
    """Retourne toutes les IPv4 routables de la machine. Combine plusieurs
    méthodes pour rester fiable même sans accès Internet, sur les machines
    derrière un proxy, ou avec une configuration réseau inhabituelle."""
    ips: set = set()

    # 1) psutil — le plus complet si dispo (énumère toutes les interfaces)
    try:
        import psutil  # type: ignore
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if getattr(a, "family", None) == socket.AF_INET:
                    ip = a.address
                    if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                        ips.add(ip)
    except ImportError:
        pass
    except Exception:
        pass

    # 2) gethostname() + getaddrinfo
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ':' not in ip and not ip.startswith('127.'):
                ips.add(ip)
    except Exception:
        pass

    # 3) UDP-trick — pas besoin que l'IP soit joignable, l'OS choisit l'iface
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    # 4) Fallback `ipconfig` parse — dernière chance si rien n'a marché
    if not ips:
        try:
            r = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5,
                encoding="utf-8", errors="ignore"
            )
            for m in re.finditer(r'(?:IPv4|IP Address).*?:\s*(\d+\.\d+\.\d+\.\d+)', r.stdout):
                ip = m.group(1)
                if not ip.startswith("127.") and ip != "0.0.0.0":
                    ips.add(ip)
        except Exception:
            pass

    return sorted(ips)

# ─── Collecte de la conformité Windows ───────────────────────────────────────
def _collect_compliance() -> dict:
    """Lit les clés de registre et les paramètres Windows pour évaluer la conformité."""
    data = {}
    try:
        import winreg

        # ── Longueur minimale du mot de passe ────────────────────────────────
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters")
            data["password_min_length"] = int(winreg.QueryValueEx(key, "MinimumPasswordLength")[0])
        except FileNotFoundError:
            pass
        except Exception:
            pass
        if "password_min_length" not in data:
            try:
                r = subprocess.run(["net", "accounts"], capture_output=True, text=True, timeout=5)
                m = re.search(r"Minimum password length\s+(\d+)", r.stdout, re.IGNORECASE)
                if m:
                    data["password_min_length"] = int(m.group(1))
            except Exception:
                pass

        # ── Protocoles TLS activés ───────────────────────────────────────────
        tls_enabled = []
        for proto, ver in [("TLS 1.0", "1.0"), ("TLS 1.1", "1.1"),
                            ("TLS 1.2", "1.2"), ("TLS 1.3", "1.3")]:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    fr"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{proto}\Client")
                enabled = winreg.QueryValueEx(key, "Enabled")[0]
                disabled_default = 0
                try:
                    disabled_default = winreg.QueryValueEx(key, "DisabledByDefault")[0]
                except Exception:
                    pass
                if enabled and not disabled_default:
                    tls_enabled.append(ver)
            except FileNotFoundError:
                # Key absent → TLS 1.2 / 1.3 enabled by default on Win10+
                if ver in ("1.2", "1.3"):
                    tls_enabled.append(ver)
            except Exception:
                pass
        if tls_enabled:
            data["tls_min_version"] = min(tls_enabled,
                                          key=lambda v: tuple(int(x) for x in v.split(".")))

        # ── Pare-feu Windows ─────────────────────────────────────────────────
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile")
            data["firewall_enabled"] = bool(winreg.QueryValueEx(key, "EnableFirewall")[0])
        except Exception:
            pass

        # ── SMBv1 ────────────────────────────────────────────────────────────
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
            val = winreg.QueryValueEx(key, "SMB1")[0]
            data["smb1_disabled"] = (val == 0)
        except FileNotFoundError:
            data["smb1_disabled"] = True   # absent = désactivé par défaut Win10+
        except Exception:
            pass

        # ── RDP NLA ──────────────────────────────────────────────────────────
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")
            data["rdp_nla_enabled"] = bool(winreg.QueryValueEx(key, "UserAuthentication")[0])
        except Exception:
            pass

        # ── Windows Defender protection temps réel ───────────────────────────
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection")
            disabled = winreg.QueryValueEx(key, "DisableRealtimeMonitoring")[0]
            data["defender_realtime"] = (disabled == 0)
        except FileNotFoundError:
            data["defender_realtime"] = True   # absent = activé par défaut
        except Exception:
            pass

        # ── Mises à jour automatiques ────────────────────────────────────────
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")
            no_auto = winreg.QueryValueEx(key, "NoAutoUpdate")[0]
            data["auto_updates_enabled"] = (no_auto == 0)
        except FileNotFoundError:
            data["auto_updates_enabled"] = True   # absent = activé par défaut
        except Exception:
            pass

        # ── Timeout verrouillage écran ───────────────────────────────────────
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop")
            val = winreg.QueryValueEx(key, "ScreenSaveTimeOut")[0]
            data["screen_lock_timeout"] = int(val)
        except Exception:
            pass

        # ── UAC (EnableLUA) ──────────────────────────────────────────────────
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            data["uac_enabled"] = bool(winreg.QueryValueEx(key, "EnableLUA")[0])
        except Exception:
            pass

        # ── Compte Invité ────────────────────────────────────────────────────
        try:
            r = subprocess.run(["net", "user", "Guest"],
                               capture_output=True, text=True, timeout=5)
            m = re.search(r"Account active\s+(Yes|No)", r.stdout, re.IGNORECASE)
            if m:
                data["guest_account_disabled"] = (m.group(1).lower() == "no")
        except Exception:
            pass

        # ── Politique de verrouillage de compte ─────────────────────────────
        try:
            r = subprocess.run(["net", "accounts"],
                               capture_output=True, text=True, timeout=5)
            m = re.search(r"Lockout threshold\s+(\d+|Never)", r.stdout, re.IGNORECASE)
            if m and m.group(1).lower() != "never":
                data["account_lockout_threshold"] = int(m.group(1))
            m = re.search(r"Lockout duration \(minutes\)\s+(\d+)", r.stdout, re.IGNORECASE)
            if m:
                data["account_lockout_duration"] = int(m.group(1))
        except Exception:
            pass

    except ImportError:
        logger.warning("winreg non disponible — conformité non collectée")
    except Exception as e:
        logger.warning(f"Erreur collecte conformité : {e}")

    # ── Règles personnalisées définies dans le dashboard (collector générique) ──
    try:
        custom = _collect_custom_rules()
        for k, v in custom.items():
            # Les built-in ont priorité — on n'écrase pas
            data.setdefault(k, v)
    except Exception as e:
        logger.warning(f"Collecte des règles personnalisées échouée : {e}")
    return data


# ─── Collecteur générique pilotté par le dashboard ────────────────────────────
_HIVE_MAP = {
    "HKLM": "HKEY_LOCAL_MACHINE",  "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",   "HKEY_CURRENT_USER":  "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",   "HKEY_CLASSES_ROOT":  "HKEY_CLASSES_ROOT",
    "HKU":  "HKEY_USERS",          "HKEY_USERS":         "HKEY_USERS",
}

def _read_registry(path: str):
    """Lit une valeur de registre. `path` au format HKLM\\Sub\\Path\\ValueName.
    Le dernier segment est interprété comme nom de valeur. Retourne la valeur
    brute (int pour DWORD/QWORD, str pour SZ, str(repr) sinon) ou None si absente."""
    import winreg
    raw = path.replace("/", "\\").strip("\\")
    parts = [p for p in raw.split("\\") if p]
    if len(parts) < 2:
        return None
    hive = _HIVE_MAP.get(parts[0].upper())
    if not hive:
        return None
    value_name = parts[-1]
    subkey = "\\".join(parts[1:-1])
    try:
        with winreg.OpenKey(getattr(winreg, hive), subkey,
                            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            val, typ = winreg.QueryValueEx(k, value_name)
            if typ in (winreg.REG_DWORD, winreg.REG_QWORD):
                return int(val)
            if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                return str(val)
            if typ == winreg.REG_MULTI_SZ:
                return ",".join(val) if isinstance(val, (list, tuple)) else str(val)
            return str(val)
    except FileNotFoundError:
        return None
    except OSError:
        return None


def _collect_custom_rules() -> dict:
    """Récupère la liste des règles personnalisées sur le serveur et exécute
    leur collecteur. Retourne {rule_id: valeur_collectée}."""
    if not state.config:
        return {}
    cfg   = state.config
    host  = cfg.get("main_server", "host",  fallback="127.0.0.1")
    port  = cfg.get("main_server", "port",  fallback="4000")
    token = cfg.get("main_server", "token", fallback="")
    try:
        r = requests.get(
            f"http://{host}:{port}/api/compliance/agent-rules",
            params={"os": "windows"},
            headers={"x-agent-token": token},
            timeout=10,
        )
        if r.status_code != 200:
            return {}
        rules = r.json() or []
    except Exception as e:
        logger.debug(f"agent-rules indisponibles : {e}")
        return {}

    out = {}
    for rule in rules:
        rid = rule.get("id");                       coll = rule.get("collector") or {}
        ctype = (coll.get("type") or "").lower()
        if not rid or not ctype:
            continue
        try:
            if ctype == "registry":
                val = _read_registry(coll.get("path", ""))
                if val is not None:
                    out[rid] = val
            # Les autres types (sysctl, file_grep, systemd_active) ne s'appliquent
            # pas à Windows. On les ignore silencieusement.
        except Exception as e:
            logger.debug(f"Collecteur '{rid}' échoué : {e}")
    return out

# ─── Envoi du rapport ────────────────────────────────────────────────────────
def send_report(max_attempts: int = 6):
    """Envoie le rapport avec retry exponentiel. Si le serveur est indisponible,
    on retente jusqu'à 6 fois (5s, 10s, 20s, 40s, 80s, 160s) puis on rend la main
    au cycle principal — qui retentera au prochain intervalle. L'agent finit
    toujours par récupérer dès que le serveur revient (icône tray repasse au
    vert sans intervention)."""
    if not state.config:
        load_config()
    cfg      = state.config
    host     = cfg.get("main_server", "host",       fallback="127.0.0.1")
    port     = cfg.get("main_server", "port",       fallback="4000")
    token    = cfg.get("main_server", "token",      fallback="changeme-secret-token")
    cve_key  = cfg.get("api",         "cve_api_key", fallback="")
    do_ports = cfg.getboolean("agent", "port_scan",  fallback=False)
    url      = f"http://{host}:{port}/api/agents/report"

    _set_status("Collecte en cours…")

    software   = collect_software()
    open_ports = scan_ports() if do_ports else []
    compliance = _collect_compliance()
    ip_addresses = _get_local_ips()

    payload = {
        "hostname":      platform.node(),
        "os":            platform.system(),
        "release":       _windows_release(),
        "os_build":      platform.version(),
        "agent_version": AGENT_VERSION,
        "timestamp":     datetime.now().isoformat(),
        "software":      software,
        "open_ports":    open_ports,
        "cve_api_key":   cve_key,
        "compliance":    compliance,
        "ip_addresses":  ip_addresses,
    }

    delay = 5
    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.post(url, json=payload, headers={"x-agent-token": token}, timeout=30)
            resp.raise_for_status()
            data  = resp.json()
            vulns = data.get("vulnerable_count", 0)
            with state.lock:
                state.connected  = True
                state.vuln_count = vulns
            msg = f"⚠️ {vulns} vulnérabilité(s)" if vulns else "✅ Aucune vulnérabilité"
            _set_status(msg, connected=True, vulns=vulns > 0)
            logger.info(f"Rapport envoyé — {msg}")
            return data
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            _set_status(f"❌ Serveur injoignable — retry {delay}s (essai {attempt}/{max_attempts})", connected=False)
            logger.warning(f"Connexion serveur échouée: {type(e).__name__}")
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code
            if 500 <= code < 600:
                _set_status(f"❌ Erreur serveur HTTP {code} — retry {delay}s", connected=False)
                logger.warning(f"HTTP {code} — retry")
            else:
                _set_status(f"❌ HTTP {code} — vérifier la config", connected=False)
                logger.error(f"HTTP {code}: {e.response.text[:200]}")
                return None  # 4xx → on abandonne (token invalide, etc.)
        except Exception as e:
            _set_status(f"❌ Erreur: {str(e)[:50]}", connected=False)
            logger.error(f"Erreur inattendue: {e}")
        if attempt < max_attempts and state.running:
            time.sleep(delay)
            delay = min(delay * 2, 300)
        elif not state.running:
            return None
    return None

def _set_status(msg: str, connected=None, vulns: bool = False):
    with state.lock:
        state.last_status = msg
        if connected is not None:
            state.connected = connected
    if state.tray_icon and TRAY_OK:
        try:
            state.tray_icon.icon  = _make_icon(state.connected, vulns)
            state.tray_icon.title = f"Heimdall — {msg}"
        except Exception:
            pass

# ─── Boucle agent ────────────────────────────────────────────────────────────
def agent_loop():
    while state.running:
        send_report()
        cfg      = state.config or configparser.ConfigParser()
        interval = int(cfg.get("agent", "interval_minutes", fallback=60)) * 60
        for i in range(interval, 0, -1):
            if not state.running or state.scan_event.is_set():
                break
            with state.lock:
                state.next_scan_in = i
            time.sleep(1)
        state.scan_event.clear()

# ─── Heartbeat ────────────────────────────────────────────────────────────────
HEARTBEAT_INTERVAL = 60  # secondes

def send_heartbeat():
    """Envoie un ping léger au serveur pour signaler que l'agent est actif."""
    if not state.config:
        return
    cfg   = state.config
    host  = cfg.get("main_server", "host",  fallback="127.0.0.1")
    port  = cfg.get("main_server", "port",  fallback="4000")
    token = cfg.get("main_server", "token", fallback="changeme-secret-token")
    try:
        requests.post(
            f"http://{host}:{port}/api/agents/{platform.node()}/heartbeat",
            json={"os": platform.system(), "release": _windows_release(),
                   "os_build": platform.version()},
            headers={"x-agent-token": token},
            timeout=5
        )
    except Exception:
        pass

def heartbeat_loop():
    """Boucle de heartbeat — s'exécute en parallèle de l'agent loop."""
    time.sleep(5)  # courte attente initiale pour laisser la config se charger
    while state.running:
        send_heartbeat()
        for _ in range(HEARTBEAT_INTERVAL):
            if not state.running:
                break
            time.sleep(1)

# ─── Auto-update ──────────────────────────────────────────────────────────────────────────────
def _version_newer(server: str, current: str) -> bool:
    """True si la version du serveur est strictement plus récente que current."""
    def _t(v):
        return tuple(int(x) for x in re.split(r'[.\-]', v) if x.isdigit())
    try:
        return _t(server) > _t(current)
    except Exception:
        return server.strip() != current.strip()


def check_for_update(silent: bool = False) -> bool:
    """Vérifie si une nouvelle version est disponible sur le serveur.
    - silent=True : aucune popup si déjà à jour.
    - Retourne True si une mise à jour a été déclenchée.
    """
    if not state.config:
        return False
    cfg   = state.config
    host  = cfg.get("main_server", "host",  fallback="127.0.0.1")
    port  = cfg.get("main_server", "port",  fallback="4000")
    token = cfg.get("main_server", "token", fallback="changeme-secret-token")
    try:
        r = requests.get(
            f"http://{host}:{port}/api/agent/version",
            headers={"x-agent-token": token},
            timeout=10,
        )
        if r.status_code != 200:
            if not silent:
                _dlg_info("Heimdall — Mise à jour",
                          f"Vérification impossible (HTTP {r.status_code}).")
            return False
        data           = r.json()
        server_version = data.get("version", "")
        if not server_version:
            return False
        if _version_newer(server_version, AGENT_VERSION):
            logger.info(f"Mise à jour disponible: {AGENT_VERSION} → {server_version}")
            _set_status(f"⬆️  Mise à jour v{server_version} disponible…")
            def _ask_and_update():
                msg = (
                    f"Une nouvelle version est disponible !\n\n"
                    f"Version actuelle : {AGENT_VERSION}\n"
                    f"Nouvelle version : {server_version}\n\n"
                    f"Mettre à jour maintenant ?\n"
                    f"L'agent redémarrera automatiquement."
                )
                if TKINTER_OK and state.tk_root:
                    def _gui_ask():
                        if _tk_msgbox.askyesno("Heimdall — Mise à jour", msg, parent=state.tk_root):
                            threading.Thread(
                                target=lambda: _do_self_update(host, port, token, data.get("download_url", "")),
                                daemon=True, name="SelfUpdate"
                            ).start()
                    state.tk_root.after(0, _gui_ask)
                else:
                    _do_self_update(host, port, token, data.get("download_url", ""))
            _ask_and_update()
            return True
        else:
            if not silent:
                _dlg_info("Heimdall — Mise à jour",
                          f"L'agent est à jour (v{AGENT_VERSION}).")
            logger.info(f"Agent à jour (v{AGENT_VERSION})")
    except Exception as e:
        if not silent:
            _dlg_error("Heimdall — Mise à jour", f"Vérification impossible :\n{e}")
        logger.warning(f"Vérification mise à jour échouée: {e}")
    return False


def _do_self_update(host: str, port: str, token: str, url: str):
    """Télécharge le nouvel exe, écrit un .bat de remplacement et quitte."""
    if not getattr(sys, "frozen", False):
        logger.warning("Auto-update: non disponible en mode source Python.")
        _dlg_info("Mise à jour",
                  "Mise à jour automatique disponible uniquement pour le .exe compilé.\n"
                  "Téléchargez la nouvelle version manuellement.")
        return
    curr_exe     = os.path.abspath(sys.executable)
    new_exe      = curr_exe + ".update"
    bat_path     = curr_exe + ".upd.bat"
    download_url = url or f"http://{host}:{port}/api/download/agent/windows/exe"
    try:
        _set_status("⬇️  Téléchargement de la mise à jour…")
        resp = requests.get(
            download_url,
            headers={"x-agent-token": token},
            timeout=120,
            stream=True,
        )
        resp.raise_for_status()
        with open(new_exe, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
        # Vérification basique : les exécutables Windows commencent par MZ
        with open(new_exe, "rb") as f:
            magic = f.read(2)
        if magic != b"MZ":
            raise ValueError("Le fichier téléchargé n'est pas un exécutable Windows valide")
        bat = (
            "@echo off\r\n"
            "ping -n 3 127.0.0.1 >nul\r\n"
            f'move /Y "{new_exe}" "{curr_exe}"\r\n'
            f'start "" "{curr_exe}"\r\n'
            "del \"%~f0\"\r\n"
        )
        with open(bat_path, "w") as f:
            f.write(bat)
        logger.info("Mise à jour téléchargée — remplacement en cours…")
        subprocess.Popen(
            ["cmd.exe", "/C", bat_path],
            creationflags=subprocess.CREATE_NO_WINDOW,
            close_fds=True,
        )
        _on_quit()
    except Exception as e:
        logger.error(f"Mise à jour échouée: {e}")
        _dlg_error("Erreur de mise à jour", f"Téléchargement échoué :\n{e}")
        try:
            os.remove(new_exe)
        except Exception:
            pass


def update_loop():
    """Vérifie la mise à jour au démarrage (après 30 s) puis toutes les 24 h."""
    for _ in range(30):
        if not state.running:
            return
        time.sleep(1)
    while state.running:
        check_for_update(silent=True)
        for _ in range(86400):  # 24 h
            if not state.running:
                return
            time.sleep(1)


def _on_check_update(_icon=None, _item=None):
    """Action tray : vérifier la mise à jour manuellement."""
    threading.Thread(
        target=lambda: check_for_update(silent=False),
        daemon=True, name="UpdateCheck"
    ).start()


# ─── Démarrage automatique Windows (clé Run registre) ────────────────────────────────────
_AUTOSTART_REG_KEY  = r"Software\Microsoft\Windows\CurrentVersion\Run"
_AUTOSTART_REG_NAME = "HeimdallSecurityAgent"


def _is_autostart_enabled() -> bool:
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _AUTOSTART_REG_KEY, 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, _AUTOSTART_REG_NAME)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def _set_autostart(enable: bool):
    """Active ou désactive le lancement au démarrage via la clé Run du registre HKCU."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _AUTOSTART_REG_KEY, 0, winreg.KEY_SET_VALUE
        )
        if enable:
            exe = os.path.abspath(
                sys.executable if getattr(sys, "frozen", False) else __file__
            )
            winreg.SetValueEx(key, _AUTOSTART_REG_NAME, 0, winreg.REG_SZ, f'"{exe}"')
            logger.info("Démarrage automatique activé.")
        else:
            try:
                winreg.DeleteValue(key, _AUTOSTART_REG_NAME)
            except FileNotFoundError:
                pass
            logger.info("Démarrage automatique désactivé.")
        winreg.CloseKey(key)
    except Exception as e:
        logger.warning(f"Démarrage automatique: {e}")


def _on_toggle_autostart(_icon=None, _item=None):
    """Bascule le démarrage automatique avec Windows."""
    new_val = not _is_autostart_enabled()
    _set_autostart(new_val)
    msg = "activé" if new_val else "désactivé"
    _dlg_info(
        "Heimdall — Démarrage auto",
        f"Démarrage automatique {msg}.\n"
        f"L'agent {'démarrera' if new_val else 'ne démarrera plus'} automatiquement avec Windows."
    )


# ─── Icône tray ───────────────────────────────────────────────────────────────
def _make_icon(connected: bool = False, has_vulns: bool = False) -> "Image.Image":
    sz = 64
    img = Image.new("RGBA", (sz, sz), (0, 0, 0, 0))
    d   = ImageDraw.Draw(img)

    # Bouclier
    shield_col = (20, 90, 200) if connected else (80, 80, 80)
    pts = [(sz // 2, 3), (sz - 5, sz // 5), (sz - 5, sz // 2),
           (sz // 2, sz - 3), (5, sz // 2), (5, sz // 5)]
    d.polygon(pts, fill=shield_col, outline=(180, 200, 255, 140))

    # H (Heimdall)
    for x1, y1, x2, y2 in [(18, 18, 18, 46), (46, 18, 46, 46), (18, 32, 46, 32)]:
        d.line([(x1, y1), (x2, y2)], fill="white", width=5)

    # Badge statut (bas droite)
    badge = (240, 160, 0) if has_vulns else ((0, 200, 60) if connected else (200, 60, 60))
    d.ellipse([44, 44, 62, 62], fill=badge, outline="white")
    return img


def _fmt_time(s: int) -> str:
    if s > 3600:
        return f"{s // 3600}h {(s % 3600) // 60}min"
    if s > 60:
        return f"{s // 60}min {s % 60}s"
    return f"{s}s"

# ─── Menu tray ────────────────────────────────────────────────────────────────
def _on_scan_now(_icon=None, _item=None):
    state.scan_event.set()

def _on_open_dashboard(_icon=None, _item=None):
    cfg  = state.config or configparser.ConfigParser()
    host = cfg.get("main_server", "host", fallback="127.0.0.1")
    port = cfg.get("main_server", "port", fallback="4000")
    webbrowser.open(f"http://{host}:{port}")

def _on_configure(_icon=None, _item=None):
    if not TKINTER_OK:
        cfg  = state.config or configparser.ConfigParser()
        path = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "HeimdallAgent", "agent.conf")
        try:
            subprocess.Popen(["notepad.exe", path])
        except Exception:
            _msgbox("Heimdall — Configuration",
                    f"Éditez le fichier de configuration :\n{path}", 0x40)
        return
    if state.tk_root:
        state.tk_root.after(0, _open_config_dialog)

def _on_quit(_icon=None, _item=None):
    state.running = False
    if state.tray_icon:
        state.tray_icon.stop()
    if state.tk_root:
        state.tk_root.after(100, state.tk_root.destroy)

# ─── Désinstallation ──────────────────────────────────────────────────────────
def _do_uninstall():
    """Désinstalle complètement l'agent Windows : retire l'autostart, supprime
    la config, et — si on est en mode .exe compilé — programme un .bat qui
    attendra notre sortie puis supprimera l'exécutable lui-même."""
    logger.info("Désinstallation demandée…")

    # 1. Retirer l'autostart (clé Run du registre)
    try:
        _set_autostart(False)
    except Exception as e:
        logger.warning(f"_set_autostart(False) a échoué: {e}")

    # 2. Supprimer la configuration utilisateur
    cfg_dir = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "HeimdallAgent")
    cfg_dir_appdata = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "HeimdallAgent")
    for d in (cfg_dir, cfg_dir_appdata):
        if os.path.isdir(d):
            try:
                import shutil as _sh
                _sh.rmtree(d, ignore_errors=True)
                logger.info(f"Configuration supprimée : {d}")
            except Exception as e:
                logger.warning(f"Suppression de {d}: {e}")

    # 3. Si on tourne en .exe compilé, programmer un .bat qui supprime l'exe
    #    après notre sortie (un fichier ne peut pas se supprimer pendant qu'il s'exécute).
    if getattr(sys, "frozen", False):
        try:
            exe_path = os.path.abspath(sys.executable)
            bat_path = exe_path + ".uninstall.bat"
            bat = (
                "@echo off\r\n"
                "ping -n 3 127.0.0.1 >nul\r\n"
                f'del /F /Q "{exe_path}" 2>nul\r\n'
                f'del /F /Q "{exe_path}.upd.bat" 2>nul\r\n'
                "del \"%~f0\"\r\n"
            )
            with open(bat_path, "w") as f:
                f.write(bat)
            subprocess.Popen(
                ["cmd.exe", "/C", bat_path],
                creationflags=subprocess.CREATE_NO_WINDOW,
                close_fds=True,
            )
            logger.info(f"Suppression de l'exe programmée via {bat_path}")
        except Exception as e:
            logger.error(f"Programmation de la suppression de l'exe échouée: {e}")

    # 4. Arrêter le tray et quitter
    _on_quit()


def _on_uninstall(_icon=None, _item=None):
    """Demande confirmation puis désinstalle l'agent."""
    msg = (
        "Désinstaller l'agent Heimdall ?\n\n"
        "Cette action :\n"
        "  • arrête l'agent\n"
        "  • retire le démarrage automatique\n"
        "  • supprime la configuration locale\n"
        "  • supprime l'exécutable (mode .exe compilé)\n\n"
        "Continuer ?"
    )
    def _ask():
        if TKINTER_OK and state.tk_root:
            if _tk_msgbox.askyesno("Heimdall — Désinstallation", msg,
                                    icon="warning", parent=state.tk_root):
                threading.Thread(target=_do_uninstall, daemon=True,
                                 name="Uninstall").start()
        else:
            # Fallback : confirmation Windows native, sans Tkinter
            ans = _msgbox("Heimdall — Désinstallation", msg, 0x24)  # MB_YESNO | MB_ICONQUESTION
            if ans == 6:  # IDYES
                threading.Thread(target=_do_uninstall, daemon=True,
                                 name="Uninstall").start()
    if state.tk_root:
        state.tk_root.after(0, _ask)
    else:
        _ask()

# ─── Dialogue de configuration ────────────────────────────────────────────────
def _open_config_dialog():
    dlg = tk.Toplevel(state.tk_root)
    dlg.title("Heimdall — Configuration")
    dlg.geometry("460x370")
    dlg.resizable(False, False)
    dlg.configure(bg="#1e293b")
    dlg.grab_set()
    dlg.focus_force()
    dlg.lift()

    # Centrage
    dlg.update_idletasks()
    sw = dlg.winfo_screenwidth()
    sh = dlg.winfo_screenheight()
    dlg.geometry(f"+{(sw - 460) // 2}+{(sh - 370) // 2}")

    cfg = state.config or configparser.ConfigParser()

    tk.Label(dlg, text="[ H ]  Heimdall Security — Configuration Agent",
             bg="#0f172a", fg="#60a5fa", font=("Segoe UI", 11, "bold"), pady=10).pack(fill="x")

    frame = tk.Frame(dlg, bg="#1e293b", padx=25, pady=12)
    frame.pack(fill="both", expand=True)

    fields = [
        ("Adresse serveur",  "main_server", "host",             cfg.get("main_server", "host",             fallback="127.0.0.1")),
        ("Port",             "main_server", "port",             cfg.get("main_server", "port",             fallback="4000")),
        ("Token secret",     "main_server", "token",            cfg.get("main_server", "token",            fallback="changeme-secret-token")),
        ("Intervalle (min)", "agent",       "interval_minutes", cfg.get("agent",       "interval_minutes", fallback="60")),
        ("Clé API CVE",     "api",         "cve_api_key",       cfg.get("api",         "cve_api_key",       fallback="")),
    ]
    entries = {}

    for i, (label, sec, key, val) in enumerate(fields):
        tk.Label(frame, text=label, bg="#1e293b", fg="#94a3b8",
                 font=("Segoe UI", 9)).grid(row=i, column=0, sticky="w", pady=7)
        e = tk.Entry(frame, bg="#334155", fg="#e2e8f0", font=("Segoe UI", 10),
                     bd=0, relief="flat", insertbackground="white", width=30,
                     show="*" if key == "token" else "")
        e.insert(0, val)
        e.grid(row=i, column=1, padx=(12, 0), pady=7, sticky="ew")
        entries[(sec, key)] = e

    ps_var = tk.BooleanVar(value=cfg.getboolean("agent", "port_scan", fallback=False))
    tk.Checkbutton(frame, text="Activer le scan de ports réseau",
                   variable=ps_var, bg="#1e293b", fg="#94a3b8",
                   activebackground="#1e293b", selectcolor="#334155",
                   font=("Segoe UI", 9)).grid(row=len(fields), column=0, columnspan=2, sticky="w", pady=7)

    frame.columnconfigure(1, weight=1)

    def _save():
        h  = entries[("main_server", "host")].get().strip()
        p  = entries[("main_server", "port")].get().strip()
        t  = entries[("main_server", "token")].get().strip()
        iv = entries[("agent", "interval_minutes")].get().strip()
        ck = entries[("api", "cve_api_key")].get().strip()
        if not h or not p or not t:
            _dlg_error("Erreur", "Tous les champs sont obligatoires.", parent=dlg)
            return
        try:
            int(p)
        except ValueError:
            _dlg_error("Erreur", "Le port doit être un entier.", parent=dlg)
            return
        save_config(h, p, t, iv, ps_var.get(), ck)
        _dlg_info("Sauvegardd", "Configuration mise \u00e0 jour.\nElle sera utilis\u00e9e d\u00e8s le prochain scan.", parent=dlg)
        dlg.destroy()

    btn_bar = tk.Frame(dlg, bg="#1e293b", padx=25, pady=10)
    btn_bar.pack(fill="x", side="bottom")
    tk.Button(btn_bar, text="Sauvegarder", bg="#3b82f6", fg="white",
              font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=7,
              cursor="hand2", command=_save).pack(side="right", padx=(6, 0))
    tk.Button(btn_bar, text="Annuler", bg="#334155", fg="#e2e8f0",
              font=("Segoe UI", 10), relief="flat", padx=20, pady=7,
              cursor="hand2", command=dlg.destroy).pack(side="right")


# ─── Assistant premier lancement ─────────────────────────────────────────────
class SetupWizard(tk.Toplevel):
    """Wizard de configuration — Toplevel (jamais un second tk.Tk)."""
    def __init__(self, parent, default_host="", default_port="4000", default_token=""):
        super().__init__(parent)
        self.title("Heimdall Agent — Installation")
        self.geometry("480x500")
        self.resizable(False, False)
        self.configure(bg="#0f172a")
        self.result = False
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Centrage
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw - 480) // 2}+{(sh - 500) // 2}")

        tk.Label(self, text="[ H ]", font=("Segoe UI", 42, "bold"), bg="#0f172a", fg="#3b82f6").pack(pady=(22, 4))
        tk.Label(self, text="Heimdall Security Agent",
                 bg="#0f172a", fg="white", font=("Segoe UI", 16, "bold")).pack()
        tk.Label(self, text="Configurez la connexion au serveur Heimdall",
                 bg="#0f172a", fg="#94a3b8", font=("Segoe UI", 10)).pack(pady=(4, 16))

        card = tk.Frame(self, bg="#1e293b", padx=28, pady=22)
        card.pack(fill="both", expand=True, padx=22)

        rows = [
            ("Adresse du serveur", default_host or "127.0.0.1", False),
            ("Port",               default_port or "4000",       False),
            ("Token secret",       default_token or "",           True),
            ("Intervalle (min)",   "60",                          False),
            ("Clé API CVE",       "",                            False),
        ]
        self._entries = []
        for i, (lbl, val, secret) in enumerate(rows):
            tk.Label(card, text=lbl, bg="#1e293b", fg="#94a3b8",
                     font=("Segoe UI", 9)).grid(row=i, column=0, sticky="w", pady=9)
            e = tk.Entry(card, bg="#334155", fg="white", font=("Segoe UI", 11),
                         bd=0, relief="flat", insertbackground="white", width=28,
                         show="*" if secret else "")
            e.insert(0, val)
            e.grid(row=i, column=1, padx=(16, 0), sticky="ew", pady=9)
            self._entries.append(e)

        self._ps_var = tk.BooleanVar(value=False)
        tk.Checkbutton(card, text="Activer le scan de ports réseau",
                       variable=self._ps_var, bg="#1e293b", fg="#94a3b8",
                       activebackground="#1e293b", selectcolor="#334155",
                       font=("Segoe UI", 9)).grid(row=len(rows), column=0, columnspan=2, sticky="w", pady=9)
        self._autostart_var = tk.BooleanVar(value=True)
        tk.Checkbutton(card, text="Démarrer automatiquement avec Windows",
                       variable=self._autostart_var, bg="#1e293b", fg="#94a3b8",
                       activebackground="#1e293b", selectcolor="#334155",
                       font=("Segoe UI", 9)).grid(row=len(rows) + 1, column=0, columnspan=2, sticky="w", pady=4)
        card.columnconfigure(1, weight=1)

        self._status_lbl = tk.Label(self, text="", bg="#0f172a", fg="#94a3b8",
                                    font=("Segoe UI", 9))
        self._status_lbl.pack(pady=(8, 0))

        btn_frame = tk.Frame(self, bg="#0f172a")
        btn_frame.pack(pady=12)
        tk.Button(btn_frame, text="  Tester la connexion  ",
                  bg="#334155", fg="#e2e8f0", font=("Segoe UI", 10),
                  relief="flat", padx=0, pady=9, cursor="hand2",
                  command=self._test).pack(side="left", padx=(0, 8))
        tk.Button(btn_frame, text="  Installer et démarrer  ",
                  bg="#3b82f6", fg="white", font=("Segoe UI", 11, "bold"),
                  relief="flat", padx=0, pady=9, cursor="hand2",
                  command=self._install).pack(side="left")

    def _get_fields(self):
        return [e.get().strip() for e in self._entries]

    def _test(self):
        fields = self._get_fields()
        host, port, token = fields[0], fields[1], fields[2]
        self._status_lbl.config(text="Test en cours...", fg="#94a3b8")
        self.update()
        try:
            r = requests.get(
                f"http://{host}:{port}/api/ping",
                headers={"x-agent-token": token},
                timeout=5
            )
            if r.status_code == 200:
                self._status_lbl.config(text="Connexion OK — token valide", fg="#4ade80")
            elif r.status_code == 401:
                self._status_lbl.config(text="Token incorrect (401 Unauthorized)", fg="#f87171")
            else:
                self._status_lbl.config(text=f"Serveur repond {r.status_code}", fg="#fb923c")
        except requests.exceptions.ConnectionError:
            self._status_lbl.config(text=f"Serveur inaccessible ({host}:{port})", fg="#f87171")
        except Exception as e:
            self._status_lbl.config(text=f"Erreur : {str(e)[:50]}", fg="#f87171")

    def _install(self):
        host, port, token, interval, cve_key = self._get_fields()
        if not host or not port:
            _dlg_error("Erreur", "Adresse et port sont obligatoires.", parent=self)
            return
        try:
            int(port)
        except ValueError:
            _dlg_error("Erreur", "Le port doit être un entier.", parent=self)
            return
        save_config(host, port, token, interval, self._ps_var.get(), cve_key)
        _set_autostart(getattr(self, "_autostart_var", None) and self._autostart_var.get())
        self.result = True
        self.destroy()

    def _on_close(self):
        self.result = False
        self.destroy()


# ─── Installation tâche planifiée ─────────────────────────────────────────────
def install_scheduled_task():
    exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
    try:
        subprocess.run(
            ["schtasks", "/Create", "/F", "/TN", "HeimdallSecurityAgent",
             "/TR", f'"{exe}"', "/SC", "ONLOGON", "/RL", "HIGHEST", "/IT"],
            check=True, capture_output=True
        )
        logger.info("Tâche planifiée Windows créée.")
        return True
    except Exception as e:
        logger.warning(f"Tâche planifiée non créée: {e}")
        return False


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Heimdall Mini Agent (Windows)")
    parser.add_argument("--once",       action="store_true", help="Envoie unique puis exit")
    parser.add_argument("--scan-ports", action="store_true", help="Forcer scan réseau")
    parser.add_argument("--no-tray",    action="store_true", help="Mode console sans icône")
    parser.add_argument("--install",    action="store_true", help="Créer la tâche planifiée")
    parser.add_argument("--server",     default="",          help="IP du serveur Heimdall")
    parser.add_argument("--port",       default="4000",      help="Port du serveur Heimdall")
    parser.add_argument("--token",      default="",          help="Token secret")
    args = parser.parse_args()

    if args.install:
        install_scheduled_task()

    # Créer la racine tkinter UNE SEULE FOIS pour tout le processus
    if TKINTER_OK:
        root = tk.Tk()
        root.withdraw()
        root.title("HeimdallAgent")
        state.tk_root = root

    # Premier lancement (ou reconfiguration forcée avec --server)
    if not config_exists() or args.server:
        if not (args.once or args.no_tray):
            if TKINTER_OK:
                wizard = SetupWizard(
                    state.tk_root,
                    default_host=args.server,
                    default_port=args.port,
                    default_token=args.token,
                )
                state.tk_root.wait_window(wizard)
                if not wizard.result:
                    sys.exit(0)
            else:
                # Fallback sans tkinter : auto-config depuis les args CLI
                host  = args.server or "127.0.0.1"
                token = args.token  or "changeme-secret-token"
                save_config(host, args.port, token, "60", False)
                _msgbox(
                    "Heimdall Agent - Configuration",
                    f"Agent configure pour {host}:{args.port}\n\n"
                    f"Pour modifier les parametres, editez :\n"
                    f"%APPDATA%\\HeimdallAgent\\agent.conf",
                    0x40
                )

    load_config()

    if args.scan_ports:
        state.config.set("agent", "port_scan", "true")

    # ── Mode console / one-shot ──
    if args.once or args.no_tray or not TRAY_OK:
        send_report()
        if not args.once:
            agent_loop()
        return

    # ── Mode icône système ──
    threading.Thread(target=agent_loop,     daemon=True, name="AgentLoop").start()
    threading.Thread(target=heartbeat_loop, daemon=True, name="Heartbeat").start()
    threading.Thread(target=update_loop,    daemon=True, name="UpdateCheck").start()

    # state.tk_root est déjà créé en début de main()

    # Menu tray dynamique
    menu = pystray.Menu(
        pystray.MenuItem("Heimdall Security Agent", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(lambda _: state.last_status,                       None, enabled=False),
        pystray.MenuItem(lambda _: f"Prochain scan: {_fmt_time(state.next_scan_in)}", None, enabled=False),
        pystray.MenuItem(lambda _: f"v{AGENT_VERSION}",                     None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("🔍  Scanner maintenant",   _on_scan_now),
        pystray.MenuItem("⚙️   Configurer…",          _on_configure),
        pystray.MenuItem("📊  Ouvrir le dashboard",  _on_open_dashboard),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("⬆️  Vérifier les mises à jour", _on_check_update),
        pystray.MenuItem("🗑  Désinstaller…", _on_uninstall),
        pystray.MenuItem("Démarrer avec Windows", _on_toggle_autostart,
                         checked=lambda _: _is_autostart_enabled()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("❌  Quitter",              _on_quit),
    )

    icon = pystray.Icon(
        "HeimdallAgent",
        _make_icon(False),
        "Heimdall Security Agent",
        menu=menu,
    )
    state.tray_icon = icon

    # pystray dans un thread séparé, tkinter dans le thread principal (si dispo)
    threading.Thread(
        target=lambda: (icon.run_detached() or None),
        daemon=True, name="TrayIcon"
    ).start()

    if TKINTER_OK and state.tk_root:
        state.tk_root.mainloop()
    else:
        # Sans tkinter : boucle simple jusqu'au signal quitter
        while state.running:
            time.sleep(1)


if __name__ == "__main__":
    main()
