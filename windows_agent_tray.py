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
    if "--selftest" in sys.argv[1:]:
        # Vérification par l'agent qui se met à jour : pas de fenêtre, code de sortie ≠ 0
        traceback.print_exception(etype, evalue, etb)
        os._exit(3)
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
import re
import socket
import subprocess
import logging
import argparse
import webbrowser

# Aucune commande console (net, ipconfig, schtasks, `cmd /c ver` lancé par platform…)
# ne doit ouvrir de fenêtre visible : on force CREATE_NO_WINDOW pour tout le processus,
# y compris les appels faits par des bibliothèques. Sans effet sur les apps graphiques (notepad).
if sys.platform == "win32":
    _popen_init = subprocess.Popen.__init__

    def _popen_no_window(self, *args, **kwargs):
        if not kwargs.get("creationflags"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        _popen_init(self, *args, **kwargs)

    subprocess.Popen.__init__ = _popen_no_window

# Version/nom de la machine lus directement (sys/socket) : le module `platform`
# lance `cmd /c ver` en arrière-plan pour obtenir ces infos.
def _win_version() -> tuple:
    # Le registre donne le build réel (ex. 26200 en 25H2) ; sys.getwindowsversion()
    # peut renvoyer celui de kernel32.dll (26100), en retard sur les mises à jour d'activation.
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            return (int(winreg.QueryValueEx(k, "CurrentMajorVersionNumber")[0]),
                    int(winreg.QueryValueEx(k, "CurrentMinorVersionNumber")[0]),
                    int(winreg.QueryValueEx(k, "CurrentBuildNumber")[0]))
    except (OSError, ValueError):
        v = sys.getwindowsversion()
        return getattr(v, "platform_version", None) or (v.major, v.minor, v.build)

def _os_build() -> str:
    return "%d.%d.%d" % _win_version()[:3]

def _win_nt_value(name: str, default=""):
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default

def _is_windows_server() -> bool:
    # InstallationType : « Client », « Server » ou « Server Core ». ProductName en repli
    # (ancien Windows Server sans InstallationType).
    itype = str(_win_nt_value("InstallationType", ""))
    if itype:
        return itype.lower().startswith("server")
    return "server" in str(_win_nt_value("ProductName", "")).lower()

# Build NT → millésime Windows Server (ProductName en repli pour les builds inconnus)
_SERVER_BUILDS = {9200: "2012", 9600: "2012 R2", 14393: "2016", 17763: "2019",
                  20348: "2022", 25398: "2022, 23H2 Edition", 26100: "2025"}

def _server_year() -> str:
    build = _win_version()[2]
    if build in _SERVER_BUILDS:
        return _SERVER_BUILDS[build]
    m = re.search(r"Server\s+(\d{4}(?:\s+R2)?)", str(_win_nt_value("ProductName", "")), re.I)
    return m.group(1) if m else ""

def _windows_release() -> str:
    major, minor, build = _win_version()[:3]
    if _is_windows_server():
        year = _server_year()
        return f"Server {year}" if year else "Server"
    if major == 10 and build >= 22000:
        return "11"
    return {(6, 3): "8.1", (6, 2): "8", (6, 1): "7"}.get((major, minor), str(major))

def _os_software_entry():
    """Le système lui-même, inventorié comme un logiciel pour que ses CVE soient
    corrélées. Nom et version suivent le format des CVE Microsoft :
    produit « Windows Server 2022 » / « Windows 11 Version 24H2 »,
    version « 10.0.<build>.<UBR> » (UBR = niveau de mise à jour cumulative)."""
    major, minor, build = _win_version()[:3]
    try:
        ubr = int(_win_nt_value("UBR", 0))
    except (TypeError, ValueError):
        ubr = 0
    if _is_windows_server():
        year = _server_year()
        if not year:
            return None
        product = f"Windows Server {year}"
        if build == 25398:  # 23H2 n'existe qu'en Server Core
            product += " (Server Core installation)"
    else:
        name = "Windows 11" if major == 10 and build >= 22000 else f"Windows {_windows_release()}"
        dv = str(_win_nt_value("DisplayVersion", "") or _win_nt_value("ReleaseId", "")).strip()
        product = f"{name} Version {dv}" if dv else name
    return {"vendor": "Microsoft", "product": product, "product_raw": str(_win_nt_value("ProductName", product)),
            "version": f"{major}.{minor}.{build}.{ubr}", "kind": "os"}

def _hostname() -> str:
    return socket.gethostname()
from datetime import datetime

AGENT_VERSION = "1.0.1"  # remplacé à chaque build par la CI (voir VERSION et server/Dockerfile)

# ─── Dépendances tierces ──────────────────────────────────────────────────────
# Mode service : lancé par la tâche planifiée au démarrage de la machine, sous le compte
# SYSTEM, sans session ouverte (session 0). Aucune fenêtre ne doit s'y afficher : une
# boîte de dialogue y bloquerait l'agent indéfiniment, personne ne pouvant la fermer.
SERVICE_MODE = "--service" in sys.argv[1:]

def _msgbox(title, msg, icon=0x40):
    """MessageBox natif Windows via ctypes — fonctionne même sans tkinter."""
    if SERVICE_MODE:
        return 0
    try:
        import ctypes
        return ctypes.windll.user32.MessageBoxW(0, str(msg), str(title), icon)
    except Exception:
        return 0

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
_PROGRAMDATA_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "HeimdallAgent")
_LOG_DIR = (_PROGRAMDATA_DIR if SERVICE_MODE
            else os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "HeimdallAgent"))
os.makedirs(_LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(_LOG_DIR, "agent.log")

from logging.handlers import RotatingFileHandler
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=2, encoding="utf-8"),
    ]
)
logger = logging.getLogger("HeimdallAgent")

def read_log_tail(n: int = 200) -> list:
    """Dernières `n` lignes du log local — envoyées au serveur (debug centralisé)
    et affichées par le menu tray / `--logs`."""
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return [l.rstrip("\n") for l in lines[-n:]]
    except FileNotFoundError:
        return []

# ─── Chemins de config ────────────────────────────────────────────────────────
_EXE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
CONFIG_PATHS = [
    os.path.join(_EXE_DIR, "agent.conf"),
    os.path.join(_LOG_DIR, "agent.conf"),
    r"C:\ProgramData\HeimdallAgent\agent.conf",
]

DEFAULT_CONFIG = {
    "main_server": {"host": "127.0.0.1", "port": "4000", "token": "changeme-secret-token"},
    "agent":      {"interval_minutes": "60", "port_scan": "false"},
    "ui":          {"theme": "dark"},
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
    """Lit UN seul fichier : le premier trouvé dans CONFIG_PATHS (dossier de l'exe,
    puis %APPDATA%, puis ProgramData). Fusionner plusieurs fichiers laissait une
    vieille config écraser la nouvelle."""
    cfg = configparser.ConfigParser()
    path = _config_path_existing()
    if path:
        cfg.read(path, encoding="utf-8")
    else:
        cfg.read_dict(DEFAULT_CONFIG)
    state.config = cfg
    return cfg

def _cfg_bool(cfg, section: str, key: str, default: bool) -> bool:
    try:
        return cfg.getboolean(section, key, fallback=default)
    except ValueError:
        return default

def _base_url(cfg=None) -> str:
    """URL de base du serveur : http(s)://hôte:port selon `[main_server] use_https`."""
    cfg = cfg or state.config or configparser.ConfigParser()
    host   = cfg.get("main_server", "host", fallback="127.0.0.1")
    port   = cfg.get("main_server", "port", fallback="4000")
    scheme = "https" if _cfg_bool(cfg, "main_server", "use_https", False) else "http"
    return f"{scheme}://{host}:{port}"

def _tls_verify(cfg=None) -> bool:
    """Vérifier le certificat du serveur ? Sans effet en HTTP. `verify_ssl = false`
    accepte un certificat auto-signé/expiré (déconseillé hors réseau interne)."""
    cfg = cfg or state.config or configparser.ConfigParser()
    if not _cfg_bool(cfg, "main_server", "use_https", False):
        return True
    verify = _cfg_bool(cfg, "main_server", "verify_ssl", True)
    if not verify:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return verify

def _config_write_path() -> str:
    """Fichier à écrire : celui qui est réellement lu (s'il est modifiable), sinon %APPDATA%."""
    existing = _config_path_existing()
    if existing and os.access(existing, os.W_OK):
        return existing
    return os.path.join(_LOG_DIR, "agent.conf")

def save_config(host: str, port: str, token: str, interval: str, port_scan: bool,
                theme: str = None, use_https: bool = None, verify_ssl: bool = None,
                auto_update: bool = None):
    path = _config_write_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # HTTPS / vérification du certificat / auto-update : valeur fournie, sinon celle déjà en config.
    prev = state.config if state.config is not None else configparser.ConfigParser()
    if use_https is None:
        use_https = _cfg_bool(prev, "main_server", "use_https", False)
    if verify_ssl is None:
        verify_ssl = _cfg_bool(prev, "main_server", "verify_ssl", True)
    if auto_update is None:
        auto_update = _cfg_bool(prev, "agent", "auto_update", True)
    # Thème : valeur fournie, sinon celle déjà en config, sinon sombre.
    if theme is None:
        theme = (state.config.get("ui", "theme", fallback="dark")
                 if state.config is not None else "dark")
    cfg = configparser.ConfigParser()
    cfg["main_server"] = {"host": host.strip(), "port": port.strip(), "token": token.strip(),
                          "use_https": "true" if use_https else "false",
                          "verify_ssl": "true" if verify_ssl else "false"}
    cfg["agent"]       = {"interval_minutes": interval.strip(), "port_scan": "true" if port_scan else "false",
                          "auto_update": "true" if auto_update else "false"}
    if state.config is not None and state.config.has_option("agent", "update_check_hours"):
        cfg["agent"]["update_check_hours"] = state.config.get("agent", "update_check_hours")
    cfg["ui"]          = {"theme": theme}
    with open(path, "w", encoding="utf-8") as f:
        cfg.write(f)
    state.config = cfg
    logger.info(f"Configuration sauvegardée → {path}")

# ─── Thèmes & logo ────────────────────────────────────────────────────────────
THEMES = {
    "dark": dict(bg="#0f172a", card="#1e293b", input="#334155", fg="#e2e8f0",
                 muted="#94a3b8", accent="#3b82f6", accent_fg="white", title="#60a5fa",
                 ok="#4ade80", err="#f87171", warn="#fb923c",
                 btn_bg="#334155", btn_fg="#e2e8f0"),
    "light": dict(bg="#f1f5f9", card="#ffffff", input="#e2e8f0", fg="#0f172a",
                  muted="#475569", accent="#2563eb", accent_fg="white", title="#1d4ed8",
                  ok="#16a34a", err="#dc2626", warn="#ea580c",
                  btn_bg="#e2e8f0", btn_fg="#0f172a"),
}
THEME_LABELS = {"dark": "Sombre", "light": "Clair", "auto": "Système (auto)"}

def _system_prefers_light() -> bool:
    """True si Windows est réglé sur le mode d'application clair."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 1
    except Exception:
        return False

def _theme_setting() -> str:
    cfg = state.config
    name = cfg.get("ui", "theme", fallback="dark") if cfg is not None else "dark"
    return name if name in THEME_LABELS else "dark"

def _pal(setting: str = None) -> dict:
    """Palette de couleurs effective (résout le mode « auto »)."""
    name = setting or _theme_setting()
    if name == "auto":
        name = "light" if _system_prefers_light() else "dark"
    return THEMES.get(name, THEMES["dark"])

def _logo_image(height: int, eye_only: bool = False):
    """Logo Heimdall (PIL) redimensionné à `height` px, ou None s'il est introuvable.
    eye_only : ne garde que l'œil (sans le texte), lisible en petit format."""
    if not TRAY_OK:
        return None
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(getattr(sys, "_MEIPASS", ""), "heimdall-logo.png"),
              os.path.join(_EXE_DIR, "heimdall-logo.png"),
              os.path.join(here, "heimdall-logo.png"),
              os.path.join(here, "server", "static", "heimdall-logo.png")):
        if os.path.isfile(p):
            try:
                img = Image.open(p).convert("RGBA")
                if eye_only:
                    img = img.crop((0, 0, img.width, int(img.height * 0.70)))
                w = max(1, round(img.width * height / img.height))
                return img.resize((w, height), Image.LANCZOS)
            except Exception:
                return None
    return None

def _logo_photo(height: int):
    """Logo au format tk.PhotoImage (à conserver dans une variable), ou None."""
    img = _logo_image(height)
    if img is None or not TKINTER_OK:
        return None
    try:
        import io, base64
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return tk.PhotoImage(data=base64.b64encode(buf.getvalue()))
    except Exception:
        return None

def _add_https_options(parent, P: dict, row: int, use_var, verify_var):
    """Cases « Utiliser HTTPS » et « Vérifier le certificat » (grille `parent`, lignes
    row et row+1). La seconde n'a de sens qu'avec HTTPS : elle est grisée sinon."""
    def _mk(text, var, r, **kw):
        cb = tk.Checkbutton(parent, text=text, variable=var, bg=P["card"], fg=P["muted"],
                            activebackground=P["card"], activeforeground=P["fg"],
                            selectcolor=P["input"], disabledforeground=P["muted"],
                            font=("Segoe UI", 9), **kw)
        cb.grid(row=r, column=0, columnspan=2, sticky="w", pady=4)
        return cb
    verify_cb = None
    def _sync():
        verify_cb.config(state="normal" if use_var.get() else "disabled")
    _mk("Utiliser HTTPS (connexion chiffrée au serveur)", use_var, row, command=_sync)
    verify_cb = _mk("Vérifier le certificat du serveur (décocher = accepter un certificat auto-signé)",
                    verify_var, row + 1)
    _sync()

def _apply_window_icon(win):
    """Icône de la barre de titre = logo Heimdall (si disponible)."""
    photo = _logo_photo(32)
    if photo is not None:
        win._heimdall_icon = photo  # référence, sinon Tk la libère
        try:
            win.iconphoto(False, photo)
        except Exception:
            pass

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
    # Dans l'exe PyInstaller, sys.executable est HeimdallAgent.exe lui-même :
    # « -m pip » relancerait l'agent au lieu de pip.
    if getattr(sys, "frozen", False):
        return packages
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
    os_entry = _os_software_entry()
    return ([os_entry] if os_entry else []) + _registry_software() + _pip_packages()

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

    return sorted(ips)

def _collect_logged_users() -> list:
    """Profils Windows connus et sessions ouvertes, sans données d'identification."""
    users = set()
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
        for i in range(winreg.QueryInfoKey(key)[0]):
            sid = winreg.EnumKey(key, i)
            try:
                with winreg.OpenKey(key, sid) as profile:
                    path, _ = winreg.QueryValueEx(profile, "ProfileImagePath")
                    name = os.path.basename(os.path.expandvars(path))
                    if name and name.lower() not in ("default", "public", "all users"):
                        users.add(name)
            except OSError:
                pass
    except Exception:
        pass
    try:
        r = subprocess.run(["query", "user"], capture_output=True, text=True, timeout=5,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        for line in r.stdout.splitlines()[1:]:
            name = line.lstrip("> ").split(maxsplit=1)[0] if line.strip() else ""
            if name: users.add(name)
    except Exception:
        pass
    return [{"username": u} for u in sorted(users)[:100]]

# ─── Politique de comptes via netapi32 (équivalent de `net accounts` / `net user`) ──
# Appels API directs : aucune console, et indépendant de la langue de Windows.
_TIMEQ_FOREVER = 0xFFFFFFFF
_UF_ACCOUNTDISABLE = 0x2
_DOMAIN_USER_RID_GUEST = 501

def _netapi():
    import ctypes
    from ctypes import wintypes
    net = ctypes.WinDLL("netapi32")
    net.NetUserModalsGet.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    net.NetUserModalsGet.restype = wintypes.DWORD
    net.NetUserEnum.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                                ctypes.POINTER(wintypes.DWORD)]
    net.NetUserEnum.restype = wintypes.DWORD
    net.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    return net

def _account_policy() -> dict:
    """{min_passwd_len, lockout_threshold, lockout_duration_s} — USER_MODALS_INFO_0 / _3."""
    import ctypes
    from ctypes import wintypes
    net, out = _netapi(), {}
    for level, fields in ((0, {0: "min_passwd_len"}),
                          (3, {0: "lockout_duration_s", 2: "lockout_threshold"})):
        buf = ctypes.c_void_p()
        if net.NetUserModalsGet(None, level, ctypes.byref(buf)) != 0 or not buf.value:
            continue
        try:
            dwords = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))
            for idx, name in fields.items():
                out[name] = int(dwords[idx])
        finally:
            net.NetApiBufferFree(buf)
    return out

def _guest_account_disabled():
    """True/False selon l'état du compte Invité (RID 501, quel que soit son nom), None si inconnu."""
    import ctypes
    from ctypes import wintypes

    class USER_INFO_20(ctypes.Structure):
        _fields_ = [("name", wintypes.LPWSTR), ("full_name", wintypes.LPWSTR),
                    ("comment", wintypes.LPWSTR), ("flags", wintypes.DWORD),
                    ("user_id", wintypes.DWORD)]

    net = _netapi()
    buf = ctypes.c_void_p()
    read, total, resume = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD(0)
    rc = net.NetUserEnum(None, 20, 2, ctypes.byref(buf), 0xFFFFFFFF,
                         ctypes.byref(read), ctypes.byref(total), ctypes.byref(resume))
    if not buf.value:
        return None
    try:
        if rc not in (0, 234):  # NERR_Success, ERROR_MORE_DATA
            return None
        users = ctypes.cast(buf, ctypes.POINTER(USER_INFO_20))
        for i in range(read.value):
            if users[i].user_id == _DOMAIN_USER_RID_GUEST:
                return bool(users[i].flags & _UF_ACCOUNTDISABLE)
    finally:
        net.NetApiBufferFree(buf)
    return None

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
        try:
            policy = _account_policy()
        except Exception:
            policy = {}
        if "password_min_length" not in data and "min_passwd_len" in policy:
            data["password_min_length"] = policy["min_passwd_len"]

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
            guest_disabled = _guest_account_disabled()
            if guest_disabled is not None:
                data["guest_account_disabled"] = guest_disabled
        except Exception:
            pass

        # ── Politique de verrouillage de compte ─────────────────────────────
        # Seuil 0 = « Jamais » ; durée en secondes côté API, en minutes dans le rapport.
        if policy.get("lockout_threshold"):
            data["account_lockout_threshold"] = policy["lockout_threshold"]
        duration = policy.get("lockout_duration_s")
        if duration is not None and duration != _TIMEQ_FOREVER:
            data["account_lockout_duration"] = duration // 60

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
    token = cfg.get("main_server", "token", fallback="")
    try:
        r = requests.get(
            f"{_base_url(cfg)}/api/compliance/agent-rules",
            params={"os": "windows"},
            headers={"x-agent-token": token},
            timeout=10,
            verify=_tls_verify(cfg),
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

# ─── Logiciels à mettre à jour (winget + Windows Update) ─────────────────────
# Windows classique : `winget upgrade` (applications) + Windows Update (système).
# Windows Server : Windows Update seulement (pas de winget ; les logiciels installés
# sont inventoriés depuis le registre). L'agent ne fait que lire : il n'installe rien.
_UPDATE_CACHE = {"at": 0.0, "data": None, "force": False}
_MAX_UPDATE_ITEMS = 500

def _parse_winget_table(text: str) -> list:
    """Analyse TOUTES les tables de `winget upgrade` (mises à jour classiques, versions
    inconnues, paquets épinglés ou à cibler explicitement). Indépendant de la langue : les
    colonnes sont repérées d'après la ligne d'en-tête située au-dessus des tirets.
    Tolère les fins de ligne Windows et les barres de progression (retours chariot)."""
    lines = [l.split("\r")[-1].rstrip() for l in text.replace("\r\n", "\n").split("\n")]
    items, seen = [], set()
    for sep, line in enumerate(lines):
        if not re.fullmatch(r"-{5,}", line.strip()):
            continue
        header = next((lines[j] for j in range(sep - 1, -1, -1) if lines[j].strip()), "")
        starts = [m.start() for m in re.finditer(r"\S+(?: \S+)*", header)]
        if len(starts) < 4:            # Nom, Id, Version, Disponible (Source facultative)
            continue
        for row in lines[sep + 1:]:
            if not row.strip() or re.fullmatch(r"-{5,}", row.strip()):
                break                  # fin de cette table (une autre peut suivre)
            if len(re.findall(r"\s{2,}", row.strip())) < 2:
                break                  # phrase (« 12 mises à niveau disponibles. ») et non ligne de tableau
            cells = [row[st:(starts[i + 1] if i + 1 < len(starts) else None)].strip()
                     for i, st in enumerate(starts)]
            if len(cells) >= 4 and cells[0] and cells[3]:
                key = (cells[1] or cells[0]).lower()
                if key not in seen:
                    seen.add(key)
                    items.append({"name": cells[0], "id": cells[1],
                                  "installed": cells[2], "available": cells[3]})
    return items

def collect_outdated_software() -> dict:
    """Résultat : {manager, ok, count, items[], checked_at, error?}. Vérification au premier
    rapport, puis toutes les `update_check_hours` (6 h par défaut) et à la demande du
    dashboard (`_UPDATE_CACHE["force"]`) ; entre-temps le dernier résultat est réutilisé.
    `update_check_hours = 0` désactive la vérification."""
    hours = 6.0
    if state.config is not None:
        try:
            hours = float(state.config.get("agent", "update_check_hours", fallback="6"))
        except ValueError:
            pass
    if hours <= 0:
        return {"manager": None, "ok": False, "error": "désactivé", "count": None, "items": []}
    fresh = time.time() - _UPDATE_CACHE["at"] < hours * 3600
    if _UPDATE_CACHE["data"] and fresh and not _UPDATE_CACHE.get("force"):
        return _UPDATE_CACHE["data"]
    _UPDATE_CACHE["force"] = False

    # Windows Server : pas de winget. Les logiciels installés viennent du registre (inventaire
    # du rapport) et les mises à jour en attente de Windows Update uniquement.
    # Windows classique : winget (applications) ET Windows Update (système), cumulés.
    wu = _windows_update_pending()
    if _is_windows_server():
        result = wu
    else:
        winget = _find_winget()
        wg = _winget_upgrades(winget) if winget else {
            "manager": "winget", "ok": False, "error": "winget introuvable", "count": None, "items": []}
        checks = [wg]
        if SERVICE_MODE:
            # Sous SYSTEM, winget ne voit que les applications installées pour toute la
            # machine (et échoue souvent) : on y ajoute la liste relevée par l'icône dans
            # la session de l'utilisateur, qui voit aussi ses applications personnelles.
            user_wg = _read_user_winget(max_age=hours * 3600 * 2)
            if user_wg:
                checks.append(user_wg)
        result = _merge_update_checks(checks + [wu], dedupe=True)
    _UPDATE_CACHE.update(at=time.time(), data=result)
    return result

# Liste winget relevée dans la session de l'utilisateur, transmise au service (SYSTEM)
_USER_WINGET_FILE = os.path.join(_PROGRAMDATA_DIR, "winget-user.json")

def _write_user_winget(data: dict):
    import json
    try:
        os.makedirs(_PROGRAMDATA_DIR, exist_ok=True)
        tmp = _USER_WINGET_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({**data, "user": os.environ.get("USERNAME", ""), "at": time.time()}, f)
        os.replace(tmp, _USER_WINGET_FILE)
    except Exception as e:
        logger.warning(f"Liste winget non transmise au service : {e}")

def _read_user_winget(max_age: float):
    import json
    try:
        with open(_USER_WINGET_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("ok") and time.time() - float(data.get("at", 0)) < max_age:
            return {"manager": "winget", "ok": True, "count": data.get("count", 0),
                    "items": data.get("items") or []}
    except (OSError, ValueError):
        pass
    return None

def refresh_user_winget():
    """Icône dans une session alors que le service fait les rapports : relève winget côté
    utilisateur (applications personnelles comprises) et le transmet au service."""
    if SERVICE_MODE or _is_windows_server():
        return
    hours = 6.0
    try:
        hours = float((state.config or configparser.ConfigParser()).get("agent", "update_check_hours", fallback="6"))
    except ValueError:
        pass
    if hours <= 0 or (time.time() - _USER_WINGET_STATE["at"] < hours * 3600 and not _USER_WINGET_STATE["force"]):
        return
    _USER_WINGET_STATE.update(at=time.time(), force=False)
    winget = _find_winget()
    if winget:
        wg = _winget_upgrades(winget)
        if wg.get("ok"):
            _write_user_winget(wg)

_USER_WINGET_STATE = {"at": 0.0, "force": False}

def _merge_update_checks(checks: list, dedupe: bool = False) -> dict:
    """Cumule plusieurs sources (winget + Windows Update). Réussi si au moins une
    source a répondu ; les échecs partiels sont signalés dans `error`."""
    ok = [c for c in checks if c.get("ok")]
    failed = [f"{c.get('manager')} : {c.get('error')}" for c in checks if not c.get("ok")]
    if not ok:
        return {"manager": " + ".join(c.get("manager") or "?" for c in checks), "ok": False,
                "error": " ; ".join(failed)[:200] or "indisponible", "count": None, "items": []}
    items = [it for c in ok for it in c.get("items") or []]
    if dedupe:
        seen, unique = set(), []
        for it in items:
            key = (it.get("id") or it.get("name") or "").lower()
            if key not in seen:
                seen.add(key)
                unique.append(it)
        items = unique
    managers = list(dict.fromkeys(c["manager"] for c in ok))
    return {"manager": " + ".join(managers), "ok": True,
            "count": len(items) if dedupe else sum(c.get("count") or 0 for c in ok),
            "items": items[:_MAX_UPDATE_ITEMS],
            "checked_at": datetime.now().isoformat(),
            **({"error": ("partiel — " + " ; ".join(failed))[:200]} if failed else {})}

def _appx_dirs(package: str) -> list:
    """Dossiers d'un paquet MSIX dans Program Files\\WindowsApps, du plus récent au plus
    ancien (tri par numéro de version : « 1.22 » est plus récent que « 1.9 »). Les
    versions remplacées y restent tant que Windows ne les a pas nettoyées."""
    import glob
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    arch = (os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or "").lower()
    arch = "arm64" if arch == "arm64" else "x64"
    dirs = (glob.glob(os.path.join(pf, "WindowsApps", f"{package}_*_{arch}__8wekyb3d8bbwe"))
            or glob.glob(os.path.join(pf, "WindowsApps", f"{package}_*__8wekyb3d8bbwe")))

    def version(path):
        m = re.match(r"[^_]+_(\d+(?:\.\d+)*)_", os.path.basename(path))
        return tuple(int(x) for x in m.group(1).split(".")) if m else ()
    return sorted(dirs, key=version, reverse=True)

def _find_winget():
    """Chemin de winget.exe, ou None. Plusieurs méthodes, car aucune ne marche partout :
    - session utilisateur : winget est un « alias d'exécution d'application », un point
      d'analyse que Windows sait lancer mais que les tests de fichier de Python
      (isfile, shutil.which) ne reconnaissent pas toujours ;
    - service (SYSTEM) : pas d'alias du tout, il faut le dossier d'App Installer."""
    import shutil
    tried = []
    found = shutil.which("winget")
    if found:
        return found
    local = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WindowsApps", "winget.exe")
    if os.path.lexists(local):      # lexists : vrai aussi pour l'alias (point d'analyse)
        return local
    tried.append("PATH et alias utilisateur")
    # Nom nu : CreateProcess résout l'alias même quand Python ne le « voit » pas.
    try:
        r = subprocess.run(["winget", "--version"], capture_output=True, text=True, timeout=60,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode == 0:
            return "winget"
        tried.append(f"« winget --version » (code {(r.returncode or 0) & 0xFFFFFFFF:#x})")
    except (OSError, subprocess.TimeoutExpired) as e:
        tried.append(f"« winget --version » ({type(e).__name__})")
    for d in _appx_dirs("Microsoft.DesktopAppInstaller"):
        exe = os.path.join(d, "winget.exe")
        if os.path.isfile(exe):
            return exe
    tried.append("Program Files\\WindowsApps")
    # Dernier recours : demander à Windows où App Installer est installé (pour tous
    # les utilisateurs — fonctionne sous SYSTEM, qui ne peut pas toujours lister le dossier).
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
             "(Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller | Sort-Object Version "
             "-Descending | Select-Object -First 1).InstallLocation"],
            capture_output=True, text=True, errors="replace", timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        location = (r.stdout or "").strip()
        exe = os.path.join(location, "winget.exe") if location else ""
        if exe and os.path.isfile(exe):
            return exe
        tried.append("Get-AppxPackage" + (f" ({location} sans winget.exe)" if location else
                                          f" ({((r.stderr or '').strip().splitlines() or ['aucun paquet'])[-1][:80]})"))
    except (OSError, subprocess.TimeoutExpired) as e:
        tried.append(f"Get-AppxPackage ({type(e).__name__})")
    logger.warning("winget introuvable — essais : " + " ; ".join(tried))
    return None

def _winget_env(winget: str):
    """Environnement d'exécution de winget.exe lancé directement depuis WindowsApps.
    Hors session utilisateur (SYSTEM), le paquet n'est pas « enregistré » : Windows ne
    trouve pas sa dépendance Microsoft.VCLibs (VCRUNTIME140_APP.dll) et winget s'arrête
    aussitôt (0xC0000135). On ajoute ces dossiers au PATH du sous-processus."""
    if "WindowsApps" not in winget or os.path.basename(os.path.dirname(winget)).lower() == "windowsapps":
        return None     # alias d'exécution utilisateur : Windows résout lui-même les dépendances
    extra = [os.path.dirname(winget)]
    for package in ("Microsoft.VCLibs.140.00.UWPDesktop", "Microsoft.VCLibs.140.00"):
        extra += _appx_dirs(package)[:1]
    return {**os.environ, "PATH": os.pathsep.join(extra + [os.environ.get("PATH", "")])}

# Codes de sortie de winget fréquents sous SYSTEM, traduits pour le dashboard
_WINGET_EXIT_CODES = {
    0xC0000135: "DLL manquante (Microsoft.VCLibs) — winget ne peut pas démarrer sous ce compte",
    0xC0000005: "plantage de winget au démarrage",
    0x8A15000F: "sources winget indisponibles (réseau ou proxy)",
    0x8A150044: "sources winget à réinitialiser (winget source reset --force)",
}

# Mises à jour Windows en attente via l'API COM Windows Update Agent (présente sur toutes
# les éditions, Server compris ; respecte un WSUS configuré). Lecture seule.
_WU_PS = (
    "$s=New-Object -ComObject Microsoft.Update.Session;"
    "$r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\");"
    "$o=@(foreach($u in $r.Updates){[pscustomobject]@{t=$u.Title;"
    "kb=(@($u.KBArticleIDs)|%{'KB'+$_}) -join ','}});"
    "$j=ConvertTo-Json -InputObject $o -Compress;"
    # base64 : indépendant de l'encodage de la console (accents des titres en français)
    "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))"
)

def _windows_update_pending() -> dict:
    import json
    result = {"manager": "windows_update", "ok": False, "error": "Windows Update indisponible",
              "count": None, "items": []}
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _WU_PS],
            capture_output=True, text=True, errors="replace",
            timeout=300, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (r.stdout or "").strip()
        if r.returncode == 0 and out:
            import base64
            data = json.loads(base64.b64decode(out).decode("utf-8"))
            if isinstance(data, dict):
                data = [data]
            items = [{"name": str(u.get("t") or "")[:200], "id": u.get("kb") or None,
                      "installed": None, "available": u.get("kb") or "disponible"}
                     for u in data if isinstance(u, dict) and u.get("t")]
            result = {"manager": "windows_update", "ok": True, "count": len(items),
                      "items": items[:_MAX_UPDATE_ITEMS],
                      "checked_at": datetime.now().isoformat()}
        else:
            result["error"] = ((r.stderr or out).strip().splitlines() or ["sortie vide"])[0][:200]
    except subprocess.TimeoutExpired:
        result["error"] = "délai dépassé (Windows Update)"
    except Exception as e:
        result["error"] = str(e)[:200]
    return result

def _winget_upgrades(winget: str) -> dict:
    result = {"manager": "winget", "ok": False, "error": "winget indisponible",
              "count": None, "items": []}
    # --include-unknown : versions non déterminables ; --include-pinned : paquets épinglés
    # (sans eux, winget les masque) ; --disable-interactivity : pas de barre de progression.
    # Les winget anciens ne connaissent pas les deux derniers : on retente sans.
    variants = [
        ["upgrade", "--include-unknown", "--include-pinned", "--accept-source-agreements",
         "--disable-interactivity"],
        ["upgrade", "--include-unknown", "--accept-source-agreements"],
    ]
    try:
        for args in variants:
            r = subprocess.run(
                [winget] + args,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                env=_winget_env(winget), cwd=os.path.dirname(winget) or None,
                # La première exécution met à jour les sources winget : 120 s ne suffisaient pas
                timeout=300, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            out = r.stdout or ""
            items = _parse_winget_table(out)
            # « Aucune mise à jour applicable » (0x8A15002B) et « aucun paquet correspondant »
            # (0x8A150014) sont des codes de retour ≠ 0 mais signifient : tout est à jour.
            rc = (r.returncode or 0) & 0xFFFFFFFF
            if items or rc in (0, 0x8A15002B, 0x8A150014) or re.search(r"-{5,}", out):
                return {"manager": "winget", "ok": True, "count": len(items),
                        "items": items[:_MAX_UPDATE_ITEMS],
                        "checked_at": datetime.now().isoformat()}
            lines = [l.split("\r")[-1].strip() for l in (r.stderr or out).splitlines()]
            message = next((l for l in reversed(lines) if l and not re.fullmatch(r"[-\\|/ █▒]*", l)), "")
            known = _WINGET_EXIT_CODES.get(rc)
            result["error"] = (f"{known or message or 'aucune sortie'} (code {rc:#010x})")[:200]
            logger.warning(f"winget {' '.join(args[1:])} : {result['error']}")
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        result["error"] = "délai dépassé (winget)"
    except Exception as e:
        result["error"] = str(e)[:200]
    return result

# ─── Surveillance du poste ───────────────────────────────────────────────────
# Analyse locale, légère, en continu : seuls les déclencheurs partent au serveur.
#   • processus : seuls les NOUVEAUX processus sont examinés (toutes les 30 s) ; la
#     ligne de commande n'est lue que pour les programmes à risque (PowerShell, cmd…) ;
#   • tâches planifiées, démarrage automatique, services, administrateurs, comptes,
#     exclusions Defender, fichier hosts : toutes les 5 min, par différence avec
#     l'instantané précédent (un fichier de tâche n'est relu que s'il a changé) ;
#   • logiciels installés : toutes les 15 min.
# Le fil tourne en mode « arrière-plan » de Windows (CPU, disque et mémoire au plus
# bas). Au premier passage, l'état existant sert de référence : rien n'est signalé,
# sauf un processus déjà en cours qui déclenche une règle moyenne ou plus.
import json
import ntpath       # chemins Windows, quel que soit l'OS qui exécute les règles (tests)
MONITOR_STATE_FILE = os.path.join(_LOG_DIR, "monitor-state.json")
_MONITOR_ALERT_TTL = 7 * 86400          # une même alerte de processus n'est renvoyée qu'après 7 jours
_MONITOR_MAX_EVENTS_PER_CYCLE = 50
_MONITOR_QUEUE_MAX = 300
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

_SCRIPT_HOSTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                 "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
                 "installutil.exe", "schtasks.exe", "wmic.exe", "bash.exe", "hh.exe", "forfiles.exe"}
_DOCUMENT_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
                  "mspub.exe", "visio.exe", "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe",
                  "foxitreader.exe", "wordpad.exe"}
# Ligne de commande lue uniquement pour ceux-ci (le reste : nom et chemin suffisent)
_CMDLINE_OF_INTEREST = _SCRIPT_HOSTS | {"vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "procdump.exe",
                                        "procdump64.exe", "reg.exe", "net.exe", "net1.exe", "sc.exe",
                                        "wevtutil.exe", "curl.exe", "taskkill.exe"}
# Binaires système souvent imités par les malwares : leur dossier légitime
_SYSTEM_BINARIES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
                    "wininit.exe", "spoolsv.exe", "taskhostw.exe", "lsaiso.exe", "dllhost.exe",
                    "conhost.exe", "explorer.exe", "rundll32.exe", "svchost32.exe"}
_OFFENSIVE_TOOLS = {"mimikatz": "critical", "rubeus": "critical", "lazagne": "high", "sharphound": "high",
                    "bloodhound": "high", "seatbelt": "high", "kerbrute": "high", "pwdump": "high",
                    "gsecdump": "high", "safetykatz": "critical", "nanodump": "critical", "chisel": "high",
                    "nc": "high", "nc64": "high", "ncat": "high", "netcat": "high", "psexesvc": "medium",
                    "psexec": "medium", "psexec64": "medium", "ngrok": "medium", "plink": "medium",
                    "rclone": "medium", "advanced_ip_scanner": "medium", "netscan": "medium",
                    "xmrig": "high", "nheqminer": "high"}
# (motif, gravité, titre) — appliqués à la ligne de commande, en minuscules
_CMDLINE_RULES = [
    (r"vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+"
     r"(catalog|systemstatebackup)|bcdedit.*recoveryenabled\s+no|bcdedit.*bootstatuspolicy\s+ignoreallfailures",
     "critical", "Suppression des sauvegardes / points de restauration (signe de rançongiciel)"),
    (r"procdump.*lsass|comsvcs(\.dll)?[\s,].*minidump|comsvcs.*#\s*24|sekurlsa|lsadump",
     "critical", "Tentative de vol d'identifiants (mémoire de LSASS)"),
    (r"\s-(e|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[a-z0-9+/=]{20,}",
     "high", "PowerShell avec commande encodée"),
    (r"(downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|"
     r"\birm\b|start-bitstransfer).*(\biex\b|invoke-expression)|(\biex\b|invoke-expression).*(downloadstring|"
     r"net\.webclient|\biwr\b|invoke-webrequest|invoke-restmethod|\birm\b)",
     "high", "Téléchargement puis exécution de code (PowerShell)"),
    (r"frombase64string.*(\biex\b|invoke-expression|\[reflection\.assembly\]::load)",
     "high", "Exécution de code décodé en mémoire (PowerShell)"),
    (r"certutil(\.exe)?.*\s[-/](urlcache|decode|decodehex)\b", "high", "Certutil détourné (téléchargement/décodage)"),
    (r"bitsadmin(\.exe)?.*\s/transfer\b", "medium", "Téléchargement via BITSAdmin"),
    (r"mshta(\.exe)?\s+[\"']?(https?:|javascript:|vbscript:)", "high", "MSHTA exécute un script distant"),
    (r"regsvr32(\.exe)?.*(/i:\s*https?:|scrobj\.dll)", "high", "Regsvr32 détourné (Squiblydoo)"),
    (r"rundll32(\.exe)?.*(javascript:|url\.dll.*(https?:|file)|shell32\.dll.*shellexec_rundll.*https?:)",
     "high", "Rundll32 détourné"),
    (r"wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog", "high", "Effacement des journaux Windows"),
    (r"set-mppreference.*-disable\w*\s+(\$true|1)|add-mppreference.*-exclusion", "high",
     "Désactivation ou exclusion de Microsoft Defender"),
    (r"net1?(\.exe)?\s+localgroup\s+\S*admin\S*\s+.*\s/add|net1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add",
     "high", "Création de compte ou ajout aux administrateurs en ligne de commande"),
    (r"-w(indowstyle)?\s+h(idden)?\b.*-(nop|noprofile)\b.*https?:|-(nop|noprofile)\b.*-w(indowstyle)?\s+h(idden)?\b.*https?:",
     "medium", "PowerShell caché qui contacte Internet"),
]
_CMDLINE_RULES = [(re.compile(p), s, t) for p, s, t in _CMDLINE_RULES]
_DOUBLE_EXTENSION = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip|rar)\.(exe|scr|com|bat|cmd|js|vbs|pif)$")

def _suspicious_location(path: str):
    """(gravité, raison) si l'exécutable est dans un dossier où un programme légitime
    n'a pas sa place, sinon None."""
    p = (path or "").lower()
    if not p:
        return None
    for marker, severity, reason in (
            ("\\$recycle.bin\\", "high", "exécuté depuis la corbeille"),
            ("\\users\\public\\", "high", "exécuté depuis C:\\Users\\Public"),
            ("c:\\perflogs\\", "high", "exécuté depuis C:\\PerfLogs"),
            ("\\appdata\\local\\temp\\", "low", "exécuté depuis un dossier temporaire"),
            ("\\windows\\temp\\", "low", "exécuté depuis C:\\Windows\\Temp"),
            ("\\downloads\\", "low", "exécuté depuis Téléchargements")):
        if marker in p:
            return severity, reason
    return None

def _command_program(command: str) -> str:
    """Exécutable d'une ligne de commande (« "C:\\Program Files\\x\\a.exe" -arg »)."""
    cmd = (command or "").strip()
    if cmd.startswith('"'):
        return cmd[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.(exe|com|bat|cmd|ps1|vbs|js|msc))(\s|$)", cmd, re.I)
    return m.group(1) if m else cmd.split(" ", 1)[0]

def _is_vendor_path(command: str) -> bool:
    """Programme installé dans Program Files ou Windows (emplacements protégés en écriture)."""
    program = os.path.expandvars(_command_program(command)).lower()
    return program.startswith(("c:\\program files\\", "c:\\program files (x86)\\", "c:\\windows\\",
                               "%systemroot%", "%windir%", "%programfiles%", "\\systemroot\\", "system32\\"))

def _rate_command(command: str):
    """Gravité d'une commande lancée par une tâche planifiée, un service ou une clé
    de démarrage : (gravité, [raisons]). « low » si rien de particulier."""
    cmd = (command or "").lower()
    reasons, severity = [], "low"
    def raise_to(level, reason):
        nonlocal severity
        reasons.append(reason)
        if _SEVERITY_ORDER.index(level) > _SEVERITY_ORDER.index(severity):
            severity = level
    for rx, level, title in _CMDLINE_RULES:
        if rx.search(cmd):
            raise_to(level, title)
    loc = _suspicious_location(cmd)
    if loc:
        raise_to("high" if loc[0] == "low" else loc[0], loc[1])
    if re.search(r"\\appdata\\(roaming|local)\\[^\\]+\.(exe|dll|bat|cmd|ps1|vbs|js)\b", cmd):
        raise_to("medium", "programme posé directement dans AppData")
    first = ntpath.basename(_command_program(cmd))
    if first in _SCRIPT_HOSTS or re.search(r"\.(ps1|vbs|js|jse|hta|bat|cmd)\b", cmd):
        raise_to("medium", "lance un interpréteur ou un script")
    if _DOUBLE_EXTENSION.search(_command_program(cmd)):
        raise_to("high", "double extension trompeuse")
    return severity, reasons

def _persistence_severity(command: str, severity: str) -> str:
    """Gravité d'un nouvel élément de démarrage : « faible » pour un programme d'éditeur
    (Program Files, Windows), « moyenne » ailleurs, sinon celle des règles."""
    if severity != "low":
        return severity
    return "low" if _is_vendor_path(command) else "medium"

def _process_findings(name: str, image: str, parent_name: str, parent_image: str,
                      cmdline: str, watchlist: list, system_root: str) -> list:
    """Règles appliquées à un nouveau processus : [(règle, gravité, titre, extra)]."""
    findings = []
    name = (name or "").lower()
    image_l = (image or "").lower()
    parent = (parent_name or "").lower()
    cmd = (cmdline or "").lower()
    stem = name[:-4] if name.endswith(".exe") else name
    sysroot = (system_root or r"C:\Windows").lower().rstrip("\\")
    if name in _SYSTEM_BINARIES and image_l:
        allowed = {sysroot + "\\system32", sysroot + "\\syswow64"}
        if name == "explorer.exe":
            allowed = {sysroot}
        if ntpath.dirname(image_l) not in allowed:
            findings.append(("masquerading_process", "critical",
                             f"{name} lancé hors de son dossier système (imitation)", {}))
    if stem in _OFFENSIVE_TOOLS:
        findings.append(("offensive_tool", _OFFENSIVE_TOOLS[stem], f"Outil offensif ou de tunnel : {name}", {}))
    for rx, level, title in _CMDLINE_RULES:
        if cmd and rx.search(cmd):
            findings.append(("suspicious_command", level, title, {}))
            break
    if parent in _DOCUMENT_APPS and name in _SCRIPT_HOSTS:
        findings.append(("document_spawns_shell", "high",
                         f"{parent} a lancé {name} (macro ou document piégé ?)", {}))
    if name in _SCRIPT_HOSTS and parent_image:
        haystack = parent_image.lower()
        for product in watchlist or []:
            if any(token in haystack for token in product.get("match") or []):
                cves = ", ".join((product.get("cves") or [])[:3])
                findings.append(("vulnerable_app_spawns_shell", "critical",
                                 f"{product.get('name')} (vulnérable : {cves}) a lancé {name} — exploitation possible",
                                 {"watchlist_match": product.get("name"), "cves": cves}))
                break
    loc = _suspicious_location(image)
    if loc:
        findings.append(("suspicious_location", loc[0], f"{name} {loc[1]}", {}))
    if _DOUBLE_EXTENSION.search(image_l):
        findings.append(("double_extension", "high", f"{name} : double extension trompeuse", {}))
    return findings

# ── Capteurs Windows ─────────────────────────────────────────────────────────
_WIN_API = {}

def _win_api():
    """kernel32/ntdll avec types d'arguments déclarés (handles 64 bits), sur des
    instances propres à la surveillance pour ne pas modifier celles du reste de l'agent."""
    if _WIN_API:
        return _WIN_API
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                               ctypes.POINTER(wintypes.DWORD)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.GetCurrentThread.restype = wintypes.HANDLE
    k32.SetThreadPriority.argtypes = [wintypes.HANDLE, ctypes.c_int]
    ntdll.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p,
                                                ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    ntdll.NtQueryInformationProcess.restype = ctypes.c_long
    _WIN_API.update(k32=k32, ntdll=ntdll)
    return _WIN_API

def _background_thread():
    """Fil en mode arrière-plan : priorité CPU, disque et mémoire minimales."""
    try:
        k32 = _win_api()["k32"]
        k32.SetThreadPriority(k32.GetCurrentThread(), 0x00010000)   # THREAD_MODE_BACKGROUND_BEGIN
    except Exception:
        pass

def _list_processes() -> dict:
    """{pid: (ppid, nom)} via un instantané ToolHelp (très peu coûteux)."""
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]
    k32 = _win_api()["k32"]
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)      # TH32CS_SNAPPROCESS
    procs = {}
    if not snap or snap == ctypes.c_void_p(-1).value:
        return procs
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            procs[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID), entry.szExeFile)
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return procs

def _process_details(pid: int, want_cmdline: bool):
    """(chemin de l'exécutable, ligne de commande ou "") — accès minimal en lecture."""
    import ctypes
    from ctypes import wintypes
    api = _win_api()
    k32, ntdll = api["k32"], api["ntdll"]
    handle = k32.OpenProcess(0x1000, False, pid)            # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return "", ""
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(1024)
        image = buf.value if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)) else ""
        cmdline = ""
        if want_cmdline:
            class UNICODE_STRING(ctypes.Structure):
                _fields_ = [("Length", ctypes.c_ushort), ("MaximumLength", ctypes.c_ushort),
                            ("Buffer", ctypes.c_void_p)]
            needed = ctypes.c_ulong(0)
            ntdll.NtQueryInformationProcess(handle, 60, None, 0, ctypes.byref(needed))  # ProcessCommandLineInformation
            if 0 < needed.value < 65536:
                raw = ctypes.create_string_buffer(needed.value)
                if ntdll.NtQueryInformationProcess(handle, 60, raw, needed.value, ctypes.byref(needed)) == 0:
                    us = UNICODE_STRING.from_buffer(raw)
                    if us.Buffer and us.Length:
                        cmdline = ctypes.wstring_at(us.Buffer, us.Length // 2)
        return image, cmdline
    except Exception:
        return "", ""
    finally:
        k32.CloseHandle(handle)

def _reg_values(root, path: str) -> dict:
    import winreg
    out = {}
    try:
        with winreg.OpenKey(root, path) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                out[name or "(par défaut)"] = str(value)[:500]
                i += 1
    except OSError:
        pass
    return out

def _snapshot_autoruns() -> dict:
    """Clés Run/RunOnce (machine et chaque utilisateur chargé), Winlogon, débogueurs
    IFEO (porte dérobée « touches rémanentes ») et dossiers Démarrage."""
    import winreg, glob
    out = {}
    run_paths = (r"Software\Microsoft\Windows\CurrentVersion\Run",
                 r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                 r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                 r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce")
    roots = [("HKLM", winreg.HKEY_LOCAL_MACHINE, "")]
    if SERVICE_MODE:
        try:
            with winreg.OpenKey(winreg.HKEY_USERS, "") as users:
                i = 0
                while True:
                    try:
                        sid = winreg.EnumKey(users, i)
                    except OSError:
                        break
                    i += 1
                    if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
                        roots.append((f"HKU\\{sid}", winreg.HKEY_USERS, sid + "\\"))
        except OSError:
            pass
    else:
        roots.append(("HKCU", winreg.HKEY_CURRENT_USER, ""))
    for label, root, prefix in roots:
        for path in run_paths:
            for name, value in _reg_values(root, prefix + path).items():
                out[f"{label}\\{path}\\{name}"] = value
    winlogon = _reg_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
    for name in ("Shell", "Userinit"):
        if name in winlogon:
            out[f"HKLM\\Winlogon\\{name}"] = winlogon[name]
    ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    for exe in ("sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe",
                "atbroker.exe", "taskmgr.exe", "lsass.exe"):
        debugger = _reg_values(winreg.HKEY_LOCAL_MACHINE, f"{ifeo}\\{exe}").get("Debugger")
        if debugger:
            out[f"HKLM\\IFEO\\{exe}\\Debugger"] = debugger
    startup_dirs = [os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                                 r"Microsoft\Windows\Start Menu\Programs\StartUp")]
    startup_dirs += glob.glob(os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users", "*",
                                           r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"))
    for d in startup_dirs:
        try:
            for entry in os.scandir(d):
                if entry.is_file() and entry.name.lower() != "desktop.ini":
                    out[f"Démarrage\\{entry.path}"] = entry.path
        except OSError:
            pass
    return out

def _snapshot_services() -> dict:
    """{service: "type|chemin"} — un nouveau service est un moyen de persistance courant."""
    import winreg
    out = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as root:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, name) as key:
                        image = str(winreg.QueryValueEx(key, "ImagePath")[0])[:500]
                        try:
                            stype = int(winreg.QueryValueEx(key, "Type")[0])
                        except OSError:
                            stype = 0
                        out[name] = f"{stype}|{image}"
                except OSError:
                    pass    # pas d'ImagePath : pilote fourni sans binaire ou clé de paramètres
    except OSError:
        pass
    return out

def _snapshot_task_files(previous: dict) -> tuple:
    """({chemin: "mtime|taille"}, [chemins nouveaux ou modifiés]) — seuls ceux-là sont relus."""
    root = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")
    current, changed = {}, []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            path = os.path.join(dirpath, f)
            try:
                st = os.stat(path)
            except OSError:
                continue
            rel = os.path.relpath(path, root)
            sig = f"{st.st_mtime_ns}|{st.st_size}"
            current[rel] = sig
            if previous.get(rel) != sig:
                changed.append(rel)
    return current, changed

def _read_task(rel: str) -> dict:
    """Action, compte et déclencheurs d'une tâche planifiée (fichier XML)."""
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks", rel)
    try:
        with open(path, "rb") as f:
            return _parse_task_xml(f.read())
    except OSError:
        return {}

def _local_group_members(sid_string: str) -> list:
    """Membres d'un groupe local identifié par son SID (nom indépendant de la langue)."""
    import ctypes
    from ctypes import wintypes
    advapi, k32 = ctypes.windll.advapi32, ctypes.windll.kernel32
    sid = ctypes.c_void_p()
    if not advapi.ConvertStringSidToSidW(sid_string, ctypes.byref(sid)):
        return []
    try:
        name, domain = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
        n, d, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
        if not advapi.LookupAccountSidW(None, sid, name, ctypes.byref(n), domain, ctypes.byref(d), ctypes.byref(use)):
            return []
    finally:
        k32.LocalFree(sid)

    class LOCALGROUP_MEMBERS_INFO_3(ctypes.Structure):
        _fields_ = [("domainandname", wintypes.LPWSTR)]
    net = ctypes.WinDLL("netapi32")
    buf = ctypes.c_void_p()
    read, total = wintypes.DWORD(), wintypes.DWORD()
    rc = net.NetLocalGroupGetMembers(None, name.value, 3, ctypes.byref(buf), 0xFFFFFFFF,
                                     ctypes.byref(read), ctypes.byref(total), None)
    if rc != 0 or not buf.value:
        return []
    try:
        members = ctypes.cast(buf, ctypes.POINTER(LOCALGROUP_MEMBERS_INFO_3))
        return sorted(members[i].domainandname for i in range(read.value) if members[i].domainandname)
    finally:
        net.NetApiBufferFree(buf)

def _local_accounts() -> list:
    """Comptes locaux (NetUserEnum, niveau 0)."""
    import ctypes
    from ctypes import wintypes
    net = _netapi()
    buf = ctypes.c_void_p()
    read, total, resume = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD(0)
    rc = net.NetUserEnum(None, 0, 2, ctypes.byref(buf), 0xFFFFFFFF,
                         ctypes.byref(read), ctypes.byref(total), ctypes.byref(resume))
    if rc not in (0, 234) or not buf.value:
        return []
    try:
        names = ctypes.cast(buf, ctypes.POINTER(wintypes.LPWSTR))
        return sorted(names[i] for i in range(read.value) if names[i])
    finally:
        net.NetApiBufferFree(buf)

def _hosts_lines() -> list:
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return sorted({l.strip() for l in f if l.strip() and not l.strip().startswith("#")})[:500]
    except OSError:
        return []

def _defender_exclusions() -> dict:
    import winreg
    out = {}
    for kind in ("Paths", "Processes", "Extensions"):
        for name in _reg_values(winreg.HKEY_LOCAL_MACHINE,
                                rf"SOFTWARE\Microsoft\Windows Defender\Exclusions\{kind}"):
            out[f"{kind}\\{name}"] = name
    return out

# ── Analyse YARA (fichiers et scripts PowerShell journalisés) ────────────────
# Règles reçues du serveur. Fichiers ciblés uniquement : exécutable des nouveaux
# processus, programmes cités par une persistance (tâche, service, démarrage), fichiers
# nouveaux ou modifiés dans Téléchargements, Temp, Bureau, C:\Users\Public… Budget
# d'octets par passage et cache taille/date.
try:
    import yara as _yara_mod
except Exception:          # module absent du build ou DLL introuvable
    _yara_mod = None
import collections
YARA_MAX_FILE = 32 << 20
YARA_BUDGET_PER_CYCLE = 32 << 20
_YARA_CACHE_MAX = 5000
_YARA_SEVERITIES = ("low", "medium", "high", "critical")
_YARA_FILE_EXT = (".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".ps1", ".psm1", ".vbs", ".vbe",
                  ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".lnk", ".msi", ".jar")

class _YaraEngine:
    """Règles compilées jeu par jeu (un jeu invalide n'empêche pas les autres)."""
    def __init__(self):
        self.compiled, self.version = [], None
        self.lock = threading.Lock()

    @property
    def ready(self) -> bool:
        return bool(self.compiled)

    def load(self, version: str, rulesets: list) -> list:
        compiled, errors = [], []
        for i, rs in enumerate(rulesets):
            name = str(rs.get("name") or f"jeu {i}")
            try:
                compiled.append((name, _yara_mod.compile(source=str(rs.get("source") or ""))))
            except Exception as e:
                errors.append(f"{name} : {str(e)[:200]}")
        with self.lock:
            self.compiled, self.version = compiled, version
        return errors

    def scan(self, path: str = None, data: bytes = None) -> list:
        with self.lock:
            compiled = list(self.compiled)
        out = []
        for name, rules in compiled:
            try:
                matches = (rules.match(filepath=path, timeout=10, fast=True) if path is not None
                           else rules.match(data=data, timeout=5, fast=True))
            except Exception:
                continue
            for m in matches:
                severity = str(m.meta.get("severity") or "high").lower()
                out.append({"rule": m.rule, "ruleset": name,
                            "severity": severity if severity in _YARA_SEVERITIES else "high",
                            "description": str(m.meta.get("description") or "")[:300]})
        return out

def _yara_skip(path: str) -> bool:
    """Fichiers de Windows et des applications du Store : non analysés (sauf Temp)."""
    p = path.lower()
    sysroot = os.environ.get("SystemRoot", r"C:\Windows").lower().rstrip("\\") + "\\"
    if p.startswith(sysroot) and not p.startswith(sysroot + "temp\\"):
        return True
    return "\\windowsapps\\" in p

def _program_file(command: str) -> str:
    """Fichier exécuté par une commande de tâche, service ou clé de démarrage."""
    program = os.path.expandvars(_command_program(command or "").strip())
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    for prefix, repl in (("\\??\\", ""), ("\\systemroot\\", sysroot + "\\")):
        if program.lower().startswith(prefix):
            program = repl + program[len(prefix):]
    if program.lower().startswith("system32\\"):
        program = os.path.join(sysroot, program)
    return program if ntpath.isabs(program) else ""

def _watched_dirs() -> list:
    """(dossier, profondeur) où un fichier déposé mérite une analyse YARA."""
    import glob
    drive = os.environ.get("SystemDrive", "C:") + "\\"
    dirs = [(os.path.join(drive, "Users", "Public"), 2), (os.environ.get("ProgramData", r"C:\ProgramData"), 0),
            (os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"), 1), (os.path.join(drive, "PerfLogs"), 2)]
    for home in glob.glob(os.path.join(drive, "Users", "*")):
        if os.path.basename(home).lower() in ("public", "default", "default user", "all users"):
            continue
        dirs += [(os.path.join(home, "Downloads"), 1), (os.path.join(home, "Desktop"), 0),
                 (os.path.join(home, "AppData", "Local", "Temp"), 1)]
    return dirs

def _walk_files(root: str, max_depth: int, extensions=None, limit: int = 3000):
    count, stack = 0, [(root, 0)]
    while stack and count < limit:
        path, depth = stack.pop()
        try:
            entries = list(os.scandir(path))
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir():
                    if depth < max_depth:
                        stack.append((e.path, depth + 1))
                elif e.is_file() and (extensions is None or e.name.lower().endswith(extensions)):
                    count += 1
                    yield e.path
            except OSError:
                continue

# ── Journaux d'événements en temps réel ──────────────────────────────────────
# Abonnement EvtSubscribe : Windows signale chaque nouvel événement, le fil dort sinon
# (aucune consommation entre deux événements). Les signets sont conservés : après un
# redémarrage, l'agent reprend où il s'était arrêté (événements de moins de 24 h).
_EVT_QUERIES = {
    "Security": ["*[System[(EventID=4625 or EventID=1102 or EventID=4720 or EventID=4728 or EventID=4732 "
                 "or EventID=4756 or EventID=4698 or EventID=4688)]]",
                 "*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='10']]"],
    "System": ["*[System[(EventID=7045 or EventID=104)]]"],
    "Microsoft-Windows-PowerShell/Operational": ["*[System[(EventID=4104)]]"],
    "Microsoft-Windows-Windows Defender/Operational": ["*[System[(EventID=1116 or EventID=5001 or EventID=5007)]]"],
    "Microsoft-Windows-Sysmon/Operational": ["*[System[(EventID=1)]]"],
}
_ADMIN_GROUP_SIDS = ("S-1-5-32-544",)                       # Administrateurs locaux
_DOMAIN_ADMIN_RIDS = ("-512", "-518", "-519")               # Admins du domaine, du schéma, de l'entreprise

def _parse_event_xml(xml: str):
    """Événement rendu en XML → {channel, id, record, time, computer, data}, ou None."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    system = root.find(ns + "System")
    if system is None:
        return None
    try:
        event_id = int(system.findtext(ns + "EventID") or 0)
    except ValueError:
        return None
    created = system.find(ns + "TimeCreated")
    data = {}
    for el in root.iter(ns + "Data"):
        if el.get("Name"):
            data[el.get("Name")] = (el.text or "").strip()
    user_data = root.find(ns + "UserData")
    if user_data is not None:
        for el in user_data.iter():
            if len(el) == 0 and el.text and el.text.strip():
                data[el.tag.split("}")[-1]] = el.text.strip()
    return {"channel": system.findtext(ns + "Channel") or "", "id": event_id,
            "record": system.findtext(ns + "EventRecordID") or "",
            "time": created.get("SystemTime", "") if created is not None else "",
            "computer": system.findtext(ns + "Computer") or "", "data": data}

def _parse_task_xml(content) -> dict:
    """Action, compte et déclencheurs d'une définition de tâche planifiée (XML)."""
    import xml.etree.ElementTree as ET
    try:
        # Octets (fichier) : l'encodage est détecté. Texte (événement 4698) : la déclaration
        # « encoding="UTF-16" » est retirée, Python refusant de l'appliquer à une chaîne.
        root = ET.fromstring(content if isinstance(content, bytes)
                             else re.sub(r"^\s*<\?xml[^>]*\?>", "", content))
    except (ET.ParseError, ValueError):
        return {}
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    def text(xpath):
        el = root.find(xpath, ns)
        return (el.text or "").strip() if el is not None and el.text else ""
    triggers = root.find("t:Triggers", ns)
    return {"command": (text("t:Actions/t:Exec/t:Command") + " " + text("t:Actions/t:Exec/t:Arguments")).strip(),
            "user": text("t:Principals/t:Principal/t:UserId") or text("t:Principals/t:Principal/t:GroupId"),
            "run_level": text("t:Principals/t:Principal/t:RunLevel"),
            "author": text("t:RegistrationInfo/t:Author"),
            "triggers": ", ".join(t.tag.split("}")[-1] for t in triggers) if triggers is not None else "",
            "com_handler": text("t:Actions/t:ComHandler/t:ClassId")}

class _RateTracker:
    """Compteurs glissants (tentatives échouées par adresse…)."""
    def __init__(self):
        self.hits = {}

    def add(self, key, now, window) -> int:
        self.hits.setdefault(key, collections.deque()).append(now)
        return self.count(key, now, window)

    def count(self, key, now, window) -> int:
        dq = self.hits.get(key)
        if not dq:
            return 0
        while dq and dq[0] < now - window:
            dq.popleft()
        if len(self.hits) > 20000:
            for k in [k for k, v in self.hits.items() if not v][:10000]:
                del self.hits[k]
        return len(dq)

def _windows_log_findings(ev: dict, tracker: "_RateTracker", watchlist: list, system_root: str,
                          now: float) -> list:
    """Règles appliquées à un événement : [(règle, gravité, titre, clé, détails)]."""
    out, d, eid, channel = [], ev["data"], ev["id"], ev["channel"]
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    def add(rule, severity, title, key, **details):
        out.append((rule, severity, title, key, {"event_id": eid, "channel": channel, **details}))
    if channel == "Security" and eid == 4625:
        ip, user = d.get("IpAddress") or "-", d.get("TargetUserName") or "?"
        source = ip if ip not in ("-", "", "::1", "127.0.0.1") else f"compte {user}"
        tracker.add(f"fail15|{source}", now, 900)
        if tracker.add(f"fail5|{source}", now, 300) >= 10:
            add("brute_force", "high", f"Attaque par force brute ({source})", f"brute_force|win|{source}|{day}",
                source_ip=ip, name=user, value=d.get("LogonType"))
    elif channel == "Security" and eid == 4624:
        ip, user = d.get("IpAddress") or "-", d.get("TargetUserName") or "?"
        failures = tracker.count(f"fail15|{ip}", now, 900)
        if failures >= 5:
            add("login_after_failures", "critical",
                f"Connexion bureau à distance réussie pour {user} depuis {ip} après {failures} échecs",
                f"login_after_failures|{ip}|{user}|{day}", source_ip=ip, name=user)
    elif (channel == "Security" and eid == 1102) or (channel == "System" and eid == 104):
        log = "de sécurité" if eid == 1102 else f"« {d.get('Channel') or d.get('channel') or 'système'} »"
        add("log_cleared", "critical" if eid == 1102 else "high", f"Journal {log} effacé",
            f"log_cleared|{channel}|{ev['record']}", name=d.get("SubjectUserName"))
    elif channel == "Security" and eid == 4720:
        user = d.get("TargetUserName") or "?"
        add("new_local_account", "medium", f"Compte créé : {user} (par {d.get('SubjectUserName') or '?'})",
            f"account|{user}", name=user)
    elif channel == "Security" and eid in (4728, 4732, 4756):
        sid = d.get("TargetSid") or ""
        group = d.get("TargetUserName") or sid
        member = (d.get("MemberName") if d.get("MemberName") not in (None, "", "-") else d.get("MemberSid")) or "?"
        if sid in _ADMIN_GROUP_SIDS or sid.endswith(_DOMAIN_ADMIN_RIDS):
            add("admin_group_added", "critical" if sid.endswith(_DOMAIN_ADMIN_RIDS) else "high",
                f"{member} ajouté au groupe {group}", f"admin|{member}",
                member=member, name=group, user=d.get("SubjectUserName"))
    elif channel == "Security" and eid == 4698:
        name = (d.get("TaskName") or "").lstrip("\\")
        info = _parse_task_xml(d.get("TaskContent") or "")
        command = info.get("command") or (f"COM {info['com_handler']}" if info.get("com_handler") else "")
        severity, reasons = _rate_command(command)
        if not (name.lower().startswith("microsoft\\") and severity in ("low", "medium")):
            add("new_scheduled_task", _persistence_severity(command, severity),
                f"Nouvelle tâche planifiée : {name}", f"task|{name}|{command[:200]}", name=name,
                command=command[:1000], user=info.get("user") or d.get("SubjectUserName"),
                triggers=info.get("triggers"), reasons=" ; ".join(reasons))
    elif channel == "System" and eid == 7045:
        name, image = d.get("ServiceName") or "?", d.get("ImagePath") or ""
        severity, reasons = _rate_command(image)
        if "kernel" in (d.get("ServiceType") or "").lower():
            reasons.append("pilote noyau")
        add("new_service", _persistence_severity(image, severity), f"Nouveau service installé : {name}",
            f"service|{name}|{image[:200]}", name=name, image=image, user=d.get("AccountName"),
            reasons=" ; ".join(reasons))
    elif (channel == "Security" and eid == 4688) or (channel.endswith("Sysmon/Operational") and eid == 1):
        image = d.get("NewProcessName") or d.get("Image") or ""
        parent_image = d.get("ParentProcessName") or d.get("ParentImage") or ""
        cmdline = d.get("CommandLine") or ""
        for rule, severity, title, extra in _process_findings(
                ntpath.basename(image), image, ntpath.basename(parent_image), parent_image, cmdline,
                watchlist, system_root):
            add(rule, severity, title, f"{rule}|{image.lower()}|{cmdline[:200].lower()}",
                image=image, parent_image=parent_image, command=cmdline[:1000], **extra)
    elif channel.endswith("PowerShell/Operational") and eid == 4104:
        text = (d.get("ScriptBlockText") or "").lower()
        for rx, severity, title in _CMDLINE_RULES:
            if rx.search(text):
                import hashlib
                add("suspicious_script", severity, f"Script PowerShell : {title}",
                    f"script|{hashlib.sha1(text[:4000].encode()).hexdigest()}",
                    command=(d.get("ScriptBlockText") or "")[:1000], path=d.get("Path"))
                break
    elif channel.endswith("Windows Defender/Operational") and eid == 1116:
        threat = d.get("Threat Name") or "?"
        level = (d.get("Severity Name") or "").lower()
        add("defender_detection", "critical" if level in ("severe", "high", "grave", "élevé") else "high",
            f"Menace détectée par Defender : {threat}", f"defender|{threat}|{d.get('Path')}",
            name=threat, path=d.get("Path"), image=d.get("Process Name"), value=d.get("Action Name"))
    elif channel.endswith("Windows Defender/Operational") and eid == 5001:
        add("defender_disabled", "high", "Protection en temps réel de Defender désactivée",
            f"defender_disabled|{day}")
    elif channel.endswith("Windows Defender/Operational") and eid == 5007:
        new = d.get("New Value") or ""
        if "\\exclusions\\" in new.lower():
            add("defender_exclusion", "high", "Exclusion ajoutée à Microsoft Defender", f"defender|{new[:200]}",
                value=new)
    return out

class _EventLogWatcher:
    """Abonnements aux journaux d'événements (wevtapi), un signal par journal."""
    def __init__(self, mon: "_Monitor"):
        import ctypes
        from ctypes import wintypes
        self.ctypes, self.wt, self.mon = ctypes, wintypes, mon
        H = ctypes.c_void_p
        w = ctypes.WinDLL("wevtapi", use_last_error=True)
        w.EvtSubscribe.argtypes = [H, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, H, ctypes.c_void_p,
                                   ctypes.c_void_p, wintypes.DWORD]
        w.EvtSubscribe.restype = H
        w.EvtNext.argtypes = [H, wintypes.DWORD, ctypes.POINTER(H), wintypes.DWORD, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD)]
        w.EvtNext.restype = wintypes.BOOL
        w.EvtRender.argtypes = [H, H, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
        w.EvtRender.restype = wintypes.BOOL
        w.EvtCreateBookmark.argtypes = [wintypes.LPCWSTR]
        w.EvtCreateBookmark.restype = H
        w.EvtUpdateBookmark.argtypes = [H, H]
        w.EvtUpdateBookmark.restype = wintypes.BOOL
        w.EvtClose.argtypes = [H]
        w.EvtClose.restype = wintypes.BOOL
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        k.CreateEventW.restype = wintypes.HANDLE
        k.ResetEvent.argtypes = [wintypes.HANDLE]
        k.WaitForMultipleObjects.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.BOOL,
                                             wintypes.DWORD]
        k.WaitForMultipleObjects.restype = wintypes.DWORD
        self.w, self.k = w, k
        self.subs = []          # [(journal, abonnement, signal, signet)]
        self.tracker = _RateTracker()

    def render(self, handle, flag: int) -> str:
        used, count = self.wt.DWORD(0), self.wt.DWORD(0)
        self.w.EvtRender(None, handle, flag, 0, None, self.ctypes.byref(used), self.ctypes.byref(count))
        if self.ctypes.get_last_error() != 122 or not used.value:          # ERROR_INSUFFICIENT_BUFFER
            return ""
        buf = self.ctypes.create_unicode_buffer(used.value // 2 + 1)
        if not self.w.EvtRender(None, handle, flag, used.value, buf, self.ctypes.byref(used),
                                self.ctypes.byref(count)):
            return ""
        return buf.value

    def subscribe(self):
        bookmarks = self.mon.state.setdefault("bookmarks", {})
        for channel, selects in _EVT_QUERIES.items():
            query = ('<QueryList><Query Id="0">' + "".join(
                f'<Select Path="{channel}">{s}</Select>' for s in selects)
                + "</Query></QueryList>")
            signal = self.k.CreateEventW(None, True, True, None)
            saved = bookmarks.get(channel)
            bookmark = self.w.EvtCreateBookmark(saved) if saved else None
            sub = None
            if bookmark:
                sub = self.w.EvtSubscribe(None, signal, None, query, bookmark, None, None, 3)   # après le signet
            if not sub:
                if bookmark:
                    self.w.EvtClose(bookmark)
                bookmark = self.w.EvtCreateBookmark(None)
                sub = self.w.EvtSubscribe(None, signal, None, query, None, None, None, 1)       # événements futurs
            if sub:
                self.subs.append((channel, sub, signal, bookmark))
            else:
                self.w.EvtClose(bookmark)
                logger.info(f"Surveillance : journal « {channel} » non suivi (absent ou accès refusé).")

    def drain(self, index: int):
        channel, sub, signal, bookmark = self.subs[index]
        handles = (self.ctypes.c_void_p * 32)()
        got_any = False
        while True:
            returned = self.wt.DWORD(0)
            if not self.w.EvtNext(sub, 32, handles, 0, 0, self.ctypes.byref(returned)):
                if self.ctypes.get_last_error() == 259:          # ERROR_NO_MORE_ITEMS
                    self.k.ResetEvent(signal)
                break
            for i in range(returned.value):
                h = handles[i]
                xml = self.render(h, 1)                          # EvtRenderEventXml
                self.w.EvtUpdateBookmark(bookmark, h)
                self.w.EvtClose(h)
                got_any = True
                if xml:
                    self.handle(xml)
        if got_any:
            mark = self.render(bookmark, 2)                       # EvtRenderBookmark
            if mark:
                with self.mon.lock:
                    self.mon.state.setdefault("bookmarks", {})[channel] = mark
                    self.mon.dirty_cache = True

    def handle(self, xml: str):
        if not (self.mon.server_enabled and _monitor_settings(state.config or configparser.ConfigParser())[0]):
            return
        ev = _parse_event_xml(xml)
        if not ev:
            return
        now = time.time()
        try:
            created = datetime.strptime(ev["time"][:19], "%Y-%m-%dT%H:%M:%S")
            if (datetime.utcnow() - created).total_seconds() > 86400:
                return          # reprise après un long arrêt : on ignore le trop ancien
        except ValueError:
            pass
        for rule, severity, title, key, details in _windows_log_findings(
                ev, self.tracker, self.mon.watchlist, os.environ.get("SystemRoot", r"C:\Windows"), now):
            self.mon.add_async(self.mon.event(rule, severity, title, key, **details))
        if ev["id"] == 4104 and self.mon.yara.ready:
            text = ev["data"].get("ScriptBlockText") or ""
            matches = self.mon.yara.scan(data=text.encode("utf-8", "replace")) if text else []
            if matches:
                import hashlib
                worst = max(matches, key=lambda m: _YARA_SEVERITIES.index(m["severity"]))
                self.mon.add_async(self.mon.event(
                    "yara_match", worst["severity"], f"Règle YARA {worst['rule']} : script PowerShell exécuté",
                    f"yara|script|{hashlib.sha1(text[:4000].encode()).hexdigest()}",
                    rules=", ".join(sorted({m['rule'] for m in matches})), description=worst["description"],
                    command=text[:1000], path=ev["data"].get("Path"), ruleset=worst["ruleset"]))

    def run(self):
        self.subscribe()
        if not self.subs:
            return
        n = len(self.subs)
        signals = (self.wt.HANDLE * n)(*[s[2] for s in self.subs])
        while state.running:
            r = self.k.WaitForMultipleObjects(n, signals, False, 2000)
            try:
                if r < n:
                    self.drain(r)
                elif r == 0x102:                 # délai : rattrape un signal manqué (coût négligeable)
                    for i in range(n):
                        self.drain(i)
            except Exception as e:
                logger.warning(f"Surveillance (journaux) : {type(e).__name__}: {e}")
                time.sleep(5)

def event_log_loop(mon: "_Monitor"):
    _background_thread()
    try:
        _EventLogWatcher(mon).run()
    except Exception as e:
        logger.warning(f"Surveillance : journaux d'événements indisponibles ({type(e).__name__}: {e})")

# ── Moteur ───────────────────────────────────────────────────────────────────
class _Monitor:
    def __init__(self):
        self.state = {"snap": {}, "alerted": {}, "queue": [], "yara_cache": {}, "bookmarks": {}}
        self.seen = set()            # (pid, ppid, nom) déjà examinés
        self.first_process_scan = True
        self.watchlist, self.server_enabled, self.watch_at = [], True, 0.0
        self.dirty = self.dirty_cache = False
        self.last_save = 0.0
        # Les journaux d'événements sont lus par un autre fil : état partagé sous verrou
        self.lock = threading.RLock()
        self.pending = []                       # alertes produites hors du passage principal
        self.wake = threading.Event()           # alerte grave : envoi sans attendre le passage suivant
        self.yara = _YaraEngine()
        self.yara_queue = collections.OrderedDict()
        try:
            with open(MONITOR_STATE_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                self.state.update({k: loaded[k] for k in self.state if k in loaded})
        except (OSError, ValueError):
            pass

    def save(self):
        """Écrit l'état si une alerte ou un instantané a changé ; le cache YARA et les
        signets des journaux, eux, au plus toutes les 5 min."""
        with self.lock:
            if not self.dirty and not (self.dirty_cache and time.time() - self.last_save > 300):
                return
            try:
                tmp = MONITOR_STATE_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self.state, f)
                os.replace(tmp, MONITOR_STATE_FILE)
                self.dirty = self.dirty_cache = False
                self.last_save = time.time()
            except OSError as e:
                logger.warning(f"Surveillance : état non enregistré ({e})")

    def event(self, rule, severity, title, key, **details):
        """Construit un événement, sauf s'il a déjà été signalé (dédoublonnage)."""
        with self.lock:
            now = time.time()
            last = self.state["alerted"].get(key)
            if last and now - last < _MONITOR_ALERT_TTL:
                return None
            self.state["alerted"][key] = now
            self.dirty = True
        return {"rule": rule, "severity": severity, "title": title[:200], "key": key[:300],
                "observed_at": datetime.utcnow().isoformat(timespec="seconds"),
                "details": {k: v for k, v in details.items() if v not in (None, "")}}

    def add_async(self, ev):
        """Alerte des journaux : envoyée au prochain passage, ou tout de suite si grave."""
        if not ev:
            return
        with self.lock:
            self.pending.append(ev)
        if ev["severity"] in ("high", "critical"):
            self.wake.set()

    # Analyse YARA
    def yara_enqueue(self, path: str, reason: str, force: bool = False):
        if not self.yara.ready or not path or (not force and _yara_skip(path)):
            return
        with self.lock:
            if len(self.yara_queue) < 20000:
                self.yara_queue.setdefault(path, reason)

    def yara_watch_dirs(self):
        for root, depth in _watched_dirs():
            for path in _walk_files(root, depth, _YARA_FILE_EXT):
                self.yara_enqueue(path, "fichier déposé")

    def yara_drain(self, budget: int) -> list:
        """Analyse la file dans la limite du budget d'octets ; fichiers inchangés ignorés."""
        events, spent = [], 0
        cache = self.state["yara_cache"]
        while spent < budget:
            with self.lock:
                if not self.yara_queue:
                    break
                path, reason = self.yara_queue.popitem(last=False)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if not os.path.isfile(path) or not 0 < st.st_size <= YARA_MAX_FILE:
                continue
            sig = f"{st.st_size}|{int(st.st_mtime)}"
            key = path.lower()
            if cache.get(key) == sig:
                continue
            with self.lock:
                cache.pop(key, None)
                cache[key] = sig
                while len(cache) > _YARA_CACHE_MAX:
                    cache.pop(next(iter(cache)))
                self.dirty_cache = True
            spent += st.st_size
            matches = self.yara.scan(path=path)
            if not matches:
                continue
            worst = max(matches, key=lambda m: _YARA_SEVERITIES.index(m["severity"]))
            rules = ", ".join(sorted({m["rule"] for m in matches}))
            try:
                import hashlib
                with open(path, "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                sha = ""
            events.append(self.event("yara_match", worst["severity"],
                                     f"Règle YARA {worst['rule']} : {ntpath.basename(path)}",
                                     f"yara|{key}|{rules}|{sig}", path=path, rules=rules,
                                     description=worst["description"], sha256=sha, reason=reason,
                                     ruleset=worst["ruleset"]))
        return [e for e in events if e]

    def diff(self, name, current: dict):
        """Éléments nouveaux ou modifiés depuis le dernier instantané (None au premier)."""
        previous = self.state["snap"].get(name)
        if previous != current:
            with self.lock:
                self.state["snap"][name] = current
                self.dirty = True
        if previous is None:
            return None
        return [(k, v, previous.get(k)) for k, v in current.items() if previous.get(k) != v]

    # Processus
    def scan_processes(self) -> list:
        procs = _list_processes()
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        events, alive = [], set()
        for pid, (ppid, name) in procs.items():
            ident = (pid, ppid, name)
            alive.add(ident)
            if ident in self.seen or pid in (0, 4):
                continue
            self.seen.add(ident)
            lname = name.lower()
            image, cmdline = _process_details(pid, lname in _CMDLINE_OF_INTEREST)
            self.yara_enqueue(image, "processus")
            parent = procs.get(ppid)
            parent_name = parent[1] if parent else ""
            parent_image = _process_details(ppid, False)[0] if parent and lname in _SCRIPT_HOSTS else ""
            for rule, severity, title, extra in _process_findings(
                    name, image, parent_name, parent_image, cmdline, self.watchlist, system_root):
                if self.first_process_scan and _SEVERITY_ORDER.index(severity) < 2:
                    continue    # référence : les processus déjà lancés ne signalent que le notable
                ev = self.event(rule, severity, title, f"{rule}|{(image or name).lower()}|{cmdline[:200].lower()}",
                                image=image or name, pid=pid, parent=parent_name, parent_image=parent_image,
                                command=cmdline[:1000], **extra)
                if ev:
                    events.append(ev)
        self.seen &= alive              # oublie les processus terminés (mémoire bornée)
        self.first_process_scan = False
        return events

    # Persistance et configuration système
    def scan_system(self) -> list:
        events = []
        tasks_prev = self.state["snap"].get("tasks")
        tasks, changed = _snapshot_task_files(tasks_prev or {})
        if tasks_prev is not None:
            for rel in changed:
                info = _read_task(rel)
                command = info.get("command") or (f"COM {info['com_handler']}" if info.get("com_handler") else "")
                self.yara_enqueue(_program_file(command), "persistance", force=True)
                severity, reasons = _rate_command(command)
                if rel.lower().startswith("microsoft\\") and severity in ("low", "medium"):
                    continue    # tâches de Windows recréées par les mises à jour
                if info.get("user", "").upper() in ("S-1-5-18", "SYSTEM") or info.get("run_level") == "HighestAvailable":
                    reasons.append("s'exécute avec les privilèges les plus élevés")
                new = rel not in tasks_prev
                ev = self.event("new_scheduled_task" if new else "modified_scheduled_task",
                                _persistence_severity(command, severity),
                                f"{'Nouvelle' if new else 'Modification de la'} tâche planifiée : {rel}",
                                f"task|{rel}|{command[:200]}", name=rel, command=command[:1000],
                                user=info.get("user"), triggers=info.get("triggers"), author=info.get("author"),
                                reasons=" ; ".join(reasons))
                if ev:
                    events.append(ev)
        if tasks != tasks_prev:
            self.state["snap"]["tasks"] = tasks
            self.dirty = True

        for key, value, old in self.diff("autoruns", _snapshot_autoruns()) or []:
            self.yara_enqueue(_program_file(value), "persistance", force=True)
            severity, reasons = _rate_command(value)
            if "\\IFEO\\" in key or "\\Winlogon\\" in key:
                severity = "critical" if "\\IFEO\\" in key else "high"
                reasons.insert(0, "détournement du démarrage de session ou d'un outil d'accessibilité")
            ev = self.event("new_autorun", _persistence_severity(value, severity),
                            f"{'Nouveau' if old is None else 'Modification d’un'} programme au démarrage : {key.rsplit(chr(92), 1)[-1]}",
                            f"autorun|{key}|{value[:200]}", path=key, value=value, previous=old,
                            reasons=" ; ".join(reasons))
            if ev:
                events.append(ev)

        for name, value, old in self.diff("services", _snapshot_services()) or []:
            stype, _, image = value.partition("|")
            self.yara_enqueue(_program_file(image), "persistance", force=True)
            severity, reasons = _rate_command(image)
            if stype in ("1", "2"):
                reasons.append("pilote noyau")
                if not image.lower().startswith(("system32\\drivers", "\\systemroot\\system32\\drivers")):
                    severity = "high" if severity in ("low", "medium") else severity
            ev = self.event("new_service", _persistence_severity(image, severity),
                            f"{'Nouveau' if old is None else 'Modification du'} service : {name}",
                            f"service|{name}|{image[:200]}", name=name, image=image, previous=old,
                            reasons=" ; ".join(reasons))
            if ev:
                events.append(ev)

        admins = {m: "1" for m in _local_group_members("S-1-5-32-544")}
        for member, _v, _o in self.diff("admins", admins) or []:
            ev = self.event("admin_group_added", "high", f"Ajout aux administrateurs locaux : {member}",
                            f"admin|{member}", member=member)
            if ev:
                events.append(ev)

        for account, _v, _o in self.diff("accounts", {a: "1" for a in _local_accounts()}) or []:
            ev = self.event("new_local_account", "medium", f"Nouveau compte local : {account}",
                            f"account|{account}", name=account)
            if ev:
                events.append(ev)

        for key, value, _o in self.diff("defender_exclusions", _defender_exclusions()) or []:
            ev = self.event("defender_exclusion", "high", f"Nouvelle exclusion Microsoft Defender : {value}",
                            f"defender|{key}", path=key, value=value)
            if ev:
                events.append(ev)

        for line, _v, _o in self.diff("hosts", {l: "1" for l in _hosts_lines()}) or []:
            ev = self.event("hosts_file_modified", "medium", "Fichier hosts modifié",
                            f"hosts|{line}", line=line)
            if ev:
                events.append(ev)
        return events

    def scan_software(self) -> list:
        current = {}
        for sw in _registry_software():
            current[(sw.get("product_raw") or sw.get("product") or "").strip()] = sw.get("version") or ""
        events = []
        for name, version, old in self.diff("software", current) or []:
            if old is not None or not name:
                continue    # simple mise à jour de version : suivie par la page Mises à jour
            ev = self.event("new_software", "low", f"Nouveau logiciel installé : {name} {version}".strip(),
                            f"software|{name.lower()}", name=name, version=version)
            if ev:
                events.append(ev)
        return events

    def refresh_watchlist(self, cfg):
        if time.time() - self.watch_at < 1800:
            return
        self.watch_at = time.time()
        try:
            r = requests.get(f"{_base_url(cfg)}/api/agents/{_hostname()}/watchlist",
                             headers={"x-agent-token": cfg.get("main_server", "token", fallback="")},
                             timeout=15, verify=_tls_verify(cfg))
            if r.ok:
                data = r.json() or {}
                self.server_enabled = bool(data.get("enabled", True))
                self.watchlist = [p for p in data.get("products") or [] if isinstance(p, dict)]
                version = data.get("yara_version")
                if version and version != self.yara.version and _yara_mod is not None:
                    self.load_yara_rules(cfg, version)
        except Exception:
            pass    # serveur injoignable : on garde la liste précédente

    def load_yara_rules(self, cfg, version: str):
        r = requests.get(f"{_base_url(cfg)}/api/agents/{_hostname()}/yara-rules",
                         headers={"x-agent-token": cfg.get("main_server", "token", fallback="")},
                         timeout=30, verify=_tls_verify(cfg))
        r.raise_for_status()
        data = r.json() or {}
        for error in self.yara.load(data.get("version") or version, data.get("rulesets") or []):
            logger.warning(f"Surveillance : jeu de règles YARA ignoré — {error}")
        with self.lock:
            self.state["yara_cache"] = {}       # nouvelles règles : les fichiers seront réanalysés
            self.dirty_cache = True
        logger.info(f"Surveillance : règles YARA chargées ({len(self.yara.compiled)} jeu(x)).")

    def flush(self, cfg, events: list):
        """Envoie les déclencheurs (file conservée si le serveur est injoignable)."""
        if len(events) > _MONITOR_MAX_EVENTS_PER_CYCLE:
            extra = len(events) - _MONITOR_MAX_EVENTS_PER_CYCLE
            events = events[:_MONITOR_MAX_EVENTS_PER_CYCLE] + [self.event(
                "event_flood", "medium", f"{extra} autre(s) alerte(s) non transmise(s) en une minute",
                f"flood|{int(time.time() // 3600)}", count=extra) or {}]
        with self.lock:
            events, self.pending = list(self.pending) + events, []
            queue = (self.state["queue"] + [e for e in events if e])[-_MONITOR_QUEUE_MAX:]
        if not queue:
            return
        try:
            r = requests.post(f"{_base_url(cfg)}/api/agents/{_hostname()}/events", json={"events": queue[:100]},
                              headers={"x-agent-token": cfg.get("main_server", "token", fallback="")},
                              timeout=20, verify=_tls_verify(cfg))
            r.raise_for_status()
            sent = queue[:100]
            queue = queue[100:]
            logger.info(f"Surveillance : {len(sent)} alerte(s) envoyée(s) au serveur.")
        except Exception as e:
            logger.warning(f"Surveillance : envoi reporté ({type(e).__name__}), {len(queue)} alerte(s) en file.")
        with self.lock:
            if queue != self.state["queue"]:
                self.state["queue"] = queue
                self.dirty = True

def _monitor_settings(cfg):
    def num(key, default, low, high):
        try:
            return max(low, min(int(cfg.get("monitoring", key, fallback=str(default))), high))
        except ValueError:
            return default
    return (_cfg_bool(cfg, "monitoring", "enabled", True),
            num("process_interval_seconds", 30, 10, 600), num("system_interval_minutes", 5, 1, 120))

def monitor_loop():
    """Boucle de surveillance, en arrière-plan. Un seul processus surveille : le
    service s'il tourne, sinon l'icône de la session."""
    _background_thread()
    time.sleep(20)          # laisse passer le démarrage de la session et le premier rapport
    mon = _Monitor()
    log_thread = None
    next_system = next_software = 0.0
    while state.running:
        cfg = state.config or configparser.ConfigParser()
        enabled, proc_interval, system_minutes = _monitor_settings(cfg)
        if enabled and (SERVICE_MODE or not _service_running()) and config_exists():
            mon.refresh_watchlist(cfg)
            if log_thread is None:
                log_thread = threading.Thread(target=event_log_loop, args=(mon,), daemon=True, name="EventLog")
                log_thread.start()
            if mon.server_enabled:
                events = []
                if time.time() >= next_system:
                    mon.yara_watch_dirs()
                for name, scan, due in (("processus", mon.scan_processes, True),
                                        ("système", mon.scan_system, time.time() >= next_system),
                                        ("logiciels", mon.scan_software, time.time() >= next_software),
                                        ("YARA", lambda: mon.yara_drain(YARA_BUDGET_PER_CYCLE), True)):
                    if not due:
                        continue
                    try:
                        events += scan()
                    except Exception as e:
                        logger.warning(f"Surveillance ({name}) : {type(e).__name__}: {e}")
                    if name == "système" and due:
                        next_system = time.time() + system_minutes * 60
                    if name == "logiciels" and due:
                        next_software = time.time() + 15 * 60
                mon.flush(cfg, [e for e in events if e])
                with mon.lock:
                    for key, ts in list(mon.state["alerted"].items()):
                        if time.time() - ts > 30 * 86400:
                            del mon.state["alerted"][key]
                            mon.dirty = True
                mon.save()
        mon.wake.wait(proc_interval)      # réveillé tout de suite par une alerte grave des journaux
        mon.wake.clear()

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
    token    = cfg.get("main_server", "token",      fallback="changeme-secret-token")
    do_ports = cfg.getboolean("agent", "port_scan",  fallback=False)
    url      = f"{_base_url(cfg)}/api/agents/report"
    verify   = _tls_verify(cfg)

    _set_status("Collecte en cours…")

    software   = collect_software()
    open_ports = scan_ports() if do_ports else []
    compliance = _collect_compliance()
    ip_addresses = _get_local_ips()
    logged_users = _collect_logged_users()
    update_check = collect_outdated_software()
    if update_check.get("ok"):
        compliance.setdefault("pending_updates", update_check["count"])

    payload = {
        "hostname":      _hostname(),
        "os":            "Windows",
        "release":       _windows_release(),
        "os_build":      _os_build(),
        "agent_version": AGENT_VERSION,
        "timestamp":     datetime.now().isoformat(),
        "software":      software,
        "open_ports":    open_ports,
        "compliance":    compliance,
        "update_check":  update_check,
        "ip_addresses":  ip_addresses,
        "logged_users":  logged_users,
        "log_tail":      read_log_tail(80),
    }

    delay = 5
    for attempt in range(1, max_attempts + 1):
        try:
            # La corrélation CVE est effectuée par le serveur avant sa réponse.
            # Sur un poste avec beaucoup de logiciels, 30 s ne suffit pas et
            # provoquait un faux « serveur injoignable » malgré un rapport reçu.
            resp = requests.post(url, json=payload, headers={"x-agent-token": token},
                                 timeout=(10, 300), verify=verify)
            resp.raise_for_status()
            data  = resp.json()
            with state.lock:
                state.connected  = True
                # L'agent collecte et transmet uniquement. La qualification des
                # CVE et leur affichage sont du ressort du serveur/dashboard.
                state.vuln_count = 0
            _set_status("Rapport envoyé au serveur", connected=True)
            logger.info("Rapport envoyé au serveur pour analyse.")
            return data
        except requests.exceptions.Timeout as e:
            _set_status(f"⏳ Analyse serveur trop longue — retry {delay}s (essai {attempt}/{max_attempts})", connected=False)
            logger.warning(f"Délai d'attente du rapport: {type(e).__name__}")
        except requests.exceptions.ConnectionError as e:
            if isinstance(e, requests.exceptions.SSLError):
                _set_status(f"❌ Certificat HTTPS refusé — retry {delay}s (Configurer → vérification du certificat)", connected=False)
                logger.warning(f"Erreur TLS: {str(e)[:200]}")
            else:
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
        if SERVICE_MODE or not _service_running():
            send_report()
        else:
            _set_status("Rapports envoyés par le service système", connected=True)
            refresh_user_winget()
        cfg      = state.config or configparser.ConfigParser()
        try:
            interval = max(1, int(cfg.get("agent", "interval_minutes", fallback="60"))) * 60
        except ValueError:   # champ vide ou invalide : ne pas tuer le thread d'envoi
            interval = 3600
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
    token = cfg.get("main_server", "token", fallback="changeme-secret-token")
    try:
        r = requests.post(
            f"{_base_url(cfg)}/api/agents/{_hostname()}/heartbeat",
            json={"os": "Windows", "release": _windows_release(),
                   "os_build": _os_build()},
            headers={"x-agent-token": token},
            timeout=5,
            verify=_tls_verify(cfg),
        )
        if r.ok and (r.json() or {}).get("refresh_updates"):
            # Demandé depuis le dashboard : nouvelle vérification winget + rapport immédiat
            logger.info("Vérification des mises à jour demandée par le serveur.")
            _UPDATE_CACHE["force"] = True
            state.scan_event.set()
    except Exception:
        pass

def heartbeat_loop():
    """Boucle de heartbeat — s'exécute en parallèle de l'agent loop."""
    time.sleep(5)  # courte attente initiale pour laisser la config se charger
    while state.running:
        if SERVICE_MODE or not _service_running():
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
    token = cfg.get("main_server", "token", fallback="changeme-secret-token")
    base  = _base_url(cfg)
    try:
        r = requests.get(
            f"{base}/api/agent/version",
            headers={"x-agent-token": token},
            timeout=10,
            verify=_tls_verify(cfg),
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
            # Automatique par défaut (même comportement que les agents Linux/macOS).
            # `[agent] auto_update = false` dans agent.conf repasse en confirmation manuelle.
            auto = SERVICE_MODE or _cfg_bool(cfg, "agent", "auto_update", True)
            if auto:
                if state.tray_icon and TRAY_OK:
                    try:
                        state.tray_icon.notify(
                            f"Mise à jour v{server_version} installée automatiquement.",
                            "Heimdall Security Agent")
                    except Exception:
                        pass
                threading.Thread(
                    target=lambda: _do_self_update(base, token, data.get("download_url", "")),
                    daemon=True, name="SelfUpdate"
                ).start()
                return True

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
                                target=lambda: _do_self_update(base, token, data.get("download_url", "")),
                                daemon=True, name="SelfUpdate"
                            ).start()
                    state.tk_root.after(0, _gui_ask)
                else:
                    _do_self_update(base, token, data.get("download_url", ""))
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


def _do_self_update(base: str, token: str, url: str):
    """Télécharge le nouvel exe, écrit un .bat de remplacement et quitte."""
    if not getattr(sys, "frozen", False):
        logger.warning("Auto-update: non disponible en mode source Python.")
        _dlg_info("Mise à jour",
                  "Mise à jour automatique disponible uniquement pour le .exe compilé.\n"
                  "Téléchargez la nouvelle version manuellement.")
        return
    curr_exe     = os.path.abspath(sys.executable)
    new_exe      = curr_exe + ".update"
    download_url = url or f"{base}/api/download/agent/windows/exe"
    try:
        _set_status("⬇️  Téléchargement de la mise à jour…")
        resp = requests.get(
            download_url,
            headers={"x-agent-token": token},
            timeout=120,
            stream=True,
            verify=_tls_verify(),
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
        # La nouvelle version doit au moins démarrer. Sinon on garde l'actuelle : une erreur
        # au chargement laisserait l'agent arrêté, donc incapable de se remettre à jour.
        _set_status("🔎 Vérification de la mise à jour…")
        check = subprocess.run([new_exe, "--selftest"], capture_output=True, text=True, errors="replace",
                               timeout=180, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if check.returncode != 0:
            detail = ((check.stderr or check.stdout).strip().splitlines() or ["aucune sortie"])[-1][:200]
            raise ValueError(f"la nouvelle version ne démarre pas (code {check.returncode} : {detail}) "
                             f"— version actuelle conservée")
        # Windows autorise le renommage d'un exe en cours d'exécution : on écarte
        # l'actuel (.old, supprimé au prochain démarrage), on met le nouveau à sa place
        # et on le lance — sans script cmd intermédiaire.
        old_exe = curr_exe + ".old"
        try:
            os.remove(old_exe)
        except FileNotFoundError:
            pass
        os.replace(curr_exe, old_exe)
        try:
            os.replace(new_exe, curr_exe)
        except Exception:
            os.replace(old_exe, curr_exe)
            raise
        logger.info("Mise à jour installée — redémarrage sur la nouvelle version…")
        subprocess.Popen([curr_exe] + (["--service"] if SERVICE_MODE else []), close_fds=True,
                         creationflags=subprocess.DETACHED_PROCESS)
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


# ─── Service : démarrage avec la machine, avant toute ouverture de session ────
# La clé Run (ci-dessus) ne lance l'agent qu'à l'ouverture d'une session : sur un
# serveur où personne ne se connecte, il ne tournerait jamais. Le service est une
# tâche planifiée « au démarrage », sous le compte SYSTEM, qui lance l'agent sans
# icône (--service). L'icône, si elle est lancée dans une session, reste l'interface
# et laisse le service envoyer rapports et heartbeats (pas de doublon).
_SERVICE_TASK  = "HeimdallSecurityAgentService"
_SERVICE_MUTEX = "Global\\HeimdallAgentService"
_SERVICE_CONF  = os.path.join(_PROGRAMDATA_DIR, "agent.conf")
_service_installed_cache = None

def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def _service_running() -> bool:
    """Le service tourne-t-il ? (mutex global créé par le processus --service)"""
    try:
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        h = k32.OpenMutexW(0x00100000, False, _SERVICE_MUTEX)  # SYNCHRONIZE
        if h:
            k32.CloseHandle(h)
            return True
        # Créé par SYSTEM : un utilisateur standard peut se voir refuser l'accès, mais
        # le mutex existe bien (ERROR_ACCESS_DENIED), donc le service tourne.
        return ctypes.get_last_error() == 5
    except Exception:
        pass
    return False

def _is_service_installed(refresh: bool = False) -> bool:
    global _service_installed_cache
    if _service_installed_cache is None or refresh:
        try:
            r = subprocess.run(["schtasks", "/Query", "/TN", _SERVICE_TASK],
                               capture_output=True, timeout=15)
            _service_installed_cache = r.returncode == 0
        except Exception:
            _service_installed_cache = False
    return _service_installed_cache

def _ps_quote(v: str) -> str:
    return "'" + str(v).replace("'", "''") + "'"

def _run_powershell(script: str, timeout: int = 60):
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-Command", script], capture_output=True, text=True, errors="replace",
                          timeout=timeout)

def _install_service():
    """Crée la tâche « au démarrage » (SYSTEM) et la démarre. Droits administrateur requis.
    Returns (ok, message)."""
    if not _is_admin():
        return False, "Droits administrateur requis."
    if not config_exists():
        return False, "Agent non configuré : renseignez d'abord le serveur et le token."
    exe = os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)
    try:
        # SYSTEM ne voit pas le %APPDATA% de l'utilisateur : copie de la configuration
        # dans ProgramData, lisible uniquement par SYSTEM et les administrateurs (token).
        cfg = load_config()
        os.makedirs(_PROGRAMDATA_DIR, exist_ok=True)
        if os.path.abspath(_config_path_existing() or "") != os.path.abspath(_SERVICE_CONF):
            with open(_SERVICE_CONF, "w", encoding="utf-8") as f:
                cfg.write(f)
        subprocess.run(["icacls", _SERVICE_CONF, "/inheritance:r", "/grant:r",
                        "*S-1-5-18:F", "*S-1-5-32-544:F"], capture_output=True, timeout=15)
        # Register-ScheduledTask plutôt que schtasks : schtasks ne sait pas retirer la
        # limite d'exécution par défaut de 72 h, qui couperait l'agent au bout de 3 jours.
        script = (
            "$ErrorActionPreference='Stop';"
            f"$a=New-ScheduledTaskAction -Execute {_ps_quote(exe)} -Argument '--service';"
            "$t=New-ScheduledTaskTrigger -AtStartup;"
            "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
            "$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 "
            "-RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries "
            "-DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew;"
            f"Register-ScheduledTask -TaskName {_ps_quote(_SERVICE_TASK)} -Action $a -Trigger $t "
            "-Principal $p -Settings $s -Description 'Heimdall Security Agent (demarrage de la machine)' -Force | Out-Null;"
            f"Start-ScheduledTask -TaskName {_ps_quote(_SERVICE_TASK)}"
        )
        r = _run_powershell(script)
        if r.returncode != 0:
            return False, ((r.stderr or r.stdout).strip().splitlines() or ["échec"])[-1][:300]
    except Exception as e:
        return False, str(e)[:300]
    _is_service_installed(refresh=True)
    logger.info("Service (tâche au démarrage) installé.")
    return True, "L'agent démarrera désormais avec la machine, avant toute ouverture de session."

def _uninstall_service():
    if not _is_admin():
        return False, "Droits administrateur requis."
    r = _run_powershell(
        f"Stop-ScheduledTask -TaskName {_ps_quote(_SERVICE_TASK)} -ErrorAction SilentlyContinue;"
        f"Unregister-ScheduledTask -TaskName {_ps_quote(_SERVICE_TASK)} -Confirm:$false -ErrorAction SilentlyContinue")
    # Arrêt du processus --service (Stop-ScheduledTask ne suffit pas après une auto-mise à jour,
    # le processus relancé ne dépendant plus de la tâche)
    _run_powershell("Get-CimInstance Win32_Process -Filter \"Name='HeimdallAgent.exe'\" | "
                    "Where-Object { $_.CommandLine -like '*--service*' } | "
                    "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }")
    _is_service_installed(refresh=True)
    logger.info("Service (tâche au démarrage) retiré.")
    return True, "Le démarrage avec la machine est désactivé."

def _run_elevated_and_wait(flag: str) -> bool:
    """Relance l'agent avec `flag` en administrateur (invite UAC) et attend sa fin."""
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
                    ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                    ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]
    frozen = getattr(sys, "frozen", False)
    exe = sys.executable
    params = flag if frozen else f'"{os.path.abspath(__file__)}" {flag}'
    info = SHELLEXECUTEINFOW(cbSize=ctypes.sizeof(SHELLEXECUTEINFOW), fMask=0x40,  # NOCLOSEPROCESS
                             lpVerb="runas", lpFile=exe, lpParameters=params, nShow=0)
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        return False  # UAC refusée
    ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, 120000)
    code = wintypes.DWORD()
    ctypes.windll.kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    ctypes.windll.kernel32.CloseHandle(info.hProcess)
    return code.value == 0

def _on_toggle_service(_icon=None, _item=None):
    enable = not _is_service_installed()
    def _work():
        ok = _run_elevated_and_wait("--service-install" if enable else "--service-uninstall")
        _is_service_installed(refresh=True)
        if ok:
            _dlg_info("Heimdall — Démarrage avec la machine",
                      "Activé : l'agent démarre désormais avec la machine, même sans session ouverte.\n"
                      "L'icône reste disponible quand vous êtes connecté."
                      if enable else "Désactivé : l'agent ne démarrera plus avant l'ouverture de session.")
        else:
            _dlg_error("Heimdall — Démarrage avec la machine",
                       "Opération annulée ou refusée (droits administrateur requis).\n"
                       f"Détails dans le journal : {LOG_FILE}")
    threading.Thread(target=_work, daemon=True, name="ToggleService").start()

def _run_service():
    """Mode --service : pas d'icône ni de fenêtre, rapports + heartbeat + mises à jour."""
    import ctypes
    mutex = ctypes.windll.kernel32.CreateMutexW(None, False, _SERVICE_MUTEX)
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        logger.info("Service déjà en cours d'exécution — sortie.")
        return
    logger.info(f"Agent démarré en mode service (v{AGENT_VERSION}).")
    while state.running and not config_exists():
        logger.error(f"Configuration introuvable ({_SERVICE_CONF}) — nouvelle tentative dans 60 s.")
        time.sleep(60)
    load_config()
    threading.Thread(target=heartbeat_loop, daemon=True, name="Heartbeat").start()
    threading.Thread(target=update_loop,    daemon=True, name="UpdateCheck").start()
    threading.Thread(target=monitor_loop,   daemon=True, name="Monitor").start()
    agent_loop()
    ctypes.windll.kernel32.CloseHandle(mutex)

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

    logo = _logo_image(sz - 8, eye_only=True)
    if logo is not None:
        # Logo Heimdall (œil), centré ; grisé tant que l'agent n'est pas connecté.
        if logo.width > sz:
            logo = logo.resize((sz, max(1, round(logo.height * sz / logo.width))), Image.LANCZOS)
        if not connected:
            alpha = logo.getchannel("A")
            logo = Image.merge("RGBA", (*logo.convert("L").split() * 3, alpha))
        img.paste(logo, ((sz - logo.width) // 2, (sz - logo.height) // 2), logo)
    else:
        # Repli si le logo est introuvable : bouclier + H
        shield_col = (20, 90, 200) if connected else (80, 80, 80)
        pts = [(sz // 2, 3), (sz - 5, sz // 5), (sz - 5, sz // 2),
               (sz // 2, sz - 3), (5, sz // 2), (5, sz // 5)]
        d.polygon(pts, fill=shield_col, outline=(180, 200, 255, 140))
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
    if _service_running():
        # Le service fait les envois réguliers ; un scan demandé depuis l'icône part tout de suite
        threading.Thread(target=send_report, daemon=True, name="ScanNow").start()
    else:
        state.scan_event.set()

def _on_open_dashboard(_icon=None, _item=None):
    webbrowser.open(_base_url())

def _on_view_logs(_icon=None, _item=None):
    """Ouvre le fichier de log local — inspection rapide en cas de souci."""
    try:
        os.startfile(LOG_FILE)
    except Exception:
        try:
            subprocess.Popen(["notepad.exe", LOG_FILE])
        except Exception as e:
            logger.error(f"Impossible d'ouvrir le fichier de log: {e}")
            _msgbox("Heimdall — Logs", f"Fichier de log :\n{LOG_FILE}", 0x40)

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

    # 1 bis. Retirer le service (démarrage avec la machine) — demande les droits admin
    if _is_service_installed(refresh=True):
        ok = _uninstall_service()[0] if _is_admin() else _run_elevated_and_wait("--service-uninstall")
        if not ok:
            logger.warning("Service non retiré (droits administrateur refusés).")

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
                f'del /F /Q "{exe_path}.old" 2>nul\r\n'
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
        "  • retire le démarrage automatique (et le service, droits admin)\n"
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
    P = _pal()
    dlg = tk.Toplevel(state.tk_root)
    dlg.title("Heimdall — Configuration")
    dlg.geometry("480x640")
    dlg.resizable(False, False)
    dlg.configure(bg=P["card"])
    _apply_window_icon(dlg)
    dlg.grab_set()
    dlg.focus_force()
    dlg.lift()

    # Centrage
    dlg.update_idletasks()
    sw = dlg.winfo_screenwidth()
    sh = dlg.winfo_screenheight()
    dlg.geometry(f"+{(sw - 480) // 2}+{max(0, (sh - 640) // 2)}")

    cfg = state.config or configparser.ConfigParser()

    header = tk.Frame(dlg, bg=P["bg"])
    header.pack(fill="x")
    logo = _logo_photo(44)
    if logo is not None:
        dlg._heimdall_logo = logo
        tk.Label(header, image=logo, bg=P["bg"]).pack(side="left", padx=(16, 8), pady=8)
    tk.Label(header, text="Heimdall Security — Configuration Agent",
             bg=P["bg"], fg=P["title"], font=("Segoe UI", 11, "bold"),
             pady=10).pack(side="left", fill="x", expand=True, anchor="w")

    frame = tk.Frame(dlg, bg=P["card"], padx=25, pady=12)
    frame.pack(fill="both", expand=True)

    fields = [
        ("Adresse serveur",  "main_server", "host",             cfg.get("main_server", "host",             fallback="127.0.0.1")),
        ("Port",             "main_server", "port",             cfg.get("main_server", "port",             fallback="4000")),
        ("Token secret",     "main_server", "token",            cfg.get("main_server", "token",            fallback="changeme-secret-token")),
        ("Intervalle (min)", "agent",       "interval_minutes", cfg.get("agent",       "interval_minutes", fallback="60")),
    ]
    entries = {}

    for i, (label, sec, key, val) in enumerate(fields):
        tk.Label(frame, text=label, bg=P["card"], fg=P["muted"],
                 font=("Segoe UI", 9)).grid(row=i, column=0, sticky="w", pady=7)
        e = tk.Entry(frame, bg=P["input"], fg=P["fg"], font=("Segoe UI", 10),
                     bd=0, relief="flat", insertbackground=P["fg"], width=30,
                     show="*" if key == "token" else "")
        e.insert(0, val)
        e.grid(row=i, column=1, padx=(12, 0), pady=7, sticky="ew")
        entries[(sec, key)] = e

    def _check(text, var, row):
        tk.Checkbutton(frame, text=text, variable=var, bg=P["card"], fg=P["muted"],
                       activebackground=P["card"], activeforeground=P["fg"],
                       selectcolor=P["input"], font=("Segoe UI", 9)
                       ).grid(row=row, column=0, columnspan=2, sticky="w", pady=5)

    ps_var = tk.BooleanVar(value=cfg.getboolean("agent", "port_scan", fallback=False))
    _check("Activer le scan de ports réseau", ps_var, len(fields))

    autostart_var = tk.BooleanVar(value=_is_autostart_enabled())
    _check("Démarrer automatiquement avec Windows", autostart_var, len(fields) + 1)

    auto_update_var = tk.BooleanVar(value=_cfg_bool(cfg, "agent", "auto_update", True))
    _check("Mise à jour automatique (sans confirmation)", auto_update_var, len(fields) + 2)

    # Connexion chiffrée : HTTPS et vérification du certificat du serveur
    https_var  = tk.BooleanVar(value=_cfg_bool(cfg, "main_server", "use_https", False))
    verify_var = tk.BooleanVar(value=_cfg_bool(cfg, "main_server", "verify_ssl", True))
    _add_https_options(frame, P, len(fields) + 3, https_var, verify_var)

    # Apparence : sombre / clair / suivre le thème Windows
    theme_row = len(fields) + 5
    tk.Label(frame, text="Apparence", bg=P["card"], fg=P["muted"],
             font=("Segoe UI", 9)).grid(row=theme_row, column=0, sticky="w", pady=7)
    theme_var = tk.StringVar(value=THEME_LABELS[_theme_setting()])
    theme_menu = tk.OptionMenu(frame, theme_var, *THEME_LABELS.values())
    theme_menu.config(bg=P["input"], fg=P["fg"], activebackground=P["input"],
                      activeforeground=P["fg"], relief="flat", bd=0,
                      highlightthickness=0, font=("Segoe UI", 10), anchor="w")
    theme_menu["menu"].config(bg=P["input"], fg=P["fg"], font=("Segoe UI", 10))
    theme_menu.grid(row=theme_row, column=1, padx=(12, 0), pady=7, sticky="ew")

    frame.columnconfigure(1, weight=1)

    def _save():
        h  = entries[("main_server", "host")].get().strip()
        p  = entries[("main_server", "port")].get().strip()
        t  = entries[("main_server", "token")].get().strip()
        iv = entries[("agent", "interval_minutes")].get().strip()
        if not h or not p or not t:
            _dlg_error("Erreur", "Tous les champs sont obligatoires.", parent=dlg)
            return
        try:
            int(p)
        except ValueError:
            _dlg_error("Erreur", "Le port doit être un entier.", parent=dlg)
            return
        theme_key = next((k for k, v in THEME_LABELS.items() if v == theme_var.get()), "dark")
        save_config(h, p, t, iv, ps_var.get(), theme=theme_key,
                    use_https=https_var.get(), verify_ssl=verify_var.get(),
                    auto_update=auto_update_var.get())
        if autostart_var.get() != _is_autostart_enabled():
            _set_autostart(autostart_var.get())
        _dlg_info("Sauvegarde", "Configuration mise \u00e0 jour.\nElle sera utilis\u00e9e d\u00e8s le prochain scan.\n"
                                "L'apparence s'applique \u00e0 la prochaine ouverture de cette fen\u00eatre.", parent=dlg)
        dlg.destroy()

    btn_bar = tk.Frame(dlg, bg=P["card"], padx=25, pady=10)
    btn_bar.pack(fill="x", side="bottom")
    tk.Button(btn_bar, text="Sauvegarder", bg=P["accent"], fg=P["accent_fg"],
              font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=7,
              cursor="hand2", command=_save).pack(side="right", padx=(6, 0))
    tk.Button(btn_bar, text="Annuler", bg=P["btn_bg"], fg=P["btn_fg"],
              font=("Segoe UI", 10), relief="flat", padx=20, pady=7,
              cursor="hand2", command=dlg.destroy).pack(side="right")


# ─── Assistant premier lancement ─────────────────────────────────────────────
class SetupWizard(tk.Toplevel):
    """Wizard de configuration — Toplevel (jamais un second tk.Tk)."""
    def __init__(self, parent, default_host="", default_port="4000", default_token="",
                 default_https=False, default_verify=True):
        super().__init__(parent)
        P = self._P = _pal()
        self.title("Heimdall Agent — Installation")
        self.geometry("480x770")
        self.resizable(False, False)
        self.configure(bg=P["bg"])
        _apply_window_icon(self)
        self.result = False
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Centrage
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw - 480) // 2}+{max(0, (sh - 770) // 2)}")

        self._logo = _logo_photo(96)
        if self._logo is not None:
            tk.Label(self, image=self._logo, bg=P["bg"]).pack(pady=(18, 4))
        else:
            tk.Label(self, text="HEIMDALL", font=("Segoe UI", 28, "bold"),
                     bg=P["bg"], fg=P["accent"]).pack(pady=(22, 4))
        tk.Label(self, text="Heimdall Security Agent",
                 bg=P["bg"], fg=P["fg"], font=("Segoe UI", 16, "bold")).pack()
        tk.Label(self, text="Configurez la connexion au serveur Heimdall",
                 bg=P["bg"], fg=P["muted"], font=("Segoe UI", 10)).pack(pady=(4, 12))

        card = tk.Frame(self, bg=P["card"], padx=28, pady=18)
        card.pack(fill="both", expand=True, padx=22)

        rows = [
            ("Adresse du serveur", default_host or "127.0.0.1", False),
            ("Port",               default_port or "4000",       False),
            ("Token secret",       default_token or "",           True),
            ("Intervalle (min)",   "60",                          False),
        ]
        self._entries = []
        for i, (lbl, val, secret) in enumerate(rows):
            tk.Label(card, text=lbl, bg=P["card"], fg=P["muted"],
                     font=("Segoe UI", 9)).grid(row=i, column=0, sticky="w", pady=8)
            e = tk.Entry(card, bg=P["input"], fg=P["fg"], font=("Segoe UI", 11),
                         bd=0, relief="flat", insertbackground=P["fg"], width=28,
                         show="*" if secret else "")
            e.insert(0, val)
            e.grid(row=i, column=1, padx=(16, 0), sticky="ew", pady=8)
            self._entries.append(e)

        def _check(text, var, row):
            tk.Checkbutton(card, text=text, variable=var, bg=P["card"], fg=P["muted"],
                           activebackground=P["card"], activeforeground=P["fg"],
                           selectcolor=P["input"], font=("Segoe UI", 9)
                           ).grid(row=row, column=0, columnspan=2, sticky="w", pady=4)

        self._ps_var = tk.BooleanVar(value=False)
        _check("Activer le scan de ports réseau", self._ps_var, len(rows))
        self._autostart_var = tk.BooleanVar(value=True)
        _check("Démarrer automatiquement avec Windows", self._autostart_var, len(rows) + 1)
        self._auto_update_var = tk.BooleanVar(value=True)
        _check("Mise à jour automatique (sans confirmation)", self._auto_update_var, len(rows) + 2)

        self._https_var  = tk.BooleanVar(value=default_https)
        self._verify_var = tk.BooleanVar(value=default_verify)
        _add_https_options(card, P, len(rows) + 3, self._https_var, self._verify_var)

        tk.Label(card, text="Apparence", bg=P["card"], fg=P["muted"],
                 font=("Segoe UI", 9)).grid(row=len(rows) + 5, column=0, sticky="w", pady=8)
        self._theme_var = tk.StringVar(value=THEME_LABELS[_theme_setting()])
        theme_menu = tk.OptionMenu(card, self._theme_var, *THEME_LABELS.values())
        theme_menu.config(bg=P["input"], fg=P["fg"], activebackground=P["input"],
                          activeforeground=P["fg"], relief="flat", bd=0,
                          highlightthickness=0, font=("Segoe UI", 10), anchor="w")
        theme_menu["menu"].config(bg=P["input"], fg=P["fg"], font=("Segoe UI", 10))
        theme_menu.grid(row=len(rows) + 5, column=1, padx=(16, 0), pady=8, sticky="ew")
        card.columnconfigure(1, weight=1)

        self._status_lbl = tk.Label(self, text="", bg=P["bg"], fg=P["muted"],
                                    font=("Segoe UI", 9))
        self._status_lbl.pack(pady=(8, 0))

        btn_frame = tk.Frame(self, bg=P["bg"])
        btn_frame.pack(pady=12)
        tk.Button(btn_frame, text="  Tester la connexion  ",
                  bg=P["btn_bg"], fg=P["btn_fg"], font=("Segoe UI", 10),
                  relief="flat", padx=0, pady=9, cursor="hand2",
                  command=self._test).pack(side="left", padx=(0, 8))
        tk.Button(btn_frame, text="  Installer et démarrer  ",
                  bg=P["accent"], fg=P["accent_fg"], font=("Segoe UI", 11, "bold"),
                  relief="flat", padx=0, pady=9, cursor="hand2",
                  command=self._install).pack(side="left")

    def _get_fields(self):
        return [e.get().strip() for e in self._entries]

    def _test(self):
        fields = self._get_fields()
        host, port, token = fields[0], fields[1], fields[2]
        P = self._P
        self._status_lbl.config(text="Test en cours...", fg=P["muted"])
        self.update()
        use_https = self._https_var.get()
        verify    = self._verify_var.get() if use_https else True
        if use_https and not verify:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        try:
            r = requests.get(
                f"{'https' if use_https else 'http'}://{host}:{port}/api/ping",
                headers={"x-agent-token": token},
                timeout=5,
                verify=verify,
            )
            if r.status_code == 200:
                self._status_lbl.config(text="Connexion OK — token valide", fg=P["ok"])
            elif r.status_code == 401:
                self._status_lbl.config(text="Token incorrect (401 Unauthorized)", fg=P["err"])
            else:
                self._status_lbl.config(text=f"Serveur repond {r.status_code}", fg=P["warn"])
        except requests.exceptions.SSLError:
            self._status_lbl.config(
                text="Certificat HTTPS refusé — décochez « Vérifier le certificat » ou installez un certificat valide",
                fg=P["err"], wraplength=420)
        except requests.exceptions.ConnectionError:
            self._status_lbl.config(text=f"Serveur inaccessible ({host}:{port})", fg=P["err"])
        except Exception as e:
            self._status_lbl.config(text=f"Erreur : {str(e)[:50]}", fg=P["err"])

    def _install(self):
        host, port, token, interval = self._get_fields()
        if not host or not port:
            _dlg_error("Erreur", "Adresse et port sont obligatoires.", parent=self)
            return
        if not token:
            _dlg_error("Erreur", "Le token secret est obligatoire (AGENT_AUTH_TOKEN du serveur).", parent=self)
            return
        try:
            int(port)
            int(interval or "60")
        except ValueError:
            _dlg_error("Erreur", "Le port et l'intervalle doivent être des nombres entiers.", parent=self)
            return
        interval = interval or "60"
        theme_key = next((k for k, v in THEME_LABELS.items() if v == self._theme_var.get()), "dark")
        save_config(host, port, token, interval, self._ps_var.get(), theme=theme_key,
                    use_https=self._https_var.get(), verify_ssl=self._verify_var.get(),
                    auto_update=self._auto_update_var.get())
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


# ─── Configuration depuis la ligne de commande ────────────────────────────────
def _apply_cli_config(args):
    """Enregistre --server/--port/--token dans agent.conf (sans assistant), en
    conservant les autres réglages déjà présents (intervalle, clé API CVE…)."""
    had_config = config_exists()
    prev  = load_config()
    token = args.token or (prev.get("main_server", "token", fallback="") if had_config else "")
    if not token or token == "changeme-secret-token":
        msg = "Token manquant : ajoutez --token <AGENT_AUTH_TOKEN> (visible côté serveur)."
        logger.error(msg)
        _msgbox("Heimdall Agent — Configuration", msg, 0x10)
        sys.exit(2)
    # None = conserver la valeur déjà en config (défaut : HTTP, certificat vérifié)
    use_https   = True if args.https else (False if args.http else None)
    verify_ssl  = False if args.no_verify_ssl else None
    auto_update = False if args.no_auto_update else None
    save_config(
        args.server.strip(), args.port, token,
        prev.get("agent", "interval_minutes", fallback="60"),
        prev.getboolean("agent", "port_scan", fallback=False),
        use_https=use_https, verify_ssl=verify_ssl, auto_update=auto_update,
    )
    logger.info(f"Serveur configuré : {_base_url()}")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    if "--selftest" in sys.argv[1:]:
        # Le module entier s'est chargé : cette version démarre (utilisé par la mise à jour)
        print(f"Heimdall Agent {AGENT_VERSION} : OK")
        return
    parser = argparse.ArgumentParser(description="Heimdall Mini Agent (Windows)")
    parser.add_argument("--once",       action="store_true", help="Envoie unique puis exit")
    parser.add_argument("--scan-ports", action="store_true", help="Forcer scan réseau")
    parser.add_argument("--no-tray",    action="store_true", help="Mode console sans icône")
    parser.add_argument("--install",    action="store_true", help="Créer la tâche planifiée")
    parser.add_argument("--server",     default="",          help="IP du serveur Heimdall")
    parser.add_argument("--port",       default="4000",      help="Port du serveur Heimdall")
    parser.add_argument("--token",      default="",          help="Token secret")
    parser.add_argument("--silent",     action="store_true",
                        help="Installation sans assistant : enregistre --server/--port/--token puis démarre")
    parser.add_argument("--autostart",  action="store_true", help="Démarrer automatiquement avec Windows")
    parser.add_argument("--https",      action="store_true", help="Se connecter au serveur en HTTPS")
    parser.add_argument("--http",       action="store_true", help="Se connecter au serveur en HTTP (désactive HTTPS)")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="HTTPS : ne pas vérifier le certificat (certificat auto-signé)")
    parser.add_argument("--no-auto-update", action="store_true",
                        help="Désactiver la mise à jour automatique (demande confirmation à la place)")
    parser.add_argument("--service",    action="store_true",
                        help="Mode service (sans icône) — lancé par la tâche « au démarrage »")
    parser.add_argument("--service-install", action="store_true",
                        help="Démarrer l'agent avec la machine, avant toute session (admin requis)")
    parser.add_argument("--service-uninstall", action="store_true",
                        help="Ne plus démarrer l'agent avec la machine (admin requis)")
    parser.add_argument("--logs",       action="store_true", help="Afficher les derniers logs locaux puis exit")
    parser.add_argument("-f", "--follow", action="store_true", help="Avec --logs : suivre en direct")
    parser.add_argument("--lines",      type=int, default=200, help="Avec --logs : nombre de lignes (défaut 200)")
    args = parser.parse_args()

    if args.logs:
        print(f"# {LOG_FILE}\n")
        for line in read_log_tail(args.lines):
            print(line)
        if args.follow:
            print("\n--- Suivi en direct (Ctrl+C pour arrêter) ---")
            try:
                with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    while True:
                        line = f.readline()
                        if line:
                            print(line, end="")
                        else:
                            time.sleep(0.5)
            except (FileNotFoundError, KeyboardInterrupt):
                pass
        sys.exit(0)

    if getattr(sys, "frozen", False):
        try:
            os.remove(os.path.abspath(sys.executable) + ".old")  # reste d'une mise à jour
        except OSError:
            pass

    if args.install:
        install_scheduled_task()

    if args.service:
        _run_service()
        return

    # Créer la racine tkinter UNE SEULE FOIS pour tout le processus
    if TKINTER_OK:
        root = tk.Tk()
        root.withdraw()
        root.title("HeimdallAgent")
        state.tk_root = root

    # Les paramètres de connexion passés en ligne de commande sont TOUJOURS pris en
    # compte. Sans assistant graphique (--silent, --once, --no-tray, tkinter absent)
    # on les enregistre directement ; sinon ils pré-remplissent l'assistant.
    service_cmd = args.service_install or args.service_uninstall
    headless = args.silent or args.once or args.no_tray or service_cmd or not TKINTER_OK
    if args.server and headless:
        _apply_cli_config(args)
    elif (not config_exists() or args.server) and not (args.once or args.no_tray or service_cmd):
        if TKINTER_OK:
            wizard = SetupWizard(
                state.tk_root,
                default_host=args.server,
                default_port=args.port,
                default_token=args.token,
                default_https=args.https and not args.http,
                default_verify=not args.no_verify_ssl,
            )
            state.tk_root.wait_window(wizard)
            if not wizard.result:
                sys.exit(0)
        else:
            # Ni tkinter ni --server : configuration par défaut à éditer à la main
            save_config("127.0.0.1", args.port, "changeme-secret-token", "60", False)
            _msgbox(
                "Heimdall Agent - Configuration",
                f"Agent configure avec les valeurs par defaut.\n\n"
                f"Editez le fichier :\n%APPDATA%\\HeimdallAgent\\agent.conf",
                0x40
            )

    if args.autostart:
        _set_autostart(True)

    if args.service_install or args.service_uninstall:
        if not _is_admin():
            ok = _run_elevated_and_wait("--service-install" if args.service_install else "--service-uninstall")
        else:
            ok, msg = _install_service() if args.service_install else _uninstall_service()
            (logger.info if ok else logger.error)(f"Service : {msg}")
            if not args.silent:
                _msgbox("Heimdall — Démarrage avec la machine", msg, 0x40 if ok else 0x10)
        sys.exit(0 if ok else 1)

    load_config()

    if args.scan_ports:
        state.config.set("agent", "port_scan", "true")

    # ── Mode console / one-shot ──
    if args.once or args.no_tray or not TRAY_OK:
        send_report()
        if not args.once:
            threading.Thread(target=monitor_loop, daemon=True, name="Monitor").start()
            agent_loop()
        return

    # ── Mode icône système ──
    threading.Thread(target=agent_loop,     daemon=True, name="AgentLoop").start()
    threading.Thread(target=heartbeat_loop, daemon=True, name="Heartbeat").start()
    threading.Thread(target=update_loop,    daemon=True, name="UpdateCheck").start()
    threading.Thread(target=monitor_loop,   daemon=True, name="Monitor").start()

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
        pystray.MenuItem("📄  Voir les logs",        _on_view_logs),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("⬆️  Vérifier les mises à jour", _on_check_update),
        pystray.MenuItem("🗑  Désinstaller…", _on_uninstall),
        pystray.MenuItem("Démarrer avec Windows", _on_toggle_autostart,
                         checked=lambda _: _is_autostart_enabled()),
        pystray.MenuItem("Démarrer avec la machine (sans session, admin)", _on_toggle_service,
                         checked=lambda _: _is_service_installed()),
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
