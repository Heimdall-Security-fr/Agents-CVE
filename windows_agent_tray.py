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

# ─── Logiciels à mettre à jour (winget) ──────────────────────────────────────
# `winget upgrade` liste les applications dont une version plus récente existe.
# L'agent ne fait que lire : il n'installe rien. Absent (winget non installé,
# Windows Server ancien…) → la vérification est simplement indiquée « non disponible ».
_UPDATE_CACHE = {"at": 0.0, "data": None, "force": False}
_MAX_UPDATE_ITEMS = 500

def _parse_winget_table(text: str) -> list:
    """Analyse la table de `winget upgrade`. Indépendant de la langue : les colonnes
    sont repérées d'après la ligne d'en-tête située juste au-dessus des tirets."""
    lines = [l.rstrip() for l in text.replace("\r", "\n").split("\n")]
    sep = next((i for i, l in enumerate(lines) if re.fullmatch(r"-{5,}", l.strip())), None)
    if not sep:
        return []
    starts = [m.start() for m in re.finditer(r"\S+(?: \S+)*", lines[sep - 1])]
    if len(starts) < 4:            # Nom, Id, Version, Disponible (Source facultative)
        return []
    items = []
    for line in lines[sep + 1:]:
        if not line.strip():
            break
        if re.match(r"^\s*\d+\s+\S+", line) and len(line.split()) <= 6:
            break                  # ligne récapitulative « 12 mises à niveau disponibles »
        cells = [line[s:(starts[i + 1] if i + 1 < len(starts) else None)].strip()
                 for i, s in enumerate(starts)]
        if cells[0] and cells[3]:
            items.append({"name": cells[0], "id": cells[1],
                          "installed": cells[2], "available": cells[3]})
    return items

def collect_outdated_software() -> dict:
    """Résultat : {manager, ok, count, items[], checked_at, error?}. winget n'est lancé
    qu'au premier rapport après le démarrage, puis uniquement sur demande du dashboard
    (`_UPDATE_CACHE["force"]`) ; entre-temps le dernier résultat est réutilisé.
    `update_check_hours = 0` désactive la vérification."""
    hours = 6.0
    if state.config is not None:
        try:
            hours = float(state.config.get("agent", "update_check_hours", fallback="6"))
        except ValueError:
            pass
    if hours <= 0:
        return {"manager": None, "ok": False, "error": "désactivé", "count": None, "items": []}
    if _UPDATE_CACHE["data"] and not _UPDATE_CACHE.get("force"):
        return _UPDATE_CACHE["data"]
    _UPDATE_CACHE["force"] = False

    winget = _find_winget()
    result = _winget_upgrades(winget) if winget else None
    if result is None or not result.get("ok"):
        # winget absent (Windows Server) ou en échec : Windows Update reste interrogeable
        wu = _windows_update_pending()
        if wu.get("ok") or result is None:
            result = wu
    _UPDATE_CACHE.update(at=time.time(), data=result)
    return result

def _find_winget():
    """winget.exe : PATH, sinon les emplacements d'App Installer (absents du PATH sous
    certains comptes / sur Windows Server où il a été installé à la main)."""
    import shutil, glob
    found = shutil.which("winget")
    if found:
        return found
    local = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WindowsApps", "winget.exe")
    if os.path.isfile(local):
        return local
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    cands = glob.glob(os.path.join(pf, "WindowsApps", "Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe", "winget.exe"))
    return sorted(cands)[-1] if cands else None

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
    try:
        r = subprocess.run(
            [winget, "upgrade", "--include-unknown", "--accept-source-agreements"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        items = _parse_winget_table(r.stdout or "")
        # « Aucune mise à jour applicable » (0x8A15002B) et « aucun paquet correspondant »
        # (0x8A150014) sont des codes de retour ≠ 0 mais signifient : tout est à jour.
        rc = (r.returncode or 0) & 0xFFFFFFFF
        if items or rc in (0, 0x8A15002B, 0x8A150014) or re.search(r"-{5,}", r.stdout or ""):
            result = {"manager": "winget", "ok": True, "count": len(items),
                      "items": items[:_MAX_UPDATE_ITEMS],
                      "checked_at": datetime.now().isoformat()}
        else:
            result["error"] = ((r.stderr or r.stdout or "").strip().splitlines() or ["sortie vide"])[0][:200]
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        result["error"] = "délai dépassé"
    except Exception as e:
        result["error"] = str(e)[:200]
    return result

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
        send_report()
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
            auto = _cfg_bool(cfg, "agent", "auto_update", True)
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
        subprocess.Popen([curr_exe], close_fds=True,
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

    # Créer la racine tkinter UNE SEULE FOIS pour tout le processus
    if TKINTER_OK:
        root = tk.Tk()
        root.withdraw()
        root.title("HeimdallAgent")
        state.tk_root = root

    # Les paramètres de connexion passés en ligne de commande sont TOUJOURS pris en
    # compte. Sans assistant graphique (--silent, --once, --no-tray, tkinter absent)
    # on les enregistre directement ; sinon ils pré-remplissent l'assistant.
    headless = args.silent or args.once or args.no_tray or not TKINTER_OK
    if args.server and headless:
        _apply_cli_config(args)
    elif (not config_exists() or args.server) and not (args.once or args.no_tray):
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
        pystray.MenuItem("📄  Voir les logs",        _on_view_logs),
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
