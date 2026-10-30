#!/usr/bin/env python3
"""
Heimdall Mini Agent — Linux / macOS

Collecte les logiciels installés, les ports ouverts, l'état de conformité,
et envoie un rapport au serveur Heimdall principal.

Fonctionnalités :
  - Auto-update : interroge le serveur, télécharge la nouvelle version,
    remplace le fichier en place et relance le service (systemd/launchd).
  - Résilience  : en cas de coupure réseau ou de serveur injoignable, l'agent
    retente avec un backoff exponentiel borné. Dès que le serveur revient,
    tout reprend automatiquement.
  - --uninstall : désinstalle proprement (stop service, suppression unit,
    suppression de /opt/heimdall-agent ou ~/Library/LaunchAgents/...).
"""
import configparser
import platform
import re
import shutil
import subprocess
import socket
import requests
import threading
import time
import logging
import os
import sys
import tempfile
import argparse
from datetime import datetime

# ─── Version ──────────────────────────────────────────────────────────────────
AGENT_VERSION = "1.0.1"  # remplacé à chaque build par la CI (voir VERSION et server/Dockerfile)

# ─── Logging ──────────────────────────────────────────────────────────────────
# Fichier local pour l'inspection sur la machine (heimdall --logs) ET base du
# log_tail envoyé au serveur à chaque rapport (débogage centralisé, dashboard).
def _log_file_path() -> str:
    for d in ("/opt/heimdall-agent", os.path.dirname(os.path.abspath(__file__))):
        if os.path.isdir(d) and os.access(d, os.W_OK):
            return os.path.join(d, "agent.log")
    home_dir = os.path.join(os.path.expanduser("~"), ".heimdall-agent")
    os.makedirs(home_dir, exist_ok=True)
    return os.path.join(home_dir, "agent.log")

LOG_FILE = _log_file_path()
_handlers = [logging.StreamHandler()]
try:
    from logging.handlers import RotatingFileHandler
    _handlers.append(RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=2, encoding="utf-8"))
except Exception:
    pass  # pas de droits d'écriture — on garde au moins la sortie console/journald

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=_handlers,
)
logger = logging.getLogger("HeimdallAgent")

def read_log_tail(n: int = 200) -> list[str]:
    """Dernières `n` lignes du log local — envoyées au serveur (debug centralisé)
    et affichées par `heimdall --logs`."""
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return [l.rstrip("\n") for l in lines[-n:]]
    except FileNotFoundError:
        return []

# ─── Configuration ────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "main_server": {"host": "127.0.0.1", "port": "4000", "token": ""},
    "agent":       {"interval_minutes": "60", "port_scan": "false"}
}

CONFIG_SEARCH_PATHS = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.conf"),
    "/opt/heimdall-agent/agent.conf",
    r"C:\ProgramData\HeimdallAgent\agent.conf",
]

def _config_path_existing():
    for p in CONFIG_SEARCH_PATHS:
        if os.path.exists(p):
            return p
    return None

def load_config():
    config = configparser.ConfigParser()
    loaded = config.read(CONFIG_SEARCH_PATHS)
    if not loaded:
        logger.warning("agent.conf introuvable — utilisation des valeurs par défaut")
        config.read_dict(DEFAULT_CONFIG)
    return config

# ─── Collecte des logiciels installés ─────────────────────────────────────────
def get_software_linux():
    packages = []
    try:
        result = subprocess.run(
            ['dpkg-query', '-W', '-f=${Package}\t${Version}\n'],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            parts = line.split('\t')
            if len(parts) == 2:
                packages.append({"vendor": parts[0], "product": parts[0], "version": parts[1].strip()})
    except FileNotFoundError:
        pass

    if not packages:
        try:
            result = subprocess.run(
                ['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}\n'],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) == 2:
                    packages.append({"vendor": parts[0], "product": parts[0], "version": parts[1]})
        except FileNotFoundError:
            pass

    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'list', '--format=columns'],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 2:
                packages.append({"vendor": "python", "product": parts[0].lower(), "version": parts[1]})
    except Exception:
        pass
    return packages

def get_software_macos():
    packages = []
    try:
        result = subprocess.run(['brew', 'list', '--versions'], capture_output=True, text=True, timeout=30)
        for line in result.stdout.splitlines():
            parts = line.split(' ', 1)
            if len(parts) == 2:
                v = parts[1].split()
                packages.append({"vendor": parts[0], "product": parts[0], "version": v[0] if v else "N/A"})
    except FileNotFoundError:
        pass

    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'list', '--format=columns'],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 2:
                packages.append({"vendor": "python", "product": parts[0].lower(), "version": parts[1]})
    except Exception:
        pass
    return packages

def get_software_windows():
    packages = []
    try:
        import winreg
        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for subkey_path in [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]:
                try:
                    key = winreg.OpenKey(root, subkey_path)
                    i = 0
                    while True:
                        try:
                            sk = winreg.OpenKey(key, winreg.EnumKey(key, i))
                            try:
                                name = winreg.QueryValueEx(sk, "DisplayName")[0]
                                ver  = winreg.QueryValueEx(sk, "DisplayVersion")[0]
                                pub  = ""
                                try: pub = winreg.QueryValueEx(sk, "Publisher")[0]
                                except: pass
                                packages.append({"vendor": pub or name, "product": name, "version": ver})
                            except FileNotFoundError:
                                pass
                            i += 1
                        except OSError:
                            break
                except Exception:
                    pass
    except ImportError:
        pass

    try:
        result = subprocess.run(
            ['winget', 'list', '--source', 'winget'],
            capture_output=True, text=True, timeout=60, encoding='utf-8', errors='ignore'
        )
        for line in result.stdout.splitlines()[3:]:
            if len(line) > 40:
                name    = line[:35].strip()
                version = line[35:55].strip()
                if name and not name.startswith('-'):
                    packages.append({"vendor": "", "product": name, "version": version})
    except Exception:
        pass

    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'list', '--format=columns'],
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
    system = platform.system()
    if system == "Linux":   return get_software_linux()
    if system == "Darwin":  return get_software_macos()
    if system == "Windows": return get_software_windows()
    logger.warning(f"OS non reconnu: {system}")
    return []

# ─── Scan de ports ────────────────────────────────────────────────────────────
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521,
                3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

def scan_ports(host="127.0.0.1", ports=None):
    ports = ports or COMMON_PORTS
    open_ports = []
    logger.info(f"Scan de {len(ports)} ports sur {host}…")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    return open_ports

# ─── Adresses IP locales ──────────────────────────────────────────────────────
def _ips_from_psutil() -> list:
    """psutil donne accès à toutes les interfaces — le plus fiable si disponible."""
    try:
        import psutil  # type: ignore
    except ImportError:
        return []
    found = []
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if getattr(a, "family", None) == socket.AF_INET:
                ip = a.address
                if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                    found.append(ip)
    return found

def _ips_from_socket() -> list:
    """Fallback : combine gethostname() + UDP-trick pour trouver l'IP sortante."""
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ':' not in ip and not ip.startswith('127.'):
                found.append(ip)
    except Exception:
        pass
    # UDP-trick : crée un socket UDP vers une IP arbitraire, l'OS choisit l'iface
    # de sortie. Pas besoin que l'IP soit joignable.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        found.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return found

def _ips_from_system_cmd() -> list:
    """Dernier recours : parse `ip -o -4 addr` (Linux) ou `ifconfig` (mac/BSD)."""
    found = []
    system = platform.system()
    if system == "Linux":
        try:
            r = subprocess.run(["ip", "-o", "-4", "addr"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                # ex: "2: eth0    inet 192.168.1.42/24 ..."
                m = re.search(r'\binet\s+(\d+\.\d+\.\d+\.\d+)/', line)
                if m: found.append(m.group(1))
        except FileNotFoundError:
            pass
    elif system == "Darwin":
        try:
            r = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
            for m in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)', r.stdout):
                found.append(m.group(1))
        except FileNotFoundError:
            pass
    return found

def get_local_ips() -> list:
    """Retourne toutes les IPv4 routables de la machine. Combine 3 méthodes
    pour maximiser les chances de trouver quelque chose même sur des configs
    réseau inhabituelles (pas d'internet, NIC docker uniquement, etc.)."""
    ips: set[str] = set()
    for finder in (_ips_from_psutil, _ips_from_socket, _ips_from_system_cmd):
        try:
            for ip in finder():
                if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                    ips.add(ip)
        except Exception:
            pass
    return sorted(ips)

def collect_logged_users() -> list[dict]:
    """Comptes observés localement (sans collecter de secrets ni d'historique sensible)."""
    users = set()
    system = platform.system()
    try:
        if system in ("Linux", "Darwin"):
            r = subprocess.run(["last", "-w", "-n", "50"], capture_output=True, text=True, timeout=8)
            for line in r.stdout.splitlines():
                name = line.split(maxsplit=1)[0] if line.strip() else ""
                if name and name not in ("reboot", "wtmp"):
                    users.add(name)
    except Exception:
        pass
    try:
        users.add(os.getlogin())
    except Exception:
        pass
    return [{"username": u} for u in sorted(users)[:100]]

# ─── Collecte de la conformité (Linux / macOS) ───────────────────────────────
def collect_compliance() -> dict:
    data = {}
    system = platform.system()

    # ── Longueur minimale du mot de passe ────────────────────────────────────
    try:
        with open("/etc/security/pwquality.conf") as f:
            for line in f:
                m = re.match(r'\s*minlen\s*=\s*(\d+)', line.strip())
                if m:
                    data["password_min_length"] = int(m.group(1))
                    break
    except FileNotFoundError:
        pass
    if "password_min_length" not in data:
        try:
            with open("/etc/login.defs") as f:
                for line in f:
                    m = re.match(r'\s*PASS_MIN_LEN\s+(\d+)', line)
                    if m:
                        data["password_min_length"] = int(m.group(1))
                    m = re.match(r'\s*PASS_MAX_DAYS\s+(\d+)', line)
                    if m:
                        data["passwd_max_days"] = int(m.group(1))
                    m = re.match(r'\s*PASS_MIN_DAYS\s+(\d+)', line)
                    if m:
                        data["passwd_min_days"] = int(m.group(1))
        except FileNotFoundError:
            pass

    # ── Pare-feu ─────────────────────────────────────────────────────────────
    try:
        r = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
        data["firewall_enabled"] = "active" in r.stdout.lower()
    except FileNotFoundError:
        try:
            r = subprocess.run(["systemctl", "is-active", "firewalld"],
                               capture_output=True, text=True, timeout=5)
            data["firewall_enabled"] = r.stdout.strip() == "active"
        except Exception:
            pass

    # ── Mises à jour automatiques ────────────────────────────────────────────
    if system == "Linux":
        try:
            r = subprocess.run(["dpkg", "-s", "unattended-upgrades"],
                               capture_output=True, text=True, timeout=5)
            data["auto_updates_enabled"] = "install ok installed" in r.stdout
        except FileNotFoundError:
            try:
                r = subprocess.run(["rpm", "-q", "dnf-automatic"],
                                   capture_output=True, text=True, timeout=5)
                data["auto_updates_enabled"] = r.returncode == 0
            except Exception:
                pass

    # ── SSH ───────────────────────────────────────────────────────────────────
    ssh_conf_paths = ["/etc/ssh/sshd_config"]
    if system == "Darwin":
        ssh_conf_paths.append("/private/etc/ssh/sshd_config")
    ssh_cfg: dict = {}
    for path in ssh_conf_paths:
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        ssh_cfg[parts[0].lower()] = parts[1].lower()
            break
        except FileNotFoundError:
            pass
    if ssh_cfg:
        root_login = ssh_cfg.get("permitrootlogin", "no")
        data["ssh_root_login_disabled"] = root_login in ("no", "without-password", "forced-commands-only")
        pwd_auth = ssh_cfg.get("passwordauthentication", "yes")
        data["ssh_password_auth_disabled"] = pwd_auth == "no"

    # ── TLS minimum (nginx / apache) ─────────────────────────────────────────
    tls_min = None
    for search_cmd in [
        ["grep", "-r", "ssl_protocols", "/etc/nginx/"],
        ["grep", "-r", "ssl_protocols", "/etc/nginx/sites-enabled/"],
    ]:
        try:
            r = subprocess.run(search_cmd, capture_output=True, text=True, timeout=5)
            protos = re.findall(r'TLSv([\d.]+)', r.stdout)
            if protos:
                tls_min = min(protos, key=lambda v: tuple(int(x) for x in v.split(".")))
                break
        except Exception:
            pass
    if tls_min is None:
        for search_cmd in [
            ["grep", "-r", "SSLProtocol", "/etc/apache2/"],
            ["grep", "-r", "SSLProtocol", "/etc/httpd/"],
        ]:
            try:
                r = subprocess.run(search_cmd, capture_output=True, text=True, timeout=5)
                protos = re.findall(r'TLSv([\d.]+)', r.stdout)
                if protos:
                    tls_min = min(protos, key=lambda v: tuple(int(x) for x in v.split(".")))
                    break
            except Exception:
                pass
    if tls_min:
        data["tls_min_version"] = tls_min

    # ── Sysctl hardening (Linux) ───────────────────────────────────────
    if system == "Linux":
        for key, param in [
            ("sysctl_ip_forwarding",   "net.ipv4.ip_forward"),
            ("sysctl_accept_redirects", "net.ipv4.conf.all.accept_redirects"),
            ("sysctl_syncookies",       "net.ipv4.tcp_syncookies"),
            ("sysctl_log_martians",     "net.ipv4.conf.all.log_martians"),
        ]:
            try:
                r = subprocess.run(["sysctl", "-n", param],
                                   capture_output=True, text=True, timeout=3)
                if r.returncode == 0:
                    data[key] = int(r.stdout.strip())
            except Exception:
                pass

        # ── Core dumps ───────────────────────────────────────────────
        try:
            r = subprocess.run(["sysctl", "-n", "fs.suid_dumpable"],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                data["core_dumps_disabled"] = (int(r.stdout.strip()) == 0)
        except Exception:
            pass

        # ── Audit daemon ─────────────────────────────────────────────
        try:
            r = subprocess.run(["systemctl", "is-active", "auditd"],
                               capture_output=True, text=True, timeout=5)
            data["audit_enabled"] = (r.stdout.strip() == "active")
        except Exception:
            pass

        # ── Umask ───────────────────────────────────────────────────
        try:
            r = subprocess.run(["sh", "-c", "umask"],
                               capture_output=True, text=True, timeout=3)
            val = r.stdout.strip()
            if re.match(r'^0?[0-7]{3}$', val):
                data["umask_value"] = val[-3:]   # normalize to 3 digits
        except Exception:
            pass

    return data


# ─── Collecteur générique pilotté par le dashboard ────────────────────────────
# L'agent récupère la liste des règles personnalisées et exécute leur collecteur.
# Types supportés sur Linux/macOS :
#   - sysctl         : key (ex: "kernel.randomize_va_space")
#   - file_grep      : path + pattern (regex, 1er groupe capturé)
#   - systemd_active : service (Linux uniquement — service en cours d'exécution ?)
#   - file_exists    : path (présent ?), optionnel `invert: true` pour "absent ?"
# Pour Windows : type `registry` (géré dans windows_agent_tray.py).

_SYSCTL_KEY_RE = re.compile(r'^[a-zA-Z0-9._-]+$')
_SERVICE_NAME_RE = re.compile(r'^[a-zA-Z0-9._@:-]+$')


def _coll_sysctl(coll: dict):
    key = (coll.get("key") or "").strip()
    if not _SYSCTL_KEY_RE.match(key):
        return None
    try:
        r = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return None
        val = r.stdout.strip()
        # Si c'est un entier, on le retourne en int pour pouvoir comparer numériquement
        try:
            return int(val)
        except ValueError:
            return val
    except Exception:
        return None


def _coll_file_grep(coll: dict):
    path = coll.get("path") or ""
    pattern = coll.get("pattern") or ""
    if not path.startswith("/") or ".." in path:
        return None  # sécurité : pas de chemin relatif ni traversée
    try:
        compiled = re.compile(pattern, re.MULTILINE)
    except re.error:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(1024 * 1024)  # cap à 1 Mo
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None
    m = compiled.search(content)
    if not m:
        return None
    # 1er groupe si présent, sinon le match complet
    return m.group(1) if m.groups() else m.group(0)


def _coll_systemd_active(coll: dict):
    if platform.system() != "Linux":
        return None
    service = (coll.get("service") or "").strip()
    if not _SERVICE_NAME_RE.match(service):
        return None
    try:
        r = subprocess.run(["systemctl", "is-active", service],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == "active"
    except FileNotFoundError:
        return None


def _coll_file_exists(coll: dict):
    path = coll.get("path") or ""
    if not path.startswith("/") or ".." in path:
        return None
    exists = os.path.exists(path)
    return (not exists) if coll.get("invert") else exists


COLLECTORS = {
    "sysctl":         _coll_sysctl,
    "file_grep":      _coll_file_grep,
    "systemd_active": _coll_systemd_active,
    "file_exists":    _coll_file_exists,
}


def collect_custom_rules(config) -> dict:
    """Récupère la liste des règles personnalisées sur le serveur et exécute
    leur collecteur. Retourne {rule_id: valeur_collectée}.
    Échec réseau ou timeout → dict vide, l'agent continue son cycle normal."""
    os_param = "linux" if platform.system() == "Linux" else (
               "darwin" if platform.system() == "Darwin" else "")
    if not os_param:
        return {}
    try:
        r = requests.get(
            f"{_server_url(config)}/api/compliance/agent-rules",
            params={"os": os_param},
            headers=_agent_headers(config),
            timeout=10,
            verify=_tls_verify(config),
        )
        if r.status_code != 200:
            return {}
        rules = r.json() or []
    except Exception as e:
        logger.debug(f"agent-rules indisponibles : {e}")
        return {}

    out = {}
    for rule in rules:
        rid = rule.get("id")
        coll = rule.get("collector") or {}
        ctype = (coll.get("type") or "").lower()
        fn = COLLECTORS.get(ctype)
        if not rid or not fn:
            continue
        try:
            val = fn(coll)
            if val is not None:
                out[rid] = val
        except Exception as e:
            logger.debug(f"Collecteur '{rid}' échoué : {e}")
    return out


# ─── Logiciels à mettre à jour (versions installées vs disponibles) ───────────
# On interroge le gestionnaire de paquets local (apt / dnf / yum / zypper / brew) :
# c'est la source la plus fiable — pas de correspondance de noms approximative,
# et l'agent ne modifie rien (aucun `apt update`, aucune installation).
# Limite : la liste dépend du cache local du gestionnaire (cf. cache_age_hours).
_UPDATE_CACHE = {"at": 0.0, "data": None}
_MAX_UPDATE_ITEMS = 500
_LC_ALL_C = {**os.environ, "LC_ALL": "C", "LANG": "C"}


def _apt_cache_age_hours():
    for p in ("/var/lib/apt/periodic/update-success-stamp",
              "/var/cache/apt/pkgcache.bin", "/var/lib/apt/lists"):
        try:
            return round((time.time() - os.path.getmtime(p)) / 3600, 1)
        except OSError:
            continue
    return None


def _outdated_apt(_installed):
    r = subprocess.run(["apt", "list", "--upgradable"], capture_output=True,
                       text=True, timeout=90, env=_LC_ALL_C)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "apt list a échoué").strip()[:200])
    items = []
    # ex : nginx/jammy-updates 1.24.0-2 amd64 [upgradable from: 1.18.0-6]
    rx = re.compile(r'^([^/\s]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s*([^\]]+)\]')
    for line in r.stdout.splitlines():
        m = rx.match(line)
        if m:
            items.append({"name": m.group(1), "installed": m.group(3).strip(),
                          "available": m.group(2)})
    return items, {"cache_age_hours": _apt_cache_age_hours()}


def _outdated_dnf(installed, binary="dnf"):
    r = subprocess.run([binary, "-q", "check-update"], capture_output=True,
                       text=True, timeout=180, env=_LC_ALL_C)
    if r.returncode not in (0, 100):        # 100 = des mises à jour existent
        raise RuntimeError((r.stderr or f"{binary} check-update a échoué").strip()[:200])
    items = []
    for line in r.stdout.splitlines():
        if line.lower().startswith("obsoleting"):
            break
        parts = line.split()
        if len(parts) >= 3 and "." in parts[0]:
            name = parts[0].rsplit(".", 1)[0]
            items.append({"name": name, "installed": installed.get(name),
                          "available": parts[1]})
    return items, {}


def _outdated_zypper(installed):
    r = subprocess.run(["zypper", "--quiet", "--non-interactive", "list-updates"],
                       capture_output=True, text=True, timeout=180, env=_LC_ALL_C)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "zypper a échoué").strip()[:200])
    items = []
    for line in r.stdout.splitlines():
        cols = [c.strip() for c in line.split("|")]
        # S | Repository | Name | Current Version | Available Version | Arch
        if len(cols) >= 5 and cols[0] in ("v", "") and cols[2] and cols[2] != "Name":
            items.append({"name": cols[2], "installed": cols[3], "available": cols[4]})
    return items, {}


def _outdated_brew(_installed):
    r = subprocess.run(["brew", "outdated", "--json=v2"], capture_output=True,
                       text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "brew outdated a échoué").strip()[:200])
    import json as _json
    doc = _json.loads(r.stdout or "{}")
    items = []
    for kind in ("formulae", "casks"):
        for p in doc.get(kind, []):
            inst = p.get("installed_versions")
            if isinstance(inst, list):
                inst = ", ".join(inst)
            items.append({"name": p.get("name"), "installed": inst,
                          "available": p.get("current_version")})
    return items, {}


def _installed_versions(software_list) -> dict:
    return {s.get("product"): s.get("version") for s in software_list or []
            if s.get("product")}


# ─── Mises à jour Windows (winget + Windows Update) ──────────────────────────
# Windows 10 / 11 : `winget upgrade` (applications) ET Windows Update (système),
# cumulés. Windows Server : Windows Update seulement (winget rarement présent).
# L'agent ne fait que lire : il n'installe rien.
def _win_is_server() -> bool:
    """True sur Windows Server. Lit InstallationType (« Client » / « Server »)
    dans le registre, avec ProductName en repli (anciens Server sans ce champ)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            try:
                itype = str(winreg.QueryValueEx(key, "InstallationType")[0] or "")
                if itype:
                    return itype.lower().startswith("server")
            except FileNotFoundError:
                pass
            try:
                return "server" in str(winreg.QueryValueEx(key, "ProductName")[0] or "").lower()
            except FileNotFoundError:
                pass
    except Exception:
        pass
    return False


def _parse_winget_table(text: str) -> list:
    """Analyse TOUTES les tables de `winget upgrade` (mises à jour classiques, versions
    inconnues, paquets épinglés). Indépendant de la langue : les colonnes sont repérées
    d'après la ligne d'en-tête située au-dessus des tirets. Tolère les fins de ligne
    Windows et les barres de progression (retours chariot)."""
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
    import json as _json, base64
    result = {"manager": "windows_update", "ok": False, "error": "Windows Update indisponible",
              "count": None, "items": []}
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _WU_PS],
            capture_output=True, text=True, errors="replace",
            timeout=300, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (r.stdout or "").strip()
        if r.returncode == 0 and out:
            data = _json.loads(base64.b64decode(out).decode("utf-8"))
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


def _outdated_windows(_installed) -> dict:
    """Windows 10 / 11 : winget (applications) ET Windows Update (système), cumulés et
    dédoublonnés. Windows Server : Windows Update seulement. Lecture seule."""
    wu = _windows_update_pending()
    if _win_is_server():
        return wu
    winget = _find_winget()
    wg = _winget_upgrades(winget) if winget else {
        "manager": "winget", "ok": False, "error": "winget introuvable", "count": None, "items": []}
    return _merge_update_checks([wg, wu], dedupe=True)


def collect_outdated_software(software_list, config=None) -> dict:
    """Résultat : {manager, ok, count, items[], checked_at, cache_age_hours?, error?}.
    Réutilise le dernier résultat pendant `update_check_hours` (défaut 6 h,
    0 = désactivé) pour ne pas solliciter le gestionnaire de paquets à chaque cycle."""
    hours = 6.0
    if config is not None:
        try:
            hours = float(config.get("agent", "update_check_hours", fallback="6"))
        except ValueError:
            pass
    if hours <= 0:
        return {"manager": None, "ok": False, "error": "désactivé", "count": None, "items": []}
    if _UPDATE_CACHE["data"] and time.time() - _UPDATE_CACHE["at"] < hours * 3600:
        return _UPDATE_CACHE["data"]

    system = platform.system()
    if system == "Windows":
        # Windows 10/11 : winget + Windows Update ; Windows Server : Windows Update seul.
        result = _outdated_windows(_installed_versions(software_list))
        _UPDATE_CACHE.update(at=time.time(), data=result)
        return result
    if system == "Darwin":
        candidates = [("brew", "brew", _outdated_brew)]
    else:
        candidates = [("apt", "apt", _outdated_apt),
                      ("dnf", "dnf", _outdated_dnf),
                      ("yum", "yum", lambda i: _outdated_dnf(i, "yum")),
                      ("zypper", "zypper", _outdated_zypper)]

    result = {"manager": None, "ok": False, "error": "aucun gestionnaire de paquets pris en charge",
              "count": None, "items": []}
    for manager, binary, fn in candidates:
        if shutil.which(binary) is None:
            continue
        try:
            items, extra = fn(_installed_versions(software_list))
            result = {"manager": manager, "ok": True, "count": len(items),
                      "items": items[:_MAX_UPDATE_ITEMS],
                      "checked_at": datetime.now().isoformat(), **extra}
        except subprocess.TimeoutExpired:
            result = {"manager": manager, "ok": False, "error": "délai dépassé",
                      "count": None, "items": []}
        except Exception as e:
            result = {"manager": manager, "ok": False, "error": str(e)[:200],
                      "count": None, "items": []}
        break
    _UPDATE_CACHE.update(at=time.time(), data=result)
    return result


# ─── Surveillance du serveur (Linux, mode démon) ──────────────────────────────
# Analyse locale, légère : seuls les déclencheurs partent au serveur.
#   • processus : seuls les NOUVEAUX processus de /proc sont examinés (toutes les 30 s) ;
#   • cron, unités systemd, clés SSH autorisées, comptes, sudoers, ld.so.preload,
#     /etc/hosts : toutes les 5 min, par différence avec l'instantané précédent ;
#   • paquets : toutes les 15 min, seulement si la base du gestionnaire a changé.
# Le fil tourne avec la priorité la plus basse (nice 19). Au premier passage, l'état
# existant sert de référence : rien n'est signalé, sauf un processus déjà lancé qui
# déclenche une règle moyenne ou plus.
import json as _json_mon
import collections
MONITOR_STATE_FILE = os.path.join(os.path.dirname(LOG_FILE), "monitor-state.json")
_MONITOR_ALERT_TTL = 7 * 86400
_MONITOR_FS_ROOT = ""        # préfixe des fichiers système lus (vide en production ; arborescence factice en test)
_MONITOR_MAX_EVENTS_PER_CYCLE = 50
_MONITOR_QUEUE_MAX = 300
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
_TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")
_SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "nc", "ncat", "netcat", "socat"}
_WEB_SERVERS = {"nginx", "apache2", "httpd", "lighttpd", "caddy"}
_APP_SERVERS = {"php-fpm", "php", "java", "node", "ruby", "tomcat", "gunicorn", "uwsgi", "mysqld",
                "postgres", "redis-server", "mongod", "jenkins"}
_OFFENSIVE_TOOLS = {"linpeas.sh": "high", "linpeas": "high", "linenum.sh": "high", "pspy": "high",
                    "pspy64": "high", "chisel": "high", "ngrok": "medium", "hydra": "high",
                    "masscan": "medium", "nmap": "medium", "sqlmap": "high", "mimipenguin": "critical",
                    "xmrig": "high", "minerd": "high", "cpuminer": "high", "kdevtmpfsi": "critical",
                    "kinsing": "critical"}
_LINUX_CMD_RULES = [
    (r"/dev/(tcp|udp)/", "critical", "Shell inversé (redirection vers /dev/tcp)"),
    (r"\b(nc|ncat|netcat)\b.*\s-(e|c)\s", "critical", "Shell inversé avec netcat"),
    (r"\bsocat\b.*\bexec:", "critical", "Shell inversé avec socat"),
    (r"mkfifo\s+\S+.*\|\s*(/bin/)?(ba)?sh\b", "critical", "Shell inversé (tube nommé)"),
    (r"\b(python[0-9.]*|perl|ruby|php)\b.*socket.*(subprocess|pty\.spawn|exec|/bin/(ba)?sh|fsockopen|proc_open)",
     "critical", "Shell inversé (script)"),
    (r"stratum\+tcp://|--donate-level", "high", "Mineur de cryptomonnaie"),
    (r"(curl|wget)\s[^|;]*\|\s*(sudo\s+)?(ba)?sh\b", "high", "Téléchargement exécuté directement dans un shell"),
    (r"base64\s+(-d|--decode)\b.*\|\s*(ba)?sh\b", "high", "Code décodé exécuté dans un shell"),
    (r"chattr\s+\+i\s+/etc/|history\s+-c\b|unset\s+histfile|>\s*/var/log/(auth|secure|syslog)",
     "high", "Effacement de traces ou verrouillage de fichiers système"),
]
_LINUX_CMD_RULES = [(re.compile(p), s, t) for p, s, t in _LINUX_CMD_RULES]

def _rate_linux_command(command: str):
    """Gravité d'une commande ajoutée à cron ou à une unité systemd : (gravité, [raisons])."""
    cmd = (command or "").lower()
    severity, reasons = "medium", []
    def raise_to(level, reason):
        nonlocal severity
        reasons.append(reason)
        if _SEVERITY_ORDER.index(level) > _SEVERITY_ORDER.index(severity):
            severity = level
    for rx, level, title in _LINUX_CMD_RULES:
        if rx.search(cmd):
            raise_to(level, title)
    if any(d in cmd for d in _TEMP_DIRS):
        raise_to("high", "programme dans un dossier temporaire")
    return severity, reasons

def _linux_process_findings(comm: str, exe: str, cmdline: str, parent_comm: str, parent_exe: str,
                            parent_cmdline: str, watchlist: list) -> list:
    """Règles appliquées à un nouveau processus : [(règle, gravité, titre, extra)]."""
    findings = []
    comm, cmd = (comm or "").lower(), (cmdline or "").lower()
    exe_l = (exe or "").lower()
    base = os.path.basename(exe_l.replace(" (deleted)", "")) or comm
    parent = (parent_comm or "").lower()
    if exe_l.startswith("/memfd:"):
        findings.append(("fileless_process", "critical", f"{comm} exécuté en mémoire sans fichier (memfd)", {}))
    elif exe_l.startswith(_TEMP_DIRS):
        deleted = " puis supprimé" if exe_l.endswith(" (deleted)") else ""
        findings.append(("suspicious_location", "high", f"{base} exécuté depuis un dossier temporaire{deleted}", {}))
    for name in (base, comm):
        if name in _OFFENSIVE_TOOLS:
            findings.append(("offensive_tool", _OFFENSIVE_TOOLS[name], f"Outil offensif ou mineur : {name}", {}))
            break
    for rx, level, title in _LINUX_CMD_RULES:
        if cmd and rx.search(cmd):
            findings.append(("suspicious_command", level, title, {}))
            break
    child_is_shell = comm in _SHELLS or base in _SHELLS
    if child_is_shell:
        haystack = f"{parent_exe} {parent_cmdline}".lower()
        match = next((p for p in watchlist or [] if any(t in haystack for t in p.get("match") or [])), None)
        if match:
            cves = ", ".join((match.get("cves") or [])[:3])
            findings.append(("vulnerable_app_spawns_shell", "critical",
                             f"{match.get('name')} (vulnérable : {cves}) a lancé {comm} — exploitation possible",
                             {"watchlist_match": match.get("name"), "cves": cves}))
        elif parent in _WEB_SERVERS:
            findings.append(("webserver_spawns_shell", "high", f"Le serveur web {parent} a lancé {comm} (webshell ?)", {}))
        elif parent in _APP_SERVERS or parent.startswith("php-fpm"):
            findings.append(("service_spawns_shell", "medium", f"Le service {parent} a lancé {comm}", {}))
    return findings

# ── Capteurs Linux ───────────────────────────────────────────────────────────
def _fs(path: str) -> str:
    return _MONITOR_FS_ROOT + path

def _read_text(path: str, limit: int = 1_000_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""

def _proc_info(pid: str):
    """(ppid, starttime, comm, exe, cmdline) d'un processus, ou None (thread noyau, terminé)."""
    stat = _read_text(f"/proc/{pid}/stat", 4096)
    if not stat or ")" not in stat:
        return None
    comm = stat[stat.index("(") + 1:stat.rindex(")")]
    fields = stat[stat.rindex(")") + 2:].split()
    try:
        ppid, start = int(fields[1]), fields[19]
    except (IndexError, ValueError):
        return None
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""
    cmdline = _read_text(f"/proc/{pid}/cmdline", 8192).replace("\x00", " ").strip()
    if not exe and not cmdline:
        return None                     # thread noyau
    return ppid, start, comm, exe, cmdline

def _cron_entries() -> dict:
    """{fichier|ligne: ligne} des crontabs système et utilisateurs."""
    import glob
    patterns = ["/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*",
                "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*"]
    files = [f[len(_MONITOR_FS_ROOT):] for p in patterns for f in glob.glob(_fs(p))]
    out = {}
    for path in files:
        if not os.path.isfile(_fs(path)):
            continue
        if "/cron." in path and not path.startswith("/etc/cron.d"):
            out[f"{path}|"] = path                       # script exécuté tel quel : sa présence suffit
            continue
        for line in _read_text(_fs(path), 200_000).splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not re.match(r"^[A-Z_]+=", line):
                out[f"{path}|{line[:300]}"] = line[:500]
    return out

def _systemd_units() -> dict:
    """{unité: ExecStart} des fichiers ajoutés par l'administrateur (/etc/systemd)."""
    out = {}
    for root in ("/etc/systemd/system", "/etc/systemd/user"):
        for dirpath, _dirs, files in os.walk(_fs(root)):
            for f in files:
                path = os.path.join(dirpath, f)
                if f.endswith((".service", ".timer")) and not os.path.islink(path):
                    execs = [l.split("=", 1)[1].strip() for l in _read_text(path, 100_000).splitlines()
                             if l.strip().startswith(("ExecStart=", "ExecStartPre=", "ExecStartPost="))]
                    out[path[len(_MONITOR_FS_ROOT):]] = " ; ".join(execs)[:500]
    return out

def _passwd_users() -> dict:
    """{utilisateur: "uid|home"}."""
    out = {}
    for line in _read_text(_fs("/etc/passwd")).splitlines():
        parts = line.split(":")
        if len(parts) >= 7:
            out[parts[0]] = f"{parts[2]}|{parts[5]}"
    return out

def _admin_group_members() -> dict:
    out = {}
    for line in _read_text(_fs("/etc/group")).splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[0] in ("sudo", "wheel", "admin", "root"):
            for member in filter(None, parts[3].split(",")):
                out[f"{parts[0]}|{member}"] = member
    return out

def _sudoers_lines() -> dict:
    import glob
    out = {}
    for path in ["/etc/sudoers"] + [f[len(_MONITOR_FS_ROOT):] for f in glob.glob(_fs("/etc/sudoers.d/*"))]:
        for line in _read_text(_fs(path), 200_000).splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "Defaults")):
                out[f"{path}|{line[:300]}"] = line[:500]
    return out

def _authorized_keys(users: dict) -> dict:
    """{utilisateur|clé: description} des clés SSH autorisées (root et comptes ≥ 1000)."""
    out = {}
    for user, info in users.items():
        uid, _, home = info.partition("|")
        if not home or not (uid == "0" or (uid.isdigit() and int(uid) >= 1000)):
            continue
        for name in ("authorized_keys", "authorized_keys2"):
            for line in _read_text(_fs(os.path.join(home, ".ssh", name)), 500_000).splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    key = next((p for p in parts if len(p) > 60), line)
                    label = f"{parts[0] if parts else ''} …{key[-16:]} {parts[-1] if len(parts) > 2 else ''}".strip()
                    out[f"{user}|{key[-40:]}"] = label[:200]
    return out

def _package_names(cache: dict) -> dict | None:
    """Paquets installés, relus seulement si la base dpkg/rpm a changé (sinon None)."""
    for db, kind in ((_fs("/var/lib/dpkg/status"), "dpkg"), (_fs("/var/lib/rpm"), "rpm")):
        try:
            mtime = os.stat(db).st_mtime
        except OSError:
            continue
        if cache.get(kind) == mtime:
            return None
        cache[kind] = mtime
        if kind == "dpkg":
            names, current, installed = {}, None, False
            for line in _read_text(db, 50_000_000).splitlines() + [""]:
                if line.startswith("Package: "):
                    current = line[9:].strip()
                elif line.startswith("Status: "):
                    installed = line.endswith(" installed")
                elif line.startswith("Version: ") and current and installed:
                    names[current] = line[9:].strip()
                elif not line:
                    current, installed = None, False
            return names
        try:
            r = subprocess.run(["rpm", "-qa", "--qf", "%{NAME}|%{VERSION}\\n"], capture_output=True,
                               text=True, timeout=120)
            return dict(l.split("|", 1) for l in r.stdout.splitlines() if "|" in l)
        except (OSError, subprocess.TimeoutExpired):
            return None
    return None

# ── Analyse YARA (fichiers) ──────────────────────────────────────────────────
# Règles reçues du serveur. N'analyse que des fichiers ciblés : exécutable des nouveaux
# processus, programmes référencés par une persistance (cron, systemd), fichiers nouveaux
# ou modifiés dans /tmp, /var/tmp, /dev/shm et les racines web. Budget d'octets par
# passage et cache taille/date : un fichier n'est relu que s'il a changé.
try:
    import yara as _yara_mod
except Exception:          # module absent ou bibliothèque native introuvable
    _yara_mod = None
YARA_MAX_FILE = 32 << 20                  # fichiers plus gros ignorés
YARA_BUDGET_PER_CYCLE = 32 << 20          # octets analysés au plus par passage (~1 Mo/s)
_YARA_CACHE_MAX = 5000
_YARA_SKIP_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/lib32/", "/bin/", "/sbin/", "/snap/", "/proc/sys",
                       "/sys/", "/boot/", "/opt/heimdall-agent/")
_YARA_TMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
_YARA_WEB_ROOTS = ("/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html")
_YARA_WEB_EXT = (".php", ".phtml", ".php5", ".php7", ".phar", ".inc", ".jsp", ".jspx", ".asp", ".aspx",
                 ".ashx", ".cgi", ".pl", ".py", ".sh")
_YARA_SEVERITIES = ("low", "medium", "high", "critical")

class _YaraEngine:
    """Règles compilées jeu par jeu (un jeu invalide n'empêche pas les autres) ; à défaut
    du module Python, la commande « yara » est utilisée si elle est installée."""
    def __init__(self, state_dir: str):
        self.compiled, self.cli_files, self.version = [], [], None
        self.state_dir = state_dir
        self.lock = threading.Lock()

    @property
    def ready(self) -> bool:
        return bool(self.compiled or self.cli_files)

    def load(self, version: str, rulesets: list) -> list:
        compiled, cli_files, errors = [], [], []
        cli = shutil.which("yara") if _yara_mod is None else None
        for i, rs in enumerate(rulesets):
            name, source = str(rs.get("name") or f"jeu {i}"), str(rs.get("source") or "")
            try:
                if _yara_mod is not None:
                    compiled.append((name, _yara_mod.compile(source=source)))
                elif cli:
                    path = os.path.join(self.state_dir, f"yara-rules-{i}.yar")
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(source)
                    cli_files.append((name, path))
            except Exception as e:
                errors.append(f"{name} : {str(e)[:200]}")
        with self.lock:
            self.compiled, self.cli_files, self.version = compiled, cli_files, version
        return errors

    def scan(self, path: str = None, data: bytes = None) -> list:
        """[{rule, ruleset, severity, description}] des règles qui correspondent."""
        out = []
        with self.lock:
            compiled, cli_files = list(self.compiled), list(self.cli_files)
        for name, rules in compiled:
            try:
                matches = (rules.match(filepath=path, timeout=10, fast=True) if path is not None
                           else rules.match(data=data, timeout=5, fast=True))
            except Exception:
                continue        # fichier illisible ou délai dépassé : on passe
            for m in matches:
                out.append(_yara_finding(m.rule, name, m.meta))
        if path is not None:
            for name, rules_file in cli_files:
                try:
                    r = subprocess.run(["yara", "-m", "-f", rules_file, path], capture_output=True,
                                       text=True, timeout=30, preexec_fn=lambda: os.nice(19))
                except (OSError, subprocess.TimeoutExpired):
                    continue
                for line in r.stdout.splitlines():
                    m = re.match(r"(\S+)\s+\[(.*)\]\s", line)
                    if m:
                        meta = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', m.group(2)))
                        out.append(_yara_finding(m.group(1), name, meta))
        return out

def _yara_finding(rule, ruleset, meta) -> dict:
    severity = str((meta or {}).get("severity") or "high").lower()
    return {"rule": str(rule), "ruleset": ruleset,
            "severity": severity if severity in _YARA_SEVERITIES else "high",
            "description": str((meta or {}).get("description") or "")[:300]}

def _walk_files(root: str, max_depth: int, extensions=None, limit: int = 20000):
    """Fichiers d'une arborescence (profondeur et nombre bornés, liens ignorés)."""
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

def _paths_in_command(command: str) -> list:
    """Fichiers absolus cités dans une commande (cron, ExecStart…)."""
    return [p for p in re.findall(r"(/[\w.+@%-]+(?:/[\w.+@%-]+)+)", command or "")
            if not p.startswith(("/dev/", "/proc/"))][:5]

# ── Journaux en temps réel ───────────────────────────────────────────────────
_AUTH_LOGS = ("/var/log/auth.log", "/var/log/secure")
_WEB_LOGS = ("/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log")
_AUDIT_LOG = "/var/log/audit/audit.log"
_LOG_POLL_SECONDS = 2
_ADMIN_GROUPS = ("sudo", "wheel", "admin", "root")

class _RateTracker:
    """Compteurs glissants (tentatives échouées par adresse…)."""
    def __init__(self):
        self.hits = {}

    def add(self, key, now, window) -> int:
        dq = self.hits.setdefault(key, collections.deque())
        dq.append(now)
        return self.count(key, now, window)

    def count(self, key, now, window) -> int:
        dq = self.hits.get(key)
        if not dq:
            return 0
        while dq and dq[0] < now - window:
            dq.popleft()
        if len(self.hits) > 20000:          # borne la mémoire face à un balayage massif
            for k in [k for k, v in self.hits.items() if not v][:10000]:
                del self.hits[k]
        return len(dq)

class _LogTail:
    """Lit les lignes ajoutées à un fichier journal (rotation et troncature gérées).
    Premier suivi : on part de la fin, sans relire l'historique."""
    def __init__(self, path: str, saved: dict | None):
        self.path, self.inode, self.offset, self.partial = path, None, 0, b""
        if saved:
            self.inode, self.offset = saved.get("inode"), int(saved.get("offset") or 0)

    def state(self) -> dict:
        return {"inode": self.inode, "offset": self.offset}

    def read_lines(self, limit: int = 1 << 20) -> list:
        try:
            st = os.stat(_fs(self.path))
        except OSError:
            return []
        if self.inode is None:
            self.inode, self.offset = st.st_ino, st.st_size          # pas d'historique
        elif st.st_ino != self.inode or st.st_size < self.offset:
            self.inode, self.offset, self.partial = st.st_ino, 0, b""  # rotation ou troncature
        elif st.st_size - self.offset > 5 * limit:
            self.offset = st.st_size - limit                          # retard important : on saute
        if st.st_size == self.offset:
            return []
        try:
            with open(_fs(self.path), "rb") as f:
                f.seek(self.offset)
                chunk = f.read(limit)
        except OSError:
            return []
        self.offset += len(chunk)
        data = self.partial + chunk
        lines = data.split(b"\n")
        self.partial = lines.pop()          # ligne incomplète : attendue au prochain passage
        return [l.decode("utf-8", "replace") for l in lines if l]

_SSH_FAIL_RE = re.compile(r"sshd\[\d+\]: (?:Failed (?:password|publickey|keyboard-interactive/pam) for "
                          r"(?:invalid user )?(\S+)|Invalid user (\S*)) from ([0-9a-fA-F.:]+)")
_SSH_OK_RE = re.compile(r"sshd\[\d+\]: Accepted (\S+) for (\S+) from ([0-9a-fA-F.:]+)")
_SUDO_RE = re.compile(r"sudo(?:\[\d+\])?:\s+(\S+) : (.*)")
_USERADD_RE = re.compile(r"useradd\[\d+\]: new user: name=([^,\s]+)")
_GROUP_ADD_RE = re.compile(r"(?:usermod|gpasswd)\[\d+\]: (?:add '([^']+)' to (?:shadow )?group '([^']+)'|"
                           r"user (\S+) added by \S+ to group (\S+))")
_WEB_LINE_RE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]*\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?')
_WEB_RULES = [
    (re.compile(r"\$\{(jndi|\$\{(lower|upper|env|::-)|::-j)"), "high", "Tentative d'exploitation Log4Shell"),
    (re.compile(r"\.(php\d?|phtml|jsp|aspx?)\?(cmd|exec|command|c|execute|shell)=[^&]+"), "high",
     "Accès à un webshell probable"),
    (re.compile(r"(\.\./){3,}|/etc/passwd|/proc/self/environ|win\.ini"), "medium", "Tentative de traversée de répertoires"),
    (re.compile(r"union(\s|\+|%20)+(all(\s|\+|%20)+)?select|information_schema|sleep\(\d+\)|benchmark\(\d+"),
     "medium", "Tentative d'injection SQL"),
]
_WEB_SCANNERS = re.compile(r"sqlmap|nikto|nuclei|wpscan|acunetix|nessus|openvas|dirbuster|gobuster|ffuf|masscan|zgrab")
_AUDIT_ARG_RE = re.compile(r' a\d+=(?:"([^"]*)"|([0-9A-Fa-f]+))')

def _linux_log_findings(source: str, line: str, tracker: "_RateTracker", now: float) -> list:
    """Règles appliquées à une ligne de journal : [(règle, gravité, titre, clé, détails)]."""
    out = []
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    if source == "auth":
        m = _SSH_FAIL_RE.search(line)
        if m:
            user, ip = m.group(1) or m.group(2) or "?", m.group(3)
            tracker.add(f"ssh15|{ip}", now, 900)
            if tracker.add(f"ssh5|{ip}", now, 300) >= 10:
                out.append(("brute_force", "high", f"Attaque par force brute SSH depuis {ip}",
                            f"brute_force|ssh|{ip}|{day}", {"source_ip": ip, "name": user, "line": line}))
            return out
        m = _SSH_OK_RE.search(line)
        if m:
            method, user, ip = m.groups()
            failures = tracker.count(f"ssh15|{ip}", now, 900)
            if failures >= 5:
                out.append(("login_after_failures", "critical",
                            f"Connexion SSH réussie pour {user} depuis {ip} après {failures} échecs",
                            f"login_after_failures|{ip}|{user}|{day}", {"source_ip": ip, "name": user, "line": line}))
            elif user == "root" and method == "password":
                out.append(("root_password_login", "medium", f"Connexion SSH de root par mot de passe depuis {ip}",
                            f"root_login|{ip}|{day}", {"source_ip": ip, "line": line}))
            return out
        m = _SUDO_RE.search(line)
        if m:
            user, rest = m.groups()
            if "user NOT in sudoers" in rest:
                out.append(("sudo_denied", "medium", f"sudo refusé : {user} n'est pas autorisé",
                            f"sudo_denied|{user}|{day}", {"name": user, "line": line}))
            elif "COMMAND=" in rest:
                command = rest.split("COMMAND=", 1)[1]
                severity, reasons = _rate_linux_command(command)
                if severity in ("high", "critical"):
                    out.append(("suspicious_command", severity, f"Commande suspecte lancée par sudo ({user})",
                                f"suspicious_command|{command[:200]}", {"name": user, "command": command,
                                                                        "reasons": " ; ".join(reasons)}))
            return out
        m = _USERADD_RE.search(line)
        if m:
            out.append(("new_local_account", "medium", f"Nouveau compte local : {m.group(1)}",
                        f"account|{m.group(1)}", {"name": m.group(1), "line": line}))
            return out
        m = _GROUP_ADD_RE.search(line)
        if m:
            user, group = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
            if group in _ADMIN_GROUPS:
                out.append(("admin_group_added", "high", f"{user} ajouté au groupe {group}",
                            f"admin|{group}|{user}", {"member": user, "name": group, "line": line}))
    elif source == "web":
        m = _WEB_LINE_RE.match(line)
        if not m:
            return out
        ip, method, url, status, agent = m.groups()
        try:
            from urllib.parse import unquote_plus
            target = unquote_plus(unquote_plus(url)).lower()
        except Exception:
            target = url.lower()
        for rx, severity, title in _WEB_RULES:
            if rx.search(target):
                if title.startswith("Accès à un webshell") and not status.startswith("2"):
                    continue        # le fichier n'existe pas : simple tentative
                out.append(("web_attack", severity, f"{title} depuis {ip}", f"web|{title}|{ip}|{day}",
                            {"source_ip": ip, "path": url[:500], "status": status, "command": (agent or "")[:300]}))
                return out
        if agent and _WEB_SCANNERS.search(agent.lower()):
            out.append(("web_scan", "low", f"Scanner de vulnérabilités web depuis {ip}", f"webscan|{ip}|{day}",
                        {"source_ip": ip, "path": url[:500], "command": agent[:300]}))
    elif source == "audit" and "type=EXECVE" in line:
        args = []
        for quoted, hexa in _AUDIT_ARG_RE.findall(line):
            if quoted:
                args.append(quoted)
            else:
                try:
                    args.append(bytes.fromhex(hexa).decode("utf-8", "replace"))
                except ValueError:
                    args.append(hexa)
        command = " ".join(args)
        for rx, severity, title in _LINUX_CMD_RULES:
            if rx.search(command.lower()):
                out.append(("suspicious_command", severity, title, f"suspicious_command|{command[:200]}",
                            {"command": command[:1000], "line": "auditd"}))
                break
    return out

def _log_sources() -> list:
    """(source, chemin) des journaux présents sur la machine."""
    out = [("auth", p) for p in _AUTH_LOGS if os.path.isfile(_fs(p))]
    out += [("web", p) for p in _WEB_LOGS if os.path.isfile(_fs(p))]
    if os.path.isfile(_fs(_AUDIT_LOG)):
        out.append(("audit", _AUDIT_LOG))
    return out

def _journal_reader(lines: "collections.deque", stop: "threading.Event"):
    """Sans auth.log/secure (distributions récentes sans rsyslog) : suivi de journald,
    messages d'authentification uniquement, en priorité minimale."""
    try:
        proc = subprocess.Popen(["journalctl", "-f", "-n", "0", "-o", "short", "SYSLOG_FACILITY=4",
                                 "SYSLOG_FACILITY=10"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, errors="replace", preexec_fn=lambda: os.nice(19))
    except OSError:
        return
    try:
        for line in proc.stdout:
            if stop.is_set():
                break
            if len(lines) < 10000:
                lines.append(line.rstrip("\n"))
    finally:
        proc.kill()

def log_watch_loop(mon: "_Monitor"):
    """Suivi des journaux en temps réel (lecture des nouvelles lignes toutes les 2 s)."""
    try:
        os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 19)
    except (AttributeError, OSError):
        pass
    tracker, tails, journal, stop = _RateTracker(), {}, collections.deque(), threading.Event()
    journal_started, refresh_at = False, 0.0
    saved = mon.state.setdefault("log_offsets", {})
    while True:
        now = time.time()
        if now >= refresh_at:       # journaux apparus ou disparus (installation de nginx…)
            refresh_at = now + 300
            sources = _log_sources()
            for source, path in sources:
                tails.setdefault(path, (source, _LogTail(path, saved.get(path))))
            if not any(s == "auth" for s, _ in sources) and not journal_started and not _MONITOR_FS_ROOT \
                    and shutil.which("journalctl"):
                journal_started = True
                threading.Thread(target=_journal_reader, args=(journal, stop), daemon=True,
                                 name="Journald").start()
        batches = [(source, tail.read_lines()) for source, tail in tails.values()]
        if journal:
            batches.append(("auth", [journal.popleft() for _ in range(len(journal))]))
        if not (mon.server_enabled and _monitor_settings(mon.config)[0]):
            batches = []        # surveillance suspendue : on avance dans les fichiers sans alerter
        for source, lines in batches:
            for line in lines:
                for rule, severity, title, key, details in _linux_log_findings(source, line, tracker, now):
                    mon.add_async(mon.event(rule, severity, title, key, **details))
        with mon.lock:
            for path, (_s, tail) in tails.items():
                if saved.get(path) != tail.state():
                    saved[path] = tail.state()
                    mon.dirty_cache = True
        time.sleep(_LOG_POLL_SECONDS)

# ── Moteur ───────────────────────────────────────────────────────────────────
class _Monitor:
    def __init__(self, config):
        self.config = config
        self.state = {"snap": {}, "alerted": {}, "queue": [], "yara_cache": {}, "log_offsets": {}}
        self.seen = set()
        self.first_process_scan = True
        self.watchlist, self.server_enabled, self.watch_at = [], True, 0.0
        self.pkg_cache = {}
        self.dirty = self.dirty_cache = False
        self.last_save = 0.0
        # Les journaux sont lus par un autre fil : accès à l'état sous verrou
        self.lock = threading.RLock()
        self.pending = []                       # alertes produites hors du passage principal
        self.wake = threading.Event()           # alerte grave : envoi sans attendre le passage suivant
        self.yara = _YaraEngine(os.path.dirname(MONITOR_STATE_FILE))
        self.yara_queue = collections.OrderedDict()
        try:
            with open(MONITOR_STATE_FILE, "r", encoding="utf-8") as f:
                loaded = _json_mon.load(f)
            if isinstance(loaded, dict):
                self.state.update({k: loaded[k] for k in self.state if k in loaded})
        except (OSError, ValueError):
            pass

    def save(self):
        """Écrit l'état si une alerte ou un instantané a changé ; le cache YARA et les
        positions de lecture des journaux, eux, au plus toutes les 5 min."""
        with self.lock:
            if not self.dirty and not (self.dirty_cache and time.time() - self.last_save > 300):
                return
            try:
                tmp = MONITOR_STATE_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    _json_mon.dump(self.state, f)
                os.chmod(tmp, 0o600)
                os.replace(tmp, MONITOR_STATE_FILE)
                self.dirty = self.dirty_cache = False
                self.last_save = time.time()
            except OSError as e:
                logger.warning(f"Surveillance : état non enregistré ({e})")

    def event(self, rule, severity, title, key, **details):
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
        """Alerte produite par la lecture des journaux : envoyée au prochain passage, ou
        tout de suite si elle est grave."""
        if not ev:
            return
        with self.lock:
            self.pending.append(ev)
        if ev["severity"] in ("high", "critical"):
            self.wake.set()

    # Analyse YARA
    def yara_enqueue(self, path: str, reason: str, force: bool = False):
        if not self.yara.ready or not path:
            return
        if not force and path.startswith(_YARA_SKIP_PREFIXES):
            return          # fichiers des paquets du système (hors persistance citée)
        with self.lock:
            if len(self.yara_queue) < 20000:
                self.yara_queue.setdefault(path, reason)

    def yara_watch_dirs(self, web: bool):
        for root in _YARA_TMP_DIRS:
            for path in _walk_files(_fs(root), 2, limit=3000):
                self.yara_enqueue(path[len(_MONITOR_FS_ROOT):] if _MONITOR_FS_ROOT else path, "dossier temporaire")
        if web:
            for root in _YARA_WEB_ROOTS:
                for path in _walk_files(_fs(root), 8, _YARA_WEB_EXT, limit=20000):
                    self.yara_enqueue(path[len(_MONITOR_FS_ROOT):] if _MONITOR_FS_ROOT else path, "racine web")

    def yara_drain(self, budget: int) -> list:
        """Analyse la file dans la limite du budget d'octets ; fichiers inchangés ignorés."""
        events, spent = [], 0
        cache = self.state["yara_cache"]
        while spent < budget:
            with self.lock:
                if not self.yara_queue:
                    break
                path, reason = self.yara_queue.popitem(last=False)
            real = _fs(path) if not path.startswith("/proc/") else path
            try:
                st = os.stat(real)
            except OSError:
                continue
            if not os.path.isfile(real) or not 0 < st.st_size <= YARA_MAX_FILE:
                continue
            sig = f"{st.st_size}|{int(st.st_mtime)}"
            if cache.get(path) == sig:
                continue
            with self.lock:
                cache.pop(path, None)
                cache[path] = sig
                while len(cache) > _YARA_CACHE_MAX:
                    cache.pop(next(iter(cache)))
                self.dirty_cache = True
            spent += st.st_size
            matches = self.yara.scan(path=real)
            if not matches:
                continue
            worst = max(matches, key=lambda m: _YARA_SEVERITIES.index(m["severity"]))
            rules = ", ".join(sorted({m["rule"] for m in matches}))
            try:
                import hashlib
                with open(real, "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                sha = ""
            events.append(self.event("yara_match", worst["severity"],
                                     f"Règle YARA {worst['rule']} : {os.path.basename(path)}",
                                     f"yara|{path}|{rules}|{sig}", path=path, rules=rules,
                                     description=worst["description"], sha256=sha, reason=reason,
                                     ruleset=worst["ruleset"]))
        return [e for e in events if e]

    def diff(self, name, current: dict):
        previous = self.state["snap"].get(name)
        if previous != current:
            self.state["snap"][name] = current
            self.dirty = True
        if previous is None:
            return None
        return [(k, v, previous.get(k)) for k, v in current.items() if previous.get(k) != v]

    def scan_processes(self) -> list:
        infos = {}
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            stat = _read_text(f"/proc/{pid}/stat", 4096)
            if ")" not in stat:
                continue
            fields = stat[stat.rindex(")") + 2:].split()
            if len(fields) > 19:
                infos[pid] = (fields[1], fields[19])        # ppid, heure de démarrage
        events, alive = [], set()
        own = str(os.getpid())
        for pid, (ppid, start) in infos.items():
            ident = (pid, start)
            alive.add(ident)
            if ident in self.seen or pid == own:
                continue
            self.seen.add(ident)
            info = _proc_info(pid)
            if not info:
                continue
            _ppid, _start, comm, exe, cmdline = info
            if exe:
                # Binaire supprimé, en mémoire ou dans /tmp : analysé via /proc/<pid>/exe
                hidden = exe.endswith(" (deleted)") or exe.startswith("/memfd:") or exe.startswith(_TEMP_DIRS)
                self.yara_enqueue(f"/proc/{pid}/exe" if hidden else exe, "processus", force=hidden)
            # Le parent ne sert qu'aux règles « tel service a lancé un shell »
            is_shell = comm.lower() in _SHELLS or os.path.basename(exe.replace(" (deleted)", "")) in _SHELLS
            parent = _proc_info(ppid) if is_shell and ppid != "0" else None
            parent_comm, parent_exe, parent_cmd = (parent[2], parent[3], parent[4]) if parent else ("", "", "")
            for rule, severity, title, extra in _linux_process_findings(
                    comm, exe, cmdline, parent_comm, parent_exe, parent_cmd, self.watchlist):
                if self.first_process_scan and _SEVERITY_ORDER.index(severity) < 2:
                    continue
                key = (f"{rule}|{cmdline[:200]}" if rule == "suspicious_command"     # même clé que auditd
                       else f"{rule}|{exe or comm}|{cmdline[:200]}")
                ev = self.event(rule, severity, title, key,
                                image=exe or comm, pid=int(pid), parent=parent_comm, parent_image=parent_exe,
                                command=cmdline[:1000], **extra)
                if ev:
                    events.append(ev)
        self.seen &= alive
        self.first_process_scan = False
        return events

    def scan_system(self) -> list:
        events = []
        def add(ev):
            if ev:
                events.append(ev)
        for key, line, _old in self.diff("cron", _cron_entries()) or []:
            path = key.split("|", 1)[0]
            severity, reasons = _rate_linux_command(line)
            for p in _paths_in_command(line):
                self.yara_enqueue(p, "persistance", force=True)
            add(self.event("new_scheduled_task", severity, f"Nouvelle tâche planifiée (cron) : {path}",
                           f"cron|{key}", path=path, line=line, reasons=" ; ".join(reasons)))
        for path, execs, old in self.diff("systemd", _systemd_units()) or []:
            severity, reasons = _rate_linux_command(execs)
            for p in _paths_in_command(execs):
                self.yara_enqueue(p, "persistance", force=True)
            add(self.event("new_service", severity,
                           f"{'Nouvelle' if old is None else 'Modification de l’'} unité systemd : {os.path.basename(path)}",
                           f"systemd|{path}|{execs[:200]}", path=path, command=execs, previous=old,
                           reasons=" ; ".join(reasons)))
        users = _passwd_users()
        for user, info, old in self.diff("users", users) or []:
            uid = info.split("|", 1)[0]
            if uid == "0" and user != "root":
                add(self.event("uid0_account", "critical", f"Compte {user} avec l'UID 0 (droits root)",
                               f"uid0|{user}", name=user))
            elif old is None:
                add(self.event("new_local_account", "medium", f"Nouveau compte local : {user}",
                               f"account|{user}", name=user, value=info))
        for key, member, _old in self.diff("admins", _admin_group_members()) or []:
            group = key.split("|", 1)[0]
            add(self.event("admin_group_added", "high", f"{member} ajouté au groupe {group}",
                           f"admin|{key}", member=member, name=group))
        for key, line, _old in self.diff("sudoers", _sudoers_lines()) or []:
            add(self.event("sudoers_modified", "critical" if "nopasswd" in line.lower() else "high",
                           "Nouvelle règle sudo", f"sudo|{key}", path=key.split("|", 1)[0], line=line))
        for key, label, _old in self.diff("ssh_keys", _authorized_keys(users)) or []:
            user = key.split("|", 1)[0]
            add(self.event("ssh_key_added", "high", f"Nouvelle clé SSH autorisée pour {user}",
                           f"sshkey|{key}", name=user, value=label))
        preload = {l.strip(): "1" for l in _read_text(_fs("/etc/ld.so.preload")).splitlines() if l.strip()}
        for lib, _v, _o in self.diff("ld_preload", preload) or []:
            add(self.event("ld_preload", "critical", f"Bibliothèque préchargée dans tous les programmes : {lib}",
                           f"preload|{lib}", path=lib))
        hosts = {l.strip(): "1" for l in _read_text(_fs("/etc/hosts")).splitlines()
                 if l.strip() and not l.strip().startswith("#")}
        for line, _v, _o in self.diff("hosts", hosts) or []:
            add(self.event("hosts_file_modified", "medium", "Fichier /etc/hosts modifié", f"hosts|{line}", line=line))
        return events

    def scan_software(self) -> list:
        names = _package_names(self.pkg_cache)
        if names is None:
            return []
        events = []
        for name, version, old in self.diff("software", names) or []:
            if old is None:
                ev = self.event("new_software", "low", f"Nouveau paquet installé : {name} {version}",
                                f"software|{name}", name=name, version=version)
                if ev:
                    events.append(ev)
        return events

    def refresh_watchlist(self):
        if time.time() - self.watch_at < 1800:
            return
        self.watch_at = time.time()
        try:
            r = requests.get(f"{_server_url(self.config)}/api/agents/{platform.node()}/watchlist",
                             headers=_agent_headers(self.config), timeout=15, verify=_tls_verify(self.config))
            if r.ok:
                data = r.json() or {}
                self.server_enabled = bool(data.get("enabled", True))
                self.watchlist = [p for p in data.get("products") or [] if isinstance(p, dict)]
                version = data.get("yara_version")
                if version and version != self.yara.version and (_yara_mod is not None or shutil.which("yara")):
                    self.load_yara_rules(version)
        except Exception:
            pass

    def load_yara_rules(self, version: str):
        r = requests.get(f"{_server_url(self.config)}/api/agents/{platform.node()}/yara-rules",
                         headers=_agent_headers(self.config), timeout=30, verify=_tls_verify(self.config))
        r.raise_for_status()
        data = r.json() or {}
        errors = self.yara.load(data.get("version") or version, data.get("rulesets") or [])
        for error in errors:
            logger.warning(f"Surveillance : jeu de règles YARA ignoré — {error}")
        with self.lock:
            self.state["yara_cache"] = {}       # nouvelles règles : les fichiers seront réanalysés
            self.dirty_cache = True
        logger.info(f"Surveillance : règles YARA chargées ({len(self.yara.compiled) or len(self.yara.cli_files)} jeu(x)).")

    def flush(self, events: list):
        if len(events) > _MONITOR_MAX_EVENTS_PER_CYCLE:
            extra = len(events) - _MONITOR_MAX_EVENTS_PER_CYCLE
            events = events[:_MONITOR_MAX_EVENTS_PER_CYCLE] + [self.event(
                "event_flood", "medium", f"{extra} autre(s) alerte(s) non transmise(s) en une minute",
                f"flood|{int(time.time() // 3600)}", count=extra)]
        with self.lock:
            events, self.pending = list(self.pending) + events, []
            queue = (self.state["queue"] + [e for e in events if e])[-_MONITOR_QUEUE_MAX:]
        if not queue:
            return
        try:
            r = requests.post(f"{_server_url(self.config)}/api/agents/{platform.node()}/events",
                              json={"events": queue[:100]}, headers=_agent_headers(self.config),
                              timeout=20, verify=_tls_verify(self.config))
            r.raise_for_status()
            logger.info(f"Surveillance : {min(len(queue), 100)} alerte(s) envoyée(s) au serveur.")
            queue = queue[100:]
        except Exception as e:
            logger.warning(f"Surveillance : envoi reporté ({type(e).__name__}), {len(queue)} alerte(s) en file.")
        with self.lock:
            if queue != self.state["queue"]:
                self.state["queue"] = queue
                self.dirty = True

def _monitor_settings(config):
    def num(key, default, low, high):
        try:
            return max(low, min(int(config.get("monitoring", key, fallback=str(default))), high))
        except ValueError:
            return default
    try:
        enabled = config.getboolean("monitoring", "enabled", fallback=True)
    except ValueError:
        enabled = True
    return enabled, num("process_interval_seconds", 30, 10, 600), num("system_interval_minutes", 5, 1, 120)

def monitor_cycle(mon: "_Monitor", now: float, due_system: bool, due_software: bool) -> list:
    """Un passage : processus, puis système et paquets s'ils sont dus. Retourne les alertes."""
    events = []
    if due_system:
        mon.yara_watch_dirs(web=True)
    for name, scan, due in (("processus", mon.scan_processes, True), ("système", mon.scan_system, due_system),
                            ("paquets", mon.scan_software, due_software),
                            ("YARA", lambda: mon.yara_drain(YARA_BUDGET_PER_CYCLE), True)):
        if due:
            try:
                events += scan()
            except Exception as e:
                logger.warning(f"Surveillance ({name}) : {type(e).__name__}: {e}")
    return [e for e in events if e]

def monitor_loop(config):
    """Boucle de surveillance (Linux, mode démon), à la priorité la plus basse."""
    try:
        os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 19)   # nice 19, ce fil seulement
    except (AttributeError, OSError):
        pass
    time.sleep(20)
    mon = _Monitor(config)
    threading.Thread(target=log_watch_loop, args=(mon,), daemon=True, name="LogWatch").start()
    next_system = next_software = 0.0
    while True:
        enabled, proc_interval, system_minutes = _monitor_settings(config)
        if enabled:
            mon.refresh_watchlist()
            if mon.server_enabled:
                now = time.time()
                events = monitor_cycle(mon, now, now >= next_system, now >= next_software)
                if now >= next_system:
                    next_system = now + system_minutes * 60
                if now >= next_software:
                    next_software = now + 15 * 60
                mon.flush(events)
                with mon.lock:
                    for key, ts in list(mon.state["alerted"].items()):
                        if now - ts > 30 * 86400:
                            del mon.state["alerted"][key]
                            mon.dirty = True
                mon.save()
        mon.wake.wait(proc_interval)      # réveillé tout de suite par une alerte grave des journaux
        mon.wake.clear()

# ─── Helpers serveur ──────────────────────────────────────────────────────────
def _cfg_bool(config, key: str, default: bool) -> bool:
    try:
        return config.getboolean("main_server", key, fallback=default)
    except ValueError:
        return default

def _server_url(config) -> str:
    """http(s)://hôte:port selon `[main_server] use_https`."""
    host = config.get("main_server", "host",  fallback="127.0.0.1")
    port = config.get("main_server", "port",  fallback="4000")
    scheme = "https" if _cfg_bool(config, "use_https", False) else "http"
    return f"{scheme}://{host}:{port}"

def _tls_verify(config) -> bool:
    """Vérifier le certificat du serveur ? Sans effet en HTTP. `verify_ssl = false`
    accepte un certificat auto-signé/expiré (déconseillé hors réseau interne)."""
    if not _cfg_bool(config, "use_https", False):
        return True
    verify = _cfg_bool(config, "verify_ssl", True)
    if not verify:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return verify

def _agent_headers(config) -> dict:
    token = config.get("main_server", "token", fallback="")
    if len(token) < 32:
        raise ValueError("agent.conf must contain a 32+ character main_server token")
    return {"x-agent-token": token}

# ─── Envoi du rapport (avec retry/backoff) ───────────────────────────────────
def _build_payload(config, software_list, open_ports) -> dict:
    # Fusion : built-in + règles personnalisées (les built-in ont priorité)
    compliance = collect_compliance()
    custom = collect_custom_rules(config)
    for k, v in custom.items():
        compliance.setdefault(k, v)
    update_check = collect_outdated_software(software_list, config)
    if update_check.get("ok"):
        compliance.setdefault("pending_updates", update_check["count"])
    return {
        "hostname":      platform.node(),
        "os":            platform.system(),
        "release":       platform.release(),
        "os_build":      platform.version(),
        "agent_version": AGENT_VERSION,
        "timestamp":     datetime.now().isoformat(),
        "software":      software_list,
        "open_ports":    open_ports,
        "compliance":    compliance,
        "update_check":  update_check,
        "ip_addresses":  get_local_ips(),
        "logged_users":  collect_logged_users(),
        "log_tail":      read_log_tail(80),
    }

def send_report(config, software_list, open_ports, max_attempts: int = 6) -> dict | None:
    """Envoie un rapport au serveur avec backoff exponentiel borné.

    En cas d'échec persistant, retourne None — l'appelant (run_daemon) continuera
    son rythme normal. Le prochain cycle retentera, donc l'agent finit toujours
    par récupérer dès que le serveur revient.
    """
    url     = f"{_server_url(config)}/api/agents/report"
    headers = _agent_headers(config)
    payload = _build_payload(config, software_list, open_ports)

    delay = 5  # seconds — démarre à 5s, plafonne à 5 min
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"Envoi du rapport à {url} (essai {attempt}/{max_attempts}, {len(software_list)} logiciels)…")
            # La corrélation CVE peut être longue sur un inventaire important.
            resp = requests.post(url, json=payload, headers=headers, timeout=(10, 300),
                                 verify=_tls_verify(config))
            resp.raise_for_status()
            data = resp.json()
            # L'agent se limite à transmettre l'inventaire. La corrélation CVE
            # et les éventuelles alertes sont centralisées sur le serveur.
            logger.info("✅ Rapport envoyé au serveur pour analyse.")
            return data
        except requests.exceptions.Timeout as e:
            logger.warning(f"Analyse serveur trop longue ({type(e).__name__}). Retry dans {delay}s…")
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ChunkedEncodingError) as e:
            logger.warning(f"Serveur injoignable ({type(e).__name__}). Retry dans {delay}s…")
        except requests.exceptions.HTTPError as e:
            # 5xx → on retente ; 4xx → on abandonne (config/auth invalide)
            code = e.response.status_code
            if 500 <= code < 600:
                logger.warning(f"HTTP {code} — retry dans {delay}s…")
            else:
                logger.error(f"HTTP {code}: {e.response.text} — abandon (vérifiez le token/la configuration)")
                return None
        except Exception as e:
            logger.error(f"Erreur inattendue: {e}")
        if attempt < max_attempts:
            time.sleep(delay)
            delay = min(delay * 2, 300)  # cap à 5 min
    logger.error("Toutes les tentatives ont échoué — on attendra le prochain cycle.")
    return None

# ─── Heartbeat ────────────────────────────────────────────────────────────────
def send_heartbeat(config) -> bool:
    """Ping léger. Retourne True si OK, False sinon (silencieux)."""
    try:
        r = requests.post(
            f"{_server_url(config)}/api/agents/{platform.node()}/heartbeat",
            json={"os": platform.system(), "release": platform.release(),
                   "os_build": platform.version(), "agent_version": AGENT_VERSION},
            headers=_agent_headers(config),
            timeout=5,
            verify=_tls_verify(config),
        )
        return r.status_code == 200
    except Exception:
        return False

# ─── Auto-update ──────────────────────────────────────────────────────────────
def _version_newer(server: str, current: str) -> bool:
    """True si server > current. Tolère les formats X.Y, X.Y.Z, X.Y.Z-suffix."""
    def _t(v):
        return tuple(int(x) for x in re.split(r'[.\-]', v) if x.isdigit())
    try:
        return _t(server) > _t(current)
    except Exception:
        return server.strip() != current.strip()

def _detect_install_target() -> tuple[str, str | None]:
    """Renvoie (script_path, service_name) ou (script_path, None) si pas géré par un service.
    script_path = chemin absolu vers mini_agent.py actuellement exécuté.
    """
    script_path = os.path.abspath(__file__)
    system = platform.system()
    service_name = None
    if system == "Linux":
        # Vérifie si une unit systemd 'heimdall-agent' existe
        try:
            r = subprocess.run(["systemctl", "list-unit-files", "heimdall-agent.service"],
                               capture_output=True, text=True, timeout=5)
            if "heimdall-agent.service" in r.stdout:
                service_name = "heimdall-agent.service"
        except Exception:
            pass
    elif system == "Darwin":
        # launchd plist utilisateur ou système
        candidates = [
            os.path.expanduser("~/Library/LaunchAgents/com.heimdall.agent.plist"),
            "/Library/LaunchDaemons/com.heimdall.agent.plist",
        ]
        for p in candidates:
            if os.path.exists(p):
                service_name = p
                break
    return script_path, service_name

def check_for_update(config) -> bool:
    """Vérifie la version serveur. Si plus récente, télécharge et applique.
    Retourne True si une mise à jour a été appliquée (le process va s'arrêter)."""
    try:
        r = requests.get(
            f"{_server_url(config)}/api/agent/version",
            headers=_agent_headers(config),
            timeout=10,
            verify=_tls_verify(config),
        )
        if r.status_code != 200:
            return False
        info = r.json()
        server_version = info.get("version", "")
        if not server_version or not _version_newer(server_version, AGENT_VERSION):
            return False
        logger.info(f"Mise à jour disponible: {AGENT_VERSION} → {server_version}")
    except Exception as e:
        logger.debug(f"Vérif update échouée (réseau): {e}")
        return False

    # Téléchargement de la nouvelle version de mini_agent.py
    try:
        r = requests.get(
            f"{_server_url(config)}/static/mini_agent.py",
            headers=_agent_headers(config),
            timeout=60,
            verify=_tls_verify(config),
        )
        r.raise_for_status()
        new_source = r.content
        if len(new_source) < 1000 or b"AGENT_VERSION" not in new_source:
            raise ValueError("Le fichier téléchargé ne semble pas être un mini_agent.py valide")
    except Exception as e:
        logger.error(f"Téléchargement de la mise à jour échoué: {e}")
        return False

    script_path, service_name = _detect_install_target()
    # Écriture atomique : on écrit dans le même dossier, puis rename
    target_dir = os.path.dirname(script_path)
    try:
        fd, tmp_path = tempfile.mkstemp(prefix=".mini_agent.", suffix=".py.new", dir=target_dir)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(new_source)
            os.chmod(tmp_path, 0o755)
            os.replace(tmp_path, script_path)
        except Exception:
            try: os.unlink(tmp_path)
            except Exception: pass
            raise
    except PermissionError:
        logger.error(f"Permission refusée pour écrire {script_path}. "
                     f"Lancez l'agent avec les droits suffisants (root pour /opt/heimdall-agent).")
        return False
    except Exception as e:
        logger.error(f"Échec de l'écriture du nouvel agent: {e}")
        return False

    logger.info(f"✅ Mise à jour appliquée → {script_path}")

    # Redémarrage : si on est géré par un service, on lui laisse faire (il nous relance).
    # Sinon, on relance soi-même via os.execv.
    if service_name and platform.system() == "Linux":
        logger.info("Sortie pour laisser systemd relancer avec la nouvelle version…")
        os._exit(0)  # Restart=on-failure relancera
    elif service_name and platform.system() == "Darwin":
        logger.info("Sortie pour laisser launchd relancer avec la nouvelle version…")
        os._exit(0)
    else:
        # Mode foreground : on s'auto-relance
        logger.info("Relance directe avec la nouvelle version…")
        os.execv(sys.executable, [sys.executable, script_path] + sys.argv[1:])
    return True

def _remove_heimdall_shortcut(errors: list):
    path = "/usr/local/bin/heimdall"
    if os.path.exists(path) or os.path.islink(path):
        try:
            os.remove(path)
        except PermissionError:
            errors.append(f"Impossible de supprimer {path} (sudo requis ?)")

# ─── Configuration / statut (commande `heimdall`) ─────────────────────────────
def _mask_token(token: str) -> str:
    return f"{token[:4]}…{token[-4:]}" if len(token) > 10 else ("****" if token else "(vide)")

def cmd_configuration(cfg):
    path = _config_path_existing()
    print(f"Heimdall Mini Agent v{AGENT_VERSION}")
    print(f"Fichier de configuration : {path or '(introuvable — valeurs par défaut)'}")
    print()
    print(f"  Serveur          : {_server_url(cfg)}")
    print(f"  Token            : {_mask_token(cfg.get('main_server', 'token', fallback=''))}")
    print(f"  Vérifier certif. : {_tls_verify(cfg)}")
    print(f"  Intervalle       : {cfg.get('agent', 'interval_minutes', fallback='60')} min")
    print(f"  Scan de ports    : {cfg.getboolean('agent', 'port_scan', fallback=False)}")
    print()
    if not path:
        print("Aucune configuration trouvée. Créez-en une avec, par exemple :")
        print("  heimdall --server <IP> --port 4000 --token <AGENT_AUTH_TOKEN> --scan")
        return
    print("Pour modifier une valeur sans éditer le fichier :")
    print("  heimdall --server <IP> --port <PORT> --token <TOKEN> [--https] [--no-verify-ssl] --scan")
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            ans = input(f"\nOuvrir {path} dans un éditeur maintenant ? [o/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans == "o":
            editor = os.environ.get("EDITOR") or next(
                (e for e in ("nano", "vi", "vim") if shutil.which(e)), None)
            if not editor:
                print(f"Aucun éditeur trouvé — éditez {path} manuellement.")
                return
            subprocess.call([editor, path])
    print("\nAprès modification, redémarrez le service :")
    if platform.system() == "Darwin":
        print("  sudo launchctl kickstart -k system/com.heimdall.agent")
    else:
        print("  sudo systemctl restart heimdall-agent")

def cmd_status(cfg):
    path = _config_path_existing()
    print(f"Heimdall Mini Agent v{AGENT_VERSION}")
    print(f"Configuration : {path or '(par défaut)'}")
    print(f"Serveur       : {_server_url(cfg)}  (vérif. certificat : {_tls_verify(cfg)})")
    print(f"Fichier de log: {LOG_FILE}  (voir aussi : heimdall --logs)")
    system = platform.system()
    if system == "Linux":
        r = subprocess.run(["systemctl", "is-active", "heimdall-agent"],
                           capture_output=True, text=True)
        print(f"Service       : {r.stdout.strip() or 'introuvable'}")
    elif system == "Darwin":
        r = subprocess.run(["launchctl", "list", "com.heimdall.agent"],
                           capture_output=True, text=True)
        print(f"Service       : {'actif' if r.returncode == 0 else 'introuvable'}")
    try:
        r = requests.get(f"{_server_url(cfg)}/api/ping", headers=_agent_headers(cfg),
                         timeout=5, verify=_tls_verify(cfg))
        print(f"Connexion     : {'OK' if r.status_code == 200 else f'HTTP {r.status_code}'}")
    except Exception as e:
        print(f"Connexion     : échec ({type(e).__name__})")

def cmd_logs(n: int, follow: bool):
    """Affiche les dernières lignes du log local — inspection sur la machine
    sans dépendre de journalctl (fonctionne même hors service systemd)."""
    print(f"# {LOG_FILE}\n")
    for line in read_log_tail(n):
        print(line)
    if not follow:
        return
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
    except FileNotFoundError:
        print("Fichier de log introuvable.")
    except KeyboardInterrupt:
        pass

# ─── Désinstallation ──────────────────────────────────────────────────────────
def uninstall_agent() -> int:
    """Désinstalle proprement l'agent. Retourne 0 si OK, 1 sinon."""
    system = platform.system()
    errors = []

    if system == "Linux":
        unit = "/etc/systemd/system/heimdall-agent.service"
        for cmd in (["systemctl", "stop",    "heimdall-agent"],
                    ["systemctl", "disable", "heimdall-agent"]):
            try:
                subprocess.run(cmd, capture_output=True, timeout=10)
            except Exception as e:
                errors.append(f"{' '.join(cmd)}: {e}")
        try:
            if os.path.exists(unit):
                os.remove(unit)
                subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=10)
        except PermissionError:
            errors.append(f"Impossible de retirer {unit} (sudo requis ?)")
        _remove_heimdall_shortcut(errors)
        # Supprime le dossier d'install
        for d in ("/opt/heimdall-agent",):
            if os.path.isdir(d):
                try:
                    shutil.rmtree(d)
                except PermissionError:
                    errors.append(f"Impossible de supprimer {d} (sudo requis ?)")
        logger.info("Désinstallation Linux terminée.")
    elif system == "Darwin":
        # Décharge le plist et le supprime
        for plist in (os.path.expanduser("~/Library/LaunchAgents/com.heimdall.agent.plist"),
                      "/Library/LaunchDaemons/com.heimdall.agent.plist"):
            if os.path.exists(plist):
                try:
                    subprocess.run(["launchctl", "unload", plist], capture_output=True, timeout=10)
                    os.remove(plist)
                except PermissionError:
                    errors.append(f"Impossible de retirer {plist} (sudo requis ?)")
                except Exception as e:
                    errors.append(f"launchctl unload {plist}: {e}")
        _remove_heimdall_shortcut(errors)
        # Dossier d'install (utilisateur ou système)
        for d in (os.path.expanduser("~/Library/Application Support/HeimdallAgent"),
                  "/opt/heimdall-agent"):
            if os.path.isdir(d):
                try:
                    shutil.rmtree(d)
                except PermissionError:
                    errors.append(f"Impossible de supprimer {d} (sudo requis ?)")
        logger.info("Désinstallation macOS terminée.")
    else:
        logger.error(f"Désinstallation non supportée sur {system}.")
        return 1

    if errors:
        for e in errors:
            logger.warning(e)
        logger.warning("Désinstallation partielle — relancez avec sudo si nécessaire.")
        return 1
    return 0

# ─── Main ─────────────────────────────────────────────────────────────────────
def run_once(config, do_port_scan=False):
    logger.info(f"--- Collecte sur {platform.node()} ({platform.system()}) v{AGENT_VERSION} ---")
    software = collect_software()
    logger.info(f"  {len(software)} logiciels collectés.")
    open_ports = []
    if do_port_scan or config.getboolean("agent", "port_scan", fallback=False):
        open_ports = scan_ports()
        logger.info(f"  Ports ouverts : {open_ports}")
    send_report(config, software, open_ports)

def run_daemon(config):
    interval = int(config.get("agent", "interval_minutes", fallback=60)) * 60
    logger.info(f"Mode démon — intervalle : {interval // 60} min — version {AGENT_VERSION}")

    def _hb_loop():
        """Heartbeat toutes les 60s. Si le serveur tombe, on continue à tenter
        en silence — dès qu'il revient, le prochain heartbeat passe et la
        machine reapparaît 'En ligne' dans le dashboard."""
        time.sleep(5)
        while True:
            send_heartbeat(config)
            time.sleep(60)

    def _update_loop():
        """Vérifie une mise à jour au démarrage (après 60s) puis toutes les 24h.
        Si le serveur est down, c'est silencieux et on retente plus tard."""
        time.sleep(60)
        while True:
            try:
                check_for_update(config)  # peut ne jamais revenir si update appliquée
            except Exception as e:
                logger.debug(f"Update loop: {e}")
            for _ in range(86400):  # 24h
                time.sleep(1)

    threading.Thread(target=_hb_loop, daemon=True, name="Heartbeat").start()
    threading.Thread(target=_update_loop, daemon=True, name="UpdateLoop").start()
    if platform.system() == "Linux":
        threading.Thread(target=monitor_loop, args=(config,), daemon=True, name="Monitor").start()

    while True:
        try:
            run_once(config)
        except Exception as e:
            logger.error(f"Cycle interrompu par une exception: {e}")
        logger.info(f"Prochain envoi dans {interval // 60} minutes.")
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="heimdall",
        description="Heimdall Security Agent — surveillance de parc et corrélation CVE.",
        epilog=(
            "Commandes courantes :\n"
            "  heimdall --scan            Scanner maintenant (un seul rapport)\n"
            "  heimdall --status          Voir l'état de l'agent et du service\n"
            "  heimdall --logs            Voir les derniers logs (--logs -f pour suivre en direct)\n"
            "  heimdall --configuration   Voir / modifier la configuration\n"
            "  heimdall --daemon          Lancer en mode démon (généralement via le service)\n"
            "  heimdall --check-update    Vérifier une mise à jour\n"
            "  heimdall --uninstall       Désinstaller l'agent\n"
            "  heimdall --version         Afficher la version"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--scan", "--once", dest="once", action="store_true",
                        help="Scanner maintenant : un seul rapport puis exit")
    parser.add_argument("--scan-ports", action="store_true", help="Activer le scan de ports réseau")
    parser.add_argument("--daemon",     action="store_true", help="Mode démon continu")
    parser.add_argument("--version",    action="store_true", help="Afficher la version puis exit")
    parser.add_argument("--status",     action="store_true", help="Afficher l'état de l'agent (config, service, connexion) puis exit")
    parser.add_argument("--logs",       action="store_true", help="Afficher les derniers logs locaux puis exit")
    parser.add_argument("-f", "--follow", action="store_true", help="Avec --logs : suivre en direct (comme tail -f)")
    parser.add_argument("--lines", type=int, default=200, help="Avec --logs : nombre de lignes (défaut 200)")
    parser.add_argument("--configuration", "--configure", dest="configuration", action="store_true",
                        help="Afficher / modifier la configuration puis exit")
    parser.add_argument("--check-update", action="store_true", help="Forcer la vérification d'une mise à jour puis exit")
    parser.add_argument("--uninstall",  action="store_true", help="Désinstaller l'agent (stop service, supprime les fichiers)")
    # Surcharges de connexion (prioritaires sur agent.conf, non enregistrées)
    parser.add_argument("--server",     default="", help="Hôte/IP du serveur Heimdall")
    parser.add_argument("--port",       default="", help="Port du serveur Heimdall")
    parser.add_argument("--token",      default="", help="Token secret (AGENT_AUTH_TOKEN, 32+ caractères)")
    parser.add_argument("--https",      action="store_true", help="Se connecter en HTTPS")
    parser.add_argument("--http",       action="store_true", help="Se connecter en HTTP (désactive HTTPS)")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="HTTPS : ne pas vérifier le certificat (certificat auto-signé)")
    args = parser.parse_args()

    if args.version:
        print(f"Heimdall Mini Agent v{AGENT_VERSION}")
        sys.exit(0)
    if args.uninstall:
        sys.exit(uninstall_agent())
    if args.logs:
        cmd_logs(args.lines, args.follow)
        sys.exit(0)

    cfg = load_config()
    if not cfg.has_section("main_server"):
        cfg.add_section("main_server")
    for key, val in (("host", args.server), ("port", args.port), ("token", args.token)):
        if val:
            cfg.set("main_server", key, val)
    if args.https or args.http:
        cfg.set("main_server", "use_https", "true" if args.https and not args.http else "false")
    if args.no_verify_ssl:
        cfg.set("main_server", "verify_ssl", "false")
    if args.status:
        cmd_status(cfg)
        sys.exit(0)
    if args.configuration:
        cmd_configuration(cfg)
        sys.exit(0)
    if args.check_update:
        check_for_update(cfg)
        sys.exit(0)
    if args.daemon:
        run_daemon(cfg)
    else:
        run_once(cfg, do_port_scan=args.scan_ports)
