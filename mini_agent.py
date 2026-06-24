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
AGENT_VERSION = "1.0.0"

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("HeimdallAgent")

# ─── Configuration ────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "main_server": {"host": "127.0.0.1", "port": "4000", "token": "changeme-secret-token"},
    "api":         {"cve_api_key": ""},
    "agent":       {"interval_minutes": "60", "port_scan": "false"}
}

def load_config():
    config = configparser.ConfigParser()
    search_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.conf"),
        "/opt/heimdall-agent/agent.conf",
        r"C:\ProgramData\HeimdallAgent\agent.conf"
    ]
    loaded = config.read(search_paths)
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


# ─── Helpers serveur ──────────────────────────────────────────────────────────
def _server_url(config) -> str:
    host = config.get("main_server", "host",  fallback="127.0.0.1")
    port = config.get("main_server", "port",  fallback="4000")
    return f"http://{host}:{port}"

def _agent_headers(config) -> dict:
    token = config.get("main_server", "token", fallback="changeme-secret-token")
    return {"x-agent-token": token}

# ─── Envoi du rapport (avec retry/backoff) ───────────────────────────────────
def _build_payload(config, software_list, open_ports) -> dict:
    # Fusion : built-in + règles personnalisées (les built-in ont priorité)
    compliance = collect_compliance()
    custom = collect_custom_rules(config)
    for k, v in custom.items():
        compliance.setdefault(k, v)
    return {
        "hostname":      platform.node(),
        "os":            platform.system(),
        "release":       platform.release(),
        "os_build":      platform.version(),
        "agent_version": AGENT_VERSION,
        "timestamp":     datetime.now().isoformat(),
        "software":      software_list,
        "open_ports":    open_ports,
        "cve_api_key":   config.get("api", "cve_api_key", fallback=""),
        "compliance":    compliance,
        "ip_addresses":  get_local_ips(),
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
            resp = requests.post(url, json=payload, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            vuln_count = data.get("vulnerable_count", 0)
            logger.info(f"✅ Rapport envoyé. {vuln_count} vulnérabilité(s) détectée(s).")
            for v in data.get("vulnerabilities", [])[:5]:
                logger.warning(f"  ⚠️  {v['software']} → {v['cves_count']} CVE "
                               f"(CRITIQUE: {v.get('critical',0)}, HAUTE: {v.get('high',0)})")
            return data
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
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
            timeout=5
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

    while True:
        try:
            run_once(config)
        except Exception as e:
            logger.error(f"Cycle interrompu par une exception: {e}")
        logger.info(f"Prochain envoi dans {interval // 60} minutes.")
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Heimdall Mini Agent")
    parser.add_argument("--once",       action="store_true", help="Un seul rapport puis exit")
    parser.add_argument("--scan-ports", action="store_true", help="Activer le scan de ports réseau")
    parser.add_argument("--daemon",     action="store_true", help="Mode démon continu")
    parser.add_argument("--version",    action="store_true", help="Afficher la version puis exit")
    parser.add_argument("--check-update", action="store_true", help="Forcer la vérification d'une mise à jour puis exit")
    parser.add_argument("--uninstall",  action="store_true", help="Désinstaller l'agent (stop service, supprime les fichiers)")
    args = parser.parse_args()

    if args.version:
        print(f"Heimdall Mini Agent v{AGENT_VERSION}")
        sys.exit(0)
    if args.uninstall:
        sys.exit(uninstall_agent())

    cfg = load_config()
    if args.check_update:
        check_for_update(cfg)
        sys.exit(0)
    if args.daemon:
        run_daemon(cfg)
    else:
        run_once(cfg, do_port_scan=args.scan_ports)
