# 🛡️ Heimdall Agents — CVE

Surveillance de parc et corrélation de vulnérabilités (CVE) **auto-hébergée**.

Des **agents légers** installés sur vos postes (Windows, Linux, macOS) collectent
l'inventaire logiciel, les ports ouverts et l'état de conformité, puis l'envoient à
**votre serveur agent**. Celui-ci croise ces données avec la base CVE Heimdall et vous
présente un tableau de bord des vulnérabilités de votre parc.

```
┌────────────┐   inventaire    ┌──────────────────┐   corrélation   ┌──────────────┐
│   Agents   │ ───────────────▶│  Serveur agent   │ ───────────────▶│  Site CVE    │
│ Win/Linux/ │   (HTTPS+token) │  + Dashboard     │   (API + clé)   │  Heimdall    │
│   macOS    │◀─── auto-update │  + MongoDB       │                 │              │
└────────────┘                 └──────────────────┘                 └──────────────┘
```

---

## 📦 Contenu du dépôt

| Fichier / dossier           | Rôle                                                            |
| --------------------------- | --------------------------------------------------------------- |
| `mini_agent.py`             | Agent Linux / macOS (CLI, mode `--once` ou démon)               |
| `windows_agent_tray.py`     | Agent Windows (icône dans la barre système, configuration in-app) |
| `build_windows.ps1`         | Compile `HeimdallAgent.exe` (PyInstaller)                       |
| `server/`                   | Serveur agent : dashboard web, API d'ingestion, corrélation CVE |
| `docker-compose.yaml`       | Déploiement du serveur agent + MongoDB en une commande          |
| `agent.conf.example`        | Modèle de configuration agent (à copier en `agent.conf`)        |

---

## 🚀 1. Déployer le serveur agent (auto-hébergé)

**Prérequis :** Docker + Docker Compose.

```bash
git clone https://github.com/Heimdall-Security-fr/Agents-CVE.git
cd Agents-CVE

# ⚠️ Éditez docker-compose.yaml et changez AU MINIMUM :
#   AGENT_AUTH_TOKEN, DEFAULT_ADMIN_PASSWORD, DASHBOARD_JWT_SECRET
docker compose up -d --build
```

Une fois démarré :

- **Dashboard admin :** http://localhost:4000/admin
- **Identifiants par défaut :** définis dans `docker-compose.yaml`
  (`DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD`) — **changez-les à la première connexion**.

### Variables d'environnement principales (serveur)

| Variable                 | Défaut                     | Description                                  |
| ------------------------ | -------------------------- | -------------------------------------------- |
| `AGENT_AUTH_TOKEN`       | `changeme-secret-token`    | Token partagé serveur ↔ agents **(à changer)** |
| `DASHBOARD_JWT_SECRET`   | _(aléatoire)_              | Clé de signature des sessions **(à fixer en prod)** |
| `DEFAULT_ADMIN_EMAIL`    | `admin@heimdall.local`     | Compte admin créé au 1er démarrage           |
| `DEFAULT_ADMIN_PASSWORD` | _(à définir)_              | Mot de passe admin — définissez-le dans votre `.env`/compose |
| `HEIMDALL_FRONT_URL`     | `http://localhost:3000`    | URL publique du site CVE Heimdall            |
| `HEIMDALL_CVE_API`       | `http://cve_api:5000`      | API CVE interrogée pour les corrélations     |
| `CVE_API_KEY`            | _(vide)_                   | Clé API CVE (optionnelle, plan premium)      |
| `SERVER_PUBLIC_HOST`     | `127.0.0.1`                | IP/domaine public de ce serveur              |

---

## 💻 2. Installer un agent sur un poste

### a. Configuration commune

Copiez le modèle et renseignez vos valeurs :

```bash
cp agent.conf.example agent.conf
```

Renseignez au minimum, dans `agent.conf` :

- `[main_server] host` → IP/domaine de votre serveur agent
- `[main_server] token` → la même valeur que `AGENT_AUTH_TOKEN` côté serveur
- `[api] cve_api_key` → votre clé API générée sur le site CVE Heimdall (optionnel)

> 🔒 `agent.conf` contient des secrets : il est **ignoré par git** et ne doit jamais
> être committé. Seul `agent.conf.example` est versionné.

### b. Windows 🪟

Téléchargez l'exécutable servi par votre serveur :

```
http://<serveur>:4000/static/heimdall-agent.exe
```

Placez `heimdall-agent.exe` et `agent.conf` dans le même dossier, puis lancez l'exe :
une icône apparaît dans la barre système (configuration et état accessibles via le menu).

Pour compiler l'exe vous-même (PowerShell admin) :

```powershell
.\build_windows.ps1
```

### c. Linux / macOS 🐧🍎

```bash
# Dépendances
pip3 install requests

# Envoi unique (test)
python3 mini_agent.py --once

# Mode démon (envoi périodique selon interval_minutes)
python3 mini_agent.py
```

Options utiles :

| Commande                          | Effet                                            |
| --------------------------------- | ------------------------------------------------ |
| `python3 mini_agent.py --once`    | Une collecte + un envoi, puis sortie             |
| `python3 mini_agent.py`           | Mode démon (boucle + heartbeat + auto-update)    |
| `python3 mini_agent.py --uninstall` | Désinstalle proprement (service + fichiers)    |

L'agent gère l'**auto-update** (récupération de la dernière version auprès du serveur)
et la **résilience réseau** (backoff exponentiel si le serveur est injoignable).

---

## 🔢 Versioning

Agents et serveur partagent la même version. Cette première release publique est la
**`1.0.0`**. Les agents s'auto-mettent à jour pour s'aligner sur la version exposée par
le serveur agent déployé.

---

## 🆘 Réinitialiser le mot de passe admin

```bash
docker exec -it heimdall_agent_mongo mongosh
> use heimdall_agents
> db.dashboard_users.deleteOne({ role: "admin" })
> exit
docker restart heimdall_agent_server   # le compte par défaut est recréé
```

---

© Heimdall Security — Agents CVE
