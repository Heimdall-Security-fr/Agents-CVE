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
| `docker-compose.yaml`       | Déploiement du serveur agent + MongoDB (image Docker Hub `heimdallsecurity/agent-cve`) |
| `agent.conf.example`        | Modèle de configuration agent (à copier en `agent.conf`)        |

---

## 🚀 1. Déployer le serveur agent (auto-hébergé)

**Prérequis :** Docker (+ Docker Compose pour l'option A).

L'image du serveur est publiée sur Docker Hub :
[`heimdallsecurity/agent-cve`](https://hub.docker.com/r/heimdallsecurity/agent-cve).
Elle embarque le dashboard, l'API d'ingestion et l'agent Windows précompilé
(`heimdall-agent.exe`) — **aucun build local nécessaire**.

| Tag                                  | Contenu                                            |
| ------------------------------------ | -------------------------------------------------- |
| `latest`                             | Dernière version de la branche principale          |
| `<sha-du-commit>`                    | Version figée (recommandé en production)           |

### Option A — Docker Compose (recommandé)

```bash
git clone https://github.com/Heimdall-Security-fr/Agents-CVE.git
cd Agents-CVE

# Créez un fichier .env avec vos secrets (le compose refuse de démarrer sans eux)
cat > .env <<'EOF'
AGENT_AUTH_TOKEN=<32+ caractères aléatoires>
DASHBOARD_JWT_SECRET=<32+ caractères aléatoires>
DEFAULT_ADMIN_EMAIL=admin@votre-domaine.tld
DEFAULT_ADMIN_PASSWORD=<12+ caractères>
# Optionnel : figer une version précise
# AGENT_CVE_VERSION=<sha-du-commit>
EOF

docker compose up -d
```

> Générer un secret : `openssl rand -hex 32`
>
> `docker compose up -d` tire l'image Docker Hub. Pour construire depuis les sources
> à la place : `docker compose up -d --build`.

### Option B — Docker sans Compose

```bash
docker network create heimdall_agents

docker run -d --name heimdall_agent_mongo --network heimdall_agents \
  --restart unless-stopped -v agent_mongo_data:/data/db mongo:7

docker run -d --name heimdall_agent_server --network heimdall_agents \
  --restart unless-stopped -p 4000:4000 \
  -e MONGO_URI="mongodb://heimdall_agent_mongo:27017/heimdall_agents" \
  -e SERVER_PUBLIC_HOST="<ip-ou-domaine-du-serveur>" \
  -e AGENT_AUTH_TOKEN="<32+ caractères>" \
  -e DASHBOARD_JWT_SECRET="<32+ caractères>" \
  -e DEFAULT_ADMIN_EMAIL="admin@votre-domaine.tld" \
  -e DEFAULT_ADMIN_PASSWORD="<12+ caractères>" \
  -e HEIMDALL_CVE_API="https://cve.heimdall-security.com" \
  -e CVE_API_KEY="<votre clé API CVE>" \
  heimdallsecurity/agent-cve:latest
```

### Mise à jour du serveur

```bash
docker compose pull && docker compose up -d      # Option A
# ou : docker pull heimdallsecurity/agent-cve:latest, puis recréer le conteneur (Option B)
```

Les données (MongoDB) sont conservées dans le volume `agent_mongo_data`. Les agents
s'auto-mettent à jour sur la version exposée par le serveur.

### Après le démarrage

- **Dashboard admin :** `http://<serveur>:4000/admin`
- **Identifiants :** ceux définis dans `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD`
  — **changez-les à la première connexion**.
- **Production :** placez le serveur derrière un reverse proxy HTTPS. Les agents envoient
  leur token et l'inventaire du parc, ils ne doivent pas transiter en clair sur Internet.

### Variables d'environnement principales (serveur)

| Variable                 | Défaut                     | Description                                  |
| ------------------------ | -------------------------- | -------------------------------------------- |
| `AGENT_AUTH_TOKEN`       | `changeme-secret-token`    | Token partagé serveur ↔ agents **(à changer)** |
| `DASHBOARD_JWT_SECRET`   | _(aléatoire)_              | Clé de signature des sessions **(à fixer en prod)** |
| `DEFAULT_ADMIN_EMAIL`    | `admin@heimdall.local`     | Compte admin créé au 1er démarrage           |
| `DEFAULT_ADMIN_PASSWORD` | _(à définir)_              | Mot de passe admin — définissez-le dans votre `.env`/compose |
| `HEIMDALL_FRONT_URL`     | `http://localhost:3000`    | URL publique du site CVE Heimdall            |
| `HEIMDALL_CVE_API`       | `http://cve_api:5000`      | API CVE interrogée pour les corrélations (hors réseau Docker Heimdall : `https://cve.heimdall-security.com`) |
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

**Installation recommandée (une commande, sans droits administrateur).** Dans PowerShell,
en remplaçant `<serveur>`, `<port>` et `<AGENT_AUTH_TOKEN>` (le dashboard, page
*Déploiement*, affiche la commande avec le serveur et le port déjà remplis) :

```powershell
irm -Headers @{ 'x-agent-token' = '<AGENT_AUTH_TOKEN>' } http://<serveur>:<port>/api/install/windows.ps1 | iex
```

Le script installe l'agent dans `%LOCALAPPDATA%\HeimdallAgent`, enregistre le serveur, le
port et le token, l'active au démarrage de Windows et le lance (icône dans la zone de
notification). Aucune invite « éditeur inconnu » ni écran SmartScreen : un téléchargement
par PowerShell n'est pas marqué comme venant d'Internet, contrairement à un téléchargement
par navigateur.

> ℹ️ `<port>` doit être le port **publié** du serveur (ex. `4012` si votre compose fait
> `4012:4000`) et `SERVER_PUBLIC_PORT` doit avoir la même valeur, sinon les agents
> installés contactent un mauvais port.

**Installation manuelle.** Téléchargez l'exe depuis le dashboard (page *Déploiement*).
Le navigateur peut afficher un avertissement SmartScreen tant que l'exécutable n'est pas
signé (*Informations complémentaires* → *Exécuter quand même*). Options en ligne de commande :

```
HeimdallAgent.exe --silent --autostart --server <serveur> --port <port> --token <token>
```

| Option        | Effet                                                                 |
| ------------- | --------------------------------------------------------------------- |
| `--server/--port/--token` | Enregistre la connexion au serveur (sans assistant avec `--silent`) |
| `--silent`    | Pas d'assistant graphique : enregistre et démarre                     |
| `--autostart` | Démarrer avec Windows                                                 |
| `--once`      | Un seul envoi puis sortie                                             |

Sans options, un assistant graphique demande le serveur, le port et le token.

Dans **Configuration** (clic droit sur l'icône), vous pouvez aussi choisir l'**apparence**
(sombre, clair ou automatique selon le thème Windows) et activer le **démarrage avec Windows**.
Le choix est enregistré dans `agent.conf` (`[ui] theme = dark | light | auto`).

Pour compiler l'exe vous-même (PowerShell admin) :

```powershell
.\build_windows.ps1
```

### c. Linux / macOS 🐧🍎

Récupérez l'agent directement depuis votre serveur (ou clonez ce dépôt) :

```bash
curl -O http://<serveur>:4000/static/mini_agent.py

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

## ✅ 3. Conformité et mises à jour

Le dashboard évalue la configuration de chaque machine (pare-feu, SSH, mots de passe,
TLS…) selon des règles modifiables, et liste les logiciels dont une version plus récente
est disponible (winget, apt, dnf, yum, zypper, brew).

📘 **[Guide utilisateur — Conformité et mises à jour](docs/GUIDE_CONFORMITE.md)** :
fonctionnement, liste des règles, règles personnalisées, droits nécessaires, dépannage.

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
