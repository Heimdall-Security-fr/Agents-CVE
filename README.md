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
| `build_windows.ps1`         | Compile `HeimdallAgent.exe` localement (PyInstaller)            |
| `make_icon.py`              | Génère l'icône de l'exe (`heimdall.ico`) depuis le logo — utilisé par la CI et `build_windows.ps1` |
| `server/`                   | Serveur agent : dashboard web, API d'ingestion, corrélation CVE. Son `Dockerfile` cross-compile aussi l'agent Windows (Wine + PyInstaller) |
| `docker-compose.yaml`       | Déploiement simple du serveur agent + MongoDB (image Docker Hub `heimdallsecurity/agent-cve`) |
| `docker-compose.prod.yaml`  | Déploiement production : MongoDB authentifié, non exposé, données sur l'hôte |
| `agent.conf.example`        | Modèle de configuration agent (à copier en `agent.conf`)        |
| `docs/GUIDE_CONFORMITE.md`  | Guide utilisateur conformité et mises à jour                     |

---

## 🚀 1. Déployer le serveur agent (auto-hébergé)

**Prérequis :** Docker (+ Docker Compose pour l'option A).

L'image du serveur est publiée sur Docker Hub :
[`heimdallsecurity/agent-cve`](https://hub.docker.com/r/heimdallsecurity/agent-cve).
Elle embarque le dashboard, l'API d'ingestion et l'agent Windows précompilé
(`heimdall-agent.exe`) — **aucun build local nécessaire**.

| Tag                                  | Contenu                                            |
| ------------------------------------ | -------------------------------------------------- |
| `latest`                             | Dernière version publiée                           |
| `1.0.<n>` (ex. `1.0.57`)             | Version numérotée (voir [Versioning](#-versioning)) — recommandé en production |
| `<sha-du-commit>`                    | Version figée sur un commit précis                 |

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
# IP/domaine que les agents utiliseront pour joindre ce serveur
SERVER_PUBLIC_HOST=<ip-ou-domaine-du-serveur>
# Clé API CVE nominative (compte Heimdall) — sans elle, aucune vulnérabilité n'est détectée
CVE_API_KEY=<votre clé API CVE>
# Hors réseau Docker Heimdall :
HEIMDALL_CVE_API=https://cve.heimdall-security.com/api
# Optionnel : figer une version précise
# AGENT_CVE_VERSION=1.0.57
EOF

docker compose up -d
```

> Générer un secret : `openssl rand -hex 32`
>
> `docker compose up -d` tire l'image Docker Hub. Pour construire depuis les sources
> à la place : `docker compose up -d --build`.
>
> **Production :** préférez `docker-compose.prod.yaml` (MongoDB avec authentification,
> non exposé, données dans `/srv/docker/agents/mongodb`). Les étapes et variables
> obligatoires (`MONGO_USER`, `MONGO_PASSWORD`…) sont décrites en tête du fichier :
> `docker compose -f docker-compose.prod.yaml up -d --pull always`.

### Option B — Docker sans Compose

```bash
docker network create heimdall_agents

docker run -d --name heimdall_agent_mongo --network heimdall_agents \
  --restart unless-stopped -v agent_mongo_data:/data/db mongo:7

docker run -d --name heimdall_agent_server --network heimdall_agents \
  --restart unless-stopped -p 4000:4000 \
  -e MONGO_URI="mongodb://heimdall_agent_mongo:27017/heimdall_agents" \
  -e SERVER_PUBLIC_HOST="<ip-ou-domaine-du-serveur>" \
  -e SERVER_PUBLIC_PORT="4000" \
  -e AGENT_AUTH_TOKEN="<32+ caractères>" \
  -e DASHBOARD_JWT_SECRET="<32+ caractères>" \
  -e DEFAULT_ADMIN_EMAIL="admin@votre-domaine.tld" \
  -e DEFAULT_ADMIN_PASSWORD="<12+ caractères>" \
  -e HEIMDALL_CVE_API="https://cve.heimdall-security.com/api" \
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
- **Déployer les agents :** page *Déploiement* du dashboard (section 2).
- **Production :** placez le serveur derrière un reverse proxy HTTPS. Les agents envoient
  leur token et l'inventaire du parc, ils ne doivent pas transiter en clair sur Internet.

### Variables d'environnement principales (serveur)

| Variable                 | Défaut                     | Description                                  |
| ------------------------ | -------------------------- | -------------------------------------------- |
| `AGENT_AUTH_TOKEN`       | _(obligatoire)_            | Clé de déploiement : token partagé serveur ↔ agents, **32+ caractères** (le serveur refuse de démarrer sinon) |
| `DASHBOARD_JWT_SECRET`   | _(obligatoire)_            | Clé de signature des sessions du dashboard, **32+ caractères** |
| `DASHBOARD_JWT_EXPIRE_DAYS` | `7`                     | Durée de validité d'une session (jours)      |
| `DASHBOARD_ALLOWED_ORIGINS` | _(vide)_                | Origines autorisées (CORS) pour le dashboard, séparées par des virgules |
| `DEFAULT_ADMIN_EMAIL`    | _(obligatoire)_            | Compte admin créé au 1er démarrage           |
| `DEFAULT_ADMIN_PASSWORD` | _(obligatoire)_            | Mot de passe admin, **12+ caractères**       |
| `SERVER_PUBLIC_HOST`     | `127.0.0.1`                | IP/domaine que les agents utilisent pour joindre ce serveur (commandes d'installation, auto-update) |
| `SERVER_PUBLIC_PORT`     | `4000`                     | Port **publié** du serveur (ex. `4012` si le compose fait `4012:4000`) |
| `HEIMDALL_FRONT_URL`     | `http://localhost:3000`    | URL publique du site CVE Heimdall (liens vers les fiches CVE) |
| `HEIMDALL_CVE_API`       | `http://cve_api:5000`      | API CVE interrogée pour les corrélations (hors réseau Docker Heimdall : `https://cve.heimdall-security.com/api`) |
| `HEIMDALL_RSS_URL`       | `http://cve_api:5000/cves/rss` | Flux RSS des nouvelles CVE (rafraîchissement du cache) |
| `CVE_API_KEY`            | _(vide)_                   | Clé API CVE nominative — **obligatoire** pour la corrélation de vulnérabilités (sans elle, aucun appel à l'API, 0 vulnérabilité détectée) ; chaque logiciel analysé consomme 1 crédit |
| `CVE_DAILY_QUERY_BUDGET` | `0` (désactivé)            | Plafond local facultatif de requêtes CVE par jour pour ce serveur. Désactivé par défaut : la limite est celle du compte (quota journalier du plan, puis crédits). Un même produit n'est interrogé qu'une fois par 24 h, quel que soit le nombre de postes |
| `MAX_CVES_PER_SOFTWARE`  | `50`                       | Nombre maximal de CVE conservées par logiciel (100 max) |
| `AI_TIMEOUT_SECONDS`     | `60`                       | Délai maximal d'une réponse de l'assistant IA (10 à 120 s) |
| `AI_PROVIDER`            | _(vide)_                   | Assistant : `openai_compatible`, `anthropic` ou `ollama` |
| `AI_BASE_URL`            | selon le fournisseur       | URL de l'API ou passerelle IA (Ollama : `http://ollama:11434`) |
| `AI_API_KEY`             | _(vide)_                   | Clé IA, gardée uniquement dans le conteneur serveur |
| `AI_MODEL`               | _(vide)_                   | Modèle à utiliser (requis pour activer le chat) |

---

## 💻 2. Installer un agent sur un poste

### Page *Déploiement* du dashboard (le plus simple)

La page **Déploiement** (`http://<serveur>:<port>/admin` → *Déploiement*) regroupe tout ce
qu'il faut pour installer un agent :

- **Clé de déploiement** : c'est le token agent (`AGENT_AUTH_TOKEN`). Elle est masquée par
  défaut, avec des boutons *Afficher* et *Copier*. Seuls les rôles **admin** et
  **deployment** la voient, et le serveur journalise chaque consultation
  (`docker logs heimdall_agent_server | grep DEPLOY`).
- **Commandes d'installation prêtes à copier** (Windows, Linux/macOS, exe en ligne de
  commande), avec le serveur et le port déjà remplis. Le bouton *Copier la commande* y
  insère la clé.
- **Téléchargements** : installateur Windows préconfiguré (`Install-HeimdallAgent.ps1`),
  exe seul, et archives Linux / macOS préconfigurées (`agent.conf` + `install.sh`).

| Rôle              | Accès                                                                 |
| ----------------- | --------------------------------------------------------------------- |
| `admin`           | Tout : utilisateurs, règles de conformité, rescan CVE, clé de déploiement, téléchargements |
| `deployment`      | Clé de déploiement, téléchargements et installateurs, liste des serveurs et inventaire |
| `inspection_logs` | Consultation : serveurs, vulnérabilités, conformité, mises à jour, logs des agents, exports CSV/PDF, quota CVE |
| `codir`           | Consultation : serveurs, conformité, mises à jour, logs, exports CSV/PDF  |

Les utilisateurs et leurs rôles se gèrent depuis la page *Utilisateurs* (admin uniquement).

> 🔒 La clé de déploiement permet d'enregistrer des agents et de télécharger les
> installateurs. Pour la changer, modifiez `AGENT_AUTH_TOKEN` puis redémarrez le serveur.
> Les agents déjà installés devront alors être reconfigurés avec la nouvelle clé.

### a. Configuration commune (installation manuelle)

Copiez le modèle et renseignez vos valeurs :

```bash
cp agent.conf.example agent.conf
```

Renseignez au minimum, dans `agent.conf` :

- `[main_server] host` → IP/domaine de votre serveur agent
- `[main_server] token` → la même valeur que `AGENT_AUTH_TOKEN` côté serveur
- `[main_server] use_https` / `verify_ssl` → connexion chiffrée au serveur et vérification de son certificat (optionnel)

> La clé API CVE n'est **pas** configurée sur les agents : elle se définit uniquement côté
> serveur agent (variable `CVE_API_KEY`), et le serveur ignore toute clé envoyée par un agent.

> 🔒 `agent.conf` contient des secrets : il est **ignoré par git** et ne doit jamais
> être committé. Seul `agent.conf.example` est versionné.

### b. Windows 🪟

Compatible Windows 10 / 11 et **Windows Server** 2016, 2019, 2022 et 2025 (y compris
Server Core). L'édition est détectée automatiquement et s'affiche sur le dashboard
(ex. « Windows Server 2022 »).

**Installation recommandée (une commande, sans droits administrateur).** Copiez-la depuis
la page *Déploiement*, où le serveur, le port et la clé sont déjà remplis. Sinon, dans
PowerShell, en remplaçant `<serveur>`, `<port>` et `<AGENT_AUTH_TOKEN>` :

```powershell
irm -Headers @{ 'x-agent-token' = '<AGENT_AUTH_TOKEN>' } http://<serveur>:<port>/api/install/windows.ps1 | iex
```

Le script installe l'agent dans `%LOCALAPPDATA%\HeimdallAgent`, enregistre le serveur, le
port et le token, l'active au démarrage de Windows et le lance (icône dans la zone de
notification). Aucune invite « éditeur inconnu » ni écran SmartScreen : un téléchargement
par PowerShell n'est pas marqué comme venant d'Internet, contrairement à un téléchargement
par navigateur.

> ℹ️ `<port>` est le port **publié** du serveur. Avec les compose fournis, définir
> `SERVER_PUBLIC_PORT=4012` dans `.env` publie le serveur sur 4012 **et** l'indique aux
> agents. Si vous faites le mapping vous-même (ou derrière un reverse proxy),
> `SERVER_PUBLIC_PORT` doit valoir le port que les agents joignent réellement.

Autre possibilité : bouton *Télécharger l'installateur* de la page *Déploiement*, puis
exécution de `Install-HeimdallAgent.ps1`. Le résultat est le même.

**Serveurs : démarrer avec la machine, sans ouverture de session.** Par défaut, l'agent
démarre à l'ouverture d'une session (icône dans la zone de notification). Sur un serveur où
personne ne se connecte, il ne tournerait donc pas. Pour qu'il démarre avec la machine :

- lancez la commande d'installation dans un **PowerShell administrateur** : c'est activé
  automatiquement ;
- ou, sur un agent déjà installé : clic droit sur l'icône → *Démarrer avec la machine*
  (invite administrateur), ou `HeimdallAgent.exe --service-install` en administrateur.

L'agent est alors lancé par une tâche planifiée « au démarrage » (`HeimdallSecurityAgentService`),
sous le compte SYSTEM et sans icône. Il envoie les rapports et les heartbeats, et applique les
mises à jour automatiquement. Sa configuration est copiée dans
`C:\ProgramData\HeimdallAgent\agent.conf`, lisible uniquement par SYSTEM et les administrateurs,
et son journal est `C:\ProgramData\HeimdallAgent\agent.log`. Quand quelqu'un ouvre une session,
l'icône reste disponible et laisse le service faire les envois : il n'y a pas de rapport en double.
Si vous modifiez ensuite la configuration depuis l'icône, désactivez puis réactivez *Démarrer avec
la machine* pour la recopier dans le service. Pour le retirer : `--service-uninstall`, ou la même
case du menu (la désinstallation de l'agent le retire aussi).

**Installation manuelle.** Téléchargez l'exe seul depuis la page *Déploiement* (bouton
*EXE seul*). Le navigateur peut afficher un avertissement SmartScreen tant que
l'exécutable n'est pas signé (*Informations complémentaires* → *Exécuter quand même*).
Options en ligne de commande :

```
HeimdallAgent.exe --silent --autostart --server <serveur> --port <port> --token <AGENT_AUTH_TOKEN>
```

| Option        | Effet                                                                 |
| ------------- | --------------------------------------------------------------------- |
| `--server/--port/--token` | Enregistre la connexion au serveur (sans assistant avec `--silent`) |
| `--https` / `--http` | Connexion au serveur en HTTPS / en HTTP                        |
| `--no-verify-ssl` | Accepter un certificat HTTPS auto-signé                           |
| `--silent`    | Pas d'assistant graphique : enregistre et démarre                     |
| `--autostart` | Démarrer avec Windows                                                 |
| `--once`      | Un seul envoi puis sortie                                             |
| `--scan-ports` | Forcer le scan de ports                                              |
| `--no-tray`   | Mode console, sans icône                                              |
| `--service-install` / `--service-uninstall` | Démarrer (ou non) avec la machine, avant toute session — administrateur requis |
| `--no-auto-update` | Redemander confirmation avant chaque mise à jour, au lieu de l'appliquer automatiquement |
| `--logs`      | Derniers logs locaux (`--logs -f` pour suivre en direct) — aussi accessible depuis le menu de l'icône (*Voir les logs*) |

Sans options, un assistant graphique demande le serveur, le port et le token.

**Mise à jour** : automatique par défaut (comme Linux/macOS), sans confirmation — une
notification s'affiche après application. Réglable depuis *Configurer…* (case « Mise à
jour automatique ») ou `[agent] auto_update = false` dans `agent.conf`.

Dans **Configuration** (clic droit sur l'icône), vous pouvez aussi choisir l'**apparence**
(sombre, clair ou automatique selon le thème Windows) et activer le **démarrage avec Windows**.
Le choix est enregistré dans `agent.conf` (`[ui] theme = dark | light | auto`).

**Exe précompilé** : l'image Docker du serveur embarque `HeimdallAgent.exe`, compilé
par la CI avec l'icône Heimdall. Pour le compiler vous-même (PowerShell admin) :

```powershell
.\build_windows.ps1
```

### c. Linux / macOS 🐧🍎

**Installation recommandée (une commande).** Copiez-la depuis la page *Déploiement*, où le
serveur, le port et la clé sont déjà remplis. Sinon, dans un terminal, en remplaçant
`<serveur>`, `<port>` et `<AGENT_AUTH_TOKEN>` :

```bash
curl -fsSL -H "x-agent-token: <AGENT_AUTH_TOKEN>" http://<serveur>:<port>/api/download/agent/linux \
  -o heimdall.zip && unzip -o heimdall.zip -d heimdall && sudo bash heimdall/install.sh
```

Sur macOS, remplacez `/api/download/agent/linux` par `/api/download/agent/macos`. Les
mêmes archives se téléchargent aussi depuis la page *Déploiement*.

Le script installe l'agent dans `/opt/heimdall-agent`, écrit `agent.conf` (serveur, port,
token — déjà renseignés), installe la seule dépendance nécessaire (`requests`, aucun
`requirements.txt` à gérer à la main), crée le service (**systemd** sur Linux, **launchd**
sur macOS), le démarre, et pose une commande **`heimdall`** dans `/usr/local/bin` pour le
piloter ensuite :

| Commande                    | Effet                                                    |
| ---------------------------- | -------------------------------------------------------- |
| `heimdall --scan`            | Scanner maintenant (un seul rapport)                     |
| `heimdall --status`          | État de l'agent : config, service, connexion au serveur  |
| `heimdall --configuration`   | Voir / modifier la configuration (édite `agent.conf`)    |
| `heimdall --logs`            | Derniers logs locaux (`--logs -f` pour suivre en direct) |
| `heimdall --daemon`          | Mode démon (normalement géré par le service, pas à lancer à la main) |
| `heimdall --check-update`    | Forcer la vérification d'une mise à jour                 |
| `heimdall --uninstall`       | Désinstaller proprement (service + fichiers + commande)  |
| `heimdall --version`         | Afficher la version installée                            |
| `heimdall --help`            | Toutes les options                                       |

Logs : `journalctl -u heimdall-agent -f` (Linux) ou `tail -f /var/log/heimdall-agent.log` (macOS).

**Installation manuelle**, sans service ni commande `heimdall` (utile pour un test ponctuel) :

```bash
curl -O http://<serveur>:<port>/static/mini_agent.py
pip3 install requests
python3 mini_agent.py --server <serveur> --port <port> --token <AGENT_AUTH_TOKEN> --scan
```

L'agent gère l'**auto-update** (récupération de la dernière version auprès du serveur)
et la **résilience réseau** (backoff exponentiel si le serveur est injoignable).

---

## ✅ 3. Conformité et mises à jour

Le dashboard évalue la configuration de chaque machine (pare-feu, SSH, mots de passe,
TLS…) selon des règles modifiables, et liste les logiciels dont une version plus récente
est disponible :
- **Windows (10/11)** : `winget` pour les applications **et** Windows Update pour le système, cumulés ;
- **Windows Server** : pas de winget. Les logiciels installés sont inventoriés depuis le registre,
  et les mises à jour en attente viennent de **Windows Update** (API intégrée, un WSUS configuré
  est respecté) ;
- **Linux / macOS** : apt, dnf, yum, zypper ou brew.

**EPSS** : chaque CVE détectée affiche sa probabilité d'exploitation dans les 30 prochains jours
(FIRST EPSS). Au-delà de 10 %, la CVE est signalée « exploitation probable ». À gravité CVSS égale,
elle passe en tête de liste. L'EPSS figure aussi dans les exports CSV et PDF.

**Vulnérabilités du système** : en plus des logiciels installés, chaque agent Windows
déclare le système lui-même, par exemple « Windows Server 2022 » en version
`10.0.20348.<niveau de patch>`. Les CVE Microsoft le concernant sont corrélées selon le
niveau de mise à jour cumulative réellement installé : une CVE corrigée par un patch déjà
appliqué n'apparaît pas.

📘 **[Guide utilisateur — Conformité et mises à jour](docs/GUIDE_CONFORMITE.md)** :
fonctionnement, liste des règles, règles personnalisées, droits nécessaires, dépannage.

**Version des agents** : le Dashboard affiche une carte « Agents à jour » (combien sont
sur la dernière version publiée par ce serveur), et chaque agent porte un badge **à
jour** / **en retard** sur la page *Serveurs*. Les agents se mettent à jour tout seuls
(section 2), ce badge sert surtout à repérer ceux restés éteints trop longtemps pour
recevoir la mise à jour automatique.

---

## 📋 Logs

Les logs du serveur agent lui-même sont consultables via `docker logs heimdall_agent_server`.
Ils ne sont envoyés vers aucune plateforme externe.

### Logs des agents installés (débogage d'un poste)

Chaque agent (Windows, Linux, macOS) écrit ses propres logs localement — inspection
directe sur la machine :

```bash
heimdall --logs        # dernières lignes
heimdall --logs -f     # suivi en direct (comme tail -f)
```

Sur Windows, le menu de l'icône propose aussi *Voir les logs* (ouvre le fichier).

À chaque rapport, l'agent envoie aussi ses ~80 dernières lignes de log au serveur
(borné niveau serveur : 200 lignes / 50 ko max, jamais conservé dans l'historique des
rapports — uniquement le dernier snapshot). Depuis le dashboard, page *Serveurs*, le
lien **📄 logs** sous chaque hôte ouvre ces logs pour déboguer sans accès SSH/RDP au
poste. Réservé aux rôles admin/inspection — l'API `/api/agents/<hôte>/logs` n'est pas
publique, contrairement à certains autres endpoints `/api/agents*` de ce serveur.

---

## 🔢 Versioning

Agents et serveur partagent la même version, écrite dans les agents au moment du build.

- **À chaque push** sur la branche `agents`, la CI construit l'image en `1.0.<numéro de run>`
  (ex. `1.0.57`) : la version augmente toujours. L'image est aussi publiée sous ce tag
  (`heimdallsecurity/agent-cve:1.0.57`), en plus de `latest` et du SHA du commit.
- **Mise à jour des agents** : un agent compare sa version à celle du serveur
  (`/api/agent/version`) au démarrage puis toutes les 24 h, et se met à jour automatiquement
  s'il est en retard (sous Windows, `auto_update = false` redemande confirmation). Il suffit
  donc de **mettre à jour le serveur** (`docker compose pull && docker compose up -d`).
- **Changement mineur/majeur** : modifiez `VERSION` et `AGENT_VERSION_BASE` dans
  `.gitea/workflows/main.yaml` (ex. `1.1`).
- Un build local (`docker compose up --build`) utilise la version du fichier `VERSION`.

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
