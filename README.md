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
| `1.1.<n>` (ex. `1.1.46`)             | Version numérotée (voir [Versioning](#-versioning)) — recommandé en production |
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
| `SMTP_HOST`              | _(vide)_                   | Serveur SMTP des notifications mail (défini : envoi activé par défaut). Tout se règle aussi depuis la page *Notifications* (section 4) |
| `SMTP_PORT`              | `587`                      | Port SMTP |
| `SMTP_SECURITY`          | `starttls`                 | `starttls`, `ssl` (TLS implicite, port 465) ou `none` |
| `SMTP_USER` / `SMTP_PASSWORD` | _(vide)_              | Identifiants SMTP (facultatifs pour un relais interne) |
| `SMTP_FROM`              | `SMTP_USER`                | Adresse d'expéditeur des mails |
| `SMTP_VERIFY_TLS`        | `true`                     | `false` pour accepter le certificat auto-signé d'un relais interne |
| `DASHBOARD_PUBLIC_URL`   | _(vide)_                   | URL du dashboard dans les liens des mails (ex. `https://agents.exemple.com/admin`) |
| `MAIL_DIGEST_MINUTES`    | `5`                        | Intervalle de regroupement des alertes mail (minutes) |

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

## ✉️ 4. Notifications mail

Page *Notifications* du dashboard. Chaque utilisateur choisit ce qu'il reçoit à l'adresse
de son compte :

| Notification | Contenu | Rôles |
|--------------|---------|-------|
| **Vulnérabilités** | | |
| Nouvelles CVE sur le parc | CVE apparues sur une machine (logiciel ajouté ou mis à jour, ou CVE publiée depuis l'analyse précédente), à partir d'une **sévérité minimale** choisie : critique (CVSS ≥ 9, par défaut), élevée (≥ 7) ou moyenne (≥ 4) | admin, inspection_logs |
| CVE à forte probabilité d'exploitation | CVE du parc dont l'EPSS atteint 10 %, quelle que soit sa note CVSS — y compris une CVE déjà connue dont l'EPSS monte | admin, inspection_logs |
| Analyse CVE interrompue | Quota épuisé, clé `CVE_API_KEY` invalide ou API injoignable (rappel au plus une fois par 24 h) | tous |
| **Logiciels** | | |
| Nouvelles mises à jour | Nouvelle version disponible pour un logiciel installé (winget, Windows Update, apt…) | admin, inspection_logs, codir |
| Logiciel installé, désinstallé ou mis à jour | Changements d'inventaire d'une machine entre deux rapports | tous |
| **Conformité** | | |
| Rapport de conformité | Score par hôte et contrôles en échec, PDF joint, **tous les X jours** (1 à 90, au choix) | admin, inspection_logs, codir |
| Contrôle qui passe en échec | Un contrôle conforme au rapport précédent échoue (pare-feu coupé…), sans attendre le rapport | admin, inspection_logs, codir |
| **Parc** | | |
| Machine hors ligne | Aucun contact depuis **X heures** (1 à 720, 24 par défaut, au choix), puis retour en ligne | tous |
| Nouvelle machine | Premier rapport d'un agent | tous |
| Nouveau port ouvert | Port qui s'ouvre sur une machine (nécessite le scan de ports de l'agent) | tous |
| Nouveau compte utilisateur | Compte jamais vu sur un serveur ou un ordinateur (profil ou session ouverte) | tous |

Les alertes sont **regroupées** : un seul mail toutes les `MAIL_DIGEST_MINUTES` (5 min),
même si tout le parc remonte en même temps. Une CVE, un compte, un port ou une mise à jour
n'est signalé **qu'une fois par machine** (un compte qui disparaît puis revient n'est pas
re-signalé) ; une dérive de conformité ou un changement de logiciel l'est à chaque fois.
Les CVE marquées « non affecté » ne sont pas envoyées. Une machine ajoutée au parc est
signalée avec ses CVE ; ses comptes, ports et mises à jour déjà présents servent de
référence. Si l'inventaire d'une machine perd brusquement plus de la moitié de ses
logiciels (collecte partielle), aucune désinstallation n'est signalée. Le premier rapport de
conformité part dans les minutes qui suivent son activation, puis tous les X jours ;
le bouton *Recevoir le rapport maintenant* l'envoie à la demande.

**Serveur d'envoi (SMTP)** — réservé à l'admin, sur la même page : serveur, port, sécurité
(STARTTLS, SSL/TLS ou aucune), identifiants, expéditeur et URL du dashboard utilisée dans
les liens des mails. Le bouton *Envoyer un mail de test* vérifie la configuration ; la
dernière erreur d'envoi s'affiche sur la page. Les mêmes réglages peuvent venir des
variables `SMTP_*` (tableau ci-dessous) : une valeur saisie dans le dashboard est prioritaire.
Le mot de passe saisi dans le dashboard est stocké dans MongoDB et n'est jamais renvoyé
au navigateur ; pour qu'il ne soit pas en base, passez-le par `SMTP_PASSWORD`.

Tant que l'envoi n'est pas activé, rien n'est mis en file : l'activer plus tard n'envoie
pas d'arriéré.

---

## 🛡️ 5. Surveillance des postes

Chaque agent analyse sa machine **en continu et localement**, et n'envoie au serveur que
les **déclencheurs**. Les alertes s'affichent sur la page *Surveillance* (rôles `admin` et
`inspection_logs`) et peuvent partir par mail (type « Alerte de surveillance », avec une
gravité minimale choisie par chaque utilisateur).

| Ce qui est surveillé | Windows | Linux |
|---|---|---|
| **Tâches automatiques** | Tâches planifiées (`System32\Tasks`) | cron (système et utilisateurs), unités systemd ajoutées dans `/etc/systemd` |
| **Démarrage automatique** | Clés Run/RunOnce (machine et chaque utilisateur), dossiers Démarrage, Winlogon, débogueurs IFEO (porte dérobée des touches rémanentes), nouveaux services et pilotes | — |
| **Logiciels** | Nouveau logiciel installé | Nouveau paquet (dpkg / rpm) |
| **Comptes et droits** | Ajout aux administrateurs locaux, nouveau compte local | Nouveau compte, compte UID 0, ajout à `sudo`/`wheel`, nouvelle règle sudo, nouvelle clé SSH autorisée |
| **Processus suspects** | PowerShell encodé ou qui télécharge et exécute, outils détournés (certutil, mshta, regsvr32, rundll32…), suppression des sauvegardes (rançongiciel), dump de LSASS, effacement des journaux, document Office qui lance un shell, imitation d'un binaire système, outils offensifs (mimikatz…), exécution depuis un dossier temporaire ou public, double extension | Shell inversé (`/dev/tcp`, netcat, socat, scripts), téléchargement exécuté dans un shell, mineur de cryptomonnaie, exécution depuis `/tmp` ou `/dev/shm`, exécution en mémoire (memfd), serveur web qui lance un shell (webshell), outils offensifs |
| **Autres** | Exclusions Microsoft Defender, fichier hosts | `/etc/ld.so.preload` (rootkit), `/etc/hosts` |

**Journaux en temps réel.**

| Windows (abonnement aux journaux, aucun coût entre deux événements) | Linux (nouvelles lignes lues toutes les 2 s) |
|---|---|
| Sécurité : force brute (≥ 10 échecs en 5 min), connexion bureau à distance réussie après des échecs, journal effacé, compte créé, ajout aux administrateurs (locaux ou du domaine), tâche planifiée créée, création de processus (4688, si l'audit est activé) | `auth.log` / `secure` (ou journald) : force brute SSH, connexion réussie après des échecs, connexion root par mot de passe, sudo refusé, commande sudo suspecte, compte créé, ajout à `sudo`/`wheel` |
| Système : service installé, journal effacé | Accès web nginx/Apache : Log4Shell, accès à un webshell, traversée de répertoires, injection SQL, scanners |
| PowerShell (4104, journalisation des blocs de script) : chargeurs, commandes encodées, contournement de l'AMSI — et analyse YARA du script | `audit.log` (auditd) : commandes exécutées (shells inversés…), y compris les plus brèves |
| Defender : menace détectée, protection désactivée, exclusion ajoutée ; Sysmon (événement 1) si installé | |

Les signets de lecture sont conservés : après un redémarrage, l'agent reprend où il s'était
arrêté. Une alerte élevée ou critique issue des journaux est envoyée **immédiatement**.
Sous Windows, le journal de sécurité n'est lisible qu'en mode service (compte SYSTEM).
Pour voir les processus les plus brefs, activez l'audit de création de processus (4688,
ligne de commande incluse) ou installez Sysmon ; sous Linux, auditd.

**Règles YARA.** Le serveur distribue aux agents un jeu de règles par défaut
(`server/yara/heimdall_default.yar` : webshells, shells inversés, Mimikatz et outils de vol
d'identifiants, chargeurs PowerShell, contournement de l'AMSI, mineurs, notes de rançon,
destruction des sauvegardes, raccourcis piégés, persistances Linux) et les jeux que vous
ajoutez depuis la page *Surveillance* (collés ou importés en `.yar`, compilés par le serveur
avant d'être acceptés ; métadonnées `severity` et `description` reconnues). Sont analysés :
l'exécutable des nouveaux processus, les programmes cités par une persistance (tâche,
service, démarrage, cron, systemd), les fichiers déposés dans les dossiers sensibles
(Téléchargements, Bureau, Temp, `C:\Users\Public`, `/tmp`, `/dev/shm`, racines web
`/var/www`…), et sous Windows les scripts PowerShell journalisés. Les fichiers de Windows
et des paquets Linux ne sont pas analysés, et un fichier n'est relu que s'il change. Le
jeu par défaut ne déclenche rien sur 7 000 fichiers système sains (800 Mo).
Agent Windows : YARA est inclus dans l'exe. Agent Linux : `yara-python` est installé
par le script d'installation si possible, sinon la commande `yara` est utilisée si elle est
présente ; sans l'un ni l'autre, la surveillance fonctionne sans analyse YARA.

**Appui sur les CVE récentes.** Toutes les 30 min, l'agent reçoit sa *liste de
surveillance* : les logiciels de **sa** machine concernés par une CVE publiée depuis moins de
60 jours (CVSS ≥ 7), critique (CVSS ≥ 9) ou probablement exploitée (EPSS ≥ 10 %). Si l'un
d'eux lance un shell (`cmd`, PowerShell, `sh`…), l'alerte est **critique** : exploitation
possible, avec la CVE en cause. Côté serveur, toute alerte qui touche un logiciel vulnérable
de la machine (chemin, ligne de commande) est rattachée à ses CVE et sa gravité est relevée.

**Performances.** Seuls les **nouveaux** processus sont examinés (toutes les 30 s) ; la ligne
de commande n'est lue que pour une courte liste de programmes à risque. Tâches, démarrage,
services et comptes sont relevés toutes les 5 min par différence avec l'instantané précédent
(un fichier de tâche n'est relu que s'il a changé), les logiciels toutes les 15 min. Le fil de
surveillance tourne en priorité minimale (mode « arrière-plan » de Windows, `nice 19` sous
Linux). Mesuré sous Linux : **~2 ms de CPU par passage** (80 processus). L'analyse YARA est
plafonnée à 32 Mo par passage de 30 s (environ 120 ms de CPU au maximum, puis rien tant
qu'aucun fichier ne change) ; un gros dépôt de fichiers est analysé progressivement. Rien
n'est envoyé tant qu'aucune règle ne se déclenche.

**Bruit.** Au premier démarrage, l'état existant sert de référence : seuls les changements
ultérieurs sont signalés (sauf un processus déjà lancé qui déclenche une règle moyenne ou
plus). Une même alerte n'est envoyée qu'une fois (dédoublonnage conservé entre les
redémarrages). Le serveur accepte au plus 500 alertes par machine et par heure, et les
conserve 90 jours.

Réglages côté agent : section `[monitoring]` de `agent.conf` (voir `agent.conf.example`).
Le bouton *Suspendre la surveillance* (admin) l'arrête sur tout le parc sous 30 min.

> Limite : ce n'est pas un EDR. Sans audit des créations de processus (4688, Sysmon ou
> auditd), un processus qui démarre et se termine entre deux relevés (30 s) peut échapper à
> l'analyse ; les persistances qu'il installe (tâche, service, clé de démarrage…) et les
> traces qu'il laisse dans les journaux sont, elles, détectées. Les règles YARA ne
> remplacent pas un antivirus : elles complètent Defender avec des règles ciblées.

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

- **Source : GitHub `main`.** On y pousse, ou on y fusionne les PR. Toutes les 10 minutes,
  le workflow Gitea `sync-from-github` aligne la branche `agents` dessus, puis construit
  et publie l'image si celle de ce commit n'est pas encore sur Docker Hub (un build
  manqué est donc rattrapé). Le fichier doit être présent sur la branche par défaut de
  Gitea (`site-cve`) : Gitea n'y planifie que les workflows de cette branche.
- **Numérotation** : `1.1.<nombre de commits de main>` (ex. `1.1.46`), qui augmente à chaque
  commit ; reconstruire le même commit redonne la même version. L'image est publiée sous ce
  tag (`heimdallsecurity/agent-cve:1.1.46`), en plus de `latest` et du SHA du commit.
  `.gitea/workflows/main.yaml` reconstruit à la main (« Run workflow »).
- **Ne poussez plus directement sur `agents` (Gitea)** : la synchro refuse de l'écraser et
  s'arrête en erreur tant que ces commits ne sont pas aussi sur GitHub.
- **Mise à jour des agents** : un agent compare sa version à celle du serveur
  (`/api/agent/version`) au démarrage puis toutes les 24 h, et se met à jour automatiquement
  s'il est en retard (sous Windows, `auto_update = false` redemande confirmation). Il suffit
  donc de **mettre à jour le serveur** (`docker compose pull && docker compose up -d`).
- **Changement mineur/majeur** : modifiez `VERSION` et `AGENT_VERSION_BASE` dans
  `.gitea/workflows/sync-from-github.yaml` et `.gitea/workflows/main.yaml` (ex. `1.2`).
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
