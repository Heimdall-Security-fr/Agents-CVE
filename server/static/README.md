╔══════════════════════════════════════════════════════════════════════════════╗
║              HEIMDALL AGENT SERVER — GUIDE DE DÉPLOIEMENT                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

─── PRÉREQUIS ────────────────────────────────────────────────────────────────
  - Docker + Docker Compose installés
  - Ports disponibles : 3000 (frontend), 4000 (agent server), 5000 (API),
                        9200 (Elasticsearch), 27017 (MongoDB)

─── DÉMARRAGE RAPIDE ─────────────────────────────────────────────────────────
  Depuis la racine du projet (là où se trouve docker-compose.yaml) :

    docker compose up -d --build

  Attendre que tous les services soient healthy (~1-2 min), puis :
    - Dashboard admin agent : http://localhost:4000/admin
    - Frontend CVE          : http://localhost:3000
    - API CVE               : http://localhost:5000

─── CREDENTIALS ──────────────────────────────────────────────────────────────
  Le compte admin et le token agent sont définis par VOUS via les variables
  d'environnement ci-dessous (dans docker-compose.yaml). Aucun identifiant par
  défaut n'est fourni : renseignez vos propres valeurs avant le démarrage.

  Pour définir les credentials sans modifier le code,
  renseigner ces variables d'environnement dans docker-compose.yaml :
    - DEFAULT_ADMIN_EMAIL
    - DEFAULT_ADMIN_PASSWORD
    - AGENT_AUTH_TOKEN
    - DASHBOARD_JWT_SECRET

─── CONFIGURATION DE L'AGENT ────────────────────────────────────────────────
  Éditer Agents/agent.conf :

    [main_server]
    host  = <IP ou domaine du serveur>
    port  = 4000
    token = <valeur de AGENT_AUTH_TOKEN>

    [api]
    cve_api_key = <clé API générée sur http://localhost:3000/api-key>

    [agent]
    interval_minutes = 60   # envoi toutes les 60 min
    port_scan        = false

    [dashboard]
    frontend_url = http://localhost:3000

─── DÉPLOYER UN AGENT WINDOWS ───────────────────────────────────────────────
  1. Lancer le serveur Heimdall (docker compose up)
  2. Télécharger l'exe depuis : http://<host>:4000/static/heimdall-agent.exe
     (ou depuis le dossier Agents/server/static/ après un build)
  3. Placer heimdall-agent.exe + agent.conf dans le même dossier sur le poste client
  4. Lancer heimdall-agent.exe -> icône dans la barre système

  Pour compiler l'exe manuellement (Windows, PowerShell en admin) :
    cd Agents
    .\build_windows.ps1

─── RESET MOT DE PASSE ADMIN ────────────────────────────────────────────────
  Si le mot de passe admin est perdu :

    docker exec -it cve_mongodb mongosh
    use heimdall_agents
    db.dashboard_users.deleteOne({ role: "admin" })
    exit

  Puis redémarrer le serveur -> le compte par défaut est recréé automatiquement :
    docker restart heimdall_agent_server

─── VARIABLES D'ENVIRONNEMENT IMPORTANTES ───────────────────────────────────
  (définies dans docker-compose.yaml, service agent_server)

  AGENT_AUTH_TOKEN       Token partagé serveur <-> agents         [CHANGER EN PROD]
  DASHBOARD_JWT_SECRET   Clé de signature JWT du dashboard        [CHANGER EN PROD]
  DEFAULT_ADMIN_EMAIL    Email du compte admin créé au 1er boot   [à définir]
  DEFAULT_ADMIN_PASSWORD Mot de passe du compte admin             [à définir]
  CVE_API_KEY            Clé API CVE (plan premium) pour les corrélations
  SERVER_PUBLIC_HOST     IP/domaine public de ce serveur
  SERVER_PUBLIC_PORT     Port public (défaut: 4000)
  HEIMDALL_FRONT_URL     URL publique du frontend Next.js

─── FICHIERS IMPORTANTS ─────────────────────────────────────────────────────
  docker-compose.yaml                 Configuration de tous les services
  Agents/agent.conf                   Configuration de l'agent (hôte, token, etc.)
  Agents/server/main_server.py        Code source du serveur agent
  Agents/server/Dockerfile            Image Docker du serveur agent
  Agents/server/static/               Fichiers servis aux agents (exe, scripts)
  Agents/server/templates/admin.html  Dashboard web

─── CE DOSSIER ──────────────────────────────────────────────────────────────
  Contient le fichier heimdall-agent.exe pré-compilé, servi aux agents Windows.
  Pour le (re)générer : lancer build_windows.ps1 depuis Agents/ -> l'exe sera
  automatiquement copié ici et servi par le conteneur agent_server.
