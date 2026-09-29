# 📘 Guide utilisateur — Conformité et mises à jour

Ce guide explique comment fonctionne la page **Conformité** du dashboard, comment
la configurer, et comment vérifier que vos logiciels sont à jour.

---

## 1. Ne pas confondre les trois notions

| Notion              | Question posée                                            | Où la voir                  |
| ------------------- | --------------------------------------------------------- | --------------------------- |
| **Vulnérabilités**  | « Un logiciel installé a-t-il une faille connue (CVE) ? » | Dashboard, Vulnérabilités   |
| **Conformité**      | « La configuration respecte-t-elle ma politique de sécurité ? » | Page **Conformité**   |
| **Mises à jour**    | « Existe-t-il une version plus récente de ce logiciel ? » | Page **Mises à jour**       |

Un logiciel peut être **à jour mais vulnérable** (faille pas encore corrigée), ou
**en retard mais sans CVE connue**. Les trois vues sont complémentaires.

---

## 2. Comment fonctionne la conformité

```
Agent (sur chaque machine)                Serveur agent
──────────────────────────                ───────────────────────────
1. lit la configuration locale   ──────▶  2. stocke les valeurs collectées
   (registre, sshd_config, sysctl…)          (ex. firewall_enabled = true)
                                          3. compare chaque valeur à vos règles
                                          4. calcule un score par machine
```

1. **Collecte** — à chaque envoi de rapport (toutes les 60 min par défaut, et dès le
   démarrage de l'agent), l'agent lit la configuration de la machine. Il ne modifie rien.
2. **Évaluation** — le serveur compare chaque valeur collectée à la **valeur attendue**
   de chaque règle **activée**.
3. **Résultat par règle** :

| Statut       | Signification                                                                 |
| ------------ | ----------------------------------------------------------------------------- |
| ✅ `pass`     | La valeur collectée respecte la règle                                         |
| ❌ `fail`     | La valeur collectée ne respecte pas la règle                                  |
| ❔ `unknown`  | L'agent n'a pas pu lire la valeur (droits, service absent, fichier introuvable) |
| ➖ `na`       | Règle non applicable à ce système (ex. règle Windows sur un serveur Linux)    |

4. **Score** = règles réussies ÷ règles applicables × 100.

> ⚠️ Les règles `unknown` **comptent comme non réussies** : elles font baisser le score.
> Un score bas peut donc venir d'un manque de droits de l'agent plutôt que d'une vraie
> non-conformité — voir la section 5.

Couleur du score moyen : vert ≥ 80 %, orange ≥ 50 %, rouge en dessous.

---

## 3. Utiliser la page Conformité

- **Filtres** Windows / Linux / macOS : n'affichent que les règles de la plateforme.
- **Interrupteur « Active »** : une règle désactivée n'est ni évaluée ni comptée dans le score.
- **Valeur attendue** : cliquez dessus pour la modifier directement (ex. passer la
  longueur minimale du mot de passe de 12 à 14).
- **`+ Règle`**, ✏️, 🗑 : créer, modifier, supprimer une règle (**administrateur** uniquement).
- **💾 Sauvegarder** : les modifications ne sont appliquées qu'après avoir sauvegardé.
  Le serveur recalcule alors les résultats (cache de 60 secondes au maximum).

Un nouveau réglage ou une nouvelle règle est **visible au prochain rapport de l'agent**
(au plus une heure), pas instantanément.

### Règles fournies

| Règle (`id`)                  | Contrôle                                            | Plateformes          | Attendu      | Active par défaut |
| ----------------------------- | --------------------------------------------------- | -------------------- | ------------ | :---------------: |
| `password_min_length`         | Longueur minimale du mot de passe                   | Windows, Linux, macOS | ≥ 12         | ✅ |
| `passwd_max_days`             | Expiration du mot de passe (jours)                  | Linux, macOS         | ≤ 90         | ✅ |
| `passwd_min_days`             | Âge minimum du mot de passe (jours)                 | Linux, macOS         | ≥ 7          | ❌ |
| `account_lockout_threshold`   | Tentatives échouées avant verrouillage              | Windows              | ≤ 5          | ✅ |
| `account_lockout_duration`    | Durée de verrouillage (min)                         | Windows              | ≥ 15         | ❌ |
| `tls_min_version`             | Version TLS minimale                                | Windows, Linux, macOS | ≥ 1.2        | ✅ |
| `firewall_enabled`            | Pare-feu actif (Windows Firewall, ufw, firewalld)   | Windows, Linux       | vrai         | ✅ |
| `sysctl_ip_forwarding`        | `net.ipv4.ip_forward`                               | Linux                | 0            | ✅ |
| `sysctl_accept_redirects`     | `net.ipv4.conf.all.accept_redirects`                | Linux                | 0            | ✅ |
| `sysctl_syncookies`           | `net.ipv4.tcp_syncookies`                           | Linux                | 1            | ✅ |
| `sysctl_log_martians`         | `net.ipv4.conf.all.log_martians`                    | Linux                | 1            | ❌ |
| `smb1_disabled`               | SMBv1 désactivé                                     | Windows              | vrai         | ✅ |
| `rdp_nla_enabled`             | RDP avec authentification NLA                       | Windows              | vrai         | ✅ |
| `defender_realtime`           | Protection temps réel Windows Defender              | Windows              | vrai         | ✅ |
| `uac_enabled`                 | Contrôle de compte d'utilisateur (UAC)              | Windows              | vrai         | ✅ |
| `guest_account_disabled`      | Compte Invité désactivé                             | Windows              | vrai         | ✅ |
| `auto_updates_enabled`        | Mises à jour automatiques du système                | Windows, Linux       | vrai         | ✅ |
| `screen_lock_timeout`         | Verrouillage d'écran (secondes)                     | Windows              | ≤ 600        | ✅ |
| `ssh_root_login_disabled`     | `PermitRootLogin` refusé                            | Linux, macOS         | vrai         | ✅ |
| `ssh_password_auth_disabled`  | SSH par clé uniquement                              | Linux, macOS         | faux (`PasswordAuthentication no`) | ❌ |
| `core_dumps_disabled`         | Core dumps désactivés                               | Linux                | vrai         | ✅ |
| `audit_enabled`               | Service `auditd` actif                              | Linux                | vrai         | ✅ |
| `umask_value`                 | Umask par défaut restrictif                         | Linux, macOS         | 027 ou 077   | ❌ |
| `pending_updates`             | Nombre de logiciels à mettre à jour                 | Windows, Linux, macOS | ≤ 0          | ❌ |

> Les règles sont **enregistrées en base dès votre première sauvegarde**. Une règle ajoutée
> plus tard dans une nouvelle version du serveur n'apparaît alors pas automatiquement :
> ajoutez-la avec `+ Règle`, ou repartez de la liste par défaut (⚠️ efface vos
> personnalisations) : `docker exec -it heimdall_agent_mongo mongosh heimdall_agents --eval 'db.compliance_config.deleteOne({_id:"rules"})'`

---

## 4. Créer vos propres règles

Dans **`+ Règle`**, renseignez le nom, la sévérité, l'opérateur, la valeur attendue et
le **type de donnée**, puis choisissez un **collecteur** : c'est lui qui indique à l'agent
*quoi lire*.

| Collecteur       | Plateformes   | Paramètres                          | Valeur retournée                    |
| ---------------- | ------------- | ----------------------------------- | ----------------------------------- |
| `sysctl`         | Linux, macOS  | `key`                               | nombre (ou texte)                   |
| `file_grep`      | Linux, macOS  | `path` absolu + `pattern` (regex)   | 1er groupe capturé (**texte**)      |
| `systemd_active` | Linux         | `service`                           | vrai / faux                         |
| `file_exists`    | Linux, macOS  | `path` absolu, `invert` (optionnel) | vrai / faux                         |
| `registry`       | Windows       | `path` = `HKLM\Chemin\NomDeLaValeur` | nombre ou texte                    |

**Exemples**

| Objectif                               | Collecteur / paramètres                                                | Opérateur / valeur / type |
| -------------------------------------- | ---------------------------------------------------------------------- | ------------------------- |
| ASLR activé                            | `sysctl` — `kernel.randomize_va_space`                                 | `==` `2` — int            |
| X11Forwarding désactivé                | `file_grep` — `/etc/ssh/sshd_config`, `^X11Forwarding\s+(\S+)`         | `==` `no` — string        |
| fail2ban actif                         | `systemd_active` — `fail2ban`                                          | `==` `true` — bool        |
| Pas de clé privée dans `/root`         | `file_exists` — `/root/.ssh/id_rsa`, « vérifier l'absence » coché      | `==` `true` — bool        |
| Accès anonyme restreint (Windows)      | `registry` — `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous` | `==` `1` — int        |

Points d'attention :

- Un collecteur `file_grep` renvoie du **texte** : utilisez le type `string`, pas `bool`.
- Les chemins Linux/macOS doivent être **absolus** et sans `..`.
- Seules les règles **activées** et ayant un collecteur sont envoyées aux agents.
- Une règle intégrée et une règle personnalisée qui ont le même `id` : l'intégrée prévaut.

---

## 5. Bien faire fonctionner la conformité

### Checklist

- [ ] **Exécutez l'agent avec les droits suffisants**
  - Linux/macOS : en `root` (service systemd). Sans cela, `ufw status`, `auditd`, certains
    `sysctl` et fichiers protégés sont illisibles → règles `unknown` (voire faux négatifs
    comme un pare-feu déclaré inactif).
  - Windows : lancez l'agent **en administrateur** (ou via la tâche planifiée
    `--install`, niveau d'exécution le plus élevé). Certaines valeurs, comme le verrouillage
    d'écran, sont propres à l'utilisateur qui exécute l'agent.
- [ ] **Token valide** : au moins 32 caractères, identique à `AGENT_AUTH_TOKEN` du serveur.
- [ ] **Agent à jour** : les agents s'auto-mettent à jour ; un vieil agent peut ne pas
  collecter toutes les règles récentes (ex. `pending_updates`).
- [ ] **Adaptez la politique** : désactivez les règles qui ne s'appliquent pas à votre
  contexte plutôt que de subir un score bas permanent, et ajustez les seuils
  (longueur de mot de passe, délais…).
- [ ] **Laissez passer un cycle** après un changement : les nouveaux résultats arrivent
  au prochain rapport (60 min par défaut, réglable via `interval_minutes`).

### Pourquoi une règle est « unknown » ?

| Cause probable                                             | Solution                                                |
| ---------------------------------------------------------- | ------------------------------------------------------- |
| L'agent ne tourne pas en root / administrateur             | Relancer avec les droits élevés                         |
| Service ou outil absent (`ufw`, `auditd`, `sysctl`…)       | Normal si non installé ; désactivez la règle si sans objet |
| Fichier introuvable (`/etc/ssh/sshd_config`, `pwquality.conf`) | Vérifier le chemin ; adapter la règle              |
| Clé de registre absente                                    | Adapter le chemin ou désactiver la règle                |
| Règle créée mais l'agent n'a pas encore envoyé de rapport  | Attendre le prochain cycle                              |
| Règle sans collecteur et non gérée nativement par l'agent  | Ajouter un collecteur à la règle                        |

---

## 6. Vérifier que les logiciels sont à jour

La page **Mises à jour** liste, pour chaque machine, les logiciels dont une **version plus
récente est disponible** — qu'ils soient vulnérables ou non.

### Comment c'est déterminé

L'agent interroge le **gestionnaire de paquets local** (lecture seule, rien n'est installé) :

| Système                    | Source        | Remarque                                                            |
| -------------------------- | ------------- | ------------------------------------------------------------------- |
| Windows                    | `winget upgrade` | Nécessite winget (App Installer, présent sur Windows 10/11 récents) |
| Debian / Ubuntu            | `apt list --upgradable` | Lit le cache local : voir ci-dessous                       |
| RHEL / Fedora / Rocky      | `dnf` / `yum check-update` | Interroge les dépôts                                   |
| SUSE                       | `zypper list-updates`      |                                                        |
| macOS                      | `brew outdated`            | Homebrew uniquement                                    |

Résultat par machine : **À jour**, **À mettre à jour** (avec le détail *version installée →
version disponible*), ou **Vérification impossible** (gestionnaire absent, erreur, délai).

### À savoir

- **Rafraîchissez le cache apt** : l'agent n'exécute pas `apt update`. Si le cache est
  ancien, la liste l'est aussi. Un badge **« cache ancien »** apparaît au-delà de 7 jours ;
  activez `unattended-upgrades` ou un `apt update` planifié.
- **Fréquence** :
  - **Windows** : au démarrage de l'agent (donc du PC), puis uniquement à la demande via le
    bouton **« 🔄 Revérifier »** de la page *Mises à jour* (transmis à l'agent sous 60 s,
    suivi d'un rapport immédiat). Aucune vérification périodique en arrière-plan.
  - **Linux / macOS** : toutes les **6 heures** (`update_check_hours = 6`).
  - `update_check_hours = 0` désactive la vérification sur tous les systèmes.
- **Couverture** : seuls les logiciels connus du gestionnaire de paquets sont couverts.
  Un logiciel installé « à la main » (zip, installeur hors winget…) n'apparaît pas.
- **Agents anciens** : affichés « Agent à mettre à jour » tant qu'ils n'ont pas reçu
  la nouvelle version.

### En faire une règle de conformité

Activez la règle **« Logiciels à jour »** (`pending_updates`) dans la page Conformité.
Par défaut elle exige **0** logiciel en retard ; mettez par exemple `5` pour tolérer un
petit retard. Elle n'est évaluée que lorsque la vérification a abouti (sinon `unknown`).

---

## 7. Dépannage rapide

| Symptôme                                     | Piste                                                               |
| -------------------------------------------- | ------------------------------------------------------------------- |
| Aucune machine dans la page                  | L'agent n'a pas envoyé de rapport : `agent.log`, token, réseau       |
| Score très bas, beaucoup de « unknown »      | Droits insuffisants de l'agent (section 5)                          |
| Une règle reste « unknown » alors que tout est configuré | Vérifiez collecteur, chemin/clé et plateformes cochées  |
| Modification de règle sans effet             | Sauvegardée ? Attendre le prochain rapport de l'agent               |
| « Vérification impossible » sur Windows      | winget absent ou bloqué (proxy, source non validée) : `winget upgrade` à la main |
| « Vérification impossible » sur Linux        | Gestionnaire non géré (pacman, apk…) ou erreur : voir le détail dans la page |

Logs de l'agent : Windows `%APPDATA%\HeimdallAgent\agent.log` — Linux : `journalctl -u heimdall-agent`.
