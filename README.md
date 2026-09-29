# Xibaar AI — Plateforme SOC assistée par l'IA

> 🏆 **1re place au concours Lamb Tech** — projet réalisé en binôme.

## Équipe

| Membre | Rôle |
|---|---|
| [Yaye Fatou Gueye (kalissi99)](https://github.com/kalissi99) |
| [Djibsonbecks19](https://github.com/Djibsonbecks19) | 
Rokhaya Ndao
*Xibaar* signifie « information / nouvelle » en wolof. La plateforme centralise les journaux de sécurité des postes Windows, détecte les comportements suspects, les rattache au framework **MITRE ATT&CK** et propose un **assistant IA** pour aider l'analyste SOC à interpréter les alertes et les scans réseau.

---

## Architecture

```
Postes Windows                    Serveur SOC (Docker Compose)
┌──────────────┐    Beats     ┌───────────┐    ┌────────────────┐    ┌─────────┐
│  Winlogbeat  │ ───────────► │ Logstash  │ ─► │ Elasticsearch  │ ─► │ Kibana  │
└──────────────┘   :5044      └───────────┘    └────────────────┘    └─────────┘
                                                        │
                        ┌──────────────┐        ┌───────▼───────┐    ┌──────────┐
   Analyste ──HTTPS──►  │    Nginx     │ ─────► │  API Express  │ ─► │PostgreSQL│
                        │ (reverse     │        │  (Node.js)    │    └──────────┘
                        │  proxy)      │ ─────► ├───────────────┤
                        └──────────────┘        │ React (Vite)  │    ┌──────────┐
                                                └───────────────┘ ─► │ LLM Groq │
                                                                     └──────────┘
```

| Service | Rôle | Port |
|---|---|---|
| Elasticsearch 8.13 | Stockage et recherche des logs | 9200 |
| Logstash 8.13 | Réception des événements Winlogbeat | 5044 |
| Kibana 8.13 | Exploration visuelle des logs | 8086 |
| PostgreSQL 16 | Utilisateurs, alertes, machines | interne |
| API (Node.js / Express) | Détection, MITRE, IA, scans | 3001 |
| Frontend (React / Vite) | Tableau de bord analyste | 3000 |
| Nginx | Reverse proxy HTTP/HTTPS | 80 / 443 |

---

## Fonctionnalités

### 1. Collecte des journaux Windows
Winlogbeat remonte les événements les plus utiles à un SOC :

| Event ID | Signification |
|---|---|
| 4624 / 4625 | Connexion réussie / échouée |
| 4648 | Connexion avec des identifiants explicites |
| 4720 | Création d'un compte utilisateur |
| 4740 | Verrouillage de compte |
| 4663 | Accès à un objet (fichier) |
| 4950 | Modification des paramètres du pare-feu |
| 7036 | Changement d'état d'un service |
| 4104 | Exécution de bloc de script PowerShell |

### 2. Détection et mapping MITRE ATT&CK
Chaque type d'événement est associé à une technique MITRE et à un niveau de sévérité (15 règles), par exemple :

| Événement | Technique | Tactique | Sévérité |
|---|---|---|---|
| Brute force | T1110 | Credential Access | Haute |
| Dump d'identifiants | T1003 | Credential Access | Critique |
| Nouveau compte admin | T1136 | Persistence | Haute |
| Exécution PowerShell | T1059.001 | Execution | Moyenne |
| Pare-feu désactivé | T1562.004 | Defense Evasion | Haute |
| Antivirus désactivé | T1562.001 | Defense Evasion | Critique |
| Connexion RDP | T1021.001 | Lateral Movement | Haute |
| Ransomware | T1486 | Impact | Critique |

### 3. Tableau de bord analyste
Authentification (JWT + mots de passe hachés avec bcrypt), liste des alertes, logs, statistiques, parc de machines surveillées et répartition des alertes par technique MITRE.

### 4. Découverte réseau
- Scan de découverte d'hôtes (`nmap -sn`) sur une plage CIDR.
- Scan de services (`nmap -sV`) sur une IP.
- Les entrées sont validées par expression régulière avant l'exécution de la commande, pour empêcher l'injection de commandes.

### 5. Assistant IA
Modèle `llama-3.1-8b-instant` via l'API Groq :
- **Chat** avec l'analyste ;
- **Analyse** des 20 dernières alertes ;
- **Interprétation** des résultats nmap (ports ouverts, risques, recommandations).

---

## Endpoints de l'API

| Méthode | Route | Description | Auth |
|---|---|---|---|
| POST | `/api/register` | Créer un compte | — |
| POST | `/api/login` | Se connecter (JWT) | — |
| GET | `/api/alerts` | Liste des alertes | JWT |
| GET | `/api/logs` | Journaux | JWT |
| GET | `/api/stats` | Statistiques | JWT |
| GET | `/api/machines` | Machines surveillées | JWT |
| GET | `/api/mitre` | Alertes par technique MITRE | JWT |
| POST | `/api/logs/ingest` | Ingestion d'un événement | — |
| POST | `/api/network/scan` | Découverte réseau | JWT |
| POST | `/api/ai/chat` | Assistant IA | JWT |
| POST | `/api/ai/analyze` | Analyse IA des alertes | JWT |
| POST | `/api/ai/nmap` | Scan + interprétation IA | JWT |

---

## Installation

### Prérequis
- Docker et Docker Compose
- 4 Go de RAM minimum (Elasticsearch)
- Une clé API Groq
- Un pipeline Logstash dans `./logstash/pipeline/` (monté par `docker-compose.yml`)

### Lancement
```bash
git clone https://github.com/Djibsonbecks19/Xibaar_AI_.git
cd Xibaar_AI_

# Créer le fichier .env (jamais commité)
cat > .env << 'EOF'
GROQ_API_KEY=votre_cle_groq
EOF

docker compose up -d --build
```

| Interface | URL |
|---|---|
| Tableau de bord | http://localhost:3000 |
| API | http://localhost:3001 |
| Kibana | http://localhost:8086 |

### Côté poste Windows
1. Installer Winlogbeat.
2. Copier `winlogbeat.yml` et remplacer `127.0.0.1:5044` par l'adresse du serveur SOC.
3. Adapter `company_id` si besoin, puis démarrer le service Winlogbeat.

---

## Sécurité : limites connues et pistes d'amélioration

Ce projet a été construit en temps limité pour le concours Lamb Tech, en environnement de laboratoire. Avant tout usage réel :

- [ ] **Sortir les secrets du `docker-compose.yml`** (mot de passe PostgreSQL, `JWT_SECRET`) vers le fichier `.env`, et les changer.
- [ ] **Activer la sécurité d'Elasticsearch** (`xpack.security.enabled=true`, TLS), désactivée ici pour simplifier le lab.
- [ ] **Authentifier `/api/logs/ingest`** (jeton partagé ou mTLS entre Logstash et l'API).
- [ ] Ne pas exposer les ports 9200, 5044 et 8086 sur Internet.
- [ ] Ajouter du rate limiting sur `/api/login`.

---

## Stack technique

Elasticsearch · Logstash · Kibana · Winlogbeat · Node.js · Express · PostgreSQL · React 19 · Vite · Nginx · Docker Compose · JWT · bcrypt · nmap · Groq (LLaMA 3.1)

---

*Projet lauréat de la 1re place au concours Lamb Tech — usage pédagogique.*
