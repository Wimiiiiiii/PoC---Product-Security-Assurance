# PoC – Manuel d’installation & configuration

> **Contexte** : ce guide documente pas-à-pas ce qui a été mis en place dans le PoC pour surveiller une application Django derrière Apache + ModSecurity (OWASP CRS) sur **VM1**, avec centralisation des logs dans **Graylog** sur **VM2**, et un volet **Wazuh** (agent/manager). Il est conçu comme un manuel reproductible en Markdown.

---

## 0) Système, réseau & prérequis (technique)

### 0.1 OS & VM (VirtualBox)

* **Hyperviseur** : Oracle VirtualBox (hôte Windows).
* **VM1 `kali1` (Web+WAF)** : Kali Rolling **2025.2** x64 (base Debian).
* **VM2 `kali2` (SIEM)** : Kali Rolling **2025.2** x64 (même profil).
* **Ressources** (chacune) : 2 vCPU, 2 GB RAM (4 GB pour la VM2, car Graylog + Wazuh sont gourmands), vidéo 128 MB, accélération VT‑x/AMD‑V, PAE/NX.

```bash
┌──(kali㉿django-vm)-[~]
└─$ cat /etc/os-release
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
VERSION_ID="2025.2"
VERSION="2025.2"
VERSION_CODENAME=kali-rolling
ID=kali
ID_LIKE=debian
HOME_URL="https://www.kali.org/"
SUPPORT_URL="https://forums.kali.org/"
BUG_REPORT_URL="https://bugs.kali.org/"
ANSI_COLOR="1;31"
```

```bash
┌──(kali㉿django-vm)-[~]
└─$ uname -a
Linux django-vm 6.12.25-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.12.25-1kali1 (2025-04-30) x86_64 GNU/Linux
```

### 0.2 Réseau (NAT + Host-Only)

* **Adaptateur 1**: NAT (accès Internet / mises à jour).
* **Adaptateur 2**: Host-Only VirtualBox Host-Only Ethernet Adapter (plage 192.168.56.0/24).
* **Rationale**: NAT pour sortir sur Internet ; Host-Only pour un réseau de labo isolé, adresses stables et trafic non routé vers l’extérieur.

### Plan d’adressage
  * Host : `192.168.56.1`
  * VM1 : `192.168.56.101`
  * VM2 : `192.168.56.102`

### Contrôles côté hôte (Windows) :
* Lister les interfaces Host-Only et leurs adresses (utile pour confirmer la plage utilisée par l’adaptateur 2)

```bash
VBoxManage list hostonlyifs
```

### 0.3 Configuration IP statique (dans les VMs)
Trouver l’interface Host‑Only  `eth1` :

```bash
ip -br a
```

Configurer **VM1** :

```bash
sudo nmcli con add type ethernet ifname eth1 con-name hostonly \
ipv4.addresses 192.168.56.101/24 ipv4.method manual
sudo nmcli con up hostonly
```

Configurer **VM2** :

```bash
sudo nmcli con add type ethernet ifname eth1 con-name hostonly \
ipv4.addresses 192.168.56.102/24 ipv4.method manual
sudo nmcli con up hostonly
```
### 0.4 Résolution de nom & tests

**Host Windows** (`C:\Windows\System32\drivers\etc\hosts`) :

```text
192.168.56.101  clienta.local
192.168.56.101  clientb.local
192.168.56.101  django.local
```

**Linux** (si nécessaire) `/etc/hosts` :

```text
192.168.56.101  clienta.local
192.168.56.101  clientb.local
192.168.56.101  django.local
```

Tests :

```bash
# Depuis Host et/ou VM2
ping 192.168.56.101   
curl -H "Host: clienta.local" http://192.168.56.101/
```



## 1) VM1 – Apache + ModSecurity (OWASP CRS) 

### 1.1 Installation et configuration d’Apache
Apache a été installé sur VM1 (192.168.56.101) pour servir de proxy inverse devant l’application Django (ProOrder).

```bash
sudo apt update
sudo apt install apache2 -y
```
Activation des modules de proxy :
```bash
sudo a2enmod proxy proxy_http
```

Préparer les répertoires d’audit ModSecurity (mode **concurrent**) :
```bash
sudo mkdir -p /var/log/modsecurity/clienta /var/log/modsecurity/clientb
sudo chmod 750 /var/log/modsecurity /var/log/modsecurity/clienta /var/log/modsecurity/clientb
```

Configuration du virtual host pour rediriger vers Django :
```bash
sudo nano /etc/apache2/sites-available/clienta.conf
sudo nano /etc/apache2/sites-available/clientb.conf
```

> Exemple pour **clienta** (adapter `clientb` en remplaçant le nom et le port 8000 → 8001) :
```bash

<VirtualHost *:80>
    ServerName clienta.local
    ServerAlias 192.168.56.101 localhost

    SecRuleEngine DetectionOnly

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/

    ErrorLog  ${APACHE_LOG_DIR}/clienta_error.log
    CustomLog ${APACHE_LOG_DIR}/clienta_access.log combined

    SecAuditEngine On
    SecAuditLogType Concurrent
    SecAuditLog /var/log/modsecurity/audit-index.log
    SecAuditLogStorageDir /var/log/modsecurity/clienta/
    SecAuditLogParts ABDEFHIJZ
</VirtualHost>
```

Désactiver le site par défaut et activer les nouveaux :
```bash
sudo a2dissite 000-default.conf
sudo a2ensite clienta.conf clientb.conf
sudo apachectl -t && sudo systemctl reload apache2
```

### 1.2 Installation et configuration de ModSecurity

ModSecurity a été installé pour inspecter le trafic HTTP en tant que pare-feu applicatif (WAF) :
```bash
sudo apt install -y libapache2-mod-security2
sudo a2enmod security2
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
# Mode global par défaut (observabilité) :
sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf
```

### 1.3 OWASP CRS

Sur Kali/Debian, security2.conf inclut :
```bash
IncludeOptional /usr/share/modsecurity-crs/*.load
```
Le fichier /usr/share/modsecurity-crs/owasp-crs.load doit charger :
```bash
Include /etc/modsecurity/crs/crs-setup.conf
Include /usr/share/modsecurity-crs/rules/*.conf
```

On télécharge donc le crs-setup.conf
```bash
sudo mkdir -p /etc/modsecurity/crs
sudo wget https://raw.githubusercontent.com/coreruleset/coreruleset/v3.3.7/crs-setup.conf.example -O /etc/modsecurity/crs/crs-setup.conf
```

> mportant : on ne rajoute pas d’Include manuel dans security2.conf (le paquet gère déjà *.load). On évite ainsi tout double-chargement.
```bash
sudo apache2ctl -t && sudo systemctl restart apache2
```
### 1.4 Tuning CRS (exemples) – `crs-setup.conf`

Exemple : baisser la sévérité de la règle **920350** (Host header = IP numérique).

```apache
# --- Overrides locaux CRS ---
SecRuleUpdateActionById 920350 "severity:NOTICE"
```

> **Note** : placer ces overrides **vers la fin** de `crs-setup.conf` ou dans un fichier séparé `custom-rules.conf` si vous préférez (voir ci‑après).

Créer `/etc/modsecurity/crs/custom-rules.conf` :

```apache
#Downgrade Host header numeric IP to NOTICE
SecRuleUpdateActionById 920350 "severity:NOTICE"
```

Il faut donc ajouter la ligne suivante dans le fichier /usr/share/modsecurity-crs/owasp-crs.load

```apache
Include /etc/modsecurity/crs/custom-rules.conf
```

Redémarrer Apache après toute modification :

```bash
sudo systemctl restart apache2
```



---

## 2) VM1 → VM2 : expédition des logs avec Vector

> Objectif : envoyer les **logs Apache** (y compris les erreurs ModSecurity présentes dans `error.log`) + **logs applicatifs Django** vers **Graylog**. Vector tourne en conteneur.

### 2.1 Arborescence & fichiers créés

#### Logs applicatifs (Django)
On sépare par « client » pour simuler le multi-tenant :

```bash
sudo mkdir -p /var/log/django/clientA /var/log/django/clientB
# Donnez les droits d’écriture à l’utilisateur qui lance Django (ex. 'kali')
sudo chown -R $USER:$USER /var/log/django
sudo chmod -R 750 /var/log/django
```
 #### Logs Apache (par vhost) – déjà définis dans les vhosts 

 ```bash
/var/log/apache2/clienta_access.log
/var/log/apache2/clienta_error.log
/var/log/apache2/clientb_access.log
/var/log/apache2/clientb_error.log
```
#### Logs ModSecurity (audit « concurrent » par client) – conservés localement (forensic) 
```bash
/var/log/modsecurity/audit-index.log
/var/log/modsecurity/clienta/    # évènements détaillés pour clienta
/var/log/modsecurity/clientb/    # évènements détaillés pour clientb

```

> Choix d’expédition : pour la SIEM, on **n’envoie pas** l’audit ModSecurity (très volumineux, multi‑lignes). On privilégie les **Apache error** (qui contiennent déjà les déclenchements `[id "xxxxxx"]`, `severity`, etc.) + les logs applicatifs (Django).

### 2.2 Lancer Vector (Docker)

```bash
# Arrêter/supprimer un ancien conteneur si besoin
sudo docker rm -f vector 2>/dev/null || true

docker run -d --name vector \
  --restart unless-stopped \
  -v /var/log/apache2:/var/log/apache2:ro \
  -v /var/log/django:/var/log/django:ro \
  -v $HOME/vector_config/vector.toml:/etc/vector/vector.toml:ro \
  -e VECTOR_SELF_NODE_NAME=django-vm \
  timberio/vector:0.39.0-debian
-c /etc/vector/vector.toml           

```


### 2.3 vector.toml

```toml
# ========== SOURCES ==========
# --- Django (app logs) ---
[sources.clienta_app]
type      = "file"
include   = ["/var/log/django/clientA/app.log"]
read_from = "beginning"

[sources.clientb_app]
type      = "file"
include   = ["/var/log/django/clientB/app.log"]
read_from = "beginning"

# --- Apache access ---
[sources.clienta_access]
type      = "file"
include   = ["/var/log/apache2/clienta_access.log"]
read_from = "beginning"

[sources.clientb_access]
type      = "file"
include   = ["/var/log/apache2/clientb_access.log"]
read_from = "beginning"

# --- Apache error (contient aussi messages ModSecurity) ---
[sources.clienta_error]
type      = "file"
include   = ["/var/log/apache2/clienta_error.log"]
read_from = "beginning"

[sources.clientb_error]
type      = "file"
include   = ["/var/log/apache2/clientb_error.log"]
read_from = "beginning"


# ========== TRANSFORMS (tagging) ==========
# .host = ce qui deviendra "source" dans Graylog (host_key="host")

[transforms.tag_clienta_app]
type   = "remap"
inputs = ["clienta_app"]
source = '''
.host = "clientA"
.facility = "django"
.level = 6
'''

[transforms.tag_clientb_app]
type   = "remap"
inputs = ["clientb_app"]
source = '''
.host = "clientB"
.facility = "django"
.level = 6
'''

[transforms.tag_clienta_access]
type   = "remap"
inputs = ["clienta_access"]
source = '''
.host = "clientA"
.facility = "apache_access"
.level = 6
'''

[transforms.tag_clientb_access]
type   = "remap"
inputs = ["clientb_access"]
source = '''
.host = "clientB"
.facility = "apache_access"
.level = 6
'''

[transforms.tag_clienta_error]
type   = "remap"
inputs = ["clienta_error"]
source = '''
.host = "clientA"
.facility = "apache_error"
.level = 3
'''

[transforms.tag_clientb_error]
type   = "remap"
inputs = ["clientb_error"]
source = '''
.host = "clientB"
.facility = "apache_error"
.level = 3
'''

# ========== SINK Graylog ==========
[sinks.graylog]
type    = "socket"
inputs  = [
  "tag_clienta_app","tag_clientb_app",
  "tag_clienta_access","tag_clientb_access",
  "tag_clienta_error","tag_clientb_error"
]
address = "192.168.56.102:12201"
mode    = "udp"

[sinks.graylog.encoding]
codec    = "gelf"
host_key = "host"
```


#### 2.4 Configuration Django – écriture des logs app

Principe. Chaque instance Django définit le « client » via la variable d’environnement TENANT (ex. clientA, clientB). Les logs JSON sont écrits dans /var/log/django/<TENANT>/app.log et expédiés par Vector.

##### settings.py (extrait)
```python
# settings.py
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

# Client courant (défini à l’exécution)
TENANT = os.getenv("TENANT", "clientA")

# Dossier de logs par client
LOG_DIR = Path("/var/log/django") / TENANT
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "file": {
            "level": "INFO",
            "class": "logging.handlers.WatchedFileHandler",
            "filename": str(LOG_DIR / "app.log"),
            "formatter": "verbose",
        },
    },
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name} {message}",
            "style": "{",
        },
    },
    "loggers": {
        # logs framework + app
        "django": {"handlers": ["file"], "level": "INFO", "propagate": True},
        "dummyorders": {"handlers": ["file"], "level": "INFO", "propagate": True},
    },
}

```
##### Enregistrement du middleware : 
```python
# settings.py
MIDDLEWARE += [
    "core.middleware.AccessLogMiddleware",
]

```

##### Middleware d’accès (login) — core/middleware.py

```python
# core/middleware.py
import time, json, logging
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger("dummyorders")
LOGIN_PREFIXES = ("/login", "/accounts/login")

class AccessLogMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request._t0 = time.time()

    def process_response(self, request, response):
        try:
            t0 = getattr(request, "_t0", time.time())
            duration_ms = int((time.time() - t0) * 1000)
            path = getattr(request, "path", "")

            if any(path.startswith(p) for p in LOGIN_PREFIXES):
                outcome = response.headers.get("X-Login-Outcome", "")
                payload = {
                    "event": "login_http_request",
                    "method": getattr(request, "method", "-"),
                    "path": path,
                    "status_code": getattr(response, "status_code", 0),
                    "duration_ms": duration_ms,
                    "client_ip": request.META.get(
                        "HTTP_X_FORWARDED_FOR",
                        request.META.get("REMOTE_ADDR", "-")
                    ).split(",")[0].strip(),
                }
                if outcome:
                    payload["outcome"] = outcome

                logger.info(json.dumps(payload, ensure_ascii=False))
        finally:
            return response


```

> Le middleware écrit une ligne par requête de login : `event`, `method`, `path`, `status_code`, `duration_ms`, `client_ip`, `outcome` (optionnel). Ici, le login illustre la détection de brute force ; d’autres middlewares peuvent être ajoutés selon les besoins.


##### Lancer 2 instances (clientA/clientB)

```python
# Instance clientA (port 8000)
TENANT=clientA python manage.py runserver 0.0.0.0:8000

# Instance clientB (port 8001)
TENANT=clientB python manage.py runserver 0.0.0.0:8001

```
##### Validation rapide

```python
# Vérifier que les fichiers applicatifs par exemple se remplissent :
tail -f /var/log/django/clientA/app.log
tail -f /var/log/django/clientB/app.log
```

---

## 3) VM2 – Graylog : inputs, pipelines, streams & alertes

### 3.1 Installation & configuration (Docker Compose, VM2)

**Rôle des composants**

* **MongoDB** : stocke la configuration Graylog (utilisateurs, dashboards, streams, alertes). **Pas** de logs.
* **OpenSearch** : indexe les **messages** de logs (recherches/agrégations rapides).
* **Graylog** : API/UI + pipeline d’ingestion + gestion des inputs/streams/alertes.

**Compatibilité retenue (environnement sans AVX)**

* **Graylog 4.3** (compatible OpenSearch 1.x)
* **MongoDB 4.4** (compatible CPU sans AVX)
* **OpenSearch 1.3.14**

> Remarque : MongoDB 5.x et OpenSearch 2.x peuvent requérir AVX ; pour éviter l’incompatibilité CPU en VM, on épingle les versions ci‑dessus.

**Étapes d’installation (VM2)**

```bash
mkdir -p ~/graylog && cd ~/graylog
```

Créer `docker-compose.yml` :

```yaml
services:
  mongodb:
    image: mongo:4.4
    container_name: mongo
    restart: unless-stopped
    networks: [graylognet]
    healthcheck:
      test: ["CMD", "mongo", "--quiet", "127.0.0.1/test", "--eval", "db.runCommand({ ping: 1 })"]
      interval: 10s
      timeout: 5s
      retries: 10

  opensearch:
    image: opensearchproject/opensearch:1.3.14
    container_name: opensearch
    environment:
      - discovery.type=single-node
      - plugins.security.disabled=true
      - OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m
    ulimits:
      memlock:
        soft: -1
        hard: -1
    restart: unless-stopped
    networks: [graylognet]
    healthcheck:
      test: ["CMD-SHELL", "curl -s http://localhost:9200 >/dev/null || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 20

  graylog:
    image: graylog/graylog:4.3
    container_name: graylog
    environment:
      - GRAYLOG_PASSWORD_SECRET=SomeRandomLongString123
      - GRAYLOG_ROOT_PASSWORD_SHA2=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918  # "admin"
      - GRAYLOG_HTTP_EXTERNAL_URI=http://192.168.56.102:9000/
      - GRAYLOG_MONGODB_URI=mongodb://mongo/graylog
      - GRAYLOG_ELASTICSEARCH_HOSTS=http://opensearch:9200
    depends_on:
      mongodb:
        condition: service_healthy
      opensearch:
        condition: service_healthy
    ports:
      - "9000:9000"        # Web UI
      - "12201:12201/udp"  # GELF UDP input
    restart: unless-stopped
    networks: [graylognet]

networks:
  graylognet:
    driver: bridge
```

Démarrer :

```bash
docker-compose up -d
```

Accès UI : `http://192.168.56.102:9000` (utilisateur **admin**, mot de passe **admin** d’après le SHA2 fourni — à changer ensuite).

**Post‑install indispensable**

1. Créer un **Input** : *System → Inputs → GELF UDP* → Port **12201** → *Launch*.
2. Vérifier l’état :

```bash
docker ps
docker logs -f graylog
```
---


### 3.2 Stream « Apache errors »

* Stream : Filtre de messages (routage par conditions) et base d’attachement des pipelines/alertes.

Créer **System → Streams → Create stream**, puis **Manage Rules** et ajouter :

- **Field** = `facility`  
- **Type** = *match exactly*  
- **Value** = `apache_error`

Démarrer le stream (*Start*). 

### 3.3 Pipelines – parsing & enrichissement (exemple)

* Pipeline : suite de règles exécutées sur les messages d’un stream pour parser/enrichir.

Créer **System → Pipelines → Manage rules -> Create rule**

```js
rule "modsec_sev_critical"
when
  has_field("facility") &&
  to_string($message.facility) == "apache_error" &&
  has_field("message") &&
  contains(to_string($message.message), "[severity \"CRITICAL\"]")
then
  set_field("severity", "CRITICAL");
  set_field("severity score", 5);
end
```

**Add new pipeline -> Apache error enrichment** :
* Stage 0 : ajouter la règle `modsec_sev_critical`
* Connecter le pipeline au stream **Apache errors**

### 3.4 Alert & Event Definition « Apache Critical Burst »

* Alert : déclencheur planifié (requête + agrégation) qui crée un événement et envoie une notification.

**Alerts & Events → Event Definitions → Create (Filter & Aggregation)**

- **Query** : `severity:CRITICAL`  
- **Streams** : `Apache errors`  
- **Search within** : `2 minutes`  
- **Execute every** : `2 minutes`  
- **Group by** : *(none)*  
- **Create Events if** : `count() >= 4`  (pour le test)
- **Notifications** : sélectionner la notification HTTP (voir §3.5)


### 3.5 Notification (HTTP Notification)

**Alerts & Events → Notifications → Create Notification**

- **Title** : `Notification center`  
- **Type** : **HTTP Notification** (`http-notification-v1`)  
- **URL** : `http://192.168.56.1:5000/graylog-webhook`  
- **Method** : `POST` (JSON par défaut)

### 3.6 Récepteur Flask (webhook côté host)

```python
#webhook_server.py
from flask import Flask, request
from datetime import datetime
import json

app = Flask(__name__)

def simple_summary(payload):
    # Champs de base
    title = payload.get("event_definition_title") or payload.get("event_definition_id")
    event = payload.get("event", {}) or {}
    ts = event.get("timestamp")
    msg = event.get("message")

    # Horodatage lisible
    ts_h = ts
    try:
        ts_h = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass

    return {
        "title": title,
        "timestamp": ts_h,l
        "message": msg,
    }

@app.route("/graylog-webhook", methods=["POST"])
def graylog_webhook():
    payload = request.get_json(force=True, silent=True) or {}
    summary = simple_summary(payload)

    # Affichage minimal
    print("\n" + "═" * 60)
    print(f"🚨 EVENT:     {summary['title']}")
    print(f"⏱  Timestamp: {summary['timestamp']}")
    print(f"💬 Message:   {summary['message']}")
    print("═" * 60, flush=True)

    # Sauvegarde fichier (optionnel)
    with open("alerts.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(summary, ensure_ascii=False) + "\n")

    return "OK", 200

if __name__ == "__main__":
    # Installer : pip install flask
    # Lancer   : python webhook_server.py
    app.run(host="0.0.0.0", port=5000)
```

## 4) Wazuh Stack (VM2)

La configuration avec Wazuh a été testée au début (avec un **vhost unique**) pour évaluer l’intégration. Elle s’est révélée plus **intrusive** (analyses système par défaut). Si l’on limite l’agent aux seuls fichiers de logs souhaités, l’efficacité revient même moins à celle d’une pile orientée **observabilité** comme Graylog ; nous avons donc privilégié Graylog pour ce PoC.


#### 4.1 Vhost unique

```apache
<VirtualHost *:80>
    ServerName django.local
    ServerAlias 192.168.56.101 localhost

    SecRuleEngine DetectionOnly

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/

    ErrorLog  ${APACHE_LOG_DIR}/django_error.log
    CustomLog ${APACHE_LOG_DIR}/django_access.log combined
</VirtualHost>
```

#### Emplacement des logs

* Apache access : `/var/log/apache2/django_access.log`
* Apache error : `/var/log/apache2/django_error.log`
* Django app   : `/home/kali/Desktop/Website/logs/app.log` (chemin initial, ensuite remplacé par `/var/log/django/...`)
* ModSecurity  : `/var/log/apache2/modsec_audit.log` (mode non‑concurrent à l’époque)


#### Lancement de la nouvelle config
```bash
sudo a2dissite 000-default.conf  # désactiver un site qui entre en conflit ( clienta, clientb..)
sudo a2ensite django.conf
sudo apachectl -t && sudo systemctl reload apache2
```

### 4.2 Installation automatisée (All-in-One)

Déploie Indexer, Manager et Dashboard :
```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
sudo bash wazuh-install.sh -a
```
### 4.3 Services & accès
```bash
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-dashboard
```

UI (certificat autosigné) :
```bash
https://192.168.56.102
```

Identifiants fournis par l’installateur :
* **Username** : `admin`
* **Password** : *(généré et affiché en fin d’installation)*

## 5) Wazuh Agent (VM1) – Collecte ciblée
### 5.1 Installation
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update
sudo apt install -y wazuh-agent
sudo systemctl enable wazuh-agent
```

### 5.2 Configuration (minimaliste et non intrusive)

Objectif : désactiver les modules intrusifs (rootcheck, FIM, SCA, inventory)
et n’expédier que les logs Apache (incluant ModSecurity via error.log)
et les logs applicatifs (Django).

Éditer /var/ossec/etc/ossec.conf :
```bash
<server>
  <address>192.168.56.102</address>
  <port>1514</port>
</server>

<!-- Disable system-wide scans -->
<rootcheck><disabled>yes</disabled></rootcheck>
<syscheck><disabled>yes</disabled></syscheck>
<wodle name="syscollector"><disabled>yes</disabled></wodle>
<sca><enabled>no</enabled></sca>

<!-- Apache logs -->
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/error.log</location>
</localfile>

<!-- ModSecurity logs -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/apache2/modsec_audit.log</location>
</localfile>

<!-- Django logs (application-level) -->
<localfile>
  <log_format>syslog</log_format>
  <location>/home/kali/Desktop/Website/logs/app.log</location> #votre emplacement du fichier des logs de l'application django
</localfile>
```
### 5.3 Enrôlement & démarrage

```bash
sudo /var/ossec/bin/agent-auth -m 192.168.56.102
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

> L’agent apparaît Active dans le Dashboard.


## 6) Scénarios de test (exemples)


> **Remarque générale** : dans les tests qui suivent, `host` peut être remplacé par `clienta.local`, `clientb.local` ou `django.local` selon le vhost que vous souhaitez tester.

### 6.1 Injection applicative

* **XSS** (CRS règle 941100) :

```text
# Dans le navigateur (si l’application le requiert, connectez‑vous d’abord)
http://<host>/search?q=<script>alert(1)</script>
```

* **SQLi** (CRS règle 942100) :

```text
# Dans le navigateur
http://<host>/products?id=1%20OR%201=1
```

### 6.2 Anomalies protocole / en‑têtes

* **User-Agent vide** (requête brute) :

```bash
printf 'GET / HTTP/1.1\r\nHost: host\r\nUser-Agent:\r\n\r\n' | nc 192.168.56.101 80
```

### 6.3 Brute force login

* **Hydra – dictionnaire RockYou** :

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  192.168.56.101 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid"
```

> Les tentatives échouées apparaissent dans les logs applicatifs (middleware login) et déclenchent une alerte **Brute Force** dans Graylog (si configuré).


### 6.4 Scan 

* **Dirb/Dirbuster (OWASP)** : envoie un grand nombre de requêtes peut activer des protections anti‑automation si configurées.

Pour tester la protection DoS de ModSecurity, nous avons :

* **Décommenté** la section dédiée à l’anti‑DoS dans le fichier de configuration CRS.
* Créé le répertoire persistant requis pour stocker l’état (stateful features) :

```bash
# Répertoire persistant (DoS + fonctionnalités stateful)
sudo mkdir -p /var/cache/modsecurity
sudo chown -R www-data:www-data /var/cache/modsecurity
```

Exemple de scan :

```bash
dirb http://<host>/
```
