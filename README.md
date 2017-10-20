
# Modern Infra avec Docker et Rancher
Ici nous allons voir comment mettre en place une infrastructure robuste pour le déploiement d'application ou service scalable.
Nous allons nous pencher sur l'utilisation de Docker ainsi que la notion d'orchestrer avec Rancher.

## Sommaire

### Les Bases de Docker
1. [Le Premier Docker File](#premierDocker)
2. [Création du Container](#creationContainer)
3. [Lancement du Container](#lancementContainer)
4. [Arrêt du Container](#arretContainer)
5. [Créer un ensemble de Container](#ensembleContainer)
6. [Le Compose File](#composeFile)
7. [Accéder à un service depuis un autre service](#accederService)
8. [Lancer le compose](#lancerCompose)

### Concernant Rancher
1. [Installer Rancher](#installRancher)
2. [Le Compose File de Rancher (a modifier)](#rancherCompose)
3. [Stocker ses Containers en ligne](#stockerContainers)
4. [Créer sa première Stack](#premiereStack)
5. [Monitorer](#monitorer)
6. [Upgrade](#upgrade)
7. [Le meilleur pour la fin](#meilleur)


## Begin with Docker
Docker permet d'introduire le concept de Container. Un Container est une sorte de mini machine virtuelle qui troune sous linux. Un Container **DOIT** contenir ( sauf rare cas ) qu'un seul processus principal. Un Container ne continue à tourner que si le processus principal ( comme un serveur ) est bloquant, c'est à dire qu'il faut un CTRL+C normalement pour le terminer.

### Installation

Pour travailler avec Docker il faut que vous l'ayez installé dans un premier temps sur votre machine. Docker est actuelement compatible avec une grande majorité des OS disponibles.

**Installer pour :**

* [Installer pour Mac](https://docs.docker.com/docker-for-mac/install/)
* [Installer pour Windows](https://docs.docker.com/docker-for-windows/install/)
* [Installer pour Ubuntu](https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/)
* [Installer pour Debian](https://docs.docker.com/engine/installation/linux/docker-ce/debian/)
* [Installer pour CentOS](https://docs.docker.com/engine/installation/linux/docker-ce/centos/)
* [Installer pour Fedora](https://docs.docker.com/engine/installation/linux/docker-ce/fedora/)

### Le Premier Docker File <a id="premierDocker"></a> 

Le Dockerfile permet d'indiquer à Docker comment compiler le Container. C'est à dire quels fichiers/répertoires il faut mettre dans le Container ainsi que les commandes (ou entrypoint) qu'il faut executer lorsque le Container sera lancé.

Il faut placer le fichier Dockerfile directement à la racine du repertoir que vous allez intégrer dans votre Container.

Voici un exemple de Dockerfile qui permet de packager une application NodeJs.

```docker
FROM node:alpine

# Create app directory
RUN mkdir -p /srv/app
WORKDIR /srv/app
 
# Bundle app source
COPY . /srv/app

EXPOSE 80

CMD [ "node", "app.js" ]
```
**FROM** : Cela permet d'indiquer l'image de départ, le ":" permet de choisir des distribution de l'image. Ici nous avons choisis l'image Alpine de Node qui permet d'avoir un Container extrêmement léger (22MB)

**RUN** : Il permet d'executer des commandes **LORSQUE VOUS CREEZ LE CONTAINER**. Dans aucun cas les commandes effectuées avec RUN seront executées lorsque vous démarrerez le Container.

**WORKDIR** : Permet d'indiquer à Docker qu'elle est dossier de travail. Cela permet de travailler en relatif plus facilement.

**COPY** : Cela permet de copier des fichiers/répertoires de votre machine vers le Container **LORSQUE VOUS CREEZ LE CONTAINER**. 
>ex : COPY /leDossier/de/ma/machine /leDossier/de/mon/container

**EXPOSE** : Permet d'exposer un port du Container et le rendre par la suite accessible.

**CMD** : Permet de lancer le processus principal **LORSQUE VOUS LANCEREZ LE CONTAINER**. Il est **IMPORTANT** de noter que vous ne pouvez mettre qu'un seul CMD dans votre Dockerfile.

**ENTRYPOINT** : C'est similaire à CMD en revanche il permet d'executer plusieurs commandes **LORSQUE VOUS LANCEREZ LE CONTAINER**. ENTRYPOINT ne peut prendre en charge que les fichiers .sh, le fichier .sh doit être présent dans le Container, il ne faut pas oublier de le copier. Vous pouvez utiliser **SOIT ENTRYPOINT OU CMD**. Votre fichier .sh doit se finir avec une commande bloquante. ex : `node app.js` 
>ex : ENTRYPOINT server.sh ou ENTRYPOINT /srv/app/server.sh

Pour plus d'informations : [Dockerfile sur le site Docker](https://docs.docker.com/engine/reference/builder/)

### Création du Container <a id="creationContainer"></a> 
Pour créer un Container, rien de plus simple il suffit juste que Docker soit démarré.
>Vous pouvez le vérifier en faisans : `docker ps`

Ensuite il ne vous reste plus qu'à vous placer de préférence dans votre dossier de travail et lancer cette commande : `docker build -t monNomDeContainer:monTag .`

Si votre Dockerfile est bien fait cela devrait lancer un process. Une fois le process fini vous pouvez vérifier que votre Container est bien créé en faisant : 
`docker images`

### Lancement du Container <a id="lancementContainer"></a> 
Vous pouvez vérifier que votre container fonctionne bien en faisans : `docker run monNomDeContainer:monTag`
Si tout se passe bien cela devrait vous montrer les logs du Container.
Pour lancer le container en tâche de fond vous pouvez faire : `docker run monNomDeContainer:monTag -d`

Cependant vous n'aurez pas accès aux logs directement. Vous pouvez consulter que votre Container a bien démarré en faisant : `docker ps`

### Arrêt du Container <a id="arretContainer"></a> 
Si vous ne l'avez pas mis en tâche de fond vous avez juste à faire un CTRL+C.
En tâche de fond, il faut récupérer l'ID du Container en faisant : `dokcer ps` puis faire `docker stop ID_CONTAINER`

### Créer un ensemble de Container <a id="ensembleContainer"></a> 
Vu que Docker pense à tout, il est possible de faire co-habiter en même temps plusieurs Containers, et créer ainsi un micro private network entre ceux ci. Ici on ne s'interresse qu'a la **VERSION 2** du Docker Compose File

#### Le Compose File <a id="composeFile"></a> 
Le docker-compose.yml est un fichier au format YAML. Il permet d'indiquer à Docker comment **LANCER** plusieurs Containers ensemble et faire des liens entre ceux ci. Il permet aussi de gérer facilement les volumes et de modifier à la volée les commande : CMD, ENTRYPOINT ( si vous avez besoin de les modifier sans re-construire les Containers concernés).

```yaml
version: '2'
services:
    server: 
        image: repoDistant/monContainerServer:monTag
        restart: unless-stopped 
        labels:
            unLabel: uneValeurDeLabel
            unAutreLabel: uneAutreValeur
        ports :
            - "80"
        volumes: 
            - /unDossier/sur/la/Machine:/leDossier/dans/leContainer:rw
        environment :
            - UNE_VARIABlE_DENVIRONNEMENT=uneValeur
            - UNE_AUTRE_VARIABlE_DENVIRONNEMENT=uneAutreValeur

    db:
        image: mongo:latest
        ports:
           - "27017"
        command: mongod --quiet
        volumes: 
         - /unRepertoire/sur/la/machine:/data/db:rw
         - /unRepertoire/sur/la/machine:/data/backup:rw
         #/data/db contient les fichier de BDD généré par Mongo
```
Ce Docker Compose vous permet de lancer une application complète avec une base de données mongoDB ( distribution officielle provenant du Docker Hub) ainsi que votre Container Server.
Voici ce que veulent dire chaque champs :

**image (obligatoire)** : Permet de d'indiquer l'image que le service doit utiliser

**restart (facultatif)** : Permet d'indiquer une règle de redémarrage, dans le cas ici présent, le container redémarre si le processus principal crash.

**labels (facultatif)** : Permet d'ajouter des valeurs qui peuvent être utiliser par Docker ( et par Rancher on verra ça plus tard )

**ports (facultatif)** : Permet d'indiquer quels ports de votre service vous voulez ouvrir **PUBLIQUEMENT**. La syntaxe peut être `- "80"` si vous voulez faire correspondre le port 80 du service au port 80 de votre machine. Sinon `- "1337:80"` indique à docker que le port 1337 de votre machine correspond au port 80 de votre service.

**volumes (facultatif)** : Permet de créer des dossier synchronisés entre votre service et votre machine. :rw signifie que le servie à les droits de lecture et d'écriture et :ro qu'il n'a que les droits de lecture. **ATTENTION** si le dossier sélectioné n'est pas vide, Docker le prendra comme dossier entier : ex : si vous avez une partie des fichiers dans votre Container et une autre partie sur la machine, ça va planter. **ATTENTION** Docker ne copie pas le contenu Static ( comme les fichiers de votre app, en gros les fichier non générés par votre app) vers la machine même si c'est en :rw.

**environment (facultatif)** : Permet de configurer des variables d'environnement à la volée pour modifier le comportement du service. **ATTENTION** les variables d'environnement sont locales que au service. On ne peut pas y accéder dans un autre service.
>ex : sous NodeJs on utilise les variables d'environnement avec `process.env.MA_VAR`

#### Accéder à un service depuis un autre service <a id="accederService"></a> 
Pour utiliser un autre service à partir d'un service vous avez juste à utiliser son nom
>ex : `mongo://db:27017/maBase` si je veux accéder à la base de donnée à partir du service serveur

#### Lancer le compose <a id="lancerCompose"></a> 
Pour lancer le Compose, rien de plus simple il suffit juste que Docker soit démarré.
>Vous pouvez le vérifier en faisans : `docker ps`

Ensuite vous pouvez faire : 
`docker-compose up` si vous êtes dans le répertoire où se trouve le fichier
sinon `docker-compose up /mon/docker-compose.yml` si vous lancez la commande d'un autre endroit.

Vous pouvez vérifier que tout se passe bien en faisant : 
`docker-compose ps`

Vous pouvez arrêter le compose :
Vous êtes dans le répertoire : `docker-compose down`
Vous êtes autre part : `docker-compose down /mon/docker-compose.yml`

Pour plus d'infos sur Docker Compose : [Docker Compose v2 sur le site Docker](https://docs.docker.com/compose/compose-file/compose-file-v2/)

## Begin with Rancher 

Vous vous doutez bien que en production ou en environnement de test vous ne pouvez pas utiliser Docker à la main en allant manuellement démarrer les Containers sur le serveur. Pour cela l'homme, plus particulièrement les Dev Ops ont inventé les Orchestreur. Nous allons nous interresser à un Orchestreur Open Source facile à mettre en place ( grâce à Docker évidemment).

### Installer Rancher <a id="installRancher"></a> 
Il vous faut une serveur avec 2GB de RAM minimum pour faire tourner sans soucis Rancher.
> Sur Digital Ocean ça coute 20$/mois : [Site de DO](https://www.digitalocean.com)

Il faut que Docker soit installé sur ce serveur.
Il faut créer un dossier : `rancher` à la racine du serveur et créer un sous-dossier `data`, un autre sous-dossier `compose` ( dans `rancher` ) et un autre sous-dossier `sql` ( dans `rancher` ).
Il faut envoyer le ficher `nginx.tmpl` vers le serveur ( scp peut être utile : [C'est quoi scp ?]( https://technique.arscenic.org/transfert-de-donnees-entre/article/scp-transfert-de-fichier-a-travers))

**Il vous faut aussi un nom de domaine (ou sous-domaine) publique qui route vers le serveur qui héberge rancher pour pouvoir obtenir le certificat SSL Let's Encrypt.**

Voici le contenu du fichier `nginx.tmpl` :

```
{{ $CurrentContainer := where $ "ID" .Docker.CurrentContainerID | first }}

{{ define "upstream" }}
	{{ if .Address }}
		{{/* If we got the containers from swarm and this container's port is published to host, use host IP:PORT */}}
		{{ if and .Container.Node.ID .Address.HostPort }}
			# {{ .Container.Node.Name }}/{{ .Container.Name }}
			server {{ .Container.Node.Address.IP }}:8080;
		{{/* If there is no swarm node or the port is not published on host, use container's IP:PORT */}}
		{{ else if .Network }}
			# {{ .Container.Name }}
			server {{ .Network.IP }}:8080;
		{{ end }}
	{{ else if .Network }}
		# {{ .Container.Name }}
		server {{ .Network.IP }}:8080;
	{{ end }}
{{ end }}

# If we receive X-Forwarded-Proto, pass it through; otherwise, pass along the
# scheme used to connect to this server
map $http_x_forwarded_proto $proxy_x_forwarded_proto {
  default $http_x_forwarded_proto;
  ''      $scheme;
}

# If we receive X-Forwarded-Port, pass it through; otherwise, pass along the
# server port the client connected to
map $http_x_forwarded_port $proxy_x_forwarded_port {
  default $http_x_forwarded_port;
  ''      $server_port;
}

# If we receive Upgrade, set Connection to "upgrade"; otherwise, delete any
# Connection header that may have been passed to this server
map $http_upgrade $proxy_connection {
  default upgrade;
  '' close;
}

# Apply fix for very long server names
server_names_hash_bucket_size 128;

# Default dhparam
ssl_dhparam /etc/nginx/dhparam/dhparam.pem;

# Set appropriate X-Forwarded-Ssl header
map $scheme $proxy_x_forwarded_ssl {
  default off;
  https on;
}

gzip_types text/plain text/css application/javascript application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;

log_format vhost '$host $remote_addr - $remote_user [$time_local] '
                 '"$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent"';

access_log off;

{{ if $.Env.RESOLVERS }}
resolver {{ $.Env.RESOLVERS }};
{{ end }}

{{ if (exists "/etc/nginx/proxy.conf") }}
include /etc/nginx/proxy.conf;
{{ else }}
# HTTP 1.1 support
proxy_http_version 1.1;
proxy_buffering off;
proxy_set_header Host $http_host;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $proxy_connection;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $proxy_x_forwarded_proto;
proxy_set_header X-Forwarded-Ssl $proxy_x_forwarded_ssl;
proxy_set_header X-Forwarded-Port $proxy_x_forwarded_port;

# Mitigate httpoxy attack (see README for details)
proxy_set_header Proxy "";
{{ end }}

{{ $enable_ipv6 := eq (or ($.Env.ENABLE_IPV6) "") "true" }}
server {
	server_name _; # This is just an invalid value which will never trigger on a real hostname.
	listen 80;
	{{ if $enable_ipv6 }}
	listen [::]:80;
	{{ end }}
	access_log /var/log/nginx/access.log vhost;
	return 503;
}

{{ if (and (exists "/etc/nginx/certs/default.crt") (exists "/etc/nginx/certs/default.key")) }}
server {
	server_name _; # This is just an invalid value which will never trigger on a real hostname.
	listen 443 ssl http2;
	{{ if $enable_ipv6 }}
	listen [::]:443 ssl http2;
	{{ end }}
	access_log /var/log/nginx/access.log vhost;
	return 503;

	ssl_session_tickets off;
	ssl_certificate /etc/nginx/certs/default.crt;
	ssl_certificate_key /etc/nginx/certs/default.key;
}
{{ end }}

{{ range $host, $containers := groupByMulti $ "Env.VIRTUAL_HOST" "," }}

{{ $host := trim $host }}
{{ $is_regexp := hasPrefix "~" $host }}
{{ $upstream_name := when $is_regexp (sha1 $host) $host }}

# {{ $host }}
upstream {{ $upstream_name }} {

{{ range $container := $containers }}
	{{ $addrLen := len $container.Addresses }}

	{{ range $knownNetwork := $CurrentContainer.Networks }}
		{{ range $containerNetwork := $container.Networks }}
			{{ if (and (ne $containerNetwork.Name "ingress") (or (eq $knownNetwork.Name $containerNetwork.Name) (eq $knownNetwork.Name "host"))) }}
				## Can be connect with "{{ $containerNetwork.Name }}" network

				{{/* If only 1 port exposed, use that */}}
				{{ if eq $addrLen 1 }}
					{{ $address := index $container.Addresses 0 }}
					{{ template "upstream" (dict "Container" $container "Address" $address "Network" $containerNetwork) }}
				{{/* If more than one port exposed, use the one matching VIRTUAL_PORT env var, falling back to standard web port 80 */}}
				{{ else }}
					{{ $port := coalesce $container.Env.VIRTUAL_PORT "80" }}
					{{ $address := where $container.Addresses "Port" $port | first }}
					{{ template "upstream" (dict "Container" $container "Address" $address "Network" $containerNetwork) }}
				{{ end }}
			{{ end }}
		{{ end }}
	{{ end }}
{{ end }}
}

{{ $default_host := or ($.Env.DEFAULT_HOST) "" }}
{{ $default_server := index (dict $host "" $default_host "default_server") $host }}

{{/* Get the VIRTUAL_PROTO defined by containers w/ the same vhost, falling back to "http" */}}
{{ $proto := trim (or (first (groupByKeys $containers "Env.VIRTUAL_PROTO")) "http") }}

{{/* Get the HTTPS_METHOD defined by containers w/ the same vhost, falling back to "redirect" */}}
{{ $https_method := or (first (groupByKeys $containers "Env.HTTPS_METHOD")) "redirect" }}

{{/* Get the first cert name defined by containers w/ the same vhost */}}
{{ $certName := (first (groupByKeys $containers "Env.CERT_NAME")) }}

{{/* Get the best matching cert  by name for the vhost. */}}
{{ $vhostCert := (closest (dir "/etc/nginx/certs") (printf "%s.crt" $host))}}

{{/* vhostCert is actually a filename so remove any suffixes since they are added later */}}
{{ $vhostCert := trimSuffix ".crt" $vhostCert }}
{{ $vhostCert := trimSuffix ".key" $vhostCert }}

{{/* Use the cert specified on the container or fallback to the best vhost match */}}
{{ $cert := (coalesce $certName $vhostCert) }}

{{ $is_https := (and (ne $https_method "nohttps") (ne $cert "") (exists (printf "/etc/nginx/certs/%s.crt" $cert)) (exists (printf "/etc/nginx/certs/%s.key" $cert))) }}

{{ if $is_https }}

{{ if eq $https_method "redirect" }}
server {
	server_name {{ $host }};
	listen 80 {{ $default_server }};
	{{ if $enable_ipv6 }}
	listen [::]:80 {{ $default_server }};
	{{ end }}
	access_log /var/log/nginx/access.log vhost;
	return 301 https://$host$request_uri;
}
{{ end }}

server {
	server_name {{ $host }};
	listen 443 ssl http2 {{ $default_server }};
	{{ if $enable_ipv6 }}
	listen [::]:443 ssl http2 {{ $default_server }};
	{{ end }}
	access_log /var/log/nginx/access.log vhost;

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
	ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:!DSS';

	ssl_prefer_server_ciphers on;
	ssl_session_timeout 5m;
	ssl_session_cache shared:SSL:50m;
	ssl_session_tickets off;

	ssl_certificate /etc/nginx/certs/{{ (printf "%s.crt" $cert) }};
	ssl_certificate_key /etc/nginx/certs/{{ (printf "%s.key" $cert) }};

	{{ if (exists (printf "/etc/nginx/certs/%s.dhparam.pem" $cert)) }}
	ssl_dhparam {{ printf "/etc/nginx/certs/%s.dhparam.pem" $cert }};
	{{ end }}

	{{ if (exists (printf "/etc/nginx/certs/%s.chain.crt" $cert)) }}
	ssl_stapling on;
	ssl_stapling_verify on;
	ssl_trusted_certificate {{ printf "/etc/nginx/certs/%s.chain.crt" $cert }};
	{{ end }}

	{{ if (ne $https_method "noredirect") }}
	add_header Strict-Transport-Security "max-age=31536000";
	{{ end }}

	{{ if (exists (printf "/etc/nginx/vhost.d/%s" $host)) }}
	include {{ printf "/etc/nginx/vhost.d/%s" $host }};
	{{ else if (exists "/etc/nginx/vhost.d/default") }}
	include /etc/nginx/vhost.d/default;
	{{ end }}

	location / {
		{{ if eq $proto "uwsgi" }}
		include uwsgi_params;
		uwsgi_pass {{ trim $proto }}://{{ trim $upstream_name }};
		{{ else }}
		proxy_pass {{ trim $proto }}://{{ trim $upstream_name }};
		{{ end }}

		{{ if (exists (printf "/etc/nginx/htpasswd/%s" $host)) }}
		auth_basic	"Restricted {{ $host }}";
		auth_basic_user_file	{{ (printf "/etc/nginx/htpasswd/%s" $host) }};
		{{ end }}
                {{ if (exists (printf "/etc/nginx/vhost.d/%s_location" $host)) }}
                include {{ printf "/etc/nginx/vhost.d/%s_location" $host}};
                {{ else if (exists "/etc/nginx/vhost.d/default_location") }}
                include /etc/nginx/vhost.d/default_location;
                {{ end }}
	}
}

{{ end }}

{{ if or (not $is_https) (eq $https_method "noredirect") }}

server {
	server_name {{ $host }};
	listen 80 {{ $default_server }};
	{{ if $enable_ipv6 }}
	listen [::]:80 {{ $default_server }};
	{{ end }}
	access_log /var/log/nginx/access.log vhost;

	{{ if (exists (printf "/etc/nginx/vhost.d/%s" $host)) }}
	include {{ printf "/etc/nginx/vhost.d/%s" $host }};
	{{ else if (exists "/etc/nginx/vhost.d/default") }}
	include /etc/nginx/vhost.d/default;
	{{ end }}

	location / {
		{{ if eq $proto "uwsgi" }}
		include uwsgi_params;
		uwsgi_pass {{ trim $proto }}://{{ trim $upstream_name }};
		{{ else }}
		proxy_pass {{ trim $proto }}://{{ trim $upstream_name }};
		{{ end }}
		{{ if (exists (printf "/etc/nginx/htpasswd/%s" $host)) }}
		auth_basic	"Restricted {{ $host }}";
		auth_basic_user_file	{{ (printf "/etc/nginx/htpasswd/%s" $host) }};
		{{ end }}
                {{ if (exists (printf "/etc/nginx/vhost.d/%s_location" $host)) }}
                include {{ printf "/etc/nginx/vhost.d/%s_location" $host}};
                {{ else if (exists "/etc/nginx/vhost.d/default_location") }}
                include /etc/nginx/vhost.d/default_location;
                {{ end }}
	}
}

{{ if (and (not $is_https) (exists "/etc/nginx/certs/default.crt") (exists "/etc/nginx/certs/default.key")) }}
server {
	server_name {{ $host }};
	listen 443 ssl http2 {{ $default_server }};
	{{ if $enable_ipv6 }}
	listen [::]:443 ssl http2 {{ $default_server }};
	{{ end }}
	access_log /var/log/nginx/access.log vhost;
	return 500;

	ssl_certificate /etc/nginx/certs/default.crt;
	ssl_certificate_key /etc/nginx/certs/default.key;
}
{{ end }}

{{ end }}
{{ end }}
```

#### Le Compose File de Rancher (a modifier) <a id="rancherCompose"></a> 
Il faut le transférer au serveur ( par scp si besoin ) dans le dossier `rancher`

```yml
version: '3'
services:
    nginx:
        image: nginx
        labels:
            com.github.jrcs.letsencrypt_nginx_proxy_companion.nginx_proxy: "true"
        container_name: nginx
        restart: unless-stopped
        ports:
            - "80:80"
            - "443:443"
        volumes:
            - /rancher/data/conf.d:/etc/nginx/conf.d
            - /rancher/data/vhost.d:/etc/nginx/vhost.d
            - /rancher/data/html:/usr/share/nginx/html
            - /rancher/data/certs:/etc/nginx/certs:ro

    nginx-gen:
        image: jwilder/docker-gen
        command: -notify-sighup nginx -watch -wait 5s:30s /etc/docker-gen/templates/nginx.tmpl /etc/nginx/conf.d/default.conf
        container_name: nginx-gen
        restart: unless-stopped
        volumes:
            - /rancher/data/conf.d:/etc/nginx/conf.d
            - /rancher/data/vhost.d:/etc/nginx/vhost.d
            - /rancher/data/html:/usr/share/nginx/html
            - /rancher/data/certs:/etc/nginx/certs:ro
            - /var/run/docker.sock:/tmp/docker.sock:ro
            - /rancher/compose/:/etc/docker-gen/templates/:ro

    nginx-letsencrypt:
        image: jrcs/letsencrypt-nginx-proxy-companion
        container_name: nginx-letsencrypt
        restart: unless-stopped
        volumes:
            - /rancher/data/conf.d:/etc/nginx/conf.d
            - /rancher/data/vhost.d:/etc/nginx/vhost.d
            - /rancher/data/html:/usr/share/nginx/html
            - /rancher/data/certs:/etc/nginx/certs:rw
            - /var/run/docker.sock:/var/run/docker.sock:ro
        environment:
            - NGINX_DOCKER_GEN_CONTAINER=nginx-gen
            - NGINX_PROXY_CONTAINER=nginx

    rancher.monNomdeDomain.domaine:
        image: rancher/server:stable
        restart: unless-stopped
        ports:
            - "8080"
        environment:
            VIRTUAL_PORT: 8080
            VIRTUAL_PROTO: http
            VIRTUAL_HOST: rancher.monNomdeDomain.domaine
            HTTPS_METHOD: redirect
            LETSENCRYPT_HOST: rancher.monNomdeDomain.domaine
            LETSENCRYPT_EMAIL: uneAddresse@email.mail
        volumes:
            - /rancher/sql:/var/lib/mysql:rw
```

Ici vous avez juste à modifier le service `rancher.monNomdeDomain.domaine`
Il ne vous reste plus qu'a vous connecter à votre serveur, vous placez dans le dossier rancher et faire : `docker-compose up -d`

Rancher mets pas mal de temps à s'initialiser, il ne vous reste plus qu'as raffraichir votre navigateur.

Lorsque Rancher est lancé pour la première fois c'est le premier utilisateur à se connecter qui devient administrateur. Une fois connecté, il est conseillé de mettre en place via les paramètres d'administration la connection OAuth avec GitHub.

Pour plus d'informations sur Rancher : [Site Officiel Rancher](http://rancher.com)

## Comment utiliser le tout ?

### Stocker ses Containers en ligne <a id="stockerContainers"></a> 

Maintenant que tout est ok, il ne reste plus qu' à faire le lien entre les Rancher et Docker.
Pour cela vous pouvez soit envoyer vos images sur le serveur ( pas scalable ) ou utiliser le [Docker Hub](https://hub.docker.com) pour envoyer vos Containers dans un repo publique ou privé.

Si vous utilisez le DockerHub vous pouvez allez sur Rancher > Infra Structure > Registres, puis ajouter les login pour que Rancher ( et vos serveurs ) puisse accéder à votre repo de Containers.

Il faut ensuite que vous ajoutiez un Host (un serveur) pour y lancer les containers. Les steps pour le faire sont très bien indiqués sur votre Rancher, pas besoin d'explique plus de choses.

### Créer sa première Stack <a id="premiereStack"></a> 

Dans un premier temps nous allons configurer un proxy.
Nous allons créer un item Catalog pour faire ceci : Rancher > Admin > Settings et ajouter `https://github.com/adi90x/rancher-active-proxy.git`.
Une fois ajouté il faut aller dans Catalog puis dans la barre de recherche "active proxy". Il devrait normalement vous trouver l'item "Rancher Active Proxy". Cliquez sur "Voir les Détails" saisissez les données requise puis cliquez sur "Lancer".

Si tout se passe bien en allant dans "Stacks" vous devriez voir la Stack Rancher Active Proxy en vert.

**IL FAUT QUE VOTRE NOM DE DOMAINE POUR VOTRE APP DIRIGE VERS LE SERVEUR QUI POSSEDE LE CONTAINER RANCHER ACTIVE PROXY**

En restant sur cette page nous allons maintenant créer notre propre Stack pour lancer notre ecosytème. Cliquez sur "Créer" puis Rancher vous demande de récupérer un docker-compose.yml sur votre machine (le rancher-compose est optionel). Pour ceci nous allons utiliser un compose file légérement différent de celui donnée en exemple tout à l'heure :

```yaml
version: '2'
services:
        server: 
        image: monRepoDockerHub/monContainerServer:monTag
        restart: unless-stopped
        labels:
            rap.host: monNomDe.DomainePourLeServeur.domaine
            rap.le_email: une.addresse@email.mail
            rap.le_host: monNomDe.DomainePourLeServeur.domaine
            io.rancher.container.pull_image: always
        volumes: 
        #Si tu veux pouvoir modifier les fichiers
            - /data/monApp:/srv/app:rw
        environment :
            - DATABASE_URI=mongodb://db:27017/mabdd
            - MA_VAR=uneValeur
    db:
        image: mongo:latest
        ports:
           - "27017"
        command: mongod --quiet
        volumes: 
         - /data/db:/data/db:rw
         - /data/backup:/data/backup:rw
```

Les labels (rap) ajouté permettent d'indiquer à la Stack Rancher Active Proxy que vous voulez utiliser le proxy et un cerficat SSL. C'est fini ! 

Rancher va déployer votre app comme un grand c'est à dire démarrer 1 par 1 chaque Container et les dispatcher sur vos différents serveurs ( si vous en avez plusieurs ).

#### Monitorer <a id="monitorer"></a> 

Pour faire des backup de votre base de donnée ou simplement charger une base de données déja existante vous avez juste à aller dans votre Stack, puis cliquer sur le service `db` , en suite cliquer sur les options du container listé et faire : "Execute Shell", vous pouvez aussi voir les logs du Container en cliquant sur "View Logs"

#### Upgrade <a id="upgrade"></a> 

Vous pouvez upgrade à tout moment vos services pour par exemple modifier les variables d'environnement, mettre à jour le container, ajouter des règles d'execution, modifier les labels, scaler un service ( multiplier les Containers ).
Pour cela allez dans Stack plus cliquez sur votre Stack puis à droite de la page vous avec une petite flèche ou un menu d'option pour chaque service.

#### Le meilleur pour la fin <a id="meilleur"></a> 

Vous pouvez créer plusieurs environnements pour travailler plus proprement entre un environnement de Dev et un environnement de Prod.














