
```sh
cd docker

docker compose -f docker-compose-dev.yml up --build keycloak -d

```

mvn package


### Exporting pfadiaargau realm

```sh
docker compose -f docker-compose-dev.yml exec keycloak /opt/keycloak/bin/kc.sh export --realm pfadiaargau --file /tmp/pfadiaargau-realm.json

```

```sh
docker exec -it keycloak-keycloak-1 sh -c \
  "cp -rp /opt/keycloak/data/h2 /tmp ; \
  /opt/keycloak/bin/kc.sh export --dir /tmp/pfadiaargau-realm --realm pfadiaargau \
    --db dev-file \
    --db-url 'jdbc:h2:file:/tmp/h2/keycloakdb;NON_KEYWORDS=VALUE'"
```

### Fix "HTTP requred" error

First start the container

```sh
docker exec -it keycloak-keycloak-1 sh -c \
  "cd /opt/keycloak/bin ; \
  ./kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin ; \
  ./kcadm.sh update realms/master -s sslRequired=NONE"
```
