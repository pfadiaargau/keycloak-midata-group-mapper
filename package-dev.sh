#!/bin/bash

mvn clean package

cp target/midata-auth-plugin-*.jar docker/plugins/midata-auth-plugin.jar

cd docker 

docker compose -f docker-compose-dev.yml up --build keycloak -d

cd ..