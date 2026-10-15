#!/bin/bash

mvn clean package

cp target/midata-auth-plugin-*.jar docker/plugins/midata-auth-plugin.jar

scp -P 244 /run/media/fwesterath/SHARED/Programming/pfadiaargau/midata-sync-plugin/docker/plugins/midata-auth-plugin.jar raik@cloud.pfadiaargau.ch:~