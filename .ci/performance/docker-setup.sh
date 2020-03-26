#!/bin/bash

# This is intended to be run inside the docker container as the command of the docker-compose.
set -ex

cd .ci

# docker will look for: "./docker-compose.yml" (and "./docker-compose.override.yml")
./docker-setup.sh
