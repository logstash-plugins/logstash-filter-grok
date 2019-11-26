#!/bin/bash

# This is intended to be run inside the docker container as the command of the docker-compose.
set -ex

CURRENT_DIR=$(dirname "${BASH_SOURCE[0]}")

docker-compose -f $CURRENT_DIR/docker-compose.yml up --exit-code-from logstash
