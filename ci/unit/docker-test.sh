#!/bin/bash

# This is intended to be run the plugin's root directory. `ci/unit/docker-test.sh`
# Ensure you have Docker installed locally and set the ELASTIC_STACK_VERSION environment variable.
set -e

if [ "$ELASTIC_STACK_VERSION" ]; then
    echo "Testing against version: $ELASTIC_STACK_VERSION"

    if [[ "$ELASTIC_STACK_VERSION" = *"-SNAPSHOT" ]]; then
        cd /tmp
        wget https://snapshots.elastic.co/docker/logstash-"$ELASTIC_STACK_VERSION".tar.gz
        tar xfvz logstash-"$ELASTIC_STACK_VERSION".tar.gz  repositories
        echo "Loading docker image: "
        cat repositories
        docker load < logstash-"$ELASTIC_STACK_VERSION".tar.gz
        rm logstash-"$ELASTIC_STACK_VERSION".tar.gz
        cd -
    fi

    if [ -f Gemfile.lock ]; then
        rm Gemfile.lock
    fi

    docker-compose -f ci/unit/docker-compose.yml down
    docker-compose -f ci/unit/docker-compose.yml up --build --exit-code-from logstash --force-recreate
else
    echo "Please set the ELASTIC_STACK_VERSION environment variable"
    echo "For example: export ELASTIC_STACK_VERSION=6.2.4"
    exit 1
fi

