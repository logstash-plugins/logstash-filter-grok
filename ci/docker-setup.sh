#!/bin/bash

# This is intended to be run the plugin's root directory. `ci/unit/docker-test.sh`
# Ensure you have Docker installed locally and set the ELASTIC_STACK_VERSION environment variable.
set -e

VERSION_URL="https://raw.githubusercontent.com/elastic/logstash/master/ci/logstash_releases.json"

if [ -z "${ELASTIC_STACK_VERSION}" ]; then
    echo "Please set the ELASTIC_STACK_VERSION environment variable"
    echo "For example: export ELASTIC_STACK_VERSION=7.x"
    exit 1
fi

echo "Fetching versions from $VERSION_URL"
VERSIONS=$(curl $VERSION_URL)

if [[ "$SNAPSHOT" = "true" ]]; then
  ELASTIC_STACK_RETRIEVED_VERSION=$(echo $VERSIONS | jq '.snapshots."'"$ELASTIC_STACK_VERSION"'"')
  echo $ELASTIC_STACK_RETRIEVED_VERSION
else
  ELASTIC_STACK_RETRIEVED_VERSION=$(echo $VERSIONS | jq '.releases."'"$ELASTIC_STACK_VERSION"'"')
fi

if [[ "$ELASTIC_STACK_RETRIEVED_VERSION" != "null" ]]; then
  # remove starting and trailing double quotes
  ELASTIC_STACK_RETRIEVED_VERSION="${ELASTIC_STACK_RETRIEVED_VERSION%\"}"
  ELASTIC_STACK_RETRIEVED_VERSION="${ELASTIC_STACK_RETRIEVED_VERSION#\"}"
  echo "Translated $ELASTIC_STACK_VERSION to ${ELASTIC_STACK_RETRIEVED_VERSION}"
  export ELASTIC_STACK_VERSION=$ELASTIC_STACK_RETRIEVED_VERSION
fi

if [[ "$DISTRIBUTION" = "oss" ]]; then
  DISTRIBUTION_SUFFIX="-oss"
else
  DISTRIBUTION_SUFFIX=""
fi

echo "Testing against version: $ELASTIC_STACK_VERSION (distribution: ${DISTRIBUTION:-"default"})"

if [[ "$ELASTIC_STACK_VERSION" = *"-SNAPSHOT" ]]; then
    cd /tmp

    jq=".build.projects.\"logstash\".packages.\"logstash$DISTRIBUTION_SUFFIX-$ELASTIC_STACK_VERSION-docker-image.tar.gz\".url"
    result=$(curl --silent https://artifacts-api.elastic.co/v1/versions/$ELASTIC_STACK_VERSION/builds/latest | jq -r $jq)
    echo $result
    curl $result > logstash-docker-image.tar.gz
    tar xfvz logstash-docker-image.tar.gz repositories
    echo "Loading docker image: "
    cat repositories
    docker load < logstash-docker-image.tar.gz
    rm logstash-docker-image.tar.gz
    cd -
fi

if [ -f Gemfile.lock ]; then
    rm Gemfile.lock
fi

CURRENT_DIR=$(dirname "${BASH_SOURCE[0]}") # e.g. "ci/unit"

docker-compose -f "$CURRENT_DIR/docker-compose.yml" down
docker-compose -f "$CURRENT_DIR/docker-compose.yml" build logstash

#docker-compose -f "$CURRENT_DIR/docker-compose.yml" up --exit-code-from logstash --force-recreate
