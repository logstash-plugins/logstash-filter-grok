#!/bin/bash
# This is intended to be run inside the docker container as the command of the docker-compose.

env

set -ex

bundle exec rspec --format=documentation --tag performance