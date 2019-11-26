#!/bin/bash

# This is intended to be run inside the docker container as the command of the docker-compose.
set -ex

jruby -rbundler/setup -S rspec -fd
