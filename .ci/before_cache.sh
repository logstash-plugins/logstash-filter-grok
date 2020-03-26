#!/bin/bash

set -ex

docker save -o docker_images/image-$ELASTIC_STACK_VERSION.tar ci_logstash
