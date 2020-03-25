#!/bin/bash

set -ex

for tar in docker_images/*.tar; do docker load -i $tar; done
