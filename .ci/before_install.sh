#!/bin/bash

set -ex

for tar docker_images/*.tar; do docker load -i $tar; done
