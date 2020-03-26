#!/bin/bash

set -ex

for file in docker_images/*; do
  [ -f "$fname" ] || continue
  docker load -i $file
done
