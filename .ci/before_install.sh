#!/bin/bash

set -ex

find docker_images -type f | xargs docker load -i
