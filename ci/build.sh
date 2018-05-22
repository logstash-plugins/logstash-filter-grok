#!/bin/bash
set -e

if [ "$LOGSTASH_VERSION" ]; then
  export LOGSTASH_PATH=$PWD/logstash-$LOGSTASH_VERSION
  export PATH=$LOGSTASH_PATH/vendor/jruby/bin:$LOGSTASH_PATH/vendor/bundle/jruby/2.3.0/bin:$PATH
  export LOGSTASH_SOURCE=1
fi
jruby -S bundle exec rspec spec
