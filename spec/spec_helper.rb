# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "stud/temporary"

module LogStash::Environment
  # running the grok code outside a logstash package means
  # LOGSTASH_HOME will not be defined, so let's set it here
  # before requiring the grok filter
  unless self.const_defined?(:LOGSTASH_HOME)
    LOGSTASH_HOME = File.expand_path("../../../", __FILE__)
  end

  # also :pattern_path method must exist so we define it too
  unless self.method_defined?(:pattern_path)
    def pattern_path(path)
      ::File.join(LOGSTASH_HOME, "patterns", path)
    end
  end
end
