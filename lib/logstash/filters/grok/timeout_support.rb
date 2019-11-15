# encoding: utf-8

require 'timeout'

# NOTE: use nested module structure so that `TimeoutError` is picked from parent (`Grok`).
module LogStash module Filters class Grok
  # Helper module to manage the timeout helper pieces.
  module TimeoutSupport

    def with_timeout_if(condition, context, &block)
      if condition
        with_timeout(context, &block)
      else
        yield
      end
    end

    def with_timeout(context, &block)
      @timeout.exec(&block)
    rescue TimeoutError => error
      handle_timeout(context, error)
    end

    def handle_timeout(context, error)
      raise GrokTimeoutException.new(context.grok, context.field, context.input)
    end

    class GrokContext

      attr_reader :grok, :field, :input

      def initialize(field = nil, input = nil)
        @field = field
        @input = input
      end

      def set_grok(grok)
        @grok = grok
      end

    end

    class NoopTimeout

      def exec
        yield
      end

    end

    class RubyTimeout

      def initialize(timeout_millis)
        # divide by float to allow fractional seconds, the Timeout class timeout value is in seconds but the underlying
        # executor resolution is in microseconds so fractional second parameter down to microseconds is possible.
        # see https://github.com/jruby/jruby/blob/9.2.7.0/core/src/main/java/org/jruby/ext/timeout/Timeout.java#L125
        @timeout_seconds = timeout_millis / 1000.0
      end

      def exec(&block)
        Timeout.timeout(@timeout_seconds, TimeoutError, &block)
      end

    end

  end # TimeoutSupport
end; end; end
