# encoding: utf-8
require_relative "../spec_helper"

begin
  require "rspec-benchmark"
rescue LoadError # due testing against LS 5.x
end
RSpec.configure do |config|
  config.include RSpec::Benchmark::Matchers if defined? RSpec::Benchmark::Matchers
end

require "logstash/filters/grok"

describe LogStash::Filters::Grok do

  subject do
    described_class.new(config).tap { |filter| filter.register }
  end

  EVENT_COUNT = 300_000

  describe "base-line performance", :performance => true do

    EXPECTED_MIN_RATE = 30_000 # per second - based on Travis CI (docker) numbers

    let(:config) do
      { 'match' => { "message" => "%{SYSLOGLINE}" }, 'overwrite' => [ "message" ] }
    end

    it "matches at least #{EXPECTED_MIN_RATE} events/second" do
      max_duration = EVENT_COUNT / EXPECTED_MIN_RATE
      message = "Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]"
      expect do
        duration = measure do
          EVENT_COUNT.times { subject.filter(LogStash::Event.new("message" => message)) }
        end
        puts "filters/grok parse rate: #{"%02.0f/sec" % (EVENT_COUNT / duration)}, elapsed: #{duration}s"
      end.to perform_under(max_duration).warmup(1).sample(2).times
    end

  end

  describe "timeout", :performance => true do

    ACCEPTED_TIMEOUT_DEGRADATION = 100 # in % (compared to timeout-less run)
    # TODO: with more real-world (pipeline) setup this usually gets bellow 10% on average

    MATCH_PATTERNS = {
      "message" => [
        "foo0: %{NUMBER:bar}", "foo1: %{NUMBER:bar}", "foo2: %{NUMBER:bar}", "foo3: %{NUMBER:bar}", "foo4: %{NUMBER:bar}",
        "foo5: %{NUMBER:bar}", "foo6: %{NUMBER:bar}", "foo7: %{NUMBER:bar}", "foo8: %{NUMBER:bar}", "foo9: %{NUMBER:bar}",
        "%{SYSLOGLINE}"
      ]
    }

    SAMPLE_MESSAGE = "Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from aaaaaaaa.aaaaaa.net[111.111.11.1]".freeze

    TIMEOUT_MILLIS = 5_000

    let(:config_wout_timeout) do
      {
        'match' => MATCH_PATTERNS,
        'timeout_scope' => "event",
        'timeout_millis' => 0 # 0 - disabled timeout
      }
    end

    let(:config_with_timeout) do
      {
        'match' => MATCH_PATTERNS,
        'timeout_scope' => "event",
        'timeout_millis' => TIMEOUT_MILLIS
      }
    end

    SAMPLE_COUNT = 2

    it "has less than #{ACCEPTED_TIMEOUT_DEGRADATION}% overhead" do
      filter_wout_timeout = LogStash::Filters::Grok.new(config_wout_timeout).tap(&:register)
      wout_timeout_duration = do_sample_filter(filter_wout_timeout) # warmup
      puts "filters/grok(timeout => 0) warmed up in #{wout_timeout_duration}"
      before_sample!
      no_timeout_durations = Array.new(SAMPLE_COUNT).map do
        do_sample_filter(filter_wout_timeout)
      end
      puts "filters/grok(timeout => 0) took #{no_timeout_durations}"

      expected_duration = avg(no_timeout_durations)
      expected_duration += (expected_duration / 100) * ACCEPTED_TIMEOUT_DEGRADATION
      puts "expected_duration #{expected_duration}"

      filter_with_timeout = LogStash::Filters::Grok.new(config_with_timeout).tap(&:register)
      with_timeout_duration = do_sample_filter(filter_with_timeout) # warmup
      puts "filters/grok(timeout_scope => event) warmed up in #{with_timeout_duration}"

      try(3) do
        before_sample!
        durations = []
        begin
          expect do
            do_sample_filter(filter_with_timeout).tap { |duration| durations << duration }
          end.to perform_under(expected_duration).sample(SAMPLE_COUNT).times
        ensure
          puts "filters/grok(timeout_scope => event) took #{durations}"
        end
      end
    end

    @private

    def do_sample_filter(filter)
      sample_event = { "message" => SAMPLE_MESSAGE }
      measure do
        for _ in (1..EVENT_COUNT) do # EVENT_COUNT.times without the block cost
          filter.filter(LogStash::Event.new(sample_event))
        end
      end
    end

  end

  @private

  def measure
    start = Time.now
    yield
    Time.now - start
  end

  def avg(ary)
    ary.inject(0) { |m, i| m + i } / ary.size.to_f
  end

  def before_sample!
    2.times { JRuby.gc }
    sleep TIMEOUT_MILLIS / 1000
  end

  def sleep(seconds)
    puts "sleeping for #{seconds} seconds (redundant - potential timeout propagation)"
    Kernel.sleep(seconds)
  end

end