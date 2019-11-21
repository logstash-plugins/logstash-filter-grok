# encoding: utf-8
require_relative "../spec_helper"

require "logstash/filters/grok"

describe LogStash::Filters::Grok do

  describe "simple syslog line" do
    # The logstash config goes here.
    # At this time, only filters are supported.
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{SYSLOGLINE}" }
          overwrite => [ "message" ]
        }
      }
    CONFIG

    sample "Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]" do
      insist { subject.get("tags") }.nil?
      insist { subject.get("logsource") } == "evita"
      insist { subject.get("timestamp") } == "Mar 16 00:01:25"
      insist { subject.get("message") } == "connect from camomile.cloud9.net[168.100.1.3]"
      insist { subject.get("program") } == "postfix/smtpd"
      insist { subject.get("pid") } == "1713"
    end
  end

  describe "ietf 5424 syslog line" do
    # The logstash config goes here.
    # At this time, only filters are supported.
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{SYSLOG5424LINE}" }
        }
      }
    CONFIG

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug 4123 - [id1 foo=\"bar\"][id2 baz=\"something\"] Hello, syslog." do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog5424_pri") } == "191"
      insist { subject.get("syslog5424_ver") } == "1"
      insist { subject.get("syslog5424_ts") } == "2009-06-30T18:30:00+02:00"
      insist { subject.get("syslog5424_host") } == "paxton.local"
      insist { subject.get("syslog5424_app") } == "grokdebug"
      insist { subject.get("syslog5424_proc") } == "4123"
      insist { subject.get("syslog5424_msgid") } == nil
      insist { subject.get("syslog5424_sd") } == "[id1 foo=\"bar\"][id2 baz=\"something\"]"
      insist { subject.get("syslog5424_msg") } == "Hello, syslog."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug - - [id1 foo=\"bar\"] No process ID." do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog5424_pri") } == "191"
      insist { subject.get("syslog5424_ver") } == "1"
      insist { subject.get("syslog5424_ts") } == "2009-06-30T18:30:00+02:00"
      insist { subject.get("syslog5424_host") } == "paxton.local"
      insist { subject.get("syslog5424_app") } == "grokdebug"
      insist { subject.get("syslog5424_proc") } == nil
      insist { subject.get("syslog5424_msgid") } == nil
      insist { subject.get("syslog5424_sd") } == "[id1 foo=\"bar\"]"
      insist { subject.get("syslog5424_msg") } == "No process ID."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug 4123 - - No structured data." do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog5424_pri") } == "191"
      insist { subject.get("syslog5424_ver") } == "1"
      insist { subject.get("syslog5424_ts") } == "2009-06-30T18:30:00+02:00"
      insist { subject.get("syslog5424_host") } == "paxton.local"
      insist { subject.get("syslog5424_app") } == "grokdebug"
      insist { subject.get("syslog5424_proc") } == "4123"
      insist { subject.get("syslog5424_msgid") } == nil
      insist { subject.get("syslog5424_sd") } == nil
      insist { subject.get("syslog5424_msg") } == "No structured data."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug - - - No PID or SD." do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog5424_pri") } == "191"
      insist { subject.get("syslog5424_ver") } == "1"
      insist { subject.get("syslog5424_ts") } == "2009-06-30T18:30:00+02:00"
      insist { subject.get("syslog5424_host") } == "paxton.local"
      insist { subject.get("syslog5424_app") } == "grokdebug"
      insist { subject.get("syslog5424_proc") } == nil
      insist { subject.get("syslog5424_msgid") } == nil
      insist { subject.get("syslog5424_sd") } == nil
      insist { subject.get("syslog5424_msg") } == "No PID or SD."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug 4123 -  Missing structured data." do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog5424_pri") } == "191"
      insist { subject.get("syslog5424_ver") } == "1"
      insist { subject.get("syslog5424_ts") } == "2009-06-30T18:30:00+02:00"
      insist { subject.get("syslog5424_host") } == "paxton.local"
      insist { subject.get("syslog5424_app") } == "grokdebug"
      insist { subject.get("syslog5424_proc") } == "4123"
      insist { subject.get("syslog5424_msgid") } == nil
      insist { subject.get("syslog5424_sd") } == nil
      insist { subject.get("syslog5424_msg") } == "Missing structured data."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug  4123 - - Additional spaces." do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog5424_pri") } == "191"
      insist { subject.get("syslog5424_ver") } == "1"
      insist { subject.get("syslog5424_ts") } == "2009-06-30T18:30:00+02:00"
      insist { subject.get("syslog5424_host") } == "paxton.local"
      insist { subject.get("syslog5424_app") } == "grokdebug"
      insist { subject.get("syslog5424_proc") } == "4123"
      insist { subject.get("syslog5424_msgid") } == nil
      insist { subject.get("syslog5424_sd") } == nil
      insist { subject.get("syslog5424_msg") } == "Additional spaces."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug  4123 -  Additional spaces and missing SD." do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog5424_pri") } == "191"
      insist { subject.get("syslog5424_ver") } == "1"
      insist { subject.get("syslog5424_ts") } == "2009-06-30T18:30:00+02:00"
      insist { subject.get("syslog5424_host") } == "paxton.local"
      insist { subject.get("syslog5424_app") } == "grokdebug"
      insist { subject.get("syslog5424_proc") } == "4123"
      insist { subject.get("syslog5424_msgid") } == nil
      insist { subject.get("syslog5424_sd") } == nil
      insist { subject.get("syslog5424_msg") } == "Additional spaces and missing SD."
    end

    sample "<30>1 2014-04-04T16:44:07+02:00 osctrl01 dnsmasq-dhcp 8048 - -  Appname contains a dash" do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog5424_pri") } == "30"
      insist { subject.get("syslog5424_ver") } == "1"
      insist { subject.get("syslog5424_ts") } == "2014-04-04T16:44:07+02:00"
      insist { subject.get("syslog5424_host") } == "osctrl01"
      insist { subject.get("syslog5424_app") } == "dnsmasq-dhcp"
      insist { subject.get("syslog5424_proc") } == "8048"
      insist { subject.get("syslog5424_msgid") } == nil
      insist { subject.get("syslog5424_sd") } == nil
      insist { subject.get("syslog5424_msg") } == "Appname contains a dash"
    end

    sample "<30>1 2014-04-04T16:44:07+02:00 osctrl01 - 8048 - -  Appname is nil" do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog5424_pri") } == "30"
      insist { subject.get("syslog5424_ver") } == "1"
      insist { subject.get("syslog5424_ts") } == "2014-04-04T16:44:07+02:00"
      insist { subject.get("syslog5424_host") } == "osctrl01"
      insist { subject.get("syslog5424_app") } == nil
      insist { subject.get("syslog5424_proc") } == "8048"
      insist { subject.get("syslog5424_msgid") } == nil
      insist { subject.get("syslog5424_sd") } == nil
      insist { subject.get("syslog5424_msg") } == "Appname is nil"
    end
  end

  describe "parsing an event with multiple messages (array of strings)", :if => false do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "(?:hello|world) %{NUMBER}" }
          named_captures_only => false
        }
      }
    CONFIG

    sample("message" => [ "hello 12345", "world 23456" ]) do
      insist { subject.get("NUMBER") } == [ "12345", "23456" ]
    end
  end

  describe "coercing matched values" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{NUMBER:foo:int} %{NUMBER:bar:float}" }
        }
      }
    CONFIG

    sample "400 454.33" do
      insist { subject.get("foo") } == 400
      insist { subject.get("foo") }.is_a?(Integer)
      insist { subject.get("bar") } == 454.33
      insist { subject.get("bar") }.is_a?(Float)
    end
  end

  describe "in-line pattern definitions" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{FIZZLE=\\d+}" }
          named_captures_only => false
        }
      }
    CONFIG

    sample "hello 1234" do
      insist { subject.get("FIZZLE") } == "1234"
    end
  end

  describe "processing selected fields" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{WORD:word}" }
          match => { "examplefield" => "%{NUMBER:num}" }
          break_on_match => false
        }
      }
    CONFIG

    sample("message" => "hello world", "examplefield" => "12345") do
      insist { subject.get("examplefield") } == "12345"
      insist { subject.get("word") } == "hello"
    end
  end

  describe "adding fields on match" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "matchme %{NUMBER:fancy}" }
          add_field => [ "new_field", "%{fancy}" ]
        }
      }
    CONFIG

    sample "matchme 1234" do
      insist { subject.get("tags") }.nil?
      insist { subject.get("new_field") } == "1234"
    end

    sample "this will not be matched" do
      insist { subject.get("tags") }.include?("_grokparsefailure")
      reject { subject }.include?("new_field")
    end
  end

  context "empty fields" do
    describe "drop by default" do
      config <<-CONFIG
        filter {
          grok {
            match => { "message" => "1=%{WORD:foo1} *(2=%{WORD:foo2})?" }
          }
        }
      CONFIG

      sample "1=test" do
        insist { subject.get("tags") }.nil?
        insist { subject }.include?("foo1")

        # Since 'foo2' was not captured, it must not be present in the event.
        reject { subject }.include?("foo2")
      end
    end

    describe "keep if keep_empty_captures is true" do
      config <<-CONFIG
        filter {
          grok {
            match => { "message" => "1=%{WORD:foo1} *(2=%{WORD:foo2})?" }
            keep_empty_captures => true
          }
        }
      CONFIG

      sample "1=test" do
        insist { subject.get("tags") }.nil?
        # use .to_hash for this test, for now, because right now
        # the Event.include? returns false for missing fields as well
        # as for fields with nil values.
        insist { subject.to_hash }.include?("foo2")
        insist { subject.to_hash }.include?("foo2")
      end
    end
  end

  describe "when named_captures_only == false" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "Hello %{WORD}. %{WORD:foo}" }
          named_captures_only => false
        }
      }
    CONFIG

    sample "Hello World, yo!" do
      insist { subject }.include?("WORD")
      insist { subject.get("WORD") } == "World"
      insist { subject }.include?("foo")
      insist { subject.get("foo") } == "yo"
    end
  end

  describe "using oniguruma named captures (?<name>regex)" do
    context "plain regexp" do
      config <<-'CONFIG'
        filter {
          grok {
            match => { "message" => "(?<foo>\w+)" }
          }
        }
      CONFIG
      sample "hello world" do
        insist { subject.get("tags") }.nil?
        insist { subject.get("foo") } == "hello"
      end
    end

    context "grok patterns" do
      config <<-'CONFIG'
        filter {
          grok {
            match => { "message" => "(?<timestamp>%{DATE_EU} %{TIME})" }
          }
        }
      CONFIG

      sample "fancy 12-12-12 12:12:12" do
        insist { subject.get("tags") }.nil?
        insist { subject.get("timestamp") } == "12-12-12 12:12:12"
      end
    end
  end

  describe "grok on integer types" do
    config <<-'CONFIG'
      filter {
        grok {
          match => { "status" => "^403$" }
          add_tag => "four_oh_three"
        }
      }
    CONFIG

    sample("status" => 403) do
      reject { subject.get("tags") }.include?("_grokparsefailure")
      insist { subject.get("tags") }.include?("four_oh_three")
    end
  end

  describe "grok on float types" do
    config <<-'CONFIG'
      filter {
        grok {
          match => { "version" => "^1.0$" }
          add_tag => "one_point_oh"
        }
      }
    CONFIG

    sample("version" => 1.0) do
      insist { subject.get("tags") }.include?("one_point_oh")
      insist { subject.get("tags") }.include?("one_point_oh")
    end
  end

  describe "grok on %{LOGLEVEL}" do
    config <<-'CONFIG'
      filter {
        grok {
          match => { "message" => "%{LOGLEVEL:level}: error!" }
        }
      }
    CONFIG

    log_level_names = %w(
      trace Trace TRACE
      debug Debug DEBUG
      notice Notice Notice
      info Info INFO
      warn warning Warn Warning WARN WARNING
      err error Err Error ERR ERROR
      crit critical Crit Critical CRIT CRITICAL
      fatal Fatal FATAL
      severe Severe SEVERE
      emerg emergency Emerg Emergency EMERG EMERGENCY
    )
    log_level_names.each do |level_name|
      sample "#{level_name}: error!" do
        insist { subject.get("level") } == level_name
      end
    end
  end

  describe "timeout on failure" do
    config <<-CONFIG
      filter {
        grok {
          match => {
            "message" => "(.*a){30}"
          }
          timeout_millis => 100
        }
      }
    CONFIG

    sample "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" do
      expect(subject.get("tags")).to include("_groktimeout")
      expect(subject.get("tags")).not_to include("_grokparsefailure")
    end
  end

  describe "no timeout on failure with multiple patterns (when timeout not grouped)" do
    config <<-CONFIG
      filter {
        grok {
          match => {
            "message" => [
              "(.*f){20}", "(.*e){20}", "(.*d){20}", "(.*c){20}", "(.*b){20}",
              "(.*a){25}", "(.*a){24}", "(.*a){23}", "(.*a){22}", "(.*a){21}",
              "(.*a){20}"
            ]
          }
          timeout_millis => 500
          timeout_scope => 'pattern'
        }
      }
    CONFIG

    sample( 'b' * 10 + 'c' * 10 + 'd' * 10 + 'e' * 10 + ' ' + 'a' * 20 ) do
      insist { subject.get("tags") }.nil?
    end
  end

  describe "timeout on grouped (multi-pattern) failure" do
    config <<-CONFIG
      filter {
        grok {
          match => {
            "message" => [
              "(.*f){20}", "(.*e){20}", "(.*d){20}", "(.*c){20}", "(.*b){20}",
              "(.*a){25}", "(.*a){24}", "(.*a){23}", "(.*a){22}", "(.*a){21}",
              "(.*a){20}"
            ]
          }
          timeout_millis => 500
          timeout_scope => 'event'
        }
      }
    CONFIG

    sample( 'b' * 10 + 'c' * 10 + 'd' * 10 + 'e' * 10 + ' ' + 'a' * 20 ) do
      expect(subject.get("tags")).to include("_groktimeout")
      expect(subject.get("tags")).not_to include("_grokparsefailure")
    end
  end

  describe "tagging on failure" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "matchme %{NUMBER:fancy}" }
          tag_on_failure => not_a_match
        }
      }
    CONFIG

    sample "matchme 1234" do
      insist { subject.get("tags") }.nil?
    end

    sample "this will not be matched" do
      insist { subject.get("tags") }.include?("not_a_match")
    end
  end

  describe "captures named fields even if the whole text matches" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{DATE_EU:stimestamp}" }
        }
      }
    CONFIG

    sample "11/01/01" do
      insist { subject.get("stimestamp") } == "11/01/01"
    end
  end

  describe "allow dashes in capture names" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{WORD:foo-bar}" }
        }
      }
    CONFIG

    sample "hello world" do
      insist { subject.get("foo-bar") } == "hello"
    end
  end

  describe "single value match with duplicate-named fields in pattern" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{INT:foo}|%{WORD:foo}" }
        }
      }
    CONFIG

    sample "hello world" do
      insist { subject.get("foo") }.is_a?(String)
    end

    sample "123 world" do
      insist { subject.get("foo") }.is_a?(String)
    end
  end

  describe "break_on_match default should be true and first match should exit filter" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{INT:foo}"
                     "somefield" => "%{INT:bar}"}
        }
      }
    CONFIG

    sample("message" => "hello world 123", "somefield" => "testme abc 999") do
      insist { subject.get("foo") } == "123"
      insist { subject.get("bar") }.nil?
    end
  end

  describe "break_on_match when set to false should try all patterns" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{INT:foo}"
                     "somefield" => "%{INT:bar}"}
          break_on_match => false
        }
      }
    CONFIG

    sample("message" => "hello world 123", "somefield" => "testme abc 999") do
      insist { subject.get("foo") } == "123"
      insist { subject.get("bar") } == "999"
    end
  end

  describe "LOGSTASH-1547 - break_on_match should work on fields with multiple patterns" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => ["%{GREEDYDATA:name1}beard", "tree%{GREEDYDATA:name2}"] }
          break_on_match => false
        }
      }
    CONFIG

    sample "treebranch" do
      insist { subject.get("name2") } == "branch"
    end

    sample "bushbeard" do
      insist { subject.get("name1") } == "bush"
    end

    sample "treebeard" do
      insist { subject.get("name1") } == "tree"
      insist { subject.get("name2") } == "beard"
    end
  end

  describe "break_on_match default for array input with single grok pattern" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{INT:foo}"}
        }
      }
    CONFIG

    # array input --
    sample("message" => ["hello world 123", "line 23"]) do
      insist { subject.get("foo") } == ["123", "23"]
      insist { subject.get("tags") }.nil?
    end

    # array input, one of them matches
    sample("message" => ["hello world 123", "abc"]) do
      insist { subject.get("foo") } == "123"
      insist { subject.get("tags") }.nil?
    end
  end

  describe "break_on_match = true (default) for array input with multiple grok pattern" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => ["%{INT:foo}", "%{WORD:bar}"] }
        }
      }
    CONFIG

    # array input --
    sample("message" => ["hello world 123", "line 23"]) do
      insist { subject.get("foo") } == ["123", "23"]
      insist { subject.get("bar") }.nil?
      insist { subject.get("tags") }.nil?
    end

    # array input, one of them matches
    sample("message" => ["hello world", "line 23"]) do
      insist { subject.get("bar") } == "hello"
      insist { subject.get("foo") } == "23"
      insist { subject.get("tags") }.nil?
    end
  end

  describe "break_on_match = false for array input with multiple grok pattern" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => ["%{INT:foo}", "%{WORD:bar}"] }
          break_on_match => false
        }
      }
    CONFIG

    # array input --
    sample("message" => ["hello world 123", "line 23"]) do
      insist { subject.get("foo") } == ["123", "23"]
      insist { subject.get("bar") } == ["hello", "line"]
      insist { subject.get("tags") }.nil?
    end

    # array input, one of them matches
    sample("message" => ["hello world", "line 23"]) do
      insist { subject.get("bar") } == ["hello", "line"]
      insist { subject.get("foo") } == "23"
      insist { subject.get("tags") }.nil?
    end
  end

  describe  "grok with unicode" do
    config <<-CONFIG
      filter {
        grok {
          #match => { "message" => "<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{PROG:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
          match => { "message" => "<%{POSINT:syslog_pri}>%{SPACE}%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{PROG:syslog_program}(:?)(?:\\[%{GREEDYDATA:syslog_pid}\\])?(:?) %{GREEDYDATA:syslog_message}" }
        }
      }
    CONFIG

    sample "<22>Jan  4 07:50:46 mailmaster postfix/policy-spf[9454]: : SPF permerror (Junk encountered in record 'v=spf1 mx a:mail.domain.no ip4:192.168.0.4 �all'): Envelope-from: email@domain.no" do
      insist { subject.get("tags") }.nil?
      insist { subject.get("syslog_pri") } == "22"
      insist { subject.get("syslog_program") } == "postfix/policy-spf"
    end
  end

  describe "patterns in the 'patterns/' dir override core patterns" do

    let(:pattern_dir) { File.join(LogStash::Environment::LOGSTASH_HOME, "patterns") }
    let(:has_pattern_dir?) { Dir.exist?(pattern_dir) }

    before do
      FileUtils.mkdir(pattern_dir) unless has_pattern_dir?
      @file = File.new(File.join(pattern_dir, 'grok.pattern'), 'w+')
      @file.write('WORD \b[2-5]\b')
      @file.close
    end

    let(:config) do
      'filter { grok { match => { "message" => "%{WORD:word}" } } }'
    end

    sample("message" => 'hello') do
      insist { subject.get("tags") } == ["_grokparsefailure"]
    end

    after do
      File.unlink @file
      FileUtils.rm_rf(pattern_dir) if has_pattern_dir?
    end
  end

  describe "patterns in custom dir override those in 'patterns/' dir" do

    let(:tmpdir) { Stud::Temporary.directory }
    let(:pattern_dir) { File.join(LogStash::Environment::LOGSTASH_HOME, "patterns") }
    let(:has_pattern_dir?) { Dir.exist?(pattern_dir) }

    before do
      FileUtils.mkdir(pattern_dir) unless has_pattern_dir?
      @file1 = File.new(File.join(pattern_dir, 'grok.pattern'), 'w+')
      @file1.write('WORD \b[2-5]\b')
      @file1.close
      @file2 = File.new(File.join(tmpdir, 'grok.pattern'), 'w+')
      @file2.write('WORD \b[0-1]\b')
      @file2.close
    end

    let(:config) do
      "filter { grok { patterns_dir => \"#{tmpdir}\" match => { \"message\" => \"%{WORD:word}\" } } }"
    end

    sample("message" => '0') do
      insist { subject.get("tags") } == nil
    end

    after do
      File.unlink @file1
      File.unlink @file2
      FileUtils.remove_entry tmpdir
      FileUtils.rm_rf(pattern_dir) unless has_pattern_dir?
    end
  end

  describe "patterns with file glob" do

    let(:tmpdir) { Stud::Temporary.directory }

    before do
      @file3 = File.new(File.join(tmpdir, 'grok.pattern'), 'w+')
      @file3.write('WORD \b[0-1]\b')
      @file3.close
      @file4 = File.new(File.join(tmpdir, 'grok.pattern.old'), 'w+')
      @file4.write('WORD \b[2-5]\b')
      @file4.close
    end

    let(:config) do
      "filter { grok { patterns_dir => \"#{tmpdir}\" patterns_files_glob => \"*.pattern\" match => { \"message\" => \"%{WORD:word}\" } } }"
    end

    sample("message" => '0') do
      insist { subject.get("tags") } == nil
    end

    after do
      File.unlink @file3
      File.unlink @file4
      FileUtils.remove_entry tmpdir
    end
  end

  describe "patterns with file glob on directory that contains subdirectories" do

    let(:tmpdir) { Stud::Temporary.directory }

    before do
      @file3 = File.new(File.join(tmpdir, 'grok.pattern'), 'w+')
      @file3.write('WORD \b[0-1]\b')
      @file3.close
      Dir.mkdir(File.join(tmpdir, "subdir"))
    end

    let(:config) do
      "filter { grok { patterns_dir => \"#{tmpdir}\" patterns_files_glob => \"*\" match => { \"message\" => \"%{WORD:word}\" } } }"
    end

    sample("message" => '0') do
      insist { subject.get("tags") } == nil
    end

    after do
      File.unlink @file3
      FileUtils.remove_entry tmpdir
    end
  end

  describe  "grok with nil coerced value" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "test (N/A|%{BASE10NUM:duration:float}ms)" }
        }
      }
    CONFIG

    sample "test 28.4ms" do
      insist { subject.get("duration") } == 28.4
      insist { subject.get("tags") }.nil?
    end

    sample "test N/A" do
      insist { insist { subject.to_hash }.include?("duration") }.fails
      insist { subject.get("tags") }.nil?
    end

    sample "test abc" do
      insist { subject.get("duration") }.nil?
      insist { subject.get("tags") } == ["_grokparsefailure"]
    end
  end

  describe  "grok with nil coerced value and keep_empty_captures" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "test (N/A|%{BASE10NUM:duration:float}ms)" }
          keep_empty_captures => true
        }
      }
    CONFIG

    sample "test N/A" do
      insist { subject.to_hash }.include?("duration")
      insist { subject.get("tags") }.nil?
    end

  end

  describe  "grok with no coercion" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "test (N/A|%{BASE10NUM:duration}ms)" }
        }
      }
    CONFIG

    sample "test 28.4ms" do
      insist { subject.get("duration") } == "28.4"
      insist { subject.get("tags") }.nil?
    end

    sample "test N/A" do
      insist { subject.get("duration") }.nil?
      insist { subject.get("tags") }.nil?
    end
  end

  describe "opening/closing" do
    let(:config) { {"match" => {"message" => "A"}} }
    subject(:plugin) do
      ::LogStash::Filters::Grok.new(config)
    end

    before do
      plugin.register
    end

    it "should close cleanly" do
      expect { plugin.do_close }.not_to raise_error
    end
  end

  describe "after grok when the event is JSON serialised the field values are unchanged" do
    config <<-CONFIG
      filter {grok {match => ["message", "Failed password for (invalid user |)%{USERNAME:username} from %{IP:src_ip} port %{BASE10NUM:port}"] remove_field => ["message","severity"] add_tag => ["ssh_failure"]}}
    CONFIG

    sample('{"facility":"auth","message":"Failed password for testuser from 1.1.1.1 port 22"}') do
      insist { subject.get("username") } == "testuser"
      insist { subject.get("port") } == "22"
      insist { subject.get("src_ip") } == "1.1.1.1"
      insist { LogStash::Json.dump(subject.get('username')) } == "\"testuser\""

      insist { subject.to_json } =~ %r|"src_ip":"1.1.1.1"|
      insist { subject.to_json } =~ %r|"@timestamp":"20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ"|
      insist { subject.to_json } =~ %r|"port":"22"|
      insist { subject.to_json } =~ %r|"@version":"1"|
      insist { subject.to_json } =~ %r|"username"|i
      insist { subject.to_json } =~ %r|"testuser"|
      insist { subject.to_json } =~ %r|"tags":\["ssh_failure"\]|
    end
  end

  describe  "grok with inline pattern definition successfully extracts fields" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{APACHE_TIME:timestamp} %{LOGLEVEL:level} %{MY_PATTERN:hindsight}" }
          pattern_definitions => { "APACHE_TIME" => "%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}"
           "MY_PATTERN" => "%{YEAR}"}
        }
      }
    CONFIG

    sample "Mon Dec 26 16:22:08 2016 error 2020" do
      insist { subject.get("timestamp") } == "Mon Dec 26 16:22:08 2016"
      insist { subject.get("level") } == "error"
      insist { subject.get("hindsight") } == "2020"
    end
  end

  describe  "grok with inline pattern definition overwrites existing pattern definition" do
    config <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{APACHE_TIME:timestamp} %{LOGLEVEL:level}" }
          # loglevel was previously ([Aa]lert|ALERT|[Tt]...
          pattern_definitions => { "APACHE_TIME" => "%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}"
           "LOGLEVEL" => "%{NUMBER}"}
        }
      }
    CONFIG

    sample "Mon Dec 26 16:22:08 2016 9999" do
      insist { subject.get("timestamp") } == "Mon Dec 26 16:22:08 2016"
      insist { subject.get("level") } == "9999"
    end
  end


  describe "direct plugin testing" do
    subject do
      plugin = LogStash::Filters::Grok.new(options)
      plugin.register
      plugin
    end

    let(:data) { {"message" => message} }
    let(:event) { LogStash::Event.new(data) }

    context 'when timeouts are explicitly disabled' do
      let(:options) do
        {
          "timeout_millis" => 0
        }
      end

      context 'when given a pathological input' do
        let(:message) { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        let(:options) { super().merge("match" => { "message" => "(.*a){30}" }) }

        it 'blocks for at least 3 seconds' do
          blocking_exception_class = Class.new(::Exception) # avoid RuntimeError
          expect do
            Timeout.timeout(3, blocking_exception_class) do
              subject.filter(event)
            end
          end.to raise_exception(blocking_exception_class)
        end
      end
    end
  end
end