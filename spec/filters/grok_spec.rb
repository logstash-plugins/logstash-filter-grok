# encoding: utf-8
require_relative "../spec_helper"

require "logstash/filters/grok"

describe LogStash::Filters::Grok do
  subject { described_class.new(config) }
  let(:config) { {} }
  let(:event) { LogStash::Event.new(data) }
  let(:data) { { "message" => message } }

  before(:each) do
    subject.register
    subject.filter(event)
  end

  def self.sample(message, &block)
    # mod = RSpec::Core::MemoizedHelpers.module_for(self)
    # mod.attr_reader :message
    # # mod.__send__(:define_method, :message) { message }
    # it("matches: #{message}") { @message = message; block.call }
    describe message do
      let(:message) { message }
      it("groks", &block)
    end
  end

  describe "simple syslog line" do
    let(:config) { { "match" => { "message" => "%{SYSLOGLINE}" }, "overwrite" => [ "message" ] } }
    let(:message) { 'Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]' }

    it "matches pattern" do
      expect( event.get("tags") ).to be nil
      expect( event.get("logsource") ).to eql "evita"
      expect( event.get("timestamp") ).to eql "Mar 16 00:01:25"
      expect( event.get("message") ).to eql "connect from camomile.cloud9.net[168.100.1.3]"
      expect( event.get("program") ).to eql "postfix/smtpd"
      expect( event.get("pid") ).to eql "1713"
    end
  end

  describe "ietf 5424 syslog line" do
    let(:config) { { "match" => { "message" => "%{SYSLOG5424LINE}" } } }

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug 4123 - [id1 foo=\"bar\"][id2 baz=\"something\"] Hello, syslog." do
      expect( event.get("tags") ).to be nil
      expect( event.get("syslog5424_pri") ).to eql "191"
      expect( event.get("syslog5424_ver") ).to eql "1"
      expect( event.get("syslog5424_ts") ).to eql "2009-06-30T18:30:00+02:00"
      expect( event.get("syslog5424_host") ).to eql "paxton.local"
      expect( event.get("syslog5424_app") ).to eql "grokdebug"
      expect( event.get("syslog5424_proc") ).to eql "4123"
      expect( event.get("syslog5424_msgid") ).to be nil
      expect( event.get("syslog5424_sd") ).to eql "[id1 foo=\"bar\"][id2 baz=\"something\"]"
      expect( event.get("syslog5424_msg") ).to eql "Hello, syslog."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug - - [id1 foo=\"bar\"] No process ID." do
      expect( event.get("tags") ).to be nil
      expect( event.get("syslog5424_pri") ).to eql "191"
      expect( event.get("syslog5424_ver") ).to eql "1"
      expect( event.get("syslog5424_ts") ).to eql "2009-06-30T18:30:00+02:00"
      expect( event.get("syslog5424_host") ).to eql "paxton.local"
      expect( event.get("syslog5424_app") ).to eql "grokdebug"
      expect( event.get("syslog5424_proc") ).to be nil
      expect( event.get("syslog5424_msgid") ).to be nil
      expect( event.get("syslog5424_sd") ).to eql "[id1 foo=\"bar\"]"
      expect( event.get("syslog5424_msg") ).to eql "No process ID."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug 4123 - - No structured data." do
      expect( event.get("tags") ).to be nil
      expect( event.get("syslog5424_pri") ).to eql "191"
      expect( event.get("syslog5424_ver") ).to eql "1"
      expect( event.get("syslog5424_ts") ).to eql "2009-06-30T18:30:00+02:00"
      expect( event.get("syslog5424_host") ).to eql "paxton.local"
      expect( event.get("syslog5424_app") ).to eql "grokdebug"
      expect( event.get("syslog5424_proc") ).to eql '4123'
      expect( event.get("syslog5424_msgid") ).to be nil
      expect( event.get("syslog5424_sd") ).to be nil
      expect( event.get("syslog5424_msg") ).to eql "No structured data."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug - - - No PID or SD." do
      expect( event.get("tags") ).to be nil
      expect( event.get("syslog5424_pri") ).to eql "191"
      expect( event.get("syslog5424_ver") ).to eql "1"
      expect( event.get("syslog5424_ts") ).to eql "2009-06-30T18:30:00+02:00"
      expect( event.get("syslog5424_host") ).to eql "paxton.local"
      expect( event.get("syslog5424_app") ).to eql "grokdebug"
      expect( event.get("syslog5424_proc") ).to be nil
      expect( event.get("syslog5424_msgid") ).to be nil
      expect( event.get("syslog5424_sd") ).to be nil
      expect( event.get("syslog5424_msg") ).to eql "No PID or SD."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug 4123 -  Missing structured data." do
      expect( event.get("tags") ).to be nil

      expect( event.get("syslog5424_proc") ).to eql '4123'
      expect( event.get("syslog5424_msgid") ).to be nil
      expect( event.get("syslog5424_sd") ).to be nil
      expect( event.get("syslog5424_msg") ).to eql "Missing structured data."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug  4123 - - Additional spaces." do
      expect( event.get("tags") ).to be nil

      expect( event.get("syslog5424_app") ).to eql "grokdebug"
      expect( event.get("syslog5424_proc") ).to eql '4123'
      expect( event.get("syslog5424_msgid") ).to be nil
      expect( event.get("syslog5424_sd") ).to be nil
      expect( event.get("syslog5424_msg") ).to eql "Additional spaces."
    end

    sample "<191>1 2009-06-30T18:30:00+02:00 paxton.local grokdebug  4123 -  Additional spaces and missing SD." do
      expect( event.get("tags") ).to be nil

      expect( event.get("syslog5424_app") ).to eql "grokdebug"
      expect( event.get("syslog5424_proc") ).to eql '4123'
      expect( event.get("syslog5424_msgid") ).to be nil
      expect( event.get("syslog5424_sd") ).to be nil
      expect( event.get("syslog5424_msg") ).to eql "Additional spaces and missing SD."
    end

    sample "<30>1 2014-04-04T16:44:07+02:00 osctrl01 dnsmasq-dhcp 8048 - -  Appname contains a dash" do
      expect( event.get("tags") ).to be nil
      expect( event.get("syslog5424_pri") ).to eql "30"
      expect( event.get("syslog5424_ver") ).to eql "1"
      expect( event.get("syslog5424_ts") ).to eql "2014-04-04T16:44:07+02:00"
      expect( event.get("syslog5424_host") ).to eql "osctrl01"
      expect( event.get("syslog5424_app") ).to eql "dnsmasq-dhcp"
      expect( event.get("syslog5424_proc") ).to eql "8048"
      expect( event.get("syslog5424_msgid") ).to be nil
      expect( event.get("syslog5424_sd") ).to be nil
      expect( event.get("syslog5424_msg") ).to eql "Appname contains a dash"
    end

    sample "<30>1 2014-04-04T16:44:07+02:00 osctrl01 - 8048 - -  Appname is nil" do
      expect( event.get("tags") ).to be nil
      expect( event.get("syslog5424_pri") ).to eql "30"
      expect( event.get("syslog5424_ver") ).to eql "1"
      expect( event.get("syslog5424_ts") ).to eql "2014-04-04T16:44:07+02:00"
      expect( event.get("syslog5424_host") ).to eql "osctrl01"
      expect( event.get("syslog5424_app") ).to be nil
      expect( event.get("syslog5424_proc") ).to eql "8048"
      expect( event.get("syslog5424_msgid") ).to be nil
      expect( event.get("syslog5424_sd") ).to be nil
      expect( event.get("syslog5424_msg") ).to eql "Appname is nil"
    end
  end

  describe "parsing an event with multiple messages (array of strings)", if: false do
    let(:config) { { "message" => "(?:hello|world) %{NUMBER}" } }
    let(:message) { [ "hello 12345", "world 23456" ] }

    it "matches them all" do
      expect( event.get("NUMBER") ).to eql [ "12345", "23456" ]
    end
  end

  describe "coercing matched values" do
    let(:config) { { "match" => { "message" => "%{NUMBER:foo:int} %{NUMBER:bar:float}" } } }
    let(:message) { '400 454.33' }

    it "coerces matched values" do
      expect( event.get("foo") ).to be_a Integer
      expect( event.get("foo") ).to eql 400
      expect( event.get("bar") ).to be_a Float
      expect( event.get("bar") ).to eql 454.33
    end
  end

  describe "in-line pattern definitions" do
    let(:config) { { "match" => { "message" => "%{FIZZLE=\\d+}" }, "named_captures_only" => false } }

    sample "hello 1234" do
      expect( event.get("FIZZLE") ).to eql '1234'
    end
  end

  describe "processing selected fields" do
    let(:config) {
      {
        'match' => { "message" => "%{WORD:word}", "examplefield" => "%{NUMBER:num}" },
        'break_on_match' => false
      }
    }
    let(:data) { { "message" => "hello world", "examplefield" => "12345" } }

    it "processes declared matches" do
      expect( event.get("word") ).to eql 'hello'
      expect( event.get("examplefield") ).to eql '12345'
    end
  end

  describe "adding fields on match" do
    let(:config) {
      {
        'match' => { "message" => "matchme %{NUMBER:fancy}" },
        'add_field' => [ "new_field", "%{fancy}" ]
      }
    }

    sample "matchme 1234" do
      expect( event.get("tags") ).to be nil
      expect( event.get("new_field") ).to eql "1234"
    end

    sample "this will not be matched" do
      expect( event.get("tags") ).to include("_grokparsefailure")
      expect( event ).not_to include 'new_field'
    end
  end

  context "empty fields" do
    describe "drop by default" do
      let(:config) {
        {
          'match' => { "message" => "1=%{WORD:foo1} *(2=%{WORD:foo2})?" }
        }
      }

      sample "1=test" do
        expect( event.get("tags") ).to be nil
        expect( event ).to include 'foo1'

        # Since 'foo2' was not captured, it must not be present in the event.
        expect( event ).not_to include 'foo2'
      end
    end

    describe "keep if keep_empty_captures is true" do
      let(:config) {
        {
          'match' => { "message" => "1=%{WORD:foo1} *(2=%{WORD:foo2})?" },
          'keep_empty_captures' => true
        }
      }

      sample "1=test" do
        expect( event.get("tags") ).to be nil
        # use .to_hash for this test, for now, because right now
        # the Event.include? returns false for missing fields as well
        # as for fields with nil values.
        expect( event.to_hash ).to include 'foo1'
        expect( event.to_hash ).to include 'foo2'
      end
    end
  end

  describe "when named_captures_only == false" do
    let(:config) {
      {
        'match' => { "message" => "Hello %{WORD}. %{WORD:foo}" },
        'named_captures_only' => false
      }
    }

    sample "Hello World, yo!" do
      expect( event ).to include 'WORD'
      expect( event.get("WORD") ).to eql "World"
      expect( event ).to include 'foo'
      expect( event.get("foo") ).to eql "yo"
    end
  end

  describe "using oniguruma named captures (?<name>regex)" do
    context "plain regexp" do
      let(:config) {
        {
          'match' => { "message" => "(?<foo>\\w+)" }
        }
      }

      sample "hello world" do
        expect( event.get("tags") ).to be nil
        expect( event.get("foo") ).to eql "hello"
      end
    end

    context "grok patterns" do
      let(:config) {
        {
          'match' => { "message" => "(?<timestamp>%{DATE_EU} %{TIME})" }
        }
      }

      sample "fancy 12-12-12 12:12:12" do
        expect( event.get("tags") ).to be nil
        expect( event.get("timestamp") ).to eql "12-12-12 12:12:12"
      end
    end
  end

  describe "grok on integer types" do
    let(:config) {
      {
        'match' => { "status" => "^403$" }, 'add_tag' => "four_oh_three"
      }
    }
    let(:data) { Hash({ "status" => 403 }) }

    it "parses" do
      expect( event.get("tags") ).not_to include "_grokparsefailure"
      expect( event.get("tags") ).to include "four_oh_three"
    end
  end

  describe "grok on float types" do
    let(:config) {
      {
        'match' => { "version" => "^1.0$" }, 'add_tag' => "one_point_oh"
      }
    }
    let(:data) { Hash({ "version" => 1.0 }) }

    it "parses" do
      expect( event.get("tags") ).not_to include "_grokparsefailure"
      expect( event.get("tags") ).to include "one_point_oh"
    end
  end

  describe "grok on %{LOGLEVEL}" do
    let(:config) {
      {
        'match' => { "message" => "%{LOGLEVEL:level}: error!" }
      }
    }

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
        expect( event.get("level") ).to eql level_name
      end
    end
  end

  describe "timeout on failure" do
    let(:config) {
      {
        'match' => { "message" => "(.*a){30}" },
        'timeout_millis' => 100
      }
    }

    sample "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" do
      expect( event.get("tags") ).to include("_groktimeout")
      expect( event.get("tags") ).not_to include("_grokparsefailure")
    end
  end

  describe "no timeout on failure with multiple patterns (when timeout not grouped)" do
    let(:config) {
      {
        'match' => {
          "message" => [
            "(.*f){20}", "(.*e){20}", "(.*d){20}", "(.*c){20}", "(.*b){20}",
            "(.*a){25}", "(.*a){24}", "(.*a){23}", "(.*a){22}", "(.*a){21}",
            "(.*a){20}"
          ]
        },
        'timeout_millis' => 500,
        'timeout_scope' => 'pattern'
      }
    }

    sample( 'b' * 10 + 'c' * 10 + 'd' * 10 + 'e' * 10 + ' ' + 'a' * 20 ) do
      expect( event.get("tags") ).to be nil
    end
  end

  describe "timeout on grouped (multi-pattern) failure" do
    let(:config) {
      {
        'match' => {
          "message" => [
            "(.*f){20}", "(.*e){20}", "(.*d){20}", "(.*c){20}", "(.*b){20}",
            "(.*a){25}", "(.*a){24}", "(.*a){23}", "(.*a){22}", "(.*a){21}",
            "(.*a){20}"
          ]
        },
        'timeout_millis' => 500,
        'timeout_scope' => 'event'
      }
    }

    sample( 'b' * 10 + 'c' * 10 + 'd' * 10 + 'e' * 10 + ' ' + 'a' * 20 ) do
      expect( event.get("tags") ).to include("_groktimeout")
      expect( event.get("tags") ).not_to include("_grokparsefailure")
    end
  end

  describe "tagging on failure" do
    let(:config) {
      {
        'match' => { "message" => "matchme %{NUMBER:fancy}" },
        'tag_on_failure' => 'not_a_match'
      }
    }

    sample "matchme 1234" do
      expect( event.get("tags") ).to be nil
    end

    sample "this will not be matched" do
      expect( event.get("tags") ).to include("not_a_match")
    end
  end

  describe "captures named fields even if the whole text matches" do
    let(:config) {
      {
        'match' => { "message" => "%{DATE_EU:stimestamp}" }
      }
    }

    sample "11/01/01" do
      expect( event.get("stimestamp") ).to eql "11/01/01"
    end
  end

  describe "allow dashes in capture names" do
    let(:config) {
      {
        'match' => { "message" => "%{WORD:foo-bar}" }
      }
    }

    sample "hello world" do
      expect( event.get("foo-bar") ).to eql "hello"
    end
  end

  describe "single value match with duplicate-named fields in pattern" do
    let(:config) {
      {
        'match' => { "message" => "%{INT:foo}|%{WORD:foo}" }
      }
    }

    sample "hello world" do
      expect( event.get("foo") ).to be_a(String)
    end

    sample "123 world" do
      expect( event.get("foo") ).to be_a(String)
    end
  end


  describe "break_on_match default should be true" do
    let(:config) {
      {
        'match' => { "message" => "%{INT:foo}", "somefield" => "%{INT:bar}" }
      }
    }
    let(:data) { Hash("message" => "hello world 123", "somefield" => "testme abc 999") }

    it 'exits filter after first match' do
      expect( event.get("foo") ).to eql '123'
      expect( event.get("bar") ).to be nil
    end
  end

  describe "break_on_match when set to false" do
    let(:config) {
      {
        'match' => { "message" => "%{INT:foo}", "somefield" => "%{INT:bar}" },
        'break_on_match' => false
      }
    }
    let(:data) { Hash("message" => "hello world 123", "somefield" => "testme abc 999") }

    it 'should try all patterns' do
      expect( event.get("foo") ).to eql '123'
      expect( event.get("bar") ).to eql '999'
    end
  end

  context "break_on_match default for array input with single grok pattern" do
    let(:config) {
      {
        'match' => { "message" => "%{INT:foo}" },
        'break_on_match' => false
      }
    }

    describe 'fully matching input' do
      let(:data) { Hash("message" => ["hello world 123", "line 23"]) } # array input --
      it 'matches' do
        expect( event.get("foo") ).to eql ["123", "23"]
        expect( event.get("tags") ).to be nil
      end
    end

    describe 'partially matching input' do
      let(:data) { Hash("message" => ["hello world 123", "abc"]) } # array input, one of them matches
      it 'matches' do
        expect( event.get("foo") ).to eql "123"
        expect( event.get("tags") ).to be nil
      end
    end
  end

  describe "break_on_match = true (default) for array input with multiple grok pattern" do
    let(:config) {
      {
        'match' => { "message" => ["%{INT:foo}", "%{WORD:bar}"] }
      }
    }

    describe 'matching input' do
      let(:data) { Hash("message" => ["hello world 123", "line 23"]) } # array input --
      it 'matches' do
        expect( event.get("foo") ).to eql ["123", "23"]
        expect( event.get("bar") ).to be nil
        expect( event.get("tags") ).to be nil
      end
    end

    describe 'partially matching input' do
      let(:data) { Hash("message" => ["hello world", "line 23"]) } # array input, one of them matches
      it 'matches' do
        expect( event.get("bar") ).to eql 'hello'
        expect( event.get("foo") ).to eql "23"
        expect( event.get("tags") ).to be nil
      end
    end
  end

  describe "break_on_match = false for array input with multiple grok pattern" do
    let(:config) {
      {
        'match' => { "message" => ["%{INT:foo}", "%{WORD:bar}"] },
        'break_on_match' => false
      }
    }

    describe 'fully matching input' do
      let(:data) { Hash("message" => ["hello world 123", "line 23"]) } # array input --
      it 'matches' do
        expect( event.get("foo") ).to eql ["123", "23"]
        expect( event.get("bar") ).to eql ["hello", "line"]
        expect( event.get("tags") ).to be nil
      end
    end

    describe 'partially matching input' do
      let(:data) { Hash("message" => ["hello world", "line 23"]) } # array input, one of them matches
      it 'matches' do
        expect( event.get("bar") ).to eql ["hello", "line"]
        expect( event.get("foo") ).to eql "23"
        expect( event.get("tags") ).to be nil
      end
    end
  end

  describe  "grok with unicode" do
    let(:config) {
      {
        #'match' => { "message" => "<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{PROG:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
        'match' => { "message" => "<%{POSINT:syslog_pri}>%{SPACE}%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{PROG:syslog_program}(:?)(?:\\[%{GREEDYDATA:syslog_pid}\\])?(:?) %{GREEDYDATA:syslog_message}" }
      }
    }

    sample "<22>Jan  4 07:50:46 mailmaster postfix/policy-spf[9454]: : SPF permerror (Junk encountered in record 'v=spf1 mx a:mail.domain.no ip4:192.168.0.4 �all'): Envelope-from: email@domain.no" do
      expect( event.get("tags") ).to be nil
      expect( event.get("syslog_pri") ).to eql "22"
      expect( event.get("syslog_program") ).to eql "postfix/policy-spf"
    end
  end

  describe  "grok with nil coerced value" do
    let(:config) {
      {
        'match' => { "message" => "test (N/A|%{BASE10NUM:duration:float}ms)" }
      }
    }

    sample "test 28.4ms" do
      expect( event.get("duration") ).to eql 28.4
      expect( event.get("tags") ).to be nil
    end

    sample "test N/A" do
      expect( event.to_hash ).not_to include("duration")
      expect( event.get("tags") ).to be nil
    end

    sample "test abc" do
      expect( event.get("duration") ).to be nil
      expect( event.get("tags") ).to eql ["_grokparsefailure"]
    end
  end

  describe  "grok with nil coerced value and keep_empty_captures" do
    let(:config) {
      {
        'match' => { "message" => "test (N/A|%{BASE10NUM:duration:float}ms)" },
        'keep_empty_captures' => true
      }
    }

    sample "test N/A" do
      expect( event.to_hash ).to include("duration")
      expect( event.get("tags") ).to be nil
    end
  end

  describe  "grok with no coercion" do
    let(:config) {
      {
        'match' => { "message" => "test (N/A|%{BASE10NUM:duration}ms)" },
      }
    }

    sample "test 28.4ms" do
      expect( event.get("duration") ).to eql '28.4'
      expect( event.get("tags") ).to be nil
    end

    sample "test N/A" do
      expect( event.get("duration") ).to be nil
      expect( event.get("tags") ).to be nil
    end
  end

  describe "opening/closing" do
    let(:config) { { "match" => {"message" => "A"} } }
    let(:message) { 'AAA' }

    it "should close cleanly" do
      expect { subject.do_close }.not_to raise_error
    end
  end

  describe "after grok when the event is JSON serialised the field values are unchanged" do
    let(:config) {
      {
        'match' => ["message", "Failed password for (invalid user |)%{USERNAME:username} from %{IP:src_ip} port %{BASE10NUM:port}"],
        'remove_field' => ["message","severity"],
        'add_tag' => ["ssh_failure"]
      }
    }

    sample('{"facility":"auth","message":"Failed password for testuser from 1.1.1.1 port 22"}') do
      expect( event.get("username") ).to eql "testuser"
      expect( event.get("port") ).to eql "22"
      expect( event.get("src_ip") ).to eql "1.1.1.1"
      expect( LogStash::Json.dump(event.get('username')) ).to eql "\"testuser\""

      expect( event.to_json ).to match %r|"src_ip":"1.1.1.1"|
      expect( event.to_json ).to match %r|"@timestamp":"20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ"|
      expect( event.to_json ).to match %r|"port":"22"|
      expect( event.to_json ).to match %r|"@version":"1"|
      expect( event.to_json ).to match %r|"username"|i
      expect( event.to_json ).to match %r|"testuser"|
      expect( event.to_json ).to match %r|"tags":\["ssh_failure"\]|
    end
  end

  describe  "grok with inline pattern definition successfully extracts fields" do
    let(:config) {
      {
        'match' => { "message" => "%{APACHE_TIME:timestamp} %{LOGLEVEL:level} %{MY_PATTERN:hindsight}" },
        'pattern_definitions' => {
          "APACHE_TIME" => "%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}",
          "MY_PATTERN" => "%{YEAR}"
        }
      }
    }

    sample "Mon Dec 26 16:22:08 2016 error 2020" do
      expect( event.get("timestamp") ).to eql "Mon Dec 26 16:22:08 2016"
      expect( event.get("level") ).to eql "error"
      expect( event.get("hindsight") ).to eql "2020"
    end
  end

  describe  "grok with inline pattern definition overwrites existing pattern definition" do
    let(:config) {
      {
        'match' => { "message" => "%{APACHE_TIME:timestamp} %{LOGLEVEL:level}" },
        # loglevel was previously ([Aa]lert|ALERT|[Tt]...
        'pattern_definitions' => {
          "APACHE_TIME" => "%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{YEAR}",
          "LOGLEVEL" => "%{NUMBER}"
        }
      }
    }

    sample "Mon Dec 26 16:22:08 2016 9999" do
      expect( event.get("timestamp") ).to eql "Mon Dec 26 16:22:08 2016"
      expect( event.get("level") ).to eql "9999"
    end
  end

  context 'when timeouts are explicitly disabled' do
    let(:config) do
      {
        "timeout_millis" => 0
      }
    end

    context 'when given a pathological input', slow: true do
      let(:message) { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
      let(:config) { super().merge("match" => { "message" => "(.*a){30}" }) }

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

describe LogStash::Filters::Grok do
  describe "(LEGACY)" do
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
  end
end