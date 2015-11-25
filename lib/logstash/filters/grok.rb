  # encoding: utf-8
  require "logstash/filters/base"
  require "logstash/namespace"
  require "logstash/environment"
  require "logstash/patterns/core"
  require "set"

  # Parse arbitrary text and structure it.
  #
  # Grok is currently the best way in logstash to parse crappy unstructured log
  # data into something structured and queryable.
  #
  # This tool is perfect for syslog logs, apache and other webserver logs, mysql
  # logs, and in general, any log format that is generally written for humans
  # and not computer consumption.
  #
  # Logstash ships with about 120 patterns by default. You can find them here:
  # <https://github.com/logstash-plugins/logstash-patterns-core/tree/master/patterns>. You can add
  # your own trivially. (See the `patterns_dir` setting)
  #
  # If you need help building patterns to match your logs, you will find the
  # <http://grokdebug.herokuapp.com> and <http://grokconstructor.appspot.com/> applications quite useful!
  #
  # ==== Grok Basics
  #
  # Grok works by combining text patterns into something that matches your
  # logs.
  #
  # The syntax for a grok pattern is `%{SYNTAX:SEMANTIC}`
  #
  # The `SYNTAX` is the name of the pattern that will match your text. For
  # example, `3.44` will be matched by the `NUMBER` pattern and `55.3.244.1` will
  # be matched by the `IP` pattern. The syntax is how you match.
  #
  # The `SEMANTIC` is the identifier you give to the piece of text being matched.
  # For example, `3.44` could be the duration of an event, so you could call it
  # simply `duration`. Further, a string `55.3.244.1` might identify the `client`
  # making a request.
  #
  # For the above example, your grok filter would look something like this:
  # [source,ruby]
  # %{NUMBER:duration} %{IP:client}
  #
  # Optionally you can add a data type conversion to your grok pattern. By default
  # all semantics are saved as strings. If you wish to convert a semantic's data type,
  # for example change a string to an integer then suffix it with the target data type.
  # For example `%{NUMBER:num:int}` which converts the `num` semantic from a string to an
  # integer. Currently the only supported conversions are `int` and `float`.
  #
  # .Examples:
  #
  # With that idea of a syntax and semantic, we can pull out useful fields from a
  # sample log like this fictional http request log:
  # [source,ruby]
  #     55.3.244.1 GET /index.html 15824 0.043
  #
  # The pattern for this could be:
  # [source,ruby]
  #     %{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}
  #
  # A more realistic example, let's read these logs from a file:
  # [source,ruby]
  #     input {
  #       file {
  #         path => "/var/log/http.log"
  #       }
  #     }
  #     filter {
  #       grok {
  #         match => { "message" => "%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}" }
  #       }
  #     }
  #
  # After the grok filter, the event will have a few extra fields in it:
  #
  # * `client: 55.3.244.1`
  # * `method: GET`
  # * `request: /index.html`
  # * `bytes: 15824`
  # * `duration: 0.043`
  #
  # ==== Regular Expressions
  #
  # Grok sits on top of regular expressions, so any regular expressions are valid
  # in grok as well. The regular expression library is Oniguruma, and you can see
  # the full supported regexp syntax https://github.com/kkos/oniguruma/blob/master/doc/RE[on the Onigiruma
  # site].
  #
  # ==== Custom Patterns
  #
  # Sometimes logstash doesn't have a pattern you need. For this, you have
  # a few options.
  #
  # First, you can use the Oniguruma syntax for named capture which will
  # let you match a piece of text and save it as a field:
  # [source,ruby]
  #     (?<field_name>the pattern here)
  #
  # For example, postfix logs have a `queue id` that is an 10 or 11-character
  # hexadecimal value. I can capture that easily like this:
  # [source,ruby]
  #     (?<queue_id>[0-9A-F]{10,11})
  #
  # Alternately, you can create a custom patterns file.
  #
  # * Create a directory called `patterns` with a file in it called `extra`
  #   (the file name doesn't matter, but name it meaningfully for yourself)
  # * In that file, write the pattern you need as the pattern name, a space, then
  #   the regexp for that pattern.
  #
  # For example, doing the postfix queue id example as above:
  # [source,ruby]
  #     # contents of ./patterns/postfix:
  #     POSTFIX_QUEUEID [0-9A-F]{10,11}
  #
  # Then use the `patterns_dir` setting in this plugin to tell logstash where
  # your custom patterns directory is. Here's a full example with a sample log:
  # [source,ruby]
  #     Jan  1 06:25:43 mailserver14 postfix/cleanup[21403]: BEF25A72965: message-id=<20130101142543.5828399CCAF@mailserver14.example.com>
  # [source,ruby]
  #     filter {
  #       grok {
  #         patterns_dir => "./patterns"
  #         match => { "message" => "%{SYSLOGBASE} %{POSTFIX_QUEUEID:queue_id}: %{GREEDYDATA:syslog_message}" }
  #       }
  #     }
  #
  # The above will match and result in the following fields:
  #
  # * `timestamp: Jan  1 06:25:43`
  # * `logsource: mailserver14`
  # * `program: postfix/cleanup`
  # * `pid: 21403`
  # * `queue_id: BEF25A72965`
  # * `syslog_message: message-id=<20130101142543.5828399CCAF@mailserver14.example.com>`
  #
  # The `timestamp`, `logsource`, `program`, and `pid` fields come from the
  # `SYSLOGBASE` pattern which itself is defined by other patterns.
  class LogStash::Filters::Grok < LogStash::Filters::Base
    config_name "grok"

    # Specify a pattern to parse with. This will match the `message` field.
    #
    # If you want to match other fields than message, use the `match` setting.
    # Multiple patterns is fine.
    config :pattern, :validate => :array, :deprecated => "You should use this instead: match => { \"message\" => \"your pattern here\" }"

    # A hash of matches of field => value
    #
    # For example:
    # [source,ruby]
    #     filter {
    #       grok { match => { "message" => "Duration: %{NUMBER:duration}" } }
    #     }
    #
    # If you need to match multiple patterns against a single field, the value can be an array of patterns
    # [source,ruby]
    #     filter {
    #       grok { match => { "message" => [ "Duration: %{NUMBER:duration}", "Speed: %{NUMBER:speed}" ] } }
    #     }

    #
    config :match, :validate => :hash, :default => {}

    #
    # Logstash ships by default with a bunch of patterns, so you don't
    # necessarily need to define this yourself unless you are adding additional
    # patterns. You can point to multiple pattern directories using this setting
    # Note that Grok will read all files in the directory and assume its a pattern
    # file (including any tilde backup files)
    # [source,ruby]
    #     patterns_dir => ["/opt/logstash/patterns", "/opt/logstash/extra_patterns"]
    #
    # Pattern files are plain text with format:
    # [source,ruby]
    #     NAME PATTERN
    #
    # For example:
    # [source,ruby]
    #     NUMBER \d+
    config :patterns_dir, :validate => :array, :default => []

    # Break on first match. The first successful match by grok will result in the
    # filter being finished. If you want grok to try all patterns (maybe you are
    # parsing different things), then set this to false.
    config :break_on_match, :validate => :boolean, :default => true

    # If `true`, only store named captures from grok.
    config :named_captures_only, :validate => :boolean, :default => true

    # If `true`, keep empty captures as event fields.
    config :keep_empty_captures, :validate => :boolean, :default => false

    # If `true`, make single-value fields simply that value, not an array
    # containing that one value.
    config :singles, :validate => :boolean, :default => true, :deprecated => "This behavior is the default now, you don't need to set it."

    # Append values to the `tags` field when there has been no
    # successful match
    config :tag_on_failure, :validate => :array, :default => ["_grokparsefailure"]

    # The fields to overwrite.
    #
    # This allows you to overwrite a value in a field that already exists.
    #
    # For example, if you have a syslog line in the `message` field, you can
    # overwrite the `message` field with part of the match like so:
    # [source,ruby]
    #     filter {
    #       grok {
    #         match => { "message" => "%{SYSLOGBASE} %{DATA:message}" }
    #         overwrite => [ "message" ]
    #       }
    #     }
    #
    # In this case, a line like `May 29 16:37:11 sadness logger: hello world`
    # will be parsed and `hello world` will overwrite the original message.
    config :overwrite, :validate => :array, :default => []

    # Register default pattern paths
    @@patterns_path ||= Set.new
    @@patterns_path += [
      LogStash::Patterns::Core.path,
      LogStash::Environment.pattern_path("*")
    ]

    public
    def initialize(params)
      super(params)
      @match["message"] ||= []
      @match["message"] += @pattern if @pattern # the config 'pattern' value (array)
      # a cache of capture name handler methods.
      @handlers = {}
    end

    public
    def register
      require "grok-pure" # rubygem 'jls-grok'

      @patternfiles = []

      # Have @@patterns_path show first. Last-in pattern definitions win; this
      # will let folks redefine built-in patterns at runtime.
      @patterns_dir = @@patterns_path.to_a + @patterns_dir
      @logger.info? and @logger.info("Grok patterns path", :patterns_dir => @patterns_dir)
      @patterns_dir.each do |path|
        if File.directory?(path)
          path = File.join(path, "*")
        end

        Dir.glob(path).each do |file|
          @logger.info? and @logger.info("Grok loading patterns from file", :path => file)
          @patternfiles << file
        end
      end

      @patterns = Hash.new { |h,k| h[k] = [] }

      @logger.info? and @logger.info("Match data", :match => @match)

      @match.each do |field, patterns|
        patterns = [patterns] if patterns.is_a?(String)

        @logger.info? and @logger.info("Grok compile", :field => field, :patterns => patterns)
        patterns.each do |pattern|
          @logger.debug? and @logger.debug("regexp: #{@type}/#{field}", :pattern => pattern)
          grok = Grok.new
          grok.logger = @logger unless @logger.nil?
          add_patterns_from_files(@patternfiles, grok)
          grok.compile(pattern, @named_captures_only)
          @patterns[field] << grok
        end
      end # @match.each
    end # def register

    public
    def filter(event)


      matched = false
      done = false

      @logger.debug? and @logger.debug("Running grok filter", :event => event);
      @patterns.each do |field, groks|
        if match(groks, field, event)
          matched = true
          break if @break_on_match
        end
        #break if done
      end # @patterns.each

      if matched
        filter_matched(event)
      else
        @tag_on_failure.each{|tag| event.tag(tag)}
      end

      @logger.debug? and @logger.debug("Event now: ", :event => event)
    end # def filter

    private
    def match(groks, field, event)
      input = event[field]
      if input.is_a?(Array)
        success = false
        input.each do |input|
          success |= match_against_groks(groks, input, event)
        end
        return success
      else
        return match_against_groks(groks, input, event)
      end
    rescue StandardError => e
      @logger.warn("Grok regexp threw exception", :exception => e.message)
    end

    private
    def match_against_groks(groks, input, event)
      matched = false
      groks.each do |grok|
        # Convert anything else to string (number, hash, etc)
        matched = grok.match_and_capture(input.to_s) do |field, value|
          matched = true
          handle(field, value, event)
        end
        break if matched and @break_on_match
      end
      return matched
    end

    private
    def handle(field, value, event)
      return if (value.nil? || (value.is_a?(String) && value.empty?)) unless @keep_empty_captures

      if @overwrite.include?(field)
        event[field] = value
      else
        v = event[field]
        if v.nil?
          event[field] = value
        elsif v.is_a?(Array)
          # do not replace the code below with:
          #   event[field] << value
          # this assumes implementation specific feature of returning a mutable object
          # from a field ref which should not be assumed and will change in the future.
          v << value
          event[field] = v
        elsif v.is_a?(String)
          # Promote to array since we aren't overwriting.
          event[field] = [v, value]
        end
      end
    end

    private
    def add_patterns_from_files(paths, grok)
      paths.each do |path|
        if !File.exists?(path)
          raise "Grok pattern file does not exist: #{path}"
        end
        grok.add_patterns_from_file(path)
      end
    end # def add_patterns_from_files

  end # class LogStash::Filters::Grok
